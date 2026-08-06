using System.Security.Cryptography;
using System.Text;
using CupriWebRTC.Dtls;
using CupriWebRTC.Dtls13;
using Xunit;

namespace CupriWebRTC.Tests;

/// <summary>
/// End-to-end DTLS 1.3 handshakes between <see cref="DtlsServer"/> and <see cref="TestDtls13Client"/> over a loopback
/// datagram pair, plus the version dispatch that decides which server role runs at all.
/// </summary>
public class Dtls13HandshakeTests
{
    /// <summary>Runs the server handshake on a background thread while the client drives it from this one.</summary>
    private static (ISecureDatagramTransport Server, TestDtls13Client Client, DtlsCertificate Certificate) Connect(
        Dtls13ServerOptions? options = null)
    {
        var certificate = DtlsCertificate.GenerateSelfSigned();
        var server = new DtlsServer(certificate, options);
        var (serverTransport, clientTransport) = InMemoryDatagramTransport.CreatePair();

        ISecureDatagramTransport? secured = null;
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try { secured = server.Accept(serverTransport); }
            catch (Exception ex) { failure = ex; }
        })
        { IsBackground = true };
        thread.Start();

        var client = new TestDtls13Client(clientTransport, requireHelloRetry: options?.CookieExchange ?? true);
        client.Handshake(TimeSpan.FromSeconds(15));

        Assert.True(thread.Join(TimeSpan.FromSeconds(15)), "the server handshake did not finish");
        if (failure is not null)
            throw new Xunit.Sdk.XunitException($"the server handshake failed: {failure}");
        Assert.NotNull(secured);
        Assert.Equal("DTLS 1.3", secured!.ProtocolVersion);
        return (secured!, client, certificate);
    }

    [Fact]
    public void Dtls13Handshake_Completes_AndCarriesApplicationDataBothWays()
    {
        var (server, client, _) = Connect();

        client.Send("hello dtls 1.3"u8);
        var buffer = new byte[2048];
        var n = server.Receive(buffer, 0, buffer.Length, 5000);
        Assert.Equal("hello dtls 1.3", Encoding.UTF8.GetString(buffer, 0, n));

        var reply = "hello back"u8.ToArray();
        server.Send(reply, 0, reply.Length);
        Assert.Equal("hello back", Encoding.UTF8.GetString(client.Receive(TimeSpan.FromSeconds(5))!));

        server.Close();
    }

    [Fact]
    public void Dtls13Handshake_PresentsTheCertificateWhoseFingerprintIsPublished()
    {
        var (server, client, certificate) = Connect();

        var presented = Assert.Single(client.ServerCertificateChain);
        Assert.Equal(certificate.Fingerprint, SHA256.HashData(presented));
        server.Close();
    }

    [Fact]
    public void Dtls13Handshake_NegotiatesAes128GcmByServerPreference()
    {
        var (server, client, _) = Connect();

        Assert.Equal(Dtls13CipherSuite.TlsAes128GcmSha256, client.NegotiatedCipherSuite.Id);
        server.Close();
    }

    [Fact]
    public void CookieExchange_IsOnByDefault_AndCostsOneExtraRoundTrip()
    {
        var (server, client, _) = Connect();

        Assert.True(client.SawHelloRetryRequest);
        server.Close();
    }

    [Fact]
    public void CookieExchange_CanBeTurnedOff_WhenIceAlreadyProvesReachability()
    {
        var (server, client, _) = Connect(new Dtls13ServerOptions { CookieExchange = false });

        Assert.False(client.SawHelloRetryRequest);
        client.Send("no retry needed"u8);
        var buffer = new byte[2048];
        var n = server.Receive(buffer, 0, buffer.Length, 5000);
        Assert.Equal("no retry needed", Encoding.UTF8.GetString(buffer, 0, n));
        server.Close();
    }

    [Fact]
    public void ServerAcceptsAPeerThatSendsNoCertificate()
    {
        var (server, client, _) = Connect(new Dtls13ServerOptions { RequestClientCertificate = false });

        client.Send("anonymous client"u8);
        var buffer = new byte[2048];
        var n = server.Receive(buffer, 0, buffer.Length, 5000);
        Assert.Equal("anonymous client", Encoding.UTF8.GetString(buffer, 0, n));
        server.Close();
    }

    [Fact]
    public void ManyMessages_FlowInOrder_OverTheSecuredTransport()
    {
        var (server, client, _) = Connect(new Dtls13ServerOptions { CookieExchange = false });

        for (var i = 0; i < 50; i++)
            client.Send(Encoding.UTF8.GetBytes($"message {i}"));

        var buffer = new byte[2048];
        for (var i = 0; i < 50; i++)
        {
            var n = server.Receive(buffer, 0, buffer.Length, 5000);
            Assert.Equal($"message {i}", Encoding.UTF8.GetString(buffer, 0, n));
        }
        server.Close();
    }

    [Fact]
    public void VersionDispatch_RoutesA13HelloTo13AndA12HelloTo12()
    {
        // The 1.2 leg is covered end-to-end by DtlsHandshakeTests; here we only pin the sniffing decision, which is
        // what a browser's DTLS-1.3-first ClientHello hinges on.
        var dtls13Hello = BuildClientHelloDatagram(offerDtls13: true);
        var dtls12Hello = BuildClientHelloDatagram(offerDtls13: false);

        Assert.True(Dtls13Peek.OffersDtls13(dtls13Hello));
        Assert.False(Dtls13Peek.OffersDtls13(dtls12Hello));
        Assert.False(Dtls13Peek.OffersDtls13([]));
        Assert.False(Dtls13Peek.OffersDtls13([0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5])); // an encrypted record
    }

    /// <summary>A minimal DTLSPlaintext record carrying a ClientHello, with or without DTLS 1.3 in supported_versions.</summary>
    private static byte[] BuildClientHelloDatagram(bool offerDtls13)
    {
        var body = new Dtls13Writer();
        body.WriteUInt16(0xFEFD);
        body.WriteBytes(new byte[32]);
        body.WriteVector8(ReadOnlySpan<byte>.Empty);
        body.WriteVector8(ReadOnlySpan<byte>.Empty);
        body.WriteUInt16(2);
        body.WriteUInt16(Dtls13CipherSuite.TlsAes128GcmSha256);
        body.WriteVector8([0]);
        var extensions = body.BeginVector16();
        body.WriteUInt16(43); // supported_versions
        var versions = body.BeginVector16();
        body.WriteUInt8(2);
        body.WriteUInt16(offerDtls13 ? (ushort)0xFEFC : (ushort)0xFEFD);
        body.EndVector(versions);
        body.EndVector(extensions);
        var helloBody = body.ToArray();

        var fragment = new byte[12 + helloBody.Length];
        fragment[0] = 1; // client_hello
        fragment[1] = (byte)(helloBody.Length >> 16);
        fragment[2] = (byte)(helloBody.Length >> 8);
        fragment[3] = (byte)helloBody.Length;
        fragment[9] = (byte)(helloBody.Length >> 16);
        fragment[10] = (byte)(helloBody.Length >> 8);
        fragment[11] = (byte)helloBody.Length;
        helloBody.CopyTo(fragment.AsSpan(12));

        var record = new byte[13 + fragment.Length];
        record[0] = 22;
        record[1] = 0xFE;
        record[2] = 0xFD;
        record[11] = (byte)(fragment.Length >> 8);
        record[12] = (byte)fragment.Length;
        fragment.CopyTo(record.AsSpan(13));
        return record;
    }
}
