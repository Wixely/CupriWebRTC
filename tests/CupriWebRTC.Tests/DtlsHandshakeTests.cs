using System.Collections.Concurrent;
using System.Text;
using CupriWebRTC.Dtls;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Xunit;

namespace CupriWebRTC.Tests;

public class DtlsHandshakeTests
{
    [Fact]
    public void DtlsHandshake_Completes_AndCarriesAppData()
    {
        var certificate = DtlsCertificate.GenerateSelfSigned();
        var server = new DtlsServer(certificate);
        var (serverTransport, clientTransport) = InMemoryDatagramTransport.CreatePair();

        // Run the (blocking) server handshake on a background thread while the client connects on this one.
        ISecureDatagramTransport? serverSecured = null;
        Exception? serverError = null;
        var serverThread = new Thread(() =>
        {
            try { serverSecured = server.Accept(serverTransport); }
            catch (Exception ex) { serverError = ex; }
        })
        { IsBackground = true };
        serverThread.Start();

        var client = new TestTlsClient(new BcTlsCrypto(new SecureRandom()));
        var clientSecured = new DtlsClientProtocol().Connect(client, clientTransport);

        Assert.True(serverThread.Join(TimeSpan.FromSeconds(15)), "server handshake timed out");
        Assert.Null(serverError);
        Assert.NotNull(serverSecured);

        // Application data flows over the secured transport, both directions.
        var buffer = new byte[2048];
        clientSecured.Send("hello dtls"u8);
        var n = serverSecured!.Receive(buffer, 0, buffer.Length, 5000);
        Assert.Equal("hello dtls", Encoding.UTF8.GetString(buffer, 0, n));

        var reply = Encoding.UTF8.GetBytes("hello back");
        serverSecured.Send(reply, 0, reply.Length);
        var m = clientSecured.Receive(buffer, 5000);
        Assert.Equal("hello back", Encoding.UTF8.GetString(buffer, 0, m));

        clientSecured.Close();
        serverSecured.Close();
    }

    /// <summary>A minimal DTLS 1.2 client that accepts any server certificate and presents no client certificate.</summary>
    private sealed class TestTlsClient(BcTlsCrypto crypto) : DefaultTlsClient(crypto)
    {
        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.DTLSv12.Only();

        public override TlsAuthentication GetAuthentication() => new AcceptAnyAuthentication();

        private sealed class AcceptAnyAuthentication : TlsAuthentication
        {
            public void NotifyServerCertificate(TlsServerCertificate serverCertificate) { /* accept any */ }
            public TlsCredentials? GetClientCredentials(CertificateRequest certificateRequest) => null;
        }
    }
}
