using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CupriWebRTC;
using CupriWebRTC.Ice;
using CupriWebRTC.Sctp;
using CupriWebRTC.Stun;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Xunit;

namespace CupriWebRTC.Tests;

/// <summary>
/// Full-stack loopback: a real UDP client drives ICE → DTLS → SCTP against a <see cref="WebRtcListener"/> and sends a
/// message, using the listener's published <see cref="WebRtcEndpointParameters"/>. This is everything a browser does,
/// minus the browser.
/// </summary>
public class WebRtcListenerTests
{
    [Fact]
    public async Task FullStack_OverUdp_ClientConnects_VerifiesFingerprint_AndSendsMessage()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var ct = cts.Token;

        var credentials = new IceCredentials("srvUfrag0", "srv-password-abcdefghij");
        await using var listener = new WebRtcListener(new IPEndPoint(IPAddress.Loopback, 0), credentials);
        var run = listener.RunAsync(ct);

        var parameters = listener.Parameters;
        var server = listener.LocalEndPoint;

        var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        listener.MessageReceived += (_, _, data) => received.TrySetResult(data);

        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));

        // 1. ICE — a STUN Binding check keyed with the published password gets a Binding Success.
        var stunKey = Encoding.UTF8.GetBytes(parameters.IcePassword);
        var check = new StunMessage(StunMessageTypes.BindingRequest, StunMessage.NewTransactionId());
        check.Add(StunAttributes.Username, Encoding.UTF8.GetBytes($"{parameters.IceUfrag}:browser"));
        check.AddMessageIntegrity(stunKey);
        check.AddFingerprint();
        var checkBytes = check.Encode();
        udp.Send(checkBytes, checkBytes.Length, server);

        udp.Client.ReceiveTimeout = 5000;
        var from = new IPEndPoint(IPAddress.Any, 0);
        var stunReply = udp.Receive(ref from);
        Assert.True(StunMessage.TryParse(stunReply, out var stunResponse));
        Assert.Equal(StunMessageTypes.BindingSuccessResponse, stunResponse.MessageType);
        Assert.True(stunResponse.VerifyMessageIntegrity(stunKey));

        // 2. DTLS — connect as the client; verify the server cert matches the published fingerprint.
        var transport = new UdpDtlsClientTransport(udp, server);
        var client = new RecordingTlsClient(new BcTlsCrypto(new SecureRandom()));
        DtlsTransport clientDtls = null!;
        var dtlsThread = new Thread(() => clientDtls = new DtlsClientProtocol().Connect(client, transport)) { IsBackground = true };
        dtlsThread.Start();
        Assert.True(dtlsThread.Join(TimeSpan.FromSeconds(15)), "client DTLS handshake timed out");
        Assert.Equal(parameters.Fingerprint, client.ServerFingerprint);

        // 3. SCTP — initiate the association and send an application message.
        using var sctp = new SctpTransport(clientDtls, new SctpAssociation());
        sctp.Start();
        sctp.Associate();
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!sctp.IsEstablished && DateTime.UtcNow < deadline)
            Thread.Sleep(20);
        Assert.True(sctp.IsEstablished, "SCTP handshake timed out");

        sctp.SendMessage(0, Dcep.PpidString, "hello from the browser"u8.ToArray());

        Assert.True(received.Task.Wait(TimeSpan.FromSeconds(10)), "listener did not receive the message");
        Assert.Equal("hello from the browser", Encoding.UTF8.GetString(received.Task.Result));

        await cts.CancelAsync();
        try { await run; } catch (OperationCanceledException) { }
    }

    /// <summary>A DTLS-over-UDP transport for the "browser" side: sends to the server, receives only DTLS (skips STUN).</summary>
    private sealed class UdpDtlsClientTransport(UdpClient udp, IPEndPoint server) : DatagramTransport
    {
        public int GetReceiveLimit() => 1500;
        public int GetSendLimit() => 1500;

        public int Receive(byte[] buf, int off, int len, int waitMillis) => Receive(buf.AsSpan(off, len), waitMillis);

        public int Receive(Span<byte> buffer, int waitMillis)
        {
            var deadline = Environment.TickCount64 + waitMillis;
            while (true)
            {
                var remaining = (int)(deadline - Environment.TickCount64);
                if (remaining <= 0)
                    return -1;
                udp.Client.ReceiveTimeout = remaining;
                var from = new IPEndPoint(IPAddress.Any, 0);
                byte[] datagram;
                try { datagram = udp.Receive(ref from); }
                catch (SocketException) { return -1; }
                if (datagram.Length == 0)
                    continue;
                if (datagram[0] is >= 20 and <= 63) // DTLS (RFC 7983 demux); ignore stray STUN
                {
                    var n = Math.Min(buffer.Length, datagram.Length);
                    datagram.AsSpan(0, n).CopyTo(buffer);
                    return n;
                }
            }
        }

        public void Send(byte[] buf, int off, int len) => Send(buf.AsSpan(off, len));

        public void Send(ReadOnlySpan<byte> buffer)
        {
            var bytes = buffer.ToArray();
            udp.Send(bytes, bytes.Length, server);
        }

        public void Close() { }
    }

    /// <summary>A DTLS client that accepts any server cert but records its fingerprint (to compare with the published one).</summary>
    private sealed class RecordingTlsClient(BcTlsCrypto crypto) : DefaultTlsClient(crypto)
    {
        public byte[]? ServerFingerprint { get; private set; }

        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.DTLSv12.Only();

        public override TlsAuthentication GetAuthentication() => new Authentication(this);

        private sealed class Authentication(RecordingTlsClient client) : TlsAuthentication
        {
            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                var der = serverCertificate.Certificate.GetCertificateAt(0).GetEncoded();
                client.ServerFingerprint = SHA256.HashData(der);
            }

            public TlsCredentials? GetClientCredentials(CertificateRequest certificateRequest) => null;
        }
    }
}
