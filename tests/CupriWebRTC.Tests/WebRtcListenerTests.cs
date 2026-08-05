using System.Collections.Concurrent;
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
/// Full-stack loopback: real UDP "browser" clients drive ICE → DTLS → SCTP against a <see cref="WebRtcListener"/>,
/// open a DataChannel (DCEP) and send a message, using the listener's published <see cref="WebRtcEndpointParameters"/>.
/// This is everything a browser does, minus the browser — including two clients sharing the listener's one UDP socket.
/// </summary>
public class WebRtcListenerTests
{
    [Fact]
    public async Task FullStack_OverUdp_ClientConnects_VerifiesFingerprint_OpensChannel_AndSendsMessage()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var ct = cts.Token;

        var credentials = new IceCredentials("srvUfrag0", "srv-password-abcdefghij");
        await using var listener = new WebRtcListener(new IPEndPoint(IPAddress.Loopback, 0), credentials);
        var run = listener.RunAsync(ct);

        var received = new TaskCompletionSource<(IPEndPoint Remote, byte[] Data)>(TaskCreationOptions.RunContinuationsAsynchronously);
        listener.ChannelOpened += channel =>
            channel.MessageReceived += (_, data) => received.TrySetResult((channel.Remote, data));

        using var browser = BrowserClient.Connect(listener.LocalEndPoint, listener.Parameters, "browser-solo");
        Assert.Equal(listener.Parameters.Fingerprint, browser.ServerFingerprint); // the browser pinned our published cert
        browser.OpenChannel("chat");
        browser.Send("hello from the browser");

        Assert.True(received.Task.Wait(TimeSpan.FromSeconds(10)), "listener did not receive the message");
        var (remote, data) = received.Task.Result;
        Assert.Equal("hello from the browser", Encoding.UTF8.GetString(data));
        Assert.Equal(browser.LocalEndPoint.Port, remote.Port); // surfaced with the peer's own source address
        Assert.Equal(1, listener.SessionCount);

        await cts.CancelAsync();
        try { await run; } catch (OperationCanceledException) { }
    }

    [Fact]
    public async Task FullStack_TwoClients_ShareOneSocket_EachDeliversItsOwnMessage()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        var ct = cts.Token;

        await using var listener = new WebRtcListener(new IPEndPoint(IPAddress.Loopback, 0));
        var run = listener.RunAsync(ct);

        var received = new ConcurrentBag<(int RemotePort, string Message)>();
        using var both = new CountdownEvent(2);
        listener.ChannelOpened += channel =>
            channel.MessageReceived += (_, data) =>
            {
                received.Add((channel.Remote.Port, Encoding.UTF8.GetString(data)));
                both.Signal();
            };

        // Two independent browsers (distinct ICE ufrags, as real browsers generate) on their own sockets, hitting the
        // listener's single UDP port concurrently.
        using var alice = BrowserClient.Connect(listener.LocalEndPoint, listener.Parameters, "alice-ufrag");
        using var bob = BrowserClient.Connect(listener.LocalEndPoint, listener.Parameters, "bob-ufrag");
        alice.OpenChannel("chat");
        bob.OpenChannel("chat");
        alice.Send("from-alice");
        bob.Send("from-bob");

        Assert.True(both.Wait(TimeSpan.FromSeconds(20)), "did not receive both clients' messages");
        var messages = received.Select(r => r.Message).ToHashSet();
        Assert.Contains("from-alice", messages);
        Assert.Contains("from-bob", messages);
        Assert.Equal(2, received.Select(r => r.RemotePort).Distinct().Count()); // demuxed to two distinct peers
        Assert.Equal(2, listener.SessionCount);

        await cts.CancelAsync();
        try { await run; } catch (OperationCanceledException) { }
    }

    [Fact]
    public async Task NatRebinding_SamePeerFromNewAddress_MigratesTheSession_NotANewOne()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        var ct = cts.Token;

        await using var listener = new WebRtcListener(new IPEndPoint(IPAddress.Loopback, 0));
        var run = listener.RunAsync(ct);

        using var alice = BrowserClient.Connect(listener.LocalEndPoint, listener.Parameters, "alice-rebind");
        alice.OpenChannel("chat");
        await WaitForAsync(() => listener.SessionCount == 1, TimeSpan.FromSeconds(10));

        // Simulate a NAT rebinding: the SAME peer (same ICE ufrag) sends its next consent check from a NEW socket/port.
        using var rebound = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        SendConnectivityCheck(rebound, listener.LocalEndPoint, listener.Parameters, "alice-rebind");
        rebound.Client.ReceiveTimeout = 5000;
        var from = new IPEndPoint(IPAddress.Any, 0);
        Assert.True(StunMessage.TryParse(rebound.Receive(ref from), out var reply));
        Assert.Equal(StunMessageTypes.BindingSuccessResponse, reply.MessageType); // endpoint answered the rebound check

        // Keyed by ufrag, the session migrates to the new address — still exactly one session, not a second one.
        await Task.Delay(300, ct); // let the ICE loop process the migration
        Assert.Equal(1, listener.SessionCount);

        await cts.CancelAsync();
        try { await run; } catch (OperationCanceledException) { }
    }

    [Fact]
    public async Task IdleSession_IsEvictedByTheTimer_AndClosesTheChannel()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(40));
        var ct = cts.Token;

        await using var listener = new WebRtcListener(
            new IPEndPoint(IPAddress.Loopback, 0), sessionIdleTimeout: TimeSpan.FromSeconds(1));
        var run = listener.RunAsync(ct);

        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        listener.ChannelOpened += channel => channel.Closed += () => closed.TrySetResult();

        using var browser = BrowserClient.Connect(listener.LocalEndPoint, listener.Parameters, "idle-peer");
        browser.OpenChannel("chat");
        await WaitForAsync(() => listener.SessionCount == 1, TimeSpan.FromSeconds(10));

        // No further ICE consent and no data: the idle sweep should evict the session and close its channel.
        Assert.True(closed.Task.Wait(TimeSpan.FromSeconds(15)), "idle session was not evicted");
        await WaitForAsync(() => listener.SessionCount == 0, TimeSpan.FromSeconds(5));
        Assert.Equal(0, listener.SessionCount);

        await cts.CancelAsync();
        try { await run; } catch (OperationCanceledException) { }
    }

    private static void SendConnectivityCheck(UdpClient udp, IPEndPoint server, WebRtcEndpointParameters parameters, string clientUfrag)
    {
        var check = new StunMessage(StunMessageTypes.BindingRequest, StunMessage.NewTransactionId());
        check.Add(StunAttributes.Username, Encoding.UTF8.GetBytes($"{parameters.IceUfrag}:{clientUfrag}"));
        check.AddMessageIntegrity(Encoding.UTF8.GetBytes(parameters.IcePassword));
        check.AddFingerprint();
        var bytes = check.Encode();
        udp.Send(bytes, bytes.Length, server);
    }

    private static async Task WaitForAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (!condition() && DateTime.UtcNow < deadline)
            await Task.Delay(50);
        Assert.True(condition(), "condition was not met within the timeout");
    }

    /// <summary>A minimal "browser": its own UDP socket, an ICE check, a DTLS client (pinning the server cert), an
    /// SCTP association, and DCEP channel open + message send — the client half of the full stack.</summary>
    private sealed class BrowserClient : IDisposable
    {
        private readonly UdpClient _udp;
        private readonly DtlsTransport _dtls;
        private readonly SctpTransport _sctp;
        private ushort _stream;

        private BrowserClient(UdpClient udp, DtlsTransport dtls, SctpTransport sctp, byte[] serverFingerprint)
        {
            _udp = udp;
            _dtls = dtls;
            _sctp = sctp;
            ServerFingerprint = serverFingerprint;
        }

        public byte[] ServerFingerprint { get; }
        public IPEndPoint LocalEndPoint => (IPEndPoint)_udp.Client.LocalEndPoint!;

        public static BrowserClient Connect(IPEndPoint server, WebRtcEndpointParameters parameters, string clientUfrag)
        {
            var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));

            // 1. ICE — a STUN Binding check keyed with the published password gets a Binding Success. Our own ufrag
            // (unique per client) rides in the USERNAME; the server keys the session by it.
            SendConnectivityCheck(udp, server, parameters, clientUfrag);

            udp.Client.ReceiveTimeout = 5000;
            var from = new IPEndPoint(IPAddress.Any, 0);
            var stunReply = udp.Receive(ref from);
            Assert.True(StunMessage.TryParse(stunReply, out var stunResponse));
            Assert.Equal(StunMessageTypes.BindingSuccessResponse, stunResponse.MessageType);
            Assert.True(stunResponse.VerifyMessageIntegrity(Encoding.UTF8.GetBytes(parameters.IcePassword)));

            // 2. DTLS — connect as the client; capture the server cert fingerprint (to compare with the published one).
            var transport = new UdpDtlsClientTransport(udp, server);
            var client = new RecordingTlsClient(new BcTlsCrypto(new SecureRandom()));
            DtlsTransport clientDtls = null!;
            var dtlsThread = new Thread(() => clientDtls = new DtlsClientProtocol().Connect(client, transport)) { IsBackground = true };
            dtlsThread.Start();
            Assert.True(dtlsThread.Join(TimeSpan.FromSeconds(15)), "client DTLS handshake timed out");

            // 3. SCTP — initiate the association.
            var sctp = new SctpTransport(clientDtls, new SctpAssociation());
            sctp.Start();
            sctp.Associate();
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (!sctp.IsEstablished && DateTime.UtcNow < deadline)
                Thread.Sleep(20);
            Assert.True(sctp.IsEstablished, "SCTP handshake timed out");

            return new BrowserClient(udp, clientDtls, sctp, client.ServerFingerprint!);
        }

        /// <summary>Opens a DataChannel via DCEP (so the server raises ChannelOpened).</summary>
        public void OpenChannel(string label, ushort stream = 0)
        {
            _stream = stream;
            _sctp.SendMessage(stream, Dcep.Ppid, Dcep.BuildOpen(new Dcep.Open(0, 0, 0, label, string.Empty)));
        }

        /// <summary>Sends an application message on the opened channel.</summary>
        public void Send(string message) => _sctp.SendMessage(_stream, Dcep.PpidString, Encoding.UTF8.GetBytes(message));

        public void Dispose()
        {
            _sctp.Dispose();
            try { _dtls.Close(); } catch { /* already closed */ }
            _udp.Dispose();
        }
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
