using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CupriWebRTC;
using CupriWebRTC.Ice;
using CupriWebRTC.Sctp;
using CupriWebRTC.Stun;
using Org.BouncyCastle.Tls;
using Xunit;

namespace CupriWebRTC.Tests;

/// <summary>
/// The full stack over <b>DTLS 1.3</b>: a real UDP peer does ICE, the managed DTLS 1.3 handshake, SCTP and DCEP
/// against a live <see cref="WebRtcListener"/> — the same path a browser takes, minus the browser. This is the test
/// that would have caught the blocker this work exists to fix: a peer that offers DTLS 1.3 first now completes,
/// where before it was answered with a 1.2 flight and gave up with <c>decode_error</c>.
/// </summary>
public class WebRtcListenerDtls13Tests
{
    [Fact]
    public async Task FullStack_OverDtls13_OpensAChannel_AndDeliversAMessage()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var credentials = new IceCredentials("srv13Ufrag", "srv-password-13-abcdefgh");
        await using var listener = new WebRtcListener(new IPEndPoint(IPAddress.Loopback, 0), credentials);
        var run = listener.RunAsync(cts.Token);

        Exception? sessionFault = null;
        listener.SessionFaulted += (_, ex) => sessionFault = ex;

        var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        listener.ChannelOpened += channel => channel.MessageReceived += (_, data) => received.TrySetResult(data);

        using var peer = Dtls13Peer.Connect(listener.LocalEndPoint, listener.Parameters, "peer13");
        Assert.Equal(listener.Parameters.Fingerprint, peer.ServerFingerprint); // the peer pinned our published cert

        peer.OpenChannel("chat");
        peer.Send("hello over dtls 1.3");

        var completed = await Task.WhenAny(received.Task, Task.Delay(TimeSpan.FromSeconds(20)));
        Assert.True(ReferenceEquals(completed, received.Task), $"no message arrived; session fault: {sessionFault}");
        Assert.Equal("hello over dtls 1.3", Encoding.UTF8.GetString(received.Task.Result));
        Assert.Null(sessionFault);
        Assert.Equal(1, listener.SessionCount);

        await cts.CancelAsync();
        try { await run; } catch (OperationCanceledException) { }
    }

    /// <summary>The client half of the stack over DTLS 1.3: UDP socket, ICE check, DTLS 1.3, SCTP, DCEP.</summary>
    private sealed class Dtls13Peer : IDisposable
    {
        private readonly UdpClient _udp;
        private readonly TestDtls13Client _dtls;
        private readonly SctpTransport _sctp;
        private ushort _stream;

        private Dtls13Peer(UdpClient udp, TestDtls13Client dtls, SctpTransport sctp, byte[] serverFingerprint)
        {
            _udp = udp;
            _dtls = dtls;
            _sctp = sctp;
            ServerFingerprint = serverFingerprint;
        }

        public byte[] ServerFingerprint { get; }

        public static Dtls13Peer Connect(IPEndPoint server, WebRtcEndpointParameters parameters, string clientUfrag)
        {
            var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));

            // ICE: one STUN Binding check keyed with the published password creates the server-side session.
            var check = new StunMessage(StunMessageTypes.BindingRequest, StunMessage.NewTransactionId());
            check.Add(StunAttributes.Username, Encoding.UTF8.GetBytes($"{parameters.IceUfrag}:{clientUfrag}"));
            check.AddMessageIntegrity(Encoding.UTF8.GetBytes(parameters.IcePassword));
            check.AddFingerprint();
            var bytes = check.Encode();
            udp.Send(bytes, bytes.Length, server);

            udp.Client.ReceiveTimeout = 5000;
            var from = new IPEndPoint(IPAddress.Any, 0);
            var reply = udp.Receive(ref from);
            Assert.True(StunMessage.TryParse(reply, out var response));
            Assert.Equal(StunMessageTypes.BindingSuccessResponse, response.MessageType);

            // DTLS 1.3 as the client (a browser is always the client; we are always setup:passive).
            var dtls = new TestDtls13Client(new UdpDatagramTransport(udp, server));
            dtls.Handshake(TimeSpan.FromSeconds(20));
            var fingerprint = SHA256.HashData(Assert.Single(dtls.ServerCertificateChain));

            // SCTP over the secured transport, then DCEP.
            var sctp = new SctpTransport(dtls, new SctpAssociation());
            sctp.Start();
            sctp.Associate();
            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (!sctp.IsEstablished && DateTime.UtcNow < deadline)
                Thread.Sleep(20);
            Assert.True(sctp.IsEstablished, "SCTP handshake timed out over DTLS 1.3");

            return new Dtls13Peer(udp, dtls, sctp, fingerprint);
        }

        public void OpenChannel(string label, ushort stream = 0)
        {
            _stream = stream;
            _sctp.SendMessage(stream, Dcep.Ppid, Dcep.BuildOpen(new Dcep.Open(0, 0, 0, label, string.Empty)));
        }

        public void Send(string message) => _sctp.SendMessage(_stream, Dcep.PpidString, Encoding.UTF8.GetBytes(message));

        public void Dispose()
        {
            _sctp.Dispose();
            _udp.Dispose();
        }
    }

    /// <summary>DTLS-over-UDP for the peer side: sends to the listener, receives only DTLS (skipping stray STUN).</summary>
    private sealed class UdpDatagramTransport(UdpClient udp, IPEndPoint server) : DatagramTransport
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
                if (datagram[0] is >= 20 and <= 63) // DTLS per the RFC 7983 demux
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
}
