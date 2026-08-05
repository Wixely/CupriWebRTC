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
        DtlsTransport? serverSecured = null;
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
        var n = serverSecured!.Receive(buffer, 5000);
        Assert.Equal("hello dtls", Encoding.UTF8.GetString(buffer, 0, n));

        serverSecured.Send("hello back"u8);
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

    /// <summary>An in-memory, reliable-enough datagram pair (BouncyCastle <see cref="DatagramTransport"/>) for tests.</summary>
    private sealed class InMemoryDatagramTransport : DatagramTransport
    {
        private const int Mtu = 1500;
        private readonly BlockingCollection<byte[]> _inbound;
        private readonly BlockingCollection<byte[]> _outbound;

        private InMemoryDatagramTransport(BlockingCollection<byte[]> inbound, BlockingCollection<byte[]> outbound)
        {
            _inbound = inbound;
            _outbound = outbound;
        }

        public static (InMemoryDatagramTransport A, InMemoryDatagramTransport B) CreatePair()
        {
            var toA = new BlockingCollection<byte[]>();
            var toB = new BlockingCollection<byte[]>();
            return (new InMemoryDatagramTransport(toA, toB), new InMemoryDatagramTransport(toB, toA));
        }

        public int GetReceiveLimit() => Mtu;
        public int GetSendLimit() => Mtu;

        public int Receive(byte[] buf, int off, int len, int waitMillis) => Receive(buf.AsSpan(off, len), waitMillis);

        public int Receive(Span<byte> buffer, int waitMillis)
        {
            if (!_inbound.TryTake(out var datagram, waitMillis))
                return -1; // timeout — DTLS will retransmit
            var n = Math.Min(buffer.Length, datagram.Length);
            datagram.AsSpan(0, n).CopyTo(buffer);
            return n;
        }

        public void Send(byte[] buf, int off, int len) => Send(buf.AsSpan(off, len));

        public void Send(ReadOnlySpan<byte> buffer)
        {
            var copy = buffer.ToArray();
            try { _outbound.Add(copy); }
            catch (InvalidOperationException) { /* closed */ }
        }

        public void Close()
        {
            try { _outbound.CompleteAdding(); }
            catch (ObjectDisposedException) { }
        }
    }
}
