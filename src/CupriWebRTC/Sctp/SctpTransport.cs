using CupriWebRTC.Dtls;
using Org.BouncyCastle.Tls;

namespace CupriWebRTC.Sctp;

/// <summary>
/// Runs an <see cref="SctpAssociation"/> over a secured datagram transport — the one a completed DTLS handshake
/// yields. A background loop reads SCTP packets (one per datagram, SCTP-over-DTLS per RFC 8261), feeds the
/// association, and writes its responses; <see cref="SendMessage"/> writes outbound DATA. Access to the (single-
/// threaded) association is serialised. The transport is an <see cref="ISecureDatagramTransport"/>, which both the
/// DTLS 1.3 and the BouncyCastle DTLS 1.2 paths implement, so SCTP is version-agnostic.
/// </summary>
public sealed class SctpTransport : IDisposable
{
    private readonly ISecureDatagramTransport _transport;
    private readonly SctpAssociation _association;
    private readonly Lock _gate = new();
    private volatile bool _closed;

    public SctpTransport(ISecureDatagramTransport transport, SctpAssociation association)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _association = association ?? throw new ArgumentNullException(nameof(association));
        _association.ChannelOpened += channel => ChannelOpened?.Invoke(channel);
        _association.MessageReceived += (stream, ppid, data) => MessageReceived?.Invoke(stream, ppid, data);
    }

    /// <summary>Runs over a plain BouncyCastle datagram transport (used by tests and by anything driving SCTP
    /// directly over an unsecured pipe).</summary>
    public SctpTransport(DatagramTransport transport, SctpAssociation association)
        : this(new DatagramTransportAdapter(transport), association)
    {
    }

    /// <summary>Raised when the peer opens a data channel.</summary>
    public event Action<SctpDataChannel>? ChannelOpened;

    /// <summary>Raised for an inbound application message: (streamId, PPID, payload).</summary>
    public event Action<ushort, uint, byte[]>? MessageReceived;

    /// <summary>Raised once when the receive loop ends (transport closed / dropped), so an owner can release the session.</summary>
    public event Action? Closed;

    /// <summary>True once the SCTP handshake has completed.</summary>
    public bool IsEstablished => _association.IsEstablished;

    /// <summary>Starts the receive loop on a dedicated background thread (call before initiating/awaiting a handshake).</summary>
    public void Start() => new Thread(ReceiveLoop) { IsBackground = true, Name = "cupriwebrtc-sctp" }.Start();

    /// <summary>Runs the receive loop on the <b>calling</b> thread until the transport closes — lets an owner drive the
    /// whole session (DTLS handshake then SCTP) on one thread instead of spawning a second. Returns when closed.</summary>
    public void RunReceiveLoop() => ReceiveLoop();

    /// <summary>Actively initiate the association (INIT). Omit this side to be the passive responder.</summary>
    public void Associate()
    {
        IReadOnlyList<byte[]> packets;
        lock (_gate)
            packets = _association.Associate();
        SendAll(packets);
    }

    /// <summary>Sends an application message on a stream.</summary>
    public void SendMessage(ushort streamId, uint ppid, byte[] data)
    {
        IReadOnlyList<byte[]> packets;
        lock (_gate)
            packets = _association.SendMessage(streamId, ppid, data);
        SendAll(packets);
    }

    private void ReceiveLoop()
    {
        try
        {
            var buffer = new byte[2048];
            while (!_closed)
            {
                int n;
                try { n = _transport.Receive(buffer, 0, buffer.Length, 1000); }
                catch { break; }
                if (n <= 0)
                    continue; // timeout or empty

                IReadOnlyList<byte[]> responses;
                lock (_gate)
                    responses = _association.HandlePacket(buffer.AsSpan(0, n));
                SendAll(responses);
            }
        }
        finally
        {
            Closed?.Invoke();
        }
    }

    private void SendAll(IReadOnlyList<byte[]> packets)
    {
        foreach (var packet in packets)
        {
            try { _transport.Send(packet, 0, packet.Length); }
            catch { break; }
        }
    }

    public void Dispose()
    {
        _closed = true;
        try { _transport.Close(); }
        catch { /* already closed */ }
    }

    /// <summary>Presents a raw BouncyCastle <see cref="DatagramTransport"/> as an <see cref="ISecureDatagramTransport"/>.</summary>
    private sealed class DatagramTransportAdapter(DatagramTransport transport) : ISecureDatagramTransport
    {
        private readonly DatagramTransport _inner = transport ?? throw new ArgumentNullException(nameof(transport));

        public string ProtocolVersion => "none (unsecured)";
        public int GetReceiveLimit() => _inner.GetReceiveLimit();
        public int GetSendLimit() => _inner.GetSendLimit();
        public int Receive(byte[] buffer, int offset, int length, int waitMillis) => _inner.Receive(buffer, offset, length, waitMillis);
        public void Send(byte[] buffer, int offset, int length) => _inner.Send(buffer, offset, length);
        public void Close() => _inner.Close();
        public void Dispose() => _inner.Close();
    }
}
