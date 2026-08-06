using System.Collections.Concurrent;
using System.Net;
using CupriWebRTC.Dtls;
using CupriWebRTC.Ice;
using Org.BouncyCastle.Tls;

namespace CupriWebRTC;

/// <summary>
/// Bridges the ICE UDP flow to a BouncyCastle <see cref="DatagramTransport"/> for DTLS. DTLS datagrams demultiplexed
/// by the <see cref="IceUdpEndpoint"/> are enqueued here; DTLS handshake/record output is sent back out the same UDP
/// socket to the peer. So DTLS (and SCTP above it) run over the very port ICE selected — no second socket.
/// </summary>
internal sealed class EndpointDatagramTransport : DatagramTransport
{
    private const int Mtu = 1500;
    private readonly IceUdpEndpoint _endpoint;
    private volatile IPEndPoint _remote;
    private readonly BlockingCollection<byte[]> _inbound = new();

    // Set CUPRIWEBRTC_PCAP=<path> to capture the DTLS flow for Wireshark; null (and free) otherwise. One file for the
    // whole process — see DtlsPcapTap.Shared — so it is never closed or truncated by a session ending.
    private readonly DtlsPcapTap? _pcap = DtlsPcapTap.Shared;

    public EndpointDatagramTransport(IceUdpEndpoint endpoint, IPEndPoint remote)
    {
        _endpoint = endpoint;
        _remote = remote;
    }

    /// <summary>Repoints outbound sends at a new peer address after a NAT rebinding (the DTLS/SCTP state is unchanged —
    /// it rides on top of whatever 5-tuple the datagrams now flow over).</summary>
    public void UpdateRemote(IPEndPoint remote) => _remote = remote;

    /// <summary>Feed one inbound DTLS datagram (called from the ICE receive loop).</summary>
    public void Enqueue(ReadOnlyMemory<byte> datagram)
    {
        _pcap?.Write(datagram.Span, _remote, _endpoint.LocalEndPoint);
        try { _inbound.Add(datagram.ToArray()); }
        catch (InvalidOperationException) { /* closed */ }
    }

    public int GetReceiveLimit() => Mtu;
    public int GetSendLimit() => Mtu;

    public int Receive(byte[] buf, int off, int len, int waitMillis) => Receive(buf.AsSpan(off, len), waitMillis);

    public int Receive(Span<byte> buffer, int waitMillis)
    {
        if (!_inbound.TryTake(out var datagram, waitMillis))
            return -1; // timeout
        var n = Math.Min(buffer.Length, datagram.Length);
        datagram.AsSpan(0, n).CopyTo(buffer);
        return n;
    }

    public void Send(byte[] buf, int off, int len) => Send(buf.AsSpan(off, len));

    public void Send(ReadOnlySpan<byte> buffer)
    {
        var copy = buffer.ToArray();
        _pcap?.Write(copy, _endpoint.LocalEndPoint, _remote);
        _endpoint.SendAsync(copy, _remote).AsTask().GetAwaiter().GetResult();
    }

    public void Close()
    {
        try { _inbound.CompleteAdding(); }
        catch (ObjectDisposedException) { }
    }
}
