using System.Net;

namespace CupriWebRTC;

/// <summary>
/// One open WebRTC DataChannel on a <see cref="WebRtcListener"/>, scoped to the peer that opened it. It is
/// self-contained — it carries the peer's <see cref="Remote"/> address and its own <see cref="MessageReceived"/> /
/// <see cref="Closed"/> events and <see cref="Send"/> — so multiple peers (each its own SCTP association on the shared
/// UDP socket) never cross-talk: a datagram is demultiplexed to a session by source address, and a message to a
/// channel by its SCTP stream within that session.
/// </summary>
public sealed class WebRtcChannel
{
    private readonly Action<ushort, uint, byte[]> _send;

    internal WebRtcChannel(IPEndPoint remote, ushort streamId, string label, string protocol, Action<ushort, uint, byte[]> send)
    {
        Remote = remote;
        StreamId = streamId;
        Label = label;
        Protocol = protocol;
        _send = send;
    }

    /// <summary>The peer's address (source of the datagrams for this channel's session).</summary>
    public IPEndPoint Remote { get; }

    /// <summary>The SCTP stream this channel occupies within its peer's association.</summary>
    public ushort StreamId { get; }

    /// <summary>The DataChannel label from the peer's DCEP open.</summary>
    public string Label { get; }

    /// <summary>The DataChannel sub-protocol from the peer's DCEP open (may be empty).</summary>
    public string Protocol { get; }

    /// <summary>Raised for an inbound application message on this channel: (PPID, payload).</summary>
    public event Action<uint, byte[]>? MessageReceived;

    /// <summary>Raised once when the channel's session closes (handshake failure, transport drop, or disposal).</summary>
    public event Action? Closed;

    /// <summary>Sends one application message on this channel (e.g. <see cref="Sctp.Dcep.PpidBinary"/>).</summary>
    public void Send(uint ppid, ReadOnlySpan<byte> data) => _send(StreamId, ppid, data.ToArray());

    internal void RaiseMessage(uint ppid, byte[] payload) => MessageReceived?.Invoke(ppid, payload);

    internal void RaiseClosed() => Closed?.Invoke();
}
