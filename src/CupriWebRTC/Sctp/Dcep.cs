using System.Buffers.Binary;
using System.Text;

namespace CupriWebRTC.Sctp;

/// <summary>
/// The WebRTC Data Channel Establishment Protocol (RFC 8832), carried in DATA chunks with PPID 50. A channel is
/// opened by a DATA_CHANNEL_OPEN and confirmed with a DATA_CHANNEL_ACK. Also defines the WebRTC data PPIDs
/// (RFC 8831) used to distinguish string vs. binary payloads.
/// </summary>
public static class Dcep
{
    /// <summary>PPID for DCEP control messages.</summary>
    public const uint Ppid = 50;

    public const byte MessageAck = 0x02;
    public const byte MessageOpen = 0x03;

    // WebRTC data PPIDs (RFC 8831). Empty payloads use distinct PPIDs because a DATA chunk can't be zero-length.
    public const uint PpidString = 51;
    public const uint PpidBinary = 53;
    public const uint PpidStringEmpty = 56;
    public const uint PpidBinaryEmpty = 57;

    /// <summary>A parsed DATA_CHANNEL_OPEN request.</summary>
    public sealed record Open(byte ChannelType, ushort Priority, uint Reliability, string Label, string Protocol);

    public static Open? TryParseOpen(ReadOnlySpan<byte> message)
    {
        if (message.Length < 12 || message[0] != MessageOpen)
            return null;
        var channelType = message[1];
        var priority = BinaryPrimitives.ReadUInt16BigEndian(message[2..]);
        var reliability = BinaryPrimitives.ReadUInt32BigEndian(message[4..]);
        var labelLength = BinaryPrimitives.ReadUInt16BigEndian(message[8..]);
        var protocolLength = BinaryPrimitives.ReadUInt16BigEndian(message[10..]);
        if (12 + labelLength + protocolLength > message.Length)
            return null;
        var label = Encoding.UTF8.GetString(message.Slice(12, labelLength));
        var protocol = Encoding.UTF8.GetString(message.Slice(12 + labelLength, protocolLength));
        return new Open(channelType, priority, reliability, label, protocol);
    }

    /// <summary>A DATA_CHANNEL_ACK message (a single byte).</summary>
    public static byte[] BuildAck() => [MessageAck];

    public static byte[] BuildOpen(Open open)
    {
        ArgumentNullException.ThrowIfNull(open);
        var label = Encoding.UTF8.GetBytes(open.Label);
        var protocol = Encoding.UTF8.GetBytes(open.Protocol);
        var message = new byte[12 + label.Length + protocol.Length];
        message[0] = MessageOpen;
        message[1] = open.ChannelType;
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(2), open.Priority);
        BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(4), open.Reliability);
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(8), (ushort)label.Length);
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(10), (ushort)protocol.Length);
        label.CopyTo(message.AsSpan(12));
        protocol.CopyTo(message.AsSpan(12 + label.Length));
        return message;
    }
}
