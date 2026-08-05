using System.Buffers.Binary;

namespace CupriWebRTC.Sctp;

/// <summary>
/// The body of an INIT or INIT-ACK chunk (RFC 4960 §3.3.2/§3.3.3): the fixed fields plus, for INIT-ACK, a mandatory
/// State Cookie parameter. Other optional parameters are parsed past but not interpreted (minimal profile).
/// </summary>
public sealed record InitData(
    uint InitiateTag,
    uint AdvertisedReceiverWindow,
    ushort OutboundStreams,
    ushort InboundStreams,
    uint InitialTsn,
    byte[]? StateCookie = null)
{
    private const ushort StateCookieParameter = 7;

    /// <summary>Builds the chunk value (the bytes after the 4-byte chunk header).</summary>
    public byte[] Encode()
    {
        var length = 16;
        if (StateCookie is not null)
            length += Pad4(4 + StateCookie.Length);

        var value = new byte[length];
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(0), InitiateTag);
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(4), AdvertisedReceiverWindow);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(8), OutboundStreams);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(10), InboundStreams);
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(12), InitialTsn);
        if (StateCookie is not null)
        {
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(16), StateCookieParameter);
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(18), (ushort)(4 + StateCookie.Length));
            StateCookie.CopyTo(value.AsSpan(20));
        }
        return value;
    }

    public static InitData Decode(ReadOnlySpan<byte> value)
    {
        var initiateTag = BinaryPrimitives.ReadUInt32BigEndian(value);
        var arwnd = BinaryPrimitives.ReadUInt32BigEndian(value[4..]);
        var outbound = BinaryPrimitives.ReadUInt16BigEndian(value[8..]);
        var inbound = BinaryPrimitives.ReadUInt16BigEndian(value[10..]);
        var initialTsn = BinaryPrimitives.ReadUInt32BigEndian(value[12..]);

        byte[]? cookie = null;
        var p = 16;
        while (p + 4 <= value.Length)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(value[p..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(value[(p + 2)..]);
            if (length < 4 || p + length > value.Length)
                break;
            if (type == StateCookieParameter)
                cookie = value.Slice(p + 4, length - 4).ToArray();
            p += Pad4(length);
        }
        return new InitData(initiateTag, arwnd, outbound, inbound, initialTsn, cookie);
    }

    private static int Pad4(int n) => (n + 3) & ~3;
}
