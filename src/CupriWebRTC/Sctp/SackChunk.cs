using System.Buffers.Binary;

namespace CupriWebRTC.Sctp;

/// <summary>
/// A SACK chunk (RFC 4960 §3.3.4), minimal profile: cumulative TSN ack + advertised receiver window, with no gap-ack
/// or duplicate-TSN blocks (in-order delivery over the reliable DTLS transport). Gap blocks are parsed past on decode.
/// </summary>
public sealed record SackChunk(uint CumulativeTsnAck, uint AdvertisedReceiverWindow)
{
    public byte[] Encode()
    {
        var value = new byte[12];
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(0), CumulativeTsnAck);
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(4), AdvertisedReceiverWindow);
        // number of gap-ack blocks (offset 8) and duplicate TSNs (offset 10) remain 0.
        return value;
    }

    public static SackChunk Decode(ReadOnlySpan<byte> value) => new(
        BinaryPrimitives.ReadUInt32BigEndian(value),
        BinaryPrimitives.ReadUInt32BigEndian(value[4..]));
}
