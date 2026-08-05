using System.Buffers.Binary;

namespace CupriWebRTC.Sctp;

/// <summary>The body of a DATA chunk (RFC 4960 §3.3.1): TSN, stream id, stream sequence, PPID, and user data.</summary>
public sealed record DataChunk(uint Tsn, ushort StreamId, ushort StreamSequence, uint Ppid, byte[] UserData)
{
    /// <summary>Last fragment of a message.</summary>
    public const byte FlagEnding = 0x01;

    /// <summary>First fragment of a message.</summary>
    public const byte FlagBeginning = 0x02;

    /// <summary>Delivered without regard to stream sequence.</summary>
    public const byte FlagUnordered = 0x04;

    public byte[] Encode()
    {
        var value = new byte[12 + UserData.Length];
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(0), Tsn);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), StreamId);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(6), StreamSequence);
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(8), Ppid);
        UserData.CopyTo(value.AsSpan(12));
        return value;
    }

    public static DataChunk Decode(ReadOnlySpan<byte> value) => new(
        BinaryPrimitives.ReadUInt32BigEndian(value),
        BinaryPrimitives.ReadUInt16BigEndian(value[4..]),
        BinaryPrimitives.ReadUInt16BigEndian(value[6..]),
        BinaryPrimitives.ReadUInt32BigEndian(value[8..]),
        value[12..].ToArray());
}
