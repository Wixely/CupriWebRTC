using System.Buffers.Binary;

namespace CupriWebRTC.Sctp;

/// <summary>
/// An SCTP packet (RFC 4960): a 12-byte common header — source/destination port, verification tag, and a CRC-32C
/// checksum — followed by one or more chunks. For WebRTC DataChannels the packet rides inside DTLS (RFC 8261), so
/// the ports are nominal; the verification tag and checksum still matter. The checksum is the reflected CRC-32C over
/// the packet with the checksum field zeroed, stored little-endian (RFC 3309).
/// </summary>
public sealed class SctpPacket
{
    public ushort SourcePort { get; set; }
    public ushort DestinationPort { get; set; }
    public uint VerificationTag { get; set; }
    public List<SctpChunk> Chunks { get; } = [];

    private const int HeaderSize = 12;

    public byte[] Encode()
    {
        var chunkBytes = new List<byte>();
        foreach (var chunk in Chunks)
            chunk.WriteTo(chunkBytes);

        var buffer = new byte[HeaderSize + chunkBytes.Count];
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0), SourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2), DestinationPort);
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(4), VerificationTag);
        // bytes [8..12] (checksum) stay zero while we compute it.
        chunkBytes.CopyTo(buffer, HeaderSize);

        var checksum = Crc32c.Compute(buffer);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(8), checksum);
        return buffer;
    }

    public static bool TryParse(ReadOnlySpan<byte> data, out SctpPacket packet, bool verifyChecksum = true)
    {
        packet = new SctpPacket();
        if (data.Length < HeaderSize)
            return false;

        if (verifyChecksum)
        {
            var stored = BinaryPrimitives.ReadUInt32LittleEndian(data[8..]);
            var zeroed = data.ToArray();
            zeroed.AsSpan(8, 4).Clear();
            if (Crc32c.Compute(zeroed) != stored)
                return false;
        }

        packet.SourcePort = BinaryPrimitives.ReadUInt16BigEndian(data);
        packet.DestinationPort = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
        packet.VerificationTag = BinaryPrimitives.ReadUInt32BigEndian(data[4..]);

        var p = HeaderSize;
        while (p + 4 <= data.Length)
        {
            var length = BinaryPrimitives.ReadUInt16BigEndian(data[(p + 2)..]);
            if (length < 4 || p + length > data.Length)
                return false;
            packet.Chunks.Add(SctpChunk.Read(data[p..], out var consumed));
            p += consumed;
        }
        return true;
    }
}
