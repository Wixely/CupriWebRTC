using CupriWebRTC.Sctp;
using Xunit;

namespace CupriWebRTC.Tests;

public class SctpPacketTests
{
    [Fact]
    public void Crc32c_MatchesStandardCheckValue()
    {
        // The canonical CRC-32C (Castagnoli) check value for the ASCII string "123456789" is 0xE3069283.
        Assert.Equal(0xE3069283u, Crc32c.Compute("123456789"u8));
    }

    [Fact]
    public void Chunk_RoundTrips_WithPadding()
    {
        // A COOKIE_ECHO with a 5-byte cookie: length field 9, padded to 12 on the wire.
        var packet = new SctpPacket { VerificationTag = 0x12345678 };
        packet.Chunks.Add(new SctpChunk { Type = SctpChunkType.CookieEcho, Value = [1, 2, 3, 4, 5] });

        Assert.True(SctpPacket.TryParse(packet.Encode(), out var parsed));
        Assert.Single(parsed.Chunks);
        Assert.Equal(SctpChunkType.CookieEcho, parsed.Chunks[0].Type);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, parsed.Chunks[0].Value);
    }

    [Fact]
    public void Packet_RoundTrips_HeaderAndMultipleChunks_ChecksumVerifies()
    {
        var packet = new SctpPacket { SourcePort = 5000, DestinationPort = 5000, VerificationTag = 0xDEADBEEF };
        packet.Chunks.Add(new SctpChunk { Type = SctpChunkType.Init, Value = new byte[16] });
        packet.Chunks.Add(new SctpChunk { Type = SctpChunkType.CookieAck });

        var wire = packet.Encode();
        Assert.True(SctpPacket.TryParse(wire, out var parsed)); // checksum must verify

        Assert.Equal(5000, parsed.SourcePort);
        Assert.Equal(5000, parsed.DestinationPort);
        Assert.Equal(0xDEADBEEFu, parsed.VerificationTag);
        Assert.Equal(2, parsed.Chunks.Count);
        Assert.Equal(SctpChunkType.Init, parsed.Chunks[0].Type);
        Assert.Equal(16, parsed.Chunks[0].Value.Length);
        Assert.Equal(SctpChunkType.CookieAck, parsed.Chunks[1].Type);
        Assert.Empty(parsed.Chunks[1].Value);
    }

    [Fact]
    public void TryParse_FailsOnCorruptedChecksum()
    {
        var packet = new SctpPacket { VerificationTag = 1 };
        packet.Chunks.Add(new SctpChunk { Type = SctpChunkType.CookieAck });
        var wire = packet.Encode();

        wire[13] ^= 0xFF; // corrupt a chunk byte, leaving the checksum stale
        Assert.False(SctpPacket.TryParse(wire, out _));
        Assert.True(SctpPacket.TryParse(wire, out _, verifyChecksum: false)); // parses if we skip the check
    }
}
