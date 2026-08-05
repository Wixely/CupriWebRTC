using System.Buffers.Binary;

namespace CupriWebRTC.Sctp;

/// <summary>SCTP chunk type codes (RFC 4960 + RFC 3758 FORWARD-TSN).</summary>
public static class SctpChunkType
{
    public const byte Data = 0;
    public const byte Init = 1;
    public const byte InitAck = 2;
    public const byte Sack = 3;
    public const byte Heartbeat = 4;
    public const byte HeartbeatAck = 5;
    public const byte Abort = 6;
    public const byte Shutdown = 7;
    public const byte ShutdownAck = 8;
    public const byte Error = 9;
    public const byte CookieEcho = 10;
    public const byte CookieAck = 11;
    public const byte ShutdownComplete = 14;
    public const byte ForwardTsn = 192;
}

/// <summary>
/// One SCTP chunk: a type + flags byte, then a 2-byte length (header + value, excluding padding), then the value,
/// padded to a 4-byte boundary. This is the generic TLV; specific chunks (INIT, DATA, SACK, …) parse the value.
/// </summary>
public sealed class SctpChunk
{
    public byte Type { get; set; }
    public byte Flags { get; set; }
    public byte[] Value { get; set; } = [];

    internal void WriteTo(List<byte> output)
    {
        var length = 4 + Value.Length; // excludes trailing padding, per RFC 4960 §3.2
        output.Add(Type);
        output.Add(Flags);
        output.Add((byte)(length >> 8));
        output.Add((byte)length);
        output.AddRange(Value);
        for (var pad = (4 - (length & 3)) & 3; pad > 0; pad--)
            output.Add(0);
    }

    internal static SctpChunk Read(ReadOnlySpan<byte> data, out int consumed)
    {
        var length = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
        var chunk = new SctpChunk
        {
            Type = data[0],
            Flags = data[1],
            Value = data.Slice(4, length - 4).ToArray(),
        };
        consumed = (length + 3) & ~3; // advance past 4-byte padding
        return chunk;
    }
}
