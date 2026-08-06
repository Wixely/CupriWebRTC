namespace CupriWebRTC.Dtls13;

/// <summary>Raised when a peer's bytes do not parse as the DTLS/TLS structure they claim to be.</summary>
internal sealed class Dtls13DecodeException(string message) : Exception(message);

/// <summary>
/// A forward-only reader over a TLS/DTLS wire structure. Every accessor is bounds-checked and throws
/// <see cref="Dtls13DecodeException"/> rather than returning garbage — a truncated or hostile record must be a clean
/// "drop it" (or a <c>decode_error</c> alert), never an index-out-of-range surfacing from deep inside a parser.
/// </summary>
internal ref struct Dtls13Reader(ReadOnlySpan<byte> data)
{
    private readonly ReadOnlySpan<byte> _data = data;
    private int _at;

    /// <summary>Bytes not yet consumed.</summary>
    public readonly int Remaining => _data.Length - _at;

    /// <summary>True once every byte has been consumed.</summary>
    public readonly bool IsEmpty => Remaining == 0;

    /// <summary>The bytes consumed so far.</summary>
    public readonly ReadOnlySpan<byte> Consumed => _data[.._at];

    public byte ReadUInt8()
    {
        Require(1);
        return _data[_at++];
    }

    public ushort ReadUInt16()
    {
        Require(2);
        var value = (ushort)((_data[_at] << 8) | _data[_at + 1]);
        _at += 2;
        return value;
    }

    public uint ReadUInt24()
    {
        Require(3);
        var value = (uint)((_data[_at] << 16) | (_data[_at + 1] << 8) | _data[_at + 2]);
        _at += 3;
        return value;
    }

    public uint ReadUInt32()
    {
        Require(4);
        var value = ((uint)_data[_at] << 24) | ((uint)_data[_at + 1] << 16) | ((uint)_data[_at + 2] << 8) | _data[_at + 3];
        _at += 4;
        return value;
    }

    public ulong ReadUInt48()
    {
        Require(6);
        ulong value = 0;
        for (var i = 0; i < 6; i++)
            value = (value << 8) | _data[_at + i];
        _at += 6;
        return value;
    }

    public ulong ReadUInt64()
    {
        Require(8);
        ulong value = 0;
        for (var i = 0; i < 8; i++)
            value = (value << 8) | _data[_at + i];
        _at += 8;
        return value;
    }

    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        Require(count);
        var slice = _data.Slice(_at, count);
        _at += count;
        return slice;
    }

    /// <summary>Reads an <c>opaque x&lt;0..2^8-1&gt;</c> vector.</summary>
    public ReadOnlySpan<byte> ReadVector8() => ReadBytes(ReadUInt8());

    /// <summary>Reads an <c>opaque x&lt;0..2^16-1&gt;</c> vector.</summary>
    public ReadOnlySpan<byte> ReadVector16() => ReadBytes(ReadUInt16());

    /// <summary>Reads an <c>opaque x&lt;0..2^24-1&gt;</c> vector.</summary>
    public ReadOnlySpan<byte> ReadVector24() => ReadBytes(checked((int)ReadUInt24()));

    /// <summary>Everything left, consumed.</summary>
    public ReadOnlySpan<byte> ReadRemaining() => ReadBytes(Remaining);

    private readonly void Require(int count)
    {
        if (count < 0 || Remaining < count)
            throw new Dtls13DecodeException($"truncated message: wanted {count} more bytes, {Remaining} remain");
    }
}

/// <summary>
/// A growable writer for TLS/DTLS wire structures. The vector helpers exist because TLS length prefixes are written
/// <em>before</em> the content they measure: <see cref="BeginVector16"/> reserves the prefix and
/// <see cref="EndVector"/> backfills it, so nested structures (extensions inside a hello, entries inside a
/// certificate list) read the way the RFC's presentation language does.
/// </summary>
internal sealed class Dtls13Writer(int capacity = 256)
{
    private byte[] _buffer = new byte[Math.Max(16, capacity)];
    private int _length;

    /// <summary>Bytes written so far.</summary>
    public int Length => _length;

    /// <summary>A view over the bytes written so far.</summary>
    public ReadOnlySpan<byte> Span => _buffer.AsSpan(0, _length);

    /// <summary>A copy of the bytes written so far.</summary>
    public byte[] ToArray() => _buffer.AsSpan(0, _length).ToArray();

    public void WriteUInt8(byte value)
    {
        Ensure(1);
        _buffer[_length++] = value;
    }

    public void WriteUInt16(ushort value)
    {
        Ensure(2);
        _buffer[_length++] = (byte)(value >> 8);
        _buffer[_length++] = (byte)value;
    }

    public void WriteUInt24(uint value)
    {
        Ensure(3);
        _buffer[_length++] = (byte)(value >> 16);
        _buffer[_length++] = (byte)(value >> 8);
        _buffer[_length++] = (byte)value;
    }

    public void WriteUInt48(ulong value)
    {
        Ensure(6);
        for (var shift = 40; shift >= 0; shift -= 8)
            _buffer[_length++] = (byte)(value >> shift);
    }

    public void WriteUInt64(ulong value)
    {
        Ensure(8);
        for (var shift = 56; shift >= 0; shift -= 8)
            _buffer[_length++] = (byte)(value >> shift);
    }

    public void WriteBytes(ReadOnlySpan<byte> value)
    {
        Ensure(value.Length);
        value.CopyTo(_buffer.AsSpan(_length));
        _length += value.Length;
    }

    /// <summary>Writes an <c>opaque x&lt;0..2^8-1&gt;</c> vector.</summary>
    public void WriteVector8(ReadOnlySpan<byte> value)
    {
        if (value.Length > byte.MaxValue)
            throw new ArgumentException("vector exceeds 255 bytes", nameof(value));
        WriteUInt8((byte)value.Length);
        WriteBytes(value);
    }

    /// <summary>Writes an <c>opaque x&lt;0..2^16-1&gt;</c> vector.</summary>
    public void WriteVector16(ReadOnlySpan<byte> value)
    {
        if (value.Length > ushort.MaxValue)
            throw new ArgumentException("vector exceeds 65535 bytes", nameof(value));
        WriteUInt16((ushort)value.Length);
        WriteBytes(value);
    }

    /// <summary>Writes an <c>opaque x&lt;0..2^24-1&gt;</c> vector.</summary>
    public void WriteVector24(ReadOnlySpan<byte> value)
    {
        WriteUInt24((uint)value.Length);
        WriteBytes(value);
    }

    /// <summary>Reserves a 1-byte length prefix; pass the returned token to <see cref="EndVector"/>.</summary>
    public int BeginVector8()
    {
        WriteUInt8(0);
        return _length | (1 << 28);
    }

    /// <summary>Reserves a 2-byte length prefix; pass the returned token to <see cref="EndVector"/>.</summary>
    public int BeginVector16()
    {
        WriteUInt16(0);
        return _length | (2 << 28);
    }

    /// <summary>Reserves a 3-byte length prefix; pass the returned token to <see cref="EndVector"/>.</summary>
    public int BeginVector24()
    {
        WriteUInt24(0);
        return _length | (3 << 28);
    }

    /// <summary>Backfills the length prefix reserved by a <c>BeginVector*</c> call.</summary>
    public void EndVector(int token)
    {
        var prefixSize = token >> 28;
        var start = token & 0x0FFFFFFF;
        var length = _length - start;
        switch (prefixSize)
        {
            case 1:
                if (length > byte.MaxValue)
                    throw new InvalidOperationException("vector exceeds 255 bytes");
                _buffer[start - 1] = (byte)length;
                break;
            case 2:
                if (length > ushort.MaxValue)
                    throw new InvalidOperationException("vector exceeds 65535 bytes");
                _buffer[start - 2] = (byte)(length >> 8);
                _buffer[start - 1] = (byte)length;
                break;
            case 3:
                _buffer[start - 3] = (byte)(length >> 16);
                _buffer[start - 2] = (byte)(length >> 8);
                _buffer[start - 1] = (byte)length;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(token));
        }
    }

    private void Ensure(int extra)
    {
        if (_length + extra <= _buffer.Length)
            return;
        var capacity = Math.Max(_buffer.Length * 2, _length + extra);
        Array.Resize(ref _buffer, capacity);
    }
}
