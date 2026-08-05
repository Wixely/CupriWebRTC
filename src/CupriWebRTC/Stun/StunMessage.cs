using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;

namespace CupriWebRTC.Stun;

/// <summary>STUN attribute type codes (RFC 5389/8489 + the ICE ones from RFC 8445).</summary>
public static class StunAttributes
{
    public const ushort MappedAddress = 0x0001;
    public const ushort Username = 0x0006;
    public const ushort MessageIntegrity = 0x0008;
    public const ushort ErrorCode = 0x0009;
    public const ushort UnknownAttributes = 0x000A;
    public const ushort XorMappedAddress = 0x0020;
    public const ushort Priority = 0x0024;
    public const ushort UseCandidate = 0x0025;
    public const ushort Software = 0x8022;
    public const ushort Fingerprint = 0x8028;
    public const ushort IceControlled = 0x8029;
    public const ushort IceControlling = 0x802A;
}

/// <summary>Common STUN message types (class + method), big-endian on the wire.</summary>
public static class StunMessageTypes
{
    public const ushort BindingRequest = 0x0001;
    public const ushort BindingIndication = 0x0011;
    public const ushort BindingSuccessResponse = 0x0101;
    public const ushort BindingErrorResponse = 0x0111;
}

/// <summary>
/// A STUN message (RFC 5389/8489): a 20-byte header (type, length, magic cookie, 96-bit transaction id) followed by
/// 4-byte-aligned TLV attributes. Supports the pieces ICE needs — MESSAGE-INTEGRITY (HMAC-SHA1), FINGERPRINT (CRC-32),
/// and XOR-MAPPED-ADDRESS. Not media/SRTP.
/// </summary>
public sealed class StunMessage
{
    public const uint MagicCookie = 0x2112A442;
    public const int TransactionIdSize = 12;

    private const int HeaderSize = 20;
    private const uint FingerprintXor = 0x5354554E; // "STUN"

    public ushort MessageType { get; set; }
    public byte[] TransactionId { get; set; } = new byte[TransactionIdSize];

    private readonly List<(ushort Type, byte[] Value)> _attributes = [];

    // Populated by TryParse, so MESSAGE-INTEGRITY / FINGERPRINT can be verified against the exact received bytes.
    private byte[]? _raw;
    private readonly Dictionary<ushort, int> _valueOffsets = [];

    public IReadOnlyList<(ushort Type, byte[] Value)> Attributes => _attributes;

    public StunMessage() { }

    public StunMessage(ushort messageType, ReadOnlySpan<byte> transactionId)
    {
        MessageType = messageType;
        if (transactionId.Length != TransactionIdSize)
            throw new ArgumentException($"Transaction id must be {TransactionIdSize} bytes.", nameof(transactionId));
        TransactionId = transactionId.ToArray();
    }

    /// <summary>A fresh 96-bit transaction id.</summary>
    public static byte[] NewTransactionId()
    {
        var id = new byte[TransactionIdSize];
        RandomNumberGenerator.Fill(id);
        return id;
    }

    public void Add(ushort type, ReadOnlySpan<byte> value) => _attributes.Add((type, value.ToArray()));

    /// <summary>The value of the first attribute of <paramref name="type"/>, or null.</summary>
    public byte[]? Find(ushort type)
    {
        foreach (var (t, v) in _attributes)
            if (t == type)
                return v;
        return null;
    }

    public byte[] Encode() => Serialize(lengthOverride: -1);

    /// <summary>Appends MESSAGE-INTEGRITY (RFC 5389 §15.4): HMAC-SHA1 over the message so far, with the header length
    /// field pointing to the end of the MESSAGE-INTEGRITY attribute. Add other attributes (except FINGERPRINT) first.</summary>
    public void AddMessageIntegrity(ReadOnlySpan<byte> key)
    {
        var macInput = Serialize(AttributesLength() + 24); // +24 = the MI attribute (4 header + 20 value)
        Span<byte> mac = stackalloc byte[20];
        HMACSHA1.HashData(key, macInput, mac);
        Add(StunAttributes.MessageIntegrity, mac);
    }

    /// <summary>Appends FINGERPRINT (RFC 5389 §15.5): CRC-32 of the message so far XOR 0x5354554E, header length
    /// pointing past it. MUST be the last attribute added.</summary>
    public void AddFingerprint()
    {
        var fpInput = Serialize(AttributesLength() + 8); // +8 = the FP attribute (4 header + 4 value)
        var crc = Crc32.Compute(fpInput) ^ FingerprintXor;
        Span<byte> value = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(value, crc);
        Add(StunAttributes.Fingerprint, value);
    }

    public static bool TryParse(ReadOnlySpan<byte> data, out StunMessage message)
    {
        message = new StunMessage();
        if (data.Length < HeaderSize)
            return false;
        if (BinaryPrimitives.ReadUInt32BigEndian(data[4..]) != MagicCookie)
            return false;

        var type = BinaryPrimitives.ReadUInt16BigEndian(data);
        var length = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
        if (HeaderSize + length > data.Length)
            return false;

        message.MessageType = type;
        message.TransactionId = data.Slice(8, TransactionIdSize).ToArray();
        message._raw = data[..(HeaderSize + length)].ToArray();

        var p = HeaderSize;
        var end = HeaderSize + length;
        while (p + 4 <= end)
        {
            var attrType = BinaryPrimitives.ReadUInt16BigEndian(data[p..]);
            var attrLen = BinaryPrimitives.ReadUInt16BigEndian(data[(p + 2)..]);
            var valueStart = p + 4;
            if (valueStart + attrLen > end)
                return false;
            message._attributes.Add((attrType, data.Slice(valueStart, attrLen).ToArray()));
            message._valueOffsets.TryAdd(attrType, valueStart);
            p = valueStart + Pad4(attrLen);
        }
        return true;
    }

    /// <summary>Verifies a parsed message's MESSAGE-INTEGRITY against <paramref name="key"/> (the peer's password).</summary>
    public bool VerifyMessageIntegrity(ReadOnlySpan<byte> key)
    {
        if (_raw is null || !_valueOffsets.TryGetValue(StunAttributes.MessageIntegrity, out var miValueOffset))
            return false;
        var miHeaderStart = miValueOffset - 4;
        var input = _raw.AsSpan(0, miHeaderStart).ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(2), (ushort)((miHeaderStart - HeaderSize) + 24));
        Span<byte> expected = stackalloc byte[20];
        HMACSHA1.HashData(key, input, expected);
        var actual = Find(StunAttributes.MessageIntegrity);
        return actual is { Length: 20 } && CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    /// <summary>Verifies a parsed message's FINGERPRINT.</summary>
    public bool VerifyFingerprint()
    {
        if (_raw is null || !_valueOffsets.TryGetValue(StunAttributes.Fingerprint, out var fpValueOffset))
            return false;
        var fpHeaderStart = fpValueOffset - 4;
        var input = _raw.AsSpan(0, fpHeaderStart).ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(2), (ushort)((fpHeaderStart - HeaderSize) + 8));
        var crc = Crc32.Compute(input) ^ FingerprintXor;
        var value = Find(StunAttributes.Fingerprint);
        return value is { Length: 4 } && BinaryPrimitives.ReadUInt32BigEndian(value) == crc;
    }

    public void AddXorMappedAddress(IPEndPoint endpoint)
        => Add(StunAttributes.XorMappedAddress, EncodeXorMappedAddress(endpoint, TransactionId));

    public IPEndPoint? GetXorMappedAddress()
    {
        var value = Find(StunAttributes.XorMappedAddress);
        return value is null ? null : DecodeXorMappedAddress(value, TransactionId);
    }

    public static byte[] EncodeXorMappedAddress(IPEndPoint endpoint, ReadOnlySpan<byte> transactionId)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        var address = endpoint.Address.GetAddressBytes();
        var isV6 = address.Length == 16;
        var value = new byte[isV6 ? 20 : 8];
        value[1] = (byte)(isV6 ? 0x02 : 0x01);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(2), (ushort)(endpoint.Port ^ (int)(MagicCookie >> 16)));

        Span<byte> mask = stackalloc byte[16];
        BinaryPrimitives.WriteUInt32BigEndian(mask, MagicCookie);
        transactionId[..TransactionIdSize].CopyTo(mask[4..]);
        for (var i = 0; i < address.Length; i++)
            value[4 + i] = (byte)(address[i] ^ mask[i]);
        return value;
    }

    public static IPEndPoint? DecodeXorMappedAddress(ReadOnlySpan<byte> value, ReadOnlySpan<byte> transactionId)
    {
        if (value.Length < 8)
            return null;
        var addressLength = value[1] == 0x02 ? 16 : 4;
        if (value.Length < 4 + addressLength)
            return null;

        var port = (BinaryPrimitives.ReadUInt16BigEndian(value[2..]) ^ (int)(MagicCookie >> 16)) & 0xFFFF;
        Span<byte> mask = stackalloc byte[16];
        BinaryPrimitives.WriteUInt32BigEndian(mask, MagicCookie);
        transactionId[..TransactionIdSize].CopyTo(mask[4..]);
        var address = new byte[addressLength];
        for (var i = 0; i < addressLength; i++)
            address[i] = (byte)(value[4 + i] ^ mask[i]);
        return new IPEndPoint(new IPAddress(address), port);
    }

    private int AttributesLength()
    {
        var length = 0;
        foreach (var (_, value) in _attributes)
            length += 4 + Pad4(value.Length);
        return length;
    }

    private byte[] Serialize(int lengthOverride)
    {
        var attributesLength = AttributesLength();
        var buffer = new byte[HeaderSize + attributesLength];
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0), MessageType);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2), (ushort)(lengthOverride >= 0 ? lengthOverride : attributesLength));
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(4), MagicCookie);
        TransactionId.AsSpan(0, TransactionIdSize).CopyTo(buffer.AsSpan(8));

        var p = HeaderSize;
        foreach (var (type, value) in _attributes)
        {
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(p), type);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(p + 2), (ushort)value.Length);
            value.CopyTo(buffer.AsSpan(p + 4));
            p += 4 + Pad4(value.Length);
        }
        return buffer;
    }

    private static int Pad4(int n) => (n + 3) & ~3;
}
