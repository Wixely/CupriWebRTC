using System.Text;
using CupriWebRTC.Dtls13.Crypto;

namespace CupriWebRTC.Dtls13;

/// <summary>
/// The TLS 1.3 key schedule (RFC 8446 §7) as DTLS 1.3 uses it. The only difference from TLS is the HKDF label prefix:
/// RFC 9147 §5.9 replaces <c>"tls13 "</c> with <c>"dtls13"</c> (no trailing space — "DTLS" is a letter longer than
/// "TLS", and the label must stay inside one hash block) so that DTLS and TLS keys can never collide.
/// </summary>
internal sealed class Dtls13KeySchedule(IDtls13Hash hash, string labelPrefix = Dtls13KeySchedule.DtlsLabelPrefix)
{
    /// <summary>RFC 9147 §5.9 — the DTLS 1.3 HKDF label prefix.</summary>
    public const string DtlsLabelPrefix = "dtls13";

    /// <summary>RFC 8446 §7.1 — the TLS 1.3 prefix. Only used to reproduce the RFC 8448 traces in tests, which are
    /// the best available oracle for a key schedule that is otherwise identical.</summary>
    public const string TlsLabelPrefix = "tls13 ";

    private readonly byte[] _labelPrefix = Encoding.ASCII.GetBytes(labelPrefix);
    private readonly IDtls13Hash _hash = hash;

    /// <summary>The digest length of the suite's hash, in bytes.</summary>
    public int HashLength => _hash.Length;

    /// <summary><c>HKDF-Extract</c> (RFC 5869 §2.2) — it is exactly HMAC(salt, ikm).</summary>
    public byte[] Extract(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> inputKeyMaterial)
    {
        // An absent salt is a string of HashLen zeros (RFC 5869 §2.2).
        Span<byte> zeros = stackalloc byte[_hash.Length];
        return _hash.Hmac(salt.IsEmpty ? zeros : salt, inputKeyMaterial);
    }

    /// <summary><c>HKDF-Expand</c> (RFC 5869 §2.3).</summary>
    public byte[] Expand(ReadOnlySpan<byte> prk, ReadOnlySpan<byte> info, int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        if (length > 255 * _hash.Length)
            throw new ArgumentOutOfRangeException(nameof(length), "HKDF-Expand output is limited to 255 hash blocks");

        var output = new byte[length];
        var block = Array.Empty<byte>();
        var written = 0;
        for (byte counter = 1; written < length; counter++)
        {
            var input = new byte[block.Length + info.Length + 1];
            block.CopyTo(input, 0);
            info.CopyTo(input.AsSpan(block.Length));
            input[^1] = counter;
            block = _hash.Hmac(prk, input);
            var take = Math.Min(block.Length, length - written);
            block.AsSpan(0, take).CopyTo(output.AsSpan(written));
            written += take;
        }
        return output;
    }

    /// <summary><c>HKDF-Expand-Label</c> (RFC 8446 §7.1) with DTLS 1.3's <c>"dtls13"</c> prefix.</summary>
    public byte[] ExpandLabel(ReadOnlySpan<byte> secret, string label, ReadOnlySpan<byte> context, int length)
    {
        var labelBytes = Encoding.ASCII.GetBytes(label);
        var fullLabelLength = _labelPrefix.Length + labelBytes.Length;
        if (fullLabelLength is < 7 or > 255)
            throw new ArgumentOutOfRangeException(nameof(label), "HkdfLabel.label must be 7..255 bytes");
        if (context.Length > 255)
            throw new ArgumentOutOfRangeException(nameof(context), "HkdfLabel.context must be at most 255 bytes");

        // struct { uint16 length; opaque label<7..255>; opaque context<0..255>; } HkdfLabel;
        var info = new byte[2 + 1 + fullLabelLength + 1 + context.Length];
        var at = 0;
        info[at++] = (byte)(length >> 8);
        info[at++] = (byte)length;
        info[at++] = (byte)fullLabelLength;
        _labelPrefix.CopyTo(info.AsSpan(at));
        at += _labelPrefix.Length;
        labelBytes.CopyTo(info.AsSpan(at));
        at += labelBytes.Length;
        info[at++] = (byte)context.Length;
        context.CopyTo(info.AsSpan(at));

        return Expand(secret, info, length);
    }

    /// <summary><c>Derive-Secret</c> (RFC 8446 §7.1) — an ExpandLabel over a transcript hash.</summary>
    public byte[] DeriveSecret(ReadOnlySpan<byte> secret, string label, ReadOnlySpan<byte> transcriptHash) =>
        ExpandLabel(secret, label, transcriptHash, _hash.Length);

    /// <summary><c>Derive-Secret(secret, label, "")</c> — the "derived" step between stages of the schedule.</summary>
    public byte[] DeriveSecretOfEmpty(ReadOnlySpan<byte> secret, string label) =>
        DeriveSecret(secret, label, _hash.Hash(ReadOnlySpan<byte>.Empty));

    /// <summary>The <c>finished_key</c> for a traffic secret (RFC 8446 §4.4.4).</summary>
    public byte[] FinishedKey(ReadOnlySpan<byte> trafficSecret) =>
        ExpandLabel(trafficSecret, "finished", ReadOnlySpan<byte>.Empty, _hash.Length);

    /// <summary>The Finished MAC over a transcript hash.</summary>
    public byte[] FinishedMac(ReadOnlySpan<byte> trafficSecret, ReadOnlySpan<byte> transcriptHash) =>
        _hash.Hmac(FinishedKey(trafficSecret), transcriptHash);

    /// <summary>
    /// The per-epoch, per-direction record-protection material: the AEAD key and IV (RFC 8446 §7.3) plus DTLS 1.3's
    /// extra <c>sn_key</c>, which masks the record sequence number in the unified header (RFC 9147 §4.2.3).
    /// </summary>
    public Dtls13TrafficKeys TrafficKeys(ReadOnlySpan<byte> trafficSecret, Dtls13CipherSuite suite) => new(
        ExpandLabel(trafficSecret, "key", ReadOnlySpan<byte>.Empty, suite.KeyLength),
        ExpandLabel(trafficSecret, "iv", ReadOnlySpan<byte>.Empty, suite.IvLength),
        ExpandLabel(trafficSecret, "sn", ReadOnlySpan<byte>.Empty, suite.KeyLength));
}

/// <summary>One direction's record-protection material for one epoch.</summary>
internal sealed record Dtls13TrafficKeys(byte[] Key, byte[] Iv, byte[] SequenceNumberKey);
