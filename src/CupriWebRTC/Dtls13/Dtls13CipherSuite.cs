using CupriWebRTC.Dtls13.Crypto;

namespace CupriWebRTC.Dtls13;

/// <summary>
/// One TLS 1.3 cipher suite: its AEAD, its hash, and the derived lengths the record layer and key schedule need.
/// TLS 1.3 suites name only an AEAD + a hash (the key exchange and authentication are negotiated by extension), so
/// this table is short and closed — all three suites below are mandatory-to-offer for WebRTC-capable browsers.
/// </summary>
internal sealed record Dtls13CipherSuite(
    ushort Id,
    string Name,
    Dtls13AeadKind Aead,
    Dtls13HashKind Hash,
    int KeyLength,
    int IvLength)
{
    public const ushort TlsAes128GcmSha256 = 0x1301;
    public const ushort TlsAes256GcmSha384 = 0x1302;
    public const ushort TlsChaCha20Poly1305Sha256 = 0x1303;

    public static readonly Dtls13CipherSuite Aes128GcmSha256 =
        new(TlsAes128GcmSha256, "TLS_AES_128_GCM_SHA256", Dtls13AeadKind.Aes128Gcm, Dtls13HashKind.Sha256, 16, 12);

    public static readonly Dtls13CipherSuite Aes256GcmSha384 =
        new(TlsAes256GcmSha384, "TLS_AES_256_GCM_SHA384", Dtls13AeadKind.Aes256Gcm, Dtls13HashKind.Sha384, 32, 12);

    public static readonly Dtls13CipherSuite ChaCha20Poly1305Sha256 =
        new(TlsChaCha20Poly1305Sha256, "TLS_CHACHA20_POLY1305_SHA256", Dtls13AeadKind.ChaCha20Poly1305, Dtls13HashKind.Sha256, 32, 12);

    /// <summary>The suites this server will negotiate, in preference order (AES-GCM first — browsers and most CPUs
    /// have hardware AES; ChaCha20 is the fallback for those that don't).</summary>
    public static readonly IReadOnlyList<Dtls13CipherSuite> Supported =
    [
        Aes128GcmSha256,
        Aes256GcmSha384,
        ChaCha20Poly1305Sha256,
    ];

    /// <summary>Looks up a supported suite by its code point, or null if we don't implement it.</summary>
    public static Dtls13CipherSuite? Find(ushort id)
    {
        foreach (var suite in Supported)
            if (suite.Id == id)
                return suite;
        return null;
    }

    /// <summary>The AEAD authentication tag length — 16 bytes for all three suites.</summary>
    public int TagLength => 16;
}
