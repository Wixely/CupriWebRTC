namespace CupriWebRTC.Dtls13.Crypto;

/// <summary>The hash (and HMAC/HKDF) function a cipher suite is built on.</summary>
public enum Dtls13HashKind
{
    Sha256,
    Sha384,
}

/// <summary>The AEAD a cipher suite protects records with.</summary>
public enum Dtls13AeadKind
{
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// <summary>
/// The primitives DTLS 1.3 needs, behind one seam. The protocol code in this namespace never touches a crypto library
/// directly — it asks an <see cref="IDtls13Crypto"/>. That keeps the "which library?" question (BouncyCastle today,
/// the BCL or CupriCurve tomorrow) out of the protocol, and makes the primitives independently testable against their
/// RFC vectors. See <see cref="BouncyCastleDtls13Crypto"/> for the default, pure-managed implementation.
/// </summary>
public interface IDtls13Crypto
{
    /// <summary>The hash/HMAC function for a suite (also the HKDF hash).</summary>
    IDtls13Hash GetHash(Dtls13HashKind kind);

    /// <summary>Creates an AEAD instance bound to <paramref name="key"/>.</summary>
    IDtls13Aead CreateAead(Dtls13AeadKind kind, ReadOnlySpan<byte> key);

    /// <summary>
    /// The record-number mask of RFC 9147 §4.2.3: AES-ECB over the ciphertext sample for the AES suites, or the
    /// ChaCha20 block function keyed by the sample for the ChaCha20 suite. <paramref name="sample"/> is the first
    /// 16 bytes of the encrypted record; the returned mask is at least 2 bytes.
    /// </summary>
    byte[] RecordNumberMask(Dtls13AeadKind kind, ReadOnlySpan<byte> snKey, ReadOnlySpan<byte> sample);

    /// <summary>Generates an ephemeral ECDHE key pair for a TLS named group (see <see cref="Dtls13NamedGroup"/>).</summary>
    IDtls13KeyExchange GenerateKeyExchange(ushort namedGroup);

    /// <summary>True if <paramref name="namedGroup"/> is one this provider can do ECDHE over.</summary>
    bool SupportsGroup(ushort namedGroup);

    /// <summary>Fills <paramref name="buffer"/> with cryptographically strong random bytes.</summary>
    void GetRandom(Span<byte> buffer);
}

/// <summary>A hash function plus its HMAC, and an incremental form for the handshake transcript.</summary>
public interface IDtls13Hash
{
    /// <summary>Digest length in bytes (32 for SHA-256, 48 for SHA-384).</summary>
    int Length { get; }

    /// <summary>One-shot digest.</summary>
    byte[] Hash(ReadOnlySpan<byte> data);

    /// <summary>HMAC keyed by <paramref name="key"/>.</summary>
    byte[] Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data);

    /// <summary>A running digest that can be snapshotted without ending it — the handshake transcript.</summary>
    IDtls13RunningHash CreateRunningHash();
}

/// <summary>A running digest over the handshake transcript; <see cref="Snapshot"/> does not disturb it.</summary>
public interface IDtls13RunningHash
{
    /// <summary>Appends bytes to the running digest.</summary>
    void Update(ReadOnlySpan<byte> data);

    /// <summary>The digest of everything appended so far, leaving the running state intact.</summary>
    byte[] Snapshot();

    /// <summary>Discards the running state and restarts it from <paramref name="seed"/> (the HelloRetryRequest
    /// <c>message_hash</c> replacement of RFC 8446 §4.4.1).</summary>
    void Restart(ReadOnlySpan<byte> seed);
}

/// <summary>An AEAD bound to one key: protects and deprotects DTLS records.</summary>
public interface IDtls13Aead : IDisposable
{
    /// <summary>Key length in bytes.</summary>
    int KeyLength { get; }

    /// <summary>Nonce (IV) length in bytes — 12 for every suite DTLS 1.3 uses.</summary>
    int NonceLength { get; }

    /// <summary>Authentication tag length in bytes.</summary>
    int TagLength { get; }

    /// <summary>Encrypts into <paramref name="output"/>, which must be <c>plaintext.Length + TagLength</c> bytes.</summary>
    void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> output);

    /// <summary>Decrypts and verifies; returns false (without throwing) if the tag does not check out, so the caller
    /// can silently drop the record as RFC 9147 §4.5.2 requires.</summary>
    bool TryDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> output, out int written);
}

/// <summary>One side of an ephemeral ECDHE exchange.</summary>
public interface IDtls13KeyExchange : IDisposable
{
    /// <summary>The named group this exchange is over.</summary>
    ushort NamedGroup { get; }

    /// <summary>Our public share, in the wire encoding the <c>key_share</c> extension uses for the group.</summary>
    byte[] PublicKey { get; }

    /// <summary>The shared secret with <paramref name="peerPublicKey"/>, or null if the peer's share is invalid
    /// (malformed, or an all-zero X25519 result).</summary>
    byte[]? Agree(ReadOnlySpan<byte> peerPublicKey);
}

/// <summary>Signs the CertificateVerify transcript with the endpoint's certificate key.</summary>
public interface IDtls13Signer
{
    /// <summary>The TLS SignatureScheme code point this signer produces (see <see cref="Dtls13SignatureScheme"/>).</summary>
    ushort SignatureScheme { get; }

    /// <summary>The DER-encoded certificate chain, end-entity first.</summary>
    IReadOnlyList<byte[]> CertificateChain { get; }

    /// <summary>Signs the CertificateVerify content (RFC 8446 §4.4.3), hashing it as the scheme requires.</summary>
    byte[] Sign(ReadOnlySpan<byte> content);
}
