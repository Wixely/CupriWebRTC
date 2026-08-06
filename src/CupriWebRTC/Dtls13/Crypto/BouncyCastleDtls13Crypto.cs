using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace CupriWebRTC.Dtls13.Crypto;

/// <summary>
/// The default <see cref="IDtls13Crypto"/>: every primitive from BouncyCastle, which keeps the stack 100% managed
/// (no OS/native interop) — the same choice the rest of CupriWebRTC and CupriNet make. Swapping in the BCL's
/// <c>AesGcm</c>/<c>HKDF</c> (OS-backed, faster) or a curve library such as CupriCurve is a matter of writing another
/// implementation of this interface; no protocol code changes.
/// </summary>
public sealed class BouncyCastleDtls13Crypto : IDtls13Crypto
{
    /// <summary>A shared instance (all state is per-call or per-returned-object).</summary>
    public static readonly BouncyCastleDtls13Crypto Instance = new();

    private static readonly BcHash Sha256Hash = new(Dtls13HashKind.Sha256);
    private static readonly BcHash Sha384Hash = new(Dtls13HashKind.Sha384);
    private readonly SecureRandom _random = new();

    public IDtls13Hash GetHash(Dtls13HashKind kind) => kind switch
    {
        Dtls13HashKind.Sha256 => Sha256Hash,
        Dtls13HashKind.Sha384 => Sha384Hash,
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    public IDtls13Aead CreateAead(Dtls13AeadKind kind, ReadOnlySpan<byte> key) => kind switch
    {
        Dtls13AeadKind.Aes128Gcm => new BcGcmAead(key, keyLength: 16),
        Dtls13AeadKind.Aes256Gcm => new BcGcmAead(key, keyLength: 32),
        Dtls13AeadKind.ChaCha20Poly1305 => new BcChaChaPolyAead(key),
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    public byte[] RecordNumberMask(Dtls13AeadKind kind, ReadOnlySpan<byte> snKey, ReadOnlySpan<byte> sample)
    {
        if (sample.Length < 16)
            throw new ArgumentException("record number mask needs a 16-byte ciphertext sample", nameof(sample));

        if (kind == Dtls13AeadKind.ChaCha20Poly1305)
        {
            // Mask = ChaCha20(sn_key, Ciphertext[0..3] as the block counter, Ciphertext[4..15] as the nonce).
            var counter = (uint)(sample[0] | (sample[1] << 8) | (sample[2] << 16) | (sample[3] << 24));
            return ChaCha20Block.Generate(snKey, counter, sample[4..16]);
        }

        // Mask = AES-ECB(sn_key, Ciphertext[0..15]) — a single raw block, no padding, no chaining.
        var aes = new AesEngine();
        aes.Init(true, new KeyParameter(snKey.ToArray()));
        var block = new byte[16];
        aes.ProcessBlock(sample[..16].ToArray(), 0, block, 0);
        return block;
    }

    public bool SupportsGroup(ushort namedGroup) =>
        namedGroup is Dtls13NamedGroup.X25519 or Dtls13NamedGroup.Secp256r1;

    public IDtls13KeyExchange GenerateKeyExchange(ushort namedGroup) => namedGroup switch
    {
        Dtls13NamedGroup.X25519 => new BcX25519KeyExchange(_random),
        Dtls13NamedGroup.Secp256r1 => new BcP256KeyExchange(_random),
        _ => throw new ArgumentOutOfRangeException(nameof(namedGroup), namedGroup, "unsupported named group"),
    };

    /// <summary>
    /// Builds a key exchange over a <em>given</em> private key rather than a fresh random one. Not part of
    /// <see cref="IDtls13Crypto"/> — the protocol must never choose its own ECDHE scalar — but it lets the tests run
    /// the RFC 7748 §6.1 known-answer vectors through the same code path the handshake uses.
    /// </summary>
    internal static IDtls13KeyExchange CreateKeyExchangeForTesting(ushort namedGroup, ReadOnlySpan<byte> privateKey) =>
        namedGroup == Dtls13NamedGroup.X25519
            ? new BcX25519KeyExchange(new X25519PrivateKeyParameters(privateKey.ToArray()))
            : throw new ArgumentOutOfRangeException(nameof(namedGroup), namedGroup, "only x25519 supports a fixed key here");

    public void GetRandom(Span<byte> buffer)
    {
        var bytes = new byte[buffer.Length];
        _random.NextBytes(bytes);
        bytes.CopyTo(buffer);
    }

    private sealed class BcHash(Dtls13HashKind kind) : IDtls13Hash
    {
        public int Length => kind == Dtls13HashKind.Sha384 ? 48 : 32;

        private IDigest NewDigest() => kind == Dtls13HashKind.Sha384 ? new Sha384Digest() : new Sha256Digest();

        public byte[] Hash(ReadOnlySpan<byte> data)
        {
            var digest = NewDigest();
            digest.BlockUpdate(data);
            var output = new byte[Length];
            digest.DoFinal(output);
            return output;
        }

        public byte[] Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
        {
            var mac = new HMac(NewDigest());
            mac.Init(new KeyParameter(key.ToArray()));
            mac.BlockUpdate(data);
            var output = new byte[mac.GetMacSize()];
            mac.DoFinal(output, 0);
            return output;
        }

        public IDtls13RunningHash CreateRunningHash() => new BcRunningHash(NewDigest(), Length, NewDigest);
    }

    private sealed class BcRunningHash(IDigest digest, int length, Func<IDigest> factory) : IDtls13RunningHash
    {
        private IDigest _digest = digest;

        public void Update(ReadOnlySpan<byte> data) => _digest.BlockUpdate(data);

        public byte[] Snapshot()
        {
            // Clone so finalising does not consume the running transcript, which keeps growing after each snapshot.
            var clone = factory();
            ((IMemoable)clone).Reset((IMemoable)_digest);
            var output = new byte[length];
            clone.DoFinal(output);
            return output;
        }

        public void Restart(ReadOnlySpan<byte> seed)
        {
            _digest = factory();
            _digest.BlockUpdate(seed);
        }
    }

    private sealed class BcGcmAead : IDtls13Aead
    {
        private readonly KeyParameter _key;

        public BcGcmAead(ReadOnlySpan<byte> key, int keyLength)
        {
            if (key.Length != keyLength)
                throw new ArgumentException($"AES-GCM key must be {keyLength} bytes", nameof(key));
            _key = new KeyParameter(key.ToArray());
            KeyLength = keyLength;
        }

        public int KeyLength { get; }
        public int NonceLength => 12;
        public int TagLength => 16;

        public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> output)
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(true, new AeadParameters(_key, 128, nonce.ToArray(), aad.ToArray()));
            var buffer = new byte[cipher.GetOutputSize(plaintext.Length)];
            var n = cipher.ProcessBytes(plaintext.ToArray(), 0, plaintext.Length, buffer, 0);
            n += cipher.DoFinal(buffer, n);
            buffer.AsSpan(0, n).CopyTo(output);
        }

        public bool TryDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> output, out int written)
        {
            written = 0;
            if (ciphertext.Length < TagLength)
                return false;
            try
            {
                var cipher = new GcmBlockCipher(new AesEngine());
                cipher.Init(false, new AeadParameters(_key, 128, nonce.ToArray(), aad.ToArray()));
                var buffer = new byte[cipher.GetOutputSize(ciphertext.Length)];
                var n = cipher.ProcessBytes(ciphertext.ToArray(), 0, ciphertext.Length, buffer, 0);
                n += cipher.DoFinal(buffer, n);
                buffer.AsSpan(0, n).CopyTo(output);
                written = n;
                return true;
            }
            catch (InvalidCipherTextException)
            {
                return false; // bad tag — the caller drops the record silently
            }
        }

        public void Dispose() { }
    }

    private sealed class BcChaChaPolyAead : IDtls13Aead
    {
        private readonly KeyParameter _key;

        public BcChaChaPolyAead(ReadOnlySpan<byte> key)
        {
            if (key.Length != 32)
                throw new ArgumentException("ChaCha20-Poly1305 key must be 32 bytes", nameof(key));
            _key = new KeyParameter(key.ToArray());
        }

        public int KeyLength => 32;
        public int NonceLength => 12;
        public int TagLength => 16;

        public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad, Span<byte> output)
        {
            var cipher = new ChaCha20Poly1305();
            cipher.Init(true, new AeadParameters(_key, 128, nonce.ToArray(), aad.ToArray()));
            var buffer = new byte[cipher.GetOutputSize(plaintext.Length)];
            var n = cipher.ProcessBytes(plaintext.ToArray(), 0, plaintext.Length, buffer, 0);
            n += cipher.DoFinal(buffer, n);
            buffer.AsSpan(0, n).CopyTo(output);
        }

        public bool TryDecrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, Span<byte> output, out int written)
        {
            written = 0;
            if (ciphertext.Length < TagLength)
                return false;
            try
            {
                var cipher = new ChaCha20Poly1305();
                cipher.Init(false, new AeadParameters(_key, 128, nonce.ToArray(), aad.ToArray()));
                var buffer = new byte[cipher.GetOutputSize(ciphertext.Length)];
                var n = cipher.ProcessBytes(ciphertext.ToArray(), 0, ciphertext.Length, buffer, 0);
                n += cipher.DoFinal(buffer, n);
                buffer.AsSpan(0, n).CopyTo(output);
                written = n;
                return true;
            }
            catch (InvalidCipherTextException)
            {
                return false;
            }
        }

        public void Dispose() { }
    }

    private sealed class BcX25519KeyExchange : IDtls13KeyExchange
    {
        private readonly X25519PrivateKeyParameters _private;

        public BcX25519KeyExchange(SecureRandom random)
        {
            var generator = new X25519KeyPairGenerator();
            generator.Init(new X25519KeyGenerationParameters(random));
            var pair = generator.GenerateKeyPair();
            _private = (X25519PrivateKeyParameters)pair.Private;
            PublicKey = ((X25519PublicKeyParameters)pair.Public).GetEncoded();
        }

        public BcX25519KeyExchange(X25519PrivateKeyParameters privateKey)
        {
            _private = privateKey;
            PublicKey = privateKey.GeneratePublicKey().GetEncoded();
        }

        public ushort NamedGroup => Dtls13NamedGroup.X25519;
        public byte[] PublicKey { get; }

        public byte[]? Agree(ReadOnlySpan<byte> peerPublicKey)
        {
            if (peerPublicKey.Length != X25519PublicKeyParameters.KeySize)
                return null;
            try
            {
                var agreement = new X25519Agreement();
                agreement.Init(_private);
                var secret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(new X25519PublicKeyParameters(peerPublicKey.ToArray()), secret, 0);
                return secret;
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            {
                return null; // a small-order/low-order peer share — RFC 8446 §7.4.2 says abort
            }
        }

        public void Dispose() { }
    }

    private sealed class BcP256KeyExchange : IDtls13KeyExchange
    {
        private static readonly X9ECParameters Curve = ECNamedCurveTable.GetByName("secp256r1");
        private static readonly ECDomainParameters Domain = new(Curve.Curve, Curve.G, Curve.N, Curve.H, Curve.GetSeed());

        private readonly ECPrivateKeyParameters _private;

        public BcP256KeyExchange(SecureRandom random)
        {
            var generator = new ECKeyPairGenerator("ECDH");
            generator.Init(new ECKeyGenerationParameters(Domain, random));
            var pair = generator.GenerateKeyPair();
            _private = (ECPrivateKeyParameters)pair.Private;
            PublicKey = ((ECPublicKeyParameters)pair.Public).Q.GetEncoded(compressed: false);
        }

        public ushort NamedGroup => Dtls13NamedGroup.Secp256r1;
        public byte[] PublicKey { get; }

        public byte[]? Agree(ReadOnlySpan<byte> peerPublicKey)
        {
            // TLS uses the uncompressed point encoding for the NIST curves (RFC 8446 §4.2.8.2).
            if (peerPublicKey.Length != 65 || peerPublicKey[0] != 0x04)
                return null;
            try
            {
                var point = Domain.Curve.DecodePoint(peerPublicKey.ToArray());
                if (!point.IsValid())
                    return null;
                var agreement = new ECDHBasicAgreement();
                agreement.Init(_private);
                var z = agreement.CalculateAgreement(new ECPublicKeyParameters(point, Domain));
                // The ECDHE shared secret is the x-coordinate, left-padded to the field size (32 bytes for P-256).
                return Org.BouncyCastle.Utilities.BigIntegers.AsUnsignedByteArray(32, z);
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or ArithmeticException)
            {
                return null;
            }
        }

        public void Dispose() { }
    }
}
