using CupriWebRTC.Dtls13;
using CupriWebRTC.Dtls13.Crypto;
using Xunit;

namespace CupriWebRTC.Tests;

/// <summary>
/// Known-answer vectors for every primitive the DTLS 1.3 stack is built on, taken straight from the RFCs. These are
/// the bottom of the verification pyramid: if the record layer or the handshake misbehaves, these tests say whether
/// the cause is below the protocol or in it.
///
/// <para>Every key, nonce and secret below — including the values named "private key" — is <b>published RFC test
/// data</b> (RFC 5869, 7748, 8439, and the NIST GCM vectors), reproduced verbatim so the expected outputs mean
/// something. None of it is, or has ever been, live key material.</para>
/// </summary>
public class Dtls13PrimitiveVectorTests
{
    private static readonly IDtls13Crypto Crypto = BouncyCastleDtls13Crypto.Instance;

    private static byte[] Hex(string hex) => Convert.FromHexString(hex.Replace(" ", "").Replace("\n", "").Replace("\r", ""));

    // ------------------------------------------------------------------ HKDF (RFC 5869)

    [Fact]
    public void Hkdf_Rfc5869_TestCase1_Sha256()
    {
        var schedule = new Dtls13KeySchedule(Crypto.GetHash(Dtls13HashKind.Sha256));
        var ikm = Hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        var salt = Hex("000102030405060708090a0b0c");
        var info = Hex("f0f1f2f3f4f5f6f7f8f9");

        var prk = schedule.Extract(salt, ikm);
        Assert.Equal(Hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), prk);

        var okm = schedule.Expand(prk, info, 42);
        Assert.Equal(Hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), okm);
    }

    [Fact]
    public void Hkdf_Rfc5869_TestCase2_Sha256_LongInputs()
    {
        var schedule = new Dtls13KeySchedule(Crypto.GetHash(Dtls13HashKind.Sha256));
        var ikm = Hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                      "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
                      "404142434445464748494a4b4c4d4e4f");
        var salt = Hex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
                       "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
                       "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        var info = Hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
                       "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
                       "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

        var prk = schedule.Extract(salt, ikm);
        Assert.Equal(Hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"), prk);

        var okm = schedule.Expand(prk, info, 82);
        Assert.Equal(
            Hex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
                "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
                "cc30c58179ec3e87c14c01d5c1f3434f1d87"),
            okm);
    }

    [Fact]
    public void Hkdf_Rfc5869_TestCase3_ZeroSaltAndInfo()
    {
        var schedule = new Dtls13KeySchedule(Crypto.GetHash(Dtls13HashKind.Sha256));
        var ikm = Hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

        // An empty salt must be treated as HashLen zeros (RFC 5869 §2.2).
        var prk = schedule.Extract(ReadOnlySpan<byte>.Empty, ikm);
        Assert.Equal(Hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"), prk);

        var okm = schedule.Expand(prk, ReadOnlySpan<byte>.Empty, 42);
        Assert.Equal(Hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"), okm);
    }

    // ------------------------------------------------------------------ ChaCha20 (RFC 8439)

    [Fact]
    public void ChaCha20Block_Rfc8439_Section2_3_2()
    {
        var key = Hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var nonce = Hex("000000090000004a00000000");
        var block = ChaCha20Block.Generate(key, counter: 1, nonce);

        Assert.Equal(
            Hex("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
                "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"),
            block);
    }

    [Fact]
    public void ChaCha20Poly1305_Rfc8439_Section2_8_2()
    {
        var key = Hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        var nonce = Hex("070000004041424344454647");
        var aad = Hex("50515253c0c1c2c3c4c5c6c7");
        var plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."u8.ToArray();

        using var aead = Crypto.CreateAead(Dtls13AeadKind.ChaCha20Poly1305, key);
        var output = new byte[plaintext.Length + aead.TagLength];
        aead.Encrypt(nonce, plaintext, aad, output);

        Assert.Equal(
            Hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
                "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
                "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
                "3ff4def08e4b7a9de576d26586cec64b6116" +
                "1ae10b594f09e26a7e902ecbd0600691"),
            output);

        var decrypted = new byte[plaintext.Length];
        Assert.True(aead.TryDecrypt(nonce, output, aad, decrypted, out var written));
        Assert.Equal(plaintext.Length, written);
        Assert.Equal(plaintext, decrypted);
    }

    // ------------------------------------------------------------------ AES-GCM

    [Fact]
    public void AesGcm_NistVector_Aes128()
    {
        // NIST CAVP gcmEncryptExtIV128, key/IV/PT/AAD case with a 96-bit IV and 128-bit tag.
        var key = Hex("feffe9928665731c6d6a8f9467308308");
        var nonce = Hex("cafebabefacedbaddecaf888");
        var plaintext = Hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
                            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        var aad = Hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");

        using var aead = Crypto.CreateAead(Dtls13AeadKind.Aes128Gcm, key);
        var output = new byte[plaintext.Length + aead.TagLength];
        aead.Encrypt(nonce, plaintext, aad, output);

        Assert.Equal(
            Hex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e" +
                "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091" +
                "5bc94fbc3221a5db94fae95ae7121a47"),
            output);
    }

    [Fact]
    public void Aead_RejectsATamperedTag()
    {
        var key = new byte[16];
        var nonce = new byte[12];
        using var aead = Crypto.CreateAead(Dtls13AeadKind.Aes128Gcm, key);
        var output = new byte[5 + aead.TagLength];
        aead.Encrypt(nonce, "hello"u8, ReadOnlySpan<byte>.Empty, output);
        output[^1] ^= 0x01;

        Assert.False(aead.TryDecrypt(nonce, output, ReadOnlySpan<byte>.Empty, new byte[5], out _));
    }

    // ------------------------------------------------------------------ X25519 (RFC 7748)

    [Fact]
    public void X25519_Rfc7748_Section6_1_AliceAndBob()
    {
        var alicePrivate = Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        var bobPrivate = Hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

        using var alice = BouncyCastleDtls13Crypto.CreateKeyExchangeForTesting(Dtls13NamedGroup.X25519, alicePrivate);
        using var bob = BouncyCastleDtls13Crypto.CreateKeyExchangeForTesting(Dtls13NamedGroup.X25519, bobPrivate);

        Assert.Equal(Hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), alice.PublicKey);
        Assert.Equal(Hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"), bob.PublicKey);

        var expected = Hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        Assert.Equal(expected, alice.Agree(bob.PublicKey));
        Assert.Equal(expected, bob.Agree(alice.PublicKey));
    }

    [Fact]
    public void X25519_RejectsAnAllZeroSharedSecret()
    {
        using var exchange = Crypto.GenerateKeyExchange(Dtls13NamedGroup.X25519);
        Assert.Null(exchange.Agree(new byte[32])); // a small-order point must not yield a usable secret
        Assert.Null(exchange.Agree(new byte[31])); // wrong length
    }

    [Fact]
    public void Secp256r1_TwoExchangesAgree()
    {
        using var a = Crypto.GenerateKeyExchange(Dtls13NamedGroup.Secp256r1);
        using var b = Crypto.GenerateKeyExchange(Dtls13NamedGroup.Secp256r1);

        Assert.Equal(65, a.PublicKey.Length);
        Assert.Equal(0x04, a.PublicKey[0]); // uncompressed point, as TLS requires
        Assert.Equal(a.Agree(b.PublicKey), b.Agree(a.PublicKey));
        Assert.Null(b.Agree(new byte[65])); // not a point on the curve
    }
}
