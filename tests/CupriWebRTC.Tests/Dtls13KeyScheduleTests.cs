using CupriWebRTC.Dtls13;
using CupriWebRTC.Dtls13.Crypto;
using Xunit;

namespace CupriWebRTC.Tests;

/// <summary>
/// Reproduces the "Simple 1-RTT Handshake" trace of <b>RFC 8448</b> end to end. That trace is the single best oracle
/// for a TLS 1.3 key schedule: it publishes every intermediate secret, key and IV for a real handshake, so agreeing
/// with it byte-for-byte means the transcript hashing, the HkdfLabel encoding and the whole secret tree are right.
///
/// <para>The trace is TLS, not DTLS, and the two differ in exactly one place — RFC 9147 §5.9 swaps the HKDF label
/// prefix from <c>"tls13 "</c> to <c>"dtls13"</c>. <see cref="Dtls13KeySchedule"/> takes that prefix as a parameter
/// precisely so this test can run the real code against the real vector; a separate test pins the DTLS prefix so the
/// production default cannot silently drift back to TLS's.</para>
///
/// <para>All the key material below is <b>published RFC 8448 test data</b>, reproduced verbatim. None of it is live.</para>
/// </summary>
public class Dtls13KeyScheduleTests
{
    private static byte[] Hex(string hex) => Convert.FromHexString(hex.Replace(" ", "").Replace("\n", "").Replace("\r", ""));

    // The handshake messages of RFC 8448 §3 verbatim, headers included — exactly what the transcript hash covers.
    private const string ClientHello =
        "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece700000613011303130201000091" +
        "0000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300" +
        "260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d002000" +
        "1e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001";

    private const string ServerHello =
        "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d00" +
        "20c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304";

    // The server's encrypted flight as one payload: EncryptedExtensions(40) ‖ Certificate(445) ‖
    // CertificateVerify(136) ‖ Finished(36) = 657 bytes. The transcript is taken at two points inside it.
    private const string ServerFlight =
        "080000240022000a00140012001d00170018001901000101010201030104001c00024001000000000b0001b9000001b50001b0" +
        "308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d" +
        "3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d0609" +
        "2a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a24" +
        "61eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38" +
        "e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f020301" +
        "0001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b0500038181008 5a" +
        "ad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21" +
        "a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f" +
        "759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b72" +
        "11f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8" +
        "d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5a" +
        "ea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718";

    /// <summary>Length of EncryptedExtensions + Certificate + CertificateVerify — the transcript CertificateVerify
    /// and the server Finished are computed over.</summary>
    private const int ThroughCertificateVerify = 40 + 445 + 136;

    private static Dtls13KeySchedule TlsSchedule() =>
        new(BouncyCastleDtls13Crypto.Instance.GetHash(Dtls13HashKind.Sha256), Dtls13KeySchedule.TlsLabelPrefix);

    [Fact]
    public void Rfc8448_SecretTree_MatchesTheTraceByteForByte()
    {
        var schedule = TlsSchedule();
        var hash = BouncyCastleDtls13Crypto.Instance.GetHash(Dtls13HashKind.Sha256);
        var zeros = new byte[32];

        // Early Secret = HKDF-Extract(0, 0)
        var earlySecret = schedule.Extract(zeros, zeros);
        Assert.Equal(Hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"), earlySecret);

        // Handshake Secret = HKDF-Extract(Derive-Secret(Early, "derived", ""), ECDHE)
        var derivedForHandshake = schedule.DeriveSecretOfEmpty(earlySecret, "derived");
        Assert.Equal(Hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"), derivedForHandshake);

        var ecdhe = Hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        var handshakeSecret = schedule.Extract(derivedForHandshake, ecdhe);
        Assert.Equal(Hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"), handshakeSecret);

        // The handshake traffic secrets hang off the transcript through ServerHello.
        var transcript = hash.CreateRunningHash();
        transcript.Update(Hex(ClientHello));
        transcript.Update(Hex(ServerHello));
        var afterServerHello = transcript.Snapshot();
        Assert.Equal(Hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"), afterServerHello);

        var clientHandshakeTraffic = schedule.DeriveSecret(handshakeSecret, "c hs traffic", afterServerHello);
        var serverHandshakeTraffic = schedule.DeriveSecret(handshakeSecret, "s hs traffic", afterServerHello);
        Assert.Equal(Hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"), clientHandshakeTraffic);
        Assert.Equal(Hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), serverHandshakeTraffic);

        // Master Secret = HKDF-Extract(Derive-Secret(Handshake, "derived", ""), 0)
        var derivedForMaster = schedule.DeriveSecretOfEmpty(handshakeSecret, "derived");
        Assert.Equal(Hex("43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4"), derivedForMaster);
        var masterSecret = schedule.Extract(derivedForMaster, zeros);
        Assert.Equal(Hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"), masterSecret);

        // The server's handshake write keys.
        var suite = Dtls13CipherSuite.Aes128GcmSha256;
        var keys = schedule.TrafficKeys(serverHandshakeTraffic, suite);
        Assert.Equal(Hex("3fce516009c21727d0f2e4e86ee403bc"), keys.Key);
        Assert.Equal(Hex("5d313eb2671276ee13000b30"), keys.Iv);

        // The server's Finished, over the transcript through CertificateVerify.
        var flight = Hex(ServerFlight);
        Assert.Equal(657, flight.Length);
        transcript.Update(flight.AsSpan(0, ThroughCertificateVerify));
        Assert.Equal(
            Hex("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"),
            schedule.FinishedKey(serverHandshakeTraffic));
        Assert.Equal(
            Hex("9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"),
            schedule.FinishedMac(serverHandshakeTraffic, transcript.Snapshot()));

        // Application traffic secrets, over the transcript through the server's Finished.
        transcript.Update(flight.AsSpan(ThroughCertificateVerify));
        var afterServerFinished = transcript.Snapshot();
        Assert.Equal(Hex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"), afterServerFinished);
        Assert.Equal(
            Hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"),
            schedule.DeriveSecret(masterSecret, "c ap traffic", afterServerFinished));
        Assert.Equal(
            Hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"),
            schedule.DeriveSecret(masterSecret, "s ap traffic", afterServerFinished));
    }

    [Fact]
    public void DtlsLabelPrefix_IsTheDefault_AndSeparatesKeysFromTls()
    {
        var hash = BouncyCastleDtls13Crypto.Instance.GetHash(Dtls13HashKind.Sha256);
        var secret = new byte[32];

        var dtls = new Dtls13KeySchedule(hash);                                          // production default
        var explicitDtls = new Dtls13KeySchedule(hash, Dtls13KeySchedule.DtlsLabelPrefix);
        var tls = new Dtls13KeySchedule(hash, Dtls13KeySchedule.TlsLabelPrefix);

        var viaDefault = dtls.ExpandLabel(secret, "key", ReadOnlySpan<byte>.Empty, 16);
        Assert.Equal(explicitDtls.ExpandLabel(secret, "key", ReadOnlySpan<byte>.Empty, 16), viaDefault);
        Assert.NotEqual(tls.ExpandLabel(secret, "key", ReadOnlySpan<byte>.Empty, 16), viaDefault);
    }

    [Fact]
    public void RunningHash_SnapshotDoesNotConsumeTheTranscript()
    {
        var hash = BouncyCastleDtls13Crypto.Instance.GetHash(Dtls13HashKind.Sha256);
        var running = hash.CreateRunningHash();
        running.Update("abc"u8);

        var first = running.Snapshot();
        Assert.Equal(hash.Hash("abc"u8), first);
        Assert.Equal(first, running.Snapshot()); // snapshotting twice must not change anything

        running.Update("def"u8);
        Assert.Equal(hash.Hash("abcdef"u8), running.Snapshot());
    }

    [Fact]
    public void RunningHash_RestartReplacesTheTranscript()
    {
        var hash = BouncyCastleDtls13Crypto.Instance.GetHash(Dtls13HashKind.Sha256);
        var running = hash.CreateRunningHash();
        running.Update("the first ClientHello"u8);

        running.Restart("synthetic message_hash"u8); // what a HelloRetryRequest does (RFC 8446 §4.4.1)
        running.Update("HelloRetryRequest"u8);

        var expected = hash.CreateRunningHash();
        expected.Update("synthetic message_hash"u8);
        expected.Update("HelloRetryRequest"u8);
        Assert.Equal(expected.Snapshot(), running.Snapshot());
    }
}
