using CupriWebRTC.Dtls13;
using CupriWebRTC.Dtls13.Crypto;
using Xunit;

namespace CupriWebRTC.Tests;

/// <summary>
/// The DTLS 1.3 record layer (RFC 9147 §4): the unified header, AEAD protection, the encrypted record sequence
/// number, epoch selection and anti-replay. Two record layers are wired back to back with mirrored keys, which is
/// how a real peer pair is arranged, so a mistake in either direction shows up as a failure to deprotect.
/// </summary>
public class Dtls13RecordLayerTests
{
    private static readonly IDtls13Crypto Crypto = BouncyCastleDtls13Crypto.Instance;

    /// <summary>Builds two record layers keyed as peers: what one sends at an epoch, the other can read.</summary>
    private static (Dtls13RecordLayer A, Dtls13RecordLayer B) CreatePair(Dtls13CipherSuite suite, params ushort[] epochs)
    {
        var a = new Dtls13RecordLayer(Crypto);
        var b = new Dtls13RecordLayer(Crypto);
        a.SetCipherSuite(suite);
        b.SetCipherSuite(suite);
        var schedule = new Dtls13KeySchedule(Crypto.GetHash(suite.Hash));
        foreach (var epoch in epochs)
        {
            var aToB = schedule.TrafficKeys(Enumerable.Repeat((byte)(epoch + 1), schedule.HashLength).ToArray(), suite);
            var bToA = schedule.TrafficKeys(Enumerable.Repeat((byte)(epoch + 101), schedule.HashLength).ToArray(), suite);
            a.SetSendKeys(epoch, aToB);
            b.SetReceiveKeys(epoch, aToB);
            b.SetSendKeys(epoch, bToA);
            a.SetReceiveKeys(epoch, bToA);
        }
        return (a, b);
    }

    [Theory]
    [InlineData(Dtls13CipherSuite.TlsAes128GcmSha256)]
    [InlineData(Dtls13CipherSuite.TlsAes256GcmSha384)]
    [InlineData(Dtls13CipherSuite.TlsChaCha20Poly1305Sha256)]
    public void ProtectedRecord_RoundTrips_ForEverySuite(ushort suiteId)
    {
        var suite = Dtls13CipherSuite.Find(suiteId)!;
        var (sender, receiver) = CreatePair(suite, Dtls13Epoch.Handshake, Dtls13Epoch.Application);

        var payload = "the quick brown fox jumps over the lazy dog"u8.ToArray();
        var record = sender.WriteCiphertextRecord(Dtls13Epoch.Application, Dtls13ContentType.ApplicationData, payload, out var sequence);

        var received = receiver.ReadDatagram(record);
        var only = Assert.Single(received);
        Assert.Equal(Dtls13ContentType.ApplicationData, only.ContentType);
        Assert.Equal(Dtls13Epoch.Application, only.Epoch);
        Assert.Equal(sequence, only.SequenceNumber);
        Assert.Equal(payload, only.Fragment);
    }

    [Fact]
    public void UnifiedHeader_HasTheFixedBits_AndAnEncryptedSequenceNumber()
    {
        var (sender, _) = CreatePair(Dtls13CipherSuite.Aes128GcmSha256, Dtls13Epoch.Handshake);

        // Send several records so a masked sequence number that happened to equal the real one is not a false pass.
        var differed = false;
        for (ushort i = 0; i < 8; i++)
        {
            var record = sender.WriteCiphertextRecord(Dtls13Epoch.Handshake, Dtls13ContentType.Handshake, [1, 2, 3], out var sequence);

            Assert.Equal(0x20, record[0] & 0xE0);        // fixed bits 001
            Assert.Equal(0x00, record[0] & 0x10);        // no Connection ID
            Assert.Equal(0x08, record[0] & 0x08);        // 16-bit sequence number
            Assert.Equal(0x04, record[0] & 0x04);        // length present
            Assert.Equal(Dtls13Epoch.Handshake, record[0] & 0x03);

            var onWire = (ulong)((record[1] << 8) | record[2]);
            if (onWire != sequence)
                differed = true;
            var length = (record[3] << 8) | record[4];
            Assert.Equal(record.Length - 5, length);
        }
        Assert.True(differed, "the record sequence number was never masked");
    }

    [Fact]
    public void SeveralRecords_InOneDatagram_AreAllRead()
    {
        var (sender, receiver) = CreatePair(Dtls13CipherSuite.Aes128GcmSha256, Dtls13Epoch.Handshake);

        var first = sender.WriteCiphertextRecord(Dtls13Epoch.Handshake, Dtls13ContentType.Handshake, "one"u8, out _);
        var second = sender.WriteCiphertextRecord(Dtls13Epoch.Handshake, Dtls13ContentType.Handshake, "two"u8, out _);
        var third = sender.WriteCiphertextRecord(Dtls13Epoch.Handshake, Dtls13ContentType.Ack, "three"u8, out _);
        var datagram = first.Concat(second).Concat(third).ToArray();

        var records = receiver.ReadDatagram(datagram);
        Assert.Equal(3, records.Count);
        Assert.Equal("one"u8.ToArray(), records[0].Fragment);
        Assert.Equal("two"u8.ToArray(), records[1].Fragment);
        Assert.Equal(Dtls13ContentType.Ack, records[2].ContentType);
    }

    [Fact]
    public void PlaintextRecord_RoundTrips_AtEpochZero()
    {
        var layer = new Dtls13RecordLayer(Crypto);
        var record = layer.WritePlaintextRecord(Dtls13ContentType.Handshake, "hello"u8, out var sequence);

        Assert.Equal(Dtls13ContentType.Handshake, record[0]);
        Assert.Equal(0xFE, record[1]);
        Assert.Equal(0xFD, record[2]); // legacy_record_version = DTLS 1.2, always
        Assert.Equal(0, (record[3] << 8) | record[4]);

        var reader = new Dtls13RecordLayer(Crypto);
        var only = Assert.Single(reader.ReadDatagram(record));
        Assert.Equal("hello"u8.ToArray(), only.Fragment);
        Assert.Equal(sequence, only.SequenceNumber);
    }

    [Fact]
    public void TamperedRecord_IsDroppedSilently()
    {
        var (sender, receiver) = CreatePair(Dtls13CipherSuite.Aes128GcmSha256, Dtls13Epoch.Application);
        var record = sender.WriteCiphertextRecord(Dtls13Epoch.Application, Dtls13ContentType.ApplicationData, "secret"u8, out _);
        record[^1] ^= 0xFF;

        Assert.Empty(receiver.ReadDatagram(record));
        Assert.Equal(1, receiver.DeprotectFailures);
    }

    [Fact]
    public void RecordForAnUnknownEpoch_IsDropped()
    {
        var (sender, receiver) = CreatePair(Dtls13CipherSuite.Aes128GcmSha256, Dtls13Epoch.Handshake, Dtls13Epoch.Application);
        var record = sender.WriteCiphertextRecord(Dtls13Epoch.Application, Dtls13ContentType.ApplicationData, "later"u8, out _);
        receiver.DropReceiveEpoch(Dtls13Epoch.Application);

        Assert.Empty(receiver.ReadDatagram(record));
    }

    [Fact]
    public void ReplayedRecord_IsRejected()
    {
        var (sender, receiver) = CreatePair(Dtls13CipherSuite.Aes128GcmSha256, Dtls13Epoch.Application);
        var record = sender.WriteCiphertextRecord(Dtls13Epoch.Application, Dtls13ContentType.ApplicationData, "once"u8, out _);

        Assert.Single(receiver.ReadDatagram(record));
        Assert.Empty(receiver.ReadDatagram(record)); // the same bytes a second time
    }

    [Fact]
    public void ReorderedRecords_AreStillAccepted()
    {
        var (sender, receiver) = CreatePair(Dtls13CipherSuite.Aes128GcmSha256, Dtls13Epoch.Application);
        var records = Enumerable.Range(0, 5)
            .Select(i => sender.WriteCiphertextRecord(Dtls13Epoch.Application, Dtls13ContentType.ApplicationData, [(byte)i], out _))
            .ToList();

        // Deliver 4, 0, 3, 1, 2 — UDP reordering, all inside the replay window.
        foreach (var index in new[] { 4, 0, 3, 1, 2 })
            Assert.Single(receiver.ReadDatagram(records[index]));
    }

    [Theory]
    // partial, bits, highest seen so far → the full sequence number
    [InlineData(0UL, 16, -1L, 0UL)]
    [InlineData(5UL, 16, 4L, 5UL)]
    [InlineData(1UL, 8, 255L, 257UL)]     // just wrapped past an 8-bit boundary
    [InlineData(255UL, 8, 257L, 255UL)]   // a late/reordered record from before the wrap
    [InlineData(0UL, 16, 65535L, 65536UL)]
    public void SequenceNumber_IsReconstructedToTheNearestCandidate(ulong partial, int bits, long highest, ulong expected) =>
        Assert.Equal(expected, Dtls13RecordLayer.ReconstructSequenceNumber(partial, bits, highest));

    [Fact]
    public void ReplayWindow_TracksDuplicatesAndTheLeftEdge()
    {
        var window = new Dtls13ReplayWindow();
        Assert.True(window.Accept(0));
        Assert.False(window.Accept(0));
        Assert.True(window.Accept(10));
        Assert.True(window.Accept(5));
        Assert.False(window.Accept(5));

        Assert.True(window.Accept(1000));  // a jump clears the window
        Assert.False(window.Accept(10));   // now far off the left edge
        Assert.True(window.Accept(999));
    }
}
