using CupriWebRTC.Dtls13.Crypto;

namespace CupriWebRTC.Dtls13;

/// <summary>One parsed, deprotected record: its true content type, the epoch it arrived under, and its full record
/// number (needed to ACK it).</summary>
internal sealed record Dtls13IncomingRecord(byte ContentType, ushort Epoch, ulong SequenceNumber, byte[] Fragment);

/// <summary>
/// The DTLS 1.3 record layer (RFC 9147 §4). Two shapes travel on the wire: <b>DTLSPlaintext</b> — the 13-byte
/// classic header, used only at epoch 0 for ClientHello/ServerHello/HelloRetryRequest — and <b>DTLSCiphertext</b>,
/// whose <em>unified header</em> is as short as 2 bytes and whose sequence number is itself encrypted with a mask
/// derived from the record's own ciphertext (§4.2.3). Everything after ServerHello is DTLSCiphertext.
///
/// <para>Three details are easy to get wrong and are called out where they are implemented: the AEAD's additional
/// data is the unified header carrying the <em>unmasked</em> sequence number (it must be — the mask is derived from
/// the ciphertext, which depends on the AAD); the AEAD nonce is built from the 64-bit sequence number alone, with the
/// epoch deliberately excluded (unlike DTLS 1.2); and the true content type lives at the end of the plaintext, after
/// any zero padding.</para>
/// </summary>
internal sealed class Dtls13RecordLayer(IDtls13Crypto crypto)
{
    /// <summary>Fixed bits <c>001</c> in the top three bits of a DTLSCiphertext header.</summary>
    private const byte CiphertextFixedBits = 0x20;
    private const byte CiphertextFixedMask = 0xE0;
    private const byte HeaderConnectionIdBit = 0x10;
    private const byte HeaderSequence16Bit = 0x08;
    private const byte HeaderLengthBit = 0x04;
    private const byte HeaderEpochMask = 0x03;

    /// <summary>The 13-byte DTLSPlaintext header.</summary>
    private const int PlaintextHeaderLength = 13;

    private readonly IDtls13Crypto _crypto = crypto;
    private readonly Dictionary<ushort, SendEpoch> _send = [];
    private readonly Dictionary<ushort, ReceiveEpoch> _receive = [];

    /// <summary>Sequence numbers for the unencrypted epoch-0 records we send.</summary>
    private ulong _plaintextSendSequence;

    private Dtls13CipherSuite _suite = Dtls13CipherSuite.Aes128GcmSha256;

    /// <summary>
    /// Fixes the negotiated suite. Epoch 0 is unencrypted, so the record layer runs before a suite is chosen; this is
    /// called once, between parsing the ClientHello and installing any keys.
    /// </summary>
    public void SetCipherSuite(Dtls13CipherSuite suite)
    {
        if (_send.Count > 0 || _receive.Count > 0)
            throw new InvalidOperationException("the cipher suite cannot change once keys are installed");
        _suite = suite;
    }

    /// <summary>The highest epoch we currently protect outgoing records with (0 until handshake keys are installed).</summary>
    public ushort CurrentSendEpoch { get; private set; }

    /// <summary>Records that failed deprotection since the connection began — a forgery/attack signal (RFC 9147 §4.5.3).</summary>
    public long DeprotectFailures { get; private set; }

    /// <summary>Installs the keys that protect records we send at <paramref name="epoch"/>.</summary>
    public void SetSendKeys(ushort epoch, Dtls13TrafficKeys keys)
    {
        _send[epoch] = new SendEpoch(_crypto.CreateAead(_suite.Aead, keys.Key), keys);
        if (epoch > CurrentSendEpoch)
            CurrentSendEpoch = epoch;
    }

    /// <summary>Installs the keys that deprotect records we receive at <paramref name="epoch"/>.</summary>
    public void SetReceiveKeys(ushort epoch, Dtls13TrafficKeys keys) =>
        _receive[epoch] = new ReceiveEpoch(epoch, _crypto.CreateAead(_suite.Aead, keys.Key), keys);

    /// <summary>True once we can deprotect records at <paramref name="epoch"/>.</summary>
    public bool CanReceiveAt(ushort epoch) => _receive.ContainsKey(epoch);

    /// <summary>Forgets an epoch's receive keys (e.g. handshake keys, once application data is flowing).</summary>
    public void DropReceiveEpoch(ushort epoch)
    {
        if (_receive.Remove(epoch, out var state))
            state.Aead.Dispose();
    }

    /// <summary>
    /// Serialises one unprotected record (epoch 0). Only ClientHello, ServerHello, HelloRetryRequest and pre-key
    /// alerts ever travel this way.
    /// </summary>
    public byte[] WritePlaintextRecord(byte contentType, ReadOnlySpan<byte> fragment, out ulong sequenceNumber)
    {
        var record = new byte[PlaintextHeaderLength + fragment.Length];
        var sequence = _plaintextSendSequence++;
        sequenceNumber = sequence;
        record[0] = contentType;
        record[1] = (byte)(Dtls13Version.Dtls12 >> 8);
        record[2] = unchecked((byte)Dtls13Version.Dtls12);
        record[3] = 0; // epoch (2 bytes) is always 0 for DTLSPlaintext in DTLS 1.3
        record[4] = 0;
        for (var i = 0; i < 6; i++)
            record[5 + i] = (byte)(sequence >> (8 * (5 - i)));
        record[11] = (byte)(fragment.Length >> 8);
        record[12] = (byte)fragment.Length;
        fragment.CopyTo(record.AsSpan(PlaintextHeaderLength));
        return record;
    }

    /// <summary>
    /// Serialises one protected record at <paramref name="epoch"/>. We always emit the "full" unified header shape
    /// (16-bit sequence number, explicit length) so several records can share a datagram and so a peer never has to
    /// infer a length from the datagram boundary.
    /// </summary>
    public byte[] WriteCiphertextRecord(ushort epoch, byte contentType, ReadOnlySpan<byte> fragment, out ulong sequenceNumber)
    {
        if (!_send.TryGetValue(epoch, out var state))
            throw new InvalidOperationException($"no send keys for epoch {epoch}");

        var sequence = state.NextSequenceNumber++;
        sequenceNumber = sequence;

        // DTLSInnerPlaintext: the real content, then the real content type, then (optionally) zero padding. Every
        // suite here has a 16-byte tag, so the ciphertext already clears the 16-byte minimum that record-number
        // masking needs and no padding is required.
        var inner = new byte[fragment.Length + 1];
        fragment.CopyTo(inner);
        inner[^1] = contentType;

        var encryptedLength = inner.Length + _suite.TagLength;
        var record = new byte[5 + encryptedLength];
        record[0] = (byte)(CiphertextFixedBits | HeaderSequence16Bit | HeaderLengthBit | (epoch & HeaderEpochMask));
        record[1] = (byte)(sequence >> 8);
        record[2] = (byte)sequence;
        record[3] = (byte)(encryptedLength >> 8);
        record[4] = (byte)encryptedLength;

        // The additional data is the header exactly as built above — i.e. with the *unmasked* sequence number. It
        // cannot be otherwise: the mask that hides the sequence number is derived from this record's ciphertext,
        // which in turn depends on the additional data.
        var aad = record.AsSpan(0, 5);
        var nonce = BuildNonce(state.Keys.Iv, sequence);
        state.Aead.Encrypt(nonce, inner, aad, record.AsSpan(5));

        // Now mask the sequence number in the header we actually transmit (RFC 9147 §4.2.3).
        var mask = _crypto.RecordNumberMask(_suite.Aead, state.Keys.SequenceNumberKey, record.AsSpan(5, 16));
        record[1] ^= mask[0];
        record[2] ^= mask[1];
        return record;
    }

    /// <summary>
    /// Parses every record in one received datagram, deprotecting as needed. Records that fail deprotection, arrive
    /// for an unknown epoch, or replay a sequence number are dropped silently (RFC 9147 §4.5.2) — on UDP, answering
    /// junk with alerts is a denial-of-service amplifier. A malformed <em>leading</em> byte abandons the rest of the
    /// datagram, since without a length there is no way to find the next record.
    /// </summary>
    public List<Dtls13IncomingRecord> ReadDatagram(ReadOnlySpan<byte> datagram)
    {
        var records = new List<Dtls13IncomingRecord>();
        var at = 0;
        while (at < datagram.Length)
        {
            var first = datagram[at];
            int consumed;
            Dtls13IncomingRecord? record;

            if (first is Dtls13ContentType.Alert or Dtls13ContentType.Handshake or Dtls13ContentType.Ack
                or Dtls13ContentType.ChangeCipherSpec or Dtls13ContentType.ApplicationData)
            {
                if (!TryReadPlaintext(datagram[at..], out record, out consumed))
                    break;
            }
            else if ((first & CiphertextFixedMask) == CiphertextFixedBits)
            {
                if (!TryReadCiphertext(datagram[at..], out record, out consumed))
                    break;
            }
            else
            {
                break; // RFC 9147 §4.1: reject as if deprotection failed
            }

            if (record is not null)
                records.Add(record);
            at += consumed;
        }
        return records;
    }

    private static bool TryReadPlaintext(ReadOnlySpan<byte> data, out Dtls13IncomingRecord? record, out int consumed)
    {
        record = null;
        consumed = 0;
        if (data.Length < PlaintextHeaderLength)
            return false;

        var epoch = (ushort)((data[3] << 8) | data[4]);
        ulong sequence = 0;
        for (var i = 0; i < 6; i++)
            sequence = (sequence << 8) | data[5 + i];
        var length = (data[11] << 8) | data[12];
        if (data.Length < PlaintextHeaderLength + length)
            return false;

        consumed = PlaintextHeaderLength + length;
        // A DTLS 1.3 peer only sends plaintext at epoch 0; anything else is a stray DTLS 1.2 record. Drop it but keep
        // walking the datagram, since the length told us where the next record starts.
        if (epoch != Dtls13Epoch.Initial)
            return true;
        record = new Dtls13IncomingRecord(data[0], epoch, sequence, data.Slice(PlaintextHeaderLength, length).ToArray());
        return true;
    }

    private bool TryReadCiphertext(ReadOnlySpan<byte> data, out Dtls13IncomingRecord? record, out int consumed)
    {
        record = null;
        consumed = 0;

        var first = data[0];
        if ((first & HeaderConnectionIdBit) != 0)
            return false; // we never negotiate a Connection ID, so we cannot know its length

        var sequenceLength = (first & HeaderSequence16Bit) != 0 ? 2 : 1;
        var headerLength = 1 + sequenceLength + ((first & HeaderLengthBit) != 0 ? 2 : 0);
        if (data.Length < headerLength)
            return false;

        int encryptedLength;
        if ((first & HeaderLengthBit) != 0)
        {
            encryptedLength = (data[1 + sequenceLength] << 8) | data[2 + sequenceLength];
            if (data.Length < headerLength + encryptedLength)
                return false;
        }
        else
        {
            encryptedLength = data.Length - headerLength; // a length-less record runs to the end of the datagram
        }

        consumed = headerLength + encryptedLength;
        if (encryptedLength < 16 || encryptedLength < _suite.TagLength + 1)
        {
            DeprotectFailures++;
            return true; // too short to unmask or to hold a content type — drop, but the datagram is still walkable
        }

        var encrypted = data.Slice(headerLength, encryptedLength);
        var state = SelectReceiveEpoch((ushort)(first & HeaderEpochMask));
        if (state is null)
            return true; // no keys for this epoch (yet, or any more) — drop

        // Unmask the sequence number before anything else: the AEAD nonce depends on it.
        var mask = _crypto.RecordNumberMask(_suite.Aead, state.Keys.SequenceNumberKey, encrypted[..16]);
        Span<byte> header = stackalloc byte[headerLength];
        data[..headerLength].CopyTo(header);
        ulong partialSequence = 0;
        for (var i = 0; i < sequenceLength; i++)
        {
            header[1 + i] ^= mask[i];
            partialSequence = (partialSequence << 8) | header[1 + i];
        }

        var sequence = ReconstructSequenceNumber(partialSequence, sequenceLength * 8, state.HighestReceived);
        var nonce = BuildNonce(state.Keys.Iv, sequence);
        var plaintext = new byte[encryptedLength - _suite.TagLength];
        if (!state.Aead.TryDecrypt(nonce, encrypted, header, plaintext, out var written))
        {
            DeprotectFailures++;
            return true;
        }

        // DTLSInnerPlaintext: strip the zero padding to find the true content type at the tail.
        var end = written - 1;
        while (end >= 0 && plaintext[end] == 0)
            end--;
        if (end < 0)
        {
            DeprotectFailures++;
            return true; // an all-zero plaintext has no content type
        }

        // Anti-replay is checked *after* deprotection so that the drop itself cannot leak the record number timing
        // (RFC 9147 §4.5.1), and the window only advances for records that actually authenticated.
        if (!state.Window.Accept(sequence))
            return true;

        record = new Dtls13IncomingRecord(plaintext[end], state.Epoch, sequence, plaintext.AsSpan(0, end).ToArray());
        return true;
    }

    /// <summary>
    /// Picks the receive epoch a record belongs to from the two epoch bits it carries: the highest installed epoch
    /// with matching low bits (RFC 9147 §4.2.2).
    /// </summary>
    private ReceiveEpoch? SelectReceiveEpoch(ushort epochLowBits)
    {
        ReceiveEpoch? best = null;
        foreach (var (epoch, state) in _receive)
            if ((epoch & HeaderEpochMask) == epochLowBits && (best is null || epoch > best.Epoch))
                best = state;
        return best;
    }

    /// <summary>
    /// Expands a truncated (8- or 16-bit) sequence number to the full 48-bit value numerically closest to one past
    /// the highest record already accepted in this epoch (the algorithm RFC 9147 §4.2.2 recommends).
    /// </summary>
    internal static ulong ReconstructSequenceNumber(ulong partial, int bits, long highestReceived)
    {
        var window = 1UL << bits;
        var mask = window - 1;
        var expected = (ulong)(highestReceived + 1);
        var candidate = (expected & ~mask) | partial;

        // Consider the neighbouring wraps too and take whichever lands closest to `expected`.
        var best = candidate;
        var bestDistance = Distance(candidate, expected);
        if (candidate >= window)
        {
            var lower = candidate - window;
            var distance = Distance(lower, expected);
            if (distance < bestDistance)
            {
                best = lower;
                bestDistance = distance;
            }
        }
        var higher = candidate + window;
        if (Distance(higher, expected) < bestDistance)
            best = higher;
        return best;

        static ulong Distance(ulong a, ulong b) => a > b ? a - b : b - a;
    }

    /// <summary>
    /// The per-record AEAD nonce (RFC 8446 §5.3 as DTLS 1.3 applies it): the 64-bit record sequence number, big-endian
    /// and left-padded with zeros to the IV length, XORed with the static write IV. Note the epoch is <em>not</em>
    /// part of it — that is a deliberate change from DTLS 1.2 (RFC 9147 §4).
    /// </summary>
    private static byte[] BuildNonce(byte[] iv, ulong sequence)
    {
        var nonce = (byte[])iv.Clone();
        for (var i = 0; i < 8; i++)
            nonce[nonce.Length - 1 - i] ^= (byte)(sequence >> (8 * i));
        return nonce;
    }

    private sealed class SendEpoch(IDtls13Aead aead, Dtls13TrafficKeys keys)
    {
        public IDtls13Aead Aead { get; } = aead;
        public Dtls13TrafficKeys Keys { get; } = keys;
        public ulong NextSequenceNumber;
    }

    private sealed class ReceiveEpoch(ushort epoch, IDtls13Aead aead, Dtls13TrafficKeys keys)
    {
        public ushort Epoch { get; } = epoch;
        public IDtls13Aead Aead { get; } = aead;
        public Dtls13TrafficKeys Keys { get; } = keys;
        public Dtls13ReplayWindow Window { get; } = new();
        public long HighestReceived => Window.Highest;
    }
}

/// <summary>
/// The sliding replay window of RFC 9147 §4.5.1 (borrowed from IPsec, RFC 4303 §3.4.3): a 64-slot bitmap anchored at
/// the highest sequence number accepted so far in an epoch. It rejects duplicates and anything that has fallen off
/// the left edge, while still tolerating the reordering UDP hands us.
/// </summary>
internal sealed class Dtls13ReplayWindow
{
    private const int WindowSize = 64;

    private ulong _bitmap;

    /// <summary>The highest sequence number accepted so far, or -1 before anything has been.</summary>
    public long Highest { get; private set; } = -1;

    /// <summary>Records <paramref name="sequence"/> as seen; false if it is a duplicate or too old to judge.</summary>
    public bool Accept(ulong sequence)
    {
        var value = (long)sequence;
        if (Highest < 0)
        {
            Highest = value;
            _bitmap = 1;
            return true;
        }
        if (value > Highest)
        {
            var shift = value - Highest;
            _bitmap = shift >= WindowSize ? 1UL : (_bitmap << (int)shift) | 1UL;
            Highest = value;
            return true;
        }

        var back = Highest - value;
        if (back >= WindowSize)
            return false; // off the left edge — cannot prove it is not a replay
        var bit = 1UL << (int)back;
        if ((_bitmap & bit) != 0)
            return false; // already seen
        _bitmap |= bit;
        return true;
    }
}
