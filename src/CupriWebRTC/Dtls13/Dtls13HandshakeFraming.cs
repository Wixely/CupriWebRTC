namespace CupriWebRTC.Dtls13;

/// <summary>A complete handshake message, in the TLS 1.3 form the transcript hashes (RFC 9147 §5.2 strips DTLS's
/// <c>message_seq</c>/<c>fragment_offset</c>/<c>fragment_length</c> before hashing).</summary>
internal sealed record Dtls13HandshakeMessage(byte Type, ushort MessageSeq, byte[] Body)
{
    /// <summary>The 4-byte TLS handshake header — the DTLS one is 12 bytes and never reaches the transcript.</summary>
    public const int TlsHeaderLength = 4;

    /// <summary>The 12-byte DTLS handshake header: <c>type(1) length(3) message_seq(2) fragment_offset(3) fragment_length(3)</c>.</summary>
    public const int DtlsHeaderLength = 12;

    /// <summary>The bytes this message contributes to the transcript hash: TLS header + body.</summary>
    public byte[] ToTranscriptBytes()
    {
        var bytes = new byte[TlsHeaderLength + Body.Length];
        bytes[0] = Type;
        bytes[1] = (byte)(Body.Length >> 16);
        bytes[2] = (byte)(Body.Length >> 8);
        bytes[3] = (byte)Body.Length;
        Body.CopyTo(bytes.AsSpan(TlsHeaderLength));
        return bytes;
    }
}

/// <summary>
/// A set of merged byte ranges over one handshake message. It answers the two questions both directions of the
/// handshake need: "have I received every byte of this message yet?" (reassembly) and "which bytes of the message I
/// sent are still unacknowledged?" (retransmission).
/// </summary>
internal sealed class Dtls13RangeSet
{
    private readonly List<(int Start, int End)> _ranges = [];
    private bool _touched;

    /// <summary>Adds <c>[offset, offset+length)</c>, merging with anything it touches.</summary>
    public void Add(int offset, int length)
    {
        _touched = true; // a zero-length message is "complete" once any fragment of it has arrived
        if (length <= 0)
            return;
        var start = offset;
        var end = offset + length;
        var index = 0;
        while (index < _ranges.Count && _ranges[index].End < start)
            index++;
        var insertAt = index;
        while (index < _ranges.Count && _ranges[index].Start <= end)
        {
            start = Math.Min(start, _ranges[index].Start);
            end = Math.Max(end, _ranges[index].End);
            _ranges.RemoveAt(index);
        }
        _ranges.Insert(insertAt, (start, end));
    }

    /// <summary>True if every byte of <c>[0, length)</c> has been added.</summary>
    public bool Covers(int length) =>
        length <= 0 ? _touched : _ranges.Count > 0 && _ranges[0].Start <= 0 && _ranges[0].End >= length;

    /// <summary>The still-missing pieces of <c>[0, length)</c>, in order.</summary>
    public IEnumerable<(int Offset, int Length)> Gaps(int length)
    {
        var at = 0;
        foreach (var (start, end) in _ranges)
        {
            if (start > at)
                yield return (at, Math.Min(start, length) - at);
            at = Math.Max(at, end);
            if (at >= length)
                yield break;
        }
        if (at < length)
            yield return (at, length - at);
    }
}

/// <summary>What one record's worth of handshake fragments produced: the messages it completed, and whether the
/// record itself may be acknowledged.</summary>
internal sealed record Dtls13ReassemblyResult(List<Dtls13HandshakeMessage> Delivered, bool Acknowledgeable);

/// <summary>
/// Reassembles inbound handshake messages from DTLS fragments (RFC 9147 §5.5). It enforces the <c>next_receive_seq</c>
/// discipline of §5.2 — messages are delivered strictly in order, later ones are buffered until their turn — and it
/// tolerates duplicate and overlapping fragments, which a retransmitting peer will send.
/// </summary>
internal sealed class Dtls13HandshakeReassembler
{
    /// <summary>A bound on how far ahead we buffer, so a peer cannot make us hold arbitrary state.</summary>
    private const int MaxBufferedMessages = 16;

    /// <summary>The largest handshake message we will reassemble — well above any real certificate chain.</summary>
    private const int MaxMessageLength = 64 * 1024;

    private readonly Dictionary<ushort, Partial> _partial = [];

    /// <summary>The message_seq we are waiting for; everything below it has been delivered.</summary>
    public ushort NextReceiveSequence { get; private set; }

    /// <summary>True if a fragment for a message we have already delivered arrived — i.e. the peer is retransmitting
    /// a flight we have already moved past, and should be re-ACKed.</summary>
    public bool SawRetransmission { get; private set; }

    /// <summary>Clears the retransmission flag after the caller has reacted to it.</summary>
    public void ClearRetransmissionFlag() => SawRetransmission = false;

    /// <summary>
    /// Feeds one record's worth of handshake bytes (which may hold several fragments) and returns whichever complete
    /// messages that made deliverable, in order, along with whether the record may be acknowledged — RFC 9147 §7
    /// forbids ACKing a record whose fragments were all discarded, since that would deadlock the peer.
    /// </summary>
    public Dtls13ReassemblyResult Add(ReadOnlySpan<byte> handshakeRecord)
    {
        var acknowledgeable = false;
        var reader = new Dtls13Reader(handshakeRecord);
        while (reader.Remaining >= Dtls13HandshakeMessage.DtlsHeaderLength)
        {
            var type = reader.ReadUInt8();
            var length = checked((int)reader.ReadUInt24());
            var messageSeq = reader.ReadUInt16();
            var fragmentOffset = checked((int)reader.ReadUInt24());
            var fragmentLength = checked((int)reader.ReadUInt24());

            if (length > MaxMessageLength)
                throw new Dtls13DecodeException($"handshake message of {length} bytes exceeds the {MaxMessageLength}-byte limit");
            if (fragmentOffset + fragmentLength > length)
                throw new Dtls13DecodeException("handshake fragment runs past the end of its message");

            var fragment = reader.ReadBytes(fragmentLength);

            if (messageSeq < NextReceiveSequence)
            {
                SawRetransmission = true;
                continue; // already delivered — RFC 9147 §5.2 says discard
            }
            if (!_partial.TryGetValue(messageSeq, out var partial))
            {
                if (_partial.Count >= MaxBufferedMessages)
                    continue; // too far ahead; the peer will retransmit once we catch up
                partial = new Partial(type, length);
                _partial[messageSeq] = partial;
            }
            if (partial.Type != type || partial.Data.Length != length)
                throw new Dtls13DecodeException("handshake fragments disagree about their message's type or length");

            fragment.CopyTo(partial.Data.AsSpan(fragmentOffset));
            partial.Received.Add(fragmentOffset, fragmentLength);
            acknowledgeable = true;
        }

        var delivered = new List<Dtls13HandshakeMessage>();
        while (_partial.TryGetValue(NextReceiveSequence, out var next) && next.Received.Covers(next.Data.Length))
        {
            delivered.Add(new Dtls13HandshakeMessage(next.Type, NextReceiveSequence, next.Data));
            _partial.Remove(NextReceiveSequence);
            NextReceiveSequence++;
        }
        return new Dtls13ReassemblyResult(delivered, acknowledgeable);
    }

    private sealed class Partial(byte type, int length)
    {
        public byte Type { get; } = type;
        public byte[] Data { get; } = new byte[length];
        public Dtls13RangeSet Received { get; } = new();
    }
}

/// <summary>
/// One outbound flight: the messages sent together and awaiting the peer's response or ACK. It fragments messages to
/// fit the datagram budget, remembers which record carried which bytes so an incoming ACK can retire them
/// (RFC 9147 §7.2), and can re-emit just the parts still outstanding. A flight can span epochs — the server's second
/// flight is exactly that, an unencrypted ServerHello followed by the encrypted remainder.
/// </summary>
internal sealed class Dtls13OutgoingFlight
{
    private readonly List<Entry> _messages = [];
    private readonly Dictionary<(ushort Epoch, ulong SequenceNumber), List<Piece>> _sentIn = [];

    /// <summary>True once every byte of every message has been acknowledged.</summary>
    public bool IsFullyAcknowledged => _messages.TrueForAll(m => m.Acknowledged.Covers(m.Message.Body.Length));

    /// <summary>True if the flight has no messages (nothing to retransmit).</summary>
    public bool IsEmpty => _messages.Count == 0;

    /// <summary>Adds a message to the flight, to be protected at <paramref name="epoch"/>.</summary>
    public void Add(Dtls13HandshakeMessage message, ushort epoch) => _messages.Add(new Entry(message, epoch));

    /// <summary>
    /// The fragments to transmit: everything on a first pass, or only the unacknowledged remainder on a
    /// retransmission. Each fragment is a ready-to-send DTLSHandshake (12-byte header + payload).
    /// </summary>
    public List<(byte[] Fragment, ushort Epoch, Piece Piece)> BuildFragments(int maxFragmentLength, bool onlyUnacknowledged)
    {
        var fragments = new List<(byte[], ushort, Piece)>();
        foreach (var entry in _messages)
        {
            // Fragmentation is over the message *body*: DTLS's 12-byte header replaces TLS's 4-byte one, and
            // fragment_offset/fragment_length index into the body alone (RFC 9147 §5.5).
            var body = entry.Message.Body;
            var pieces = onlyUnacknowledged ? [.. entry.Acknowledged.Gaps(body.Length)] : new List<(int Offset, int Length)> { (0, body.Length) };
            foreach (var (offset, length) in pieces)
            {
                var at = offset;
                do
                {
                    var take = Math.Min(length - (at - offset), maxFragmentLength);
                    fragments.Add((BuildFragment(entry.Message, at, take), entry.Epoch, new Piece(entry, at, take)));
                    at += take;
                }
                while (at < offset + length); // a zero-length body still emits exactly one empty fragment
            }
        }
        return fragments;
    }

    /// <summary>One ready-to-send DTLSHandshake: the 12-byte header then <c>body[offset, offset+length)</c>.</summary>
    private static byte[] BuildFragment(Dtls13HandshakeMessage message, int offset, int length)
    {
        var fragment = new byte[Dtls13HandshakeMessage.DtlsHeaderLength + length];
        fragment[0] = message.Type;
        fragment[1] = (byte)(message.Body.Length >> 16);
        fragment[2] = (byte)(message.Body.Length >> 8);
        fragment[3] = (byte)message.Body.Length;
        fragment[4] = (byte)(message.MessageSeq >> 8);
        fragment[5] = (byte)message.MessageSeq;
        fragment[6] = (byte)(offset >> 16);
        fragment[7] = (byte)(offset >> 8);
        fragment[8] = (byte)offset;
        fragment[9] = (byte)(length >> 16);
        fragment[10] = (byte)(length >> 8);
        fragment[11] = (byte)length;
        message.Body.AsSpan(offset, length).CopyTo(fragment.AsSpan(Dtls13HandshakeMessage.DtlsHeaderLength));
        return fragment;
    }

    /// <summary>Notes that a record carried these pieces, so a later ACK for it can retire them.</summary>
    public void RecordSent(ushort epoch, ulong sequenceNumber, IEnumerable<Piece> pieces) =>
        _sentIn[(epoch, sequenceNumber)] = [.. pieces];

    /// <summary>Applies a peer ACK: every byte carried by an acknowledged record is retired.</summary>
    public void Acknowledge(ulong epoch, ulong sequenceNumber)
    {
        if (!_sentIn.TryGetValue(((ushort)epoch, sequenceNumber), out var pieces))
            return;
        foreach (var piece in pieces)
            piece.Entry.Acknowledged.Add(piece.Offset, piece.Length);
    }

    /// <summary>Marks the whole flight acknowledged — what receipt of the peer's next flight implies (RFC 9147 §7.1).</summary>
    public void AcknowledgeAll()
    {
        foreach (var entry in _messages)
            entry.Acknowledged.Add(0, entry.Message.Body.Length);
    }

    /// <summary>A contiguous slice of one message as carried in one record.</summary>
    internal sealed record Piece(Entry Entry, int Offset, int Length);

    /// <summary>One message in the flight, the epoch it is protected at, and how much of it the peer has acknowledged.</summary>
    internal sealed class Entry(Dtls13HandshakeMessage message, ushort epoch)
    {
        public Dtls13HandshakeMessage Message { get; } = message;
        public ushort Epoch { get; } = epoch;
        public Dtls13RangeSet Acknowledged { get; } = new();
    }
}
