using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CupriWebRTC.Sctp;

/// <summary>A data channel opened by the peer (RFC 8832): its stream id and negotiated label/protocol.</summary>
public sealed record SctpDataChannel(ushort StreamId, string Label, string Protocol);

/// <summary>
/// A minimal SCTP association for WebRTC DataChannels — the <b>passive/responder</b> side (the peer, e.g. a browser,
/// initiates). It runs the four-way handshake (INIT → INIT-ACK with a stateless HMAC state cookie → COOKIE-ECHO →
/// COOKIE-ACK), then delivers ordered DATA (acking with SACK), handles DCEP channel open/ack, and sends messages.
///
/// <para>Model: <see cref="HandlePacket"/> takes one inbound SCTP packet and returns the packets to send back;
/// delivered channels/messages surface via events. This keeps the state machine pure and testable, independent of the
/// DTLS transport it will run over.</para>
///
/// <para>Minimal profile (first cut): in-order single-chunk messages, cumulative SACK only (no gap blocks), no
/// congestion control, and no fragmentation/reassembly. Enough for DCEP + small messages; larger messages and loss
/// recovery come later.</para>
/// </summary>
public sealed class SctpAssociation
{
    private const uint LocalReceiverWindow = 128 * 1024;
    private const ushort MaxStreams = 65535;
    private static readonly byte[][] NoPackets = [];

    private readonly ushort _localPort;
    private readonly ushort _remotePort;
    private readonly byte[] _cookieSecret = RandomNumberGenerator.GetBytes(32);
    private readonly Dictionary<ushort, ushort> _outboundStreamSequence = [];
    private readonly List<(uint Tsn, byte[] Packet)> _unacknowledged = [];

    private bool _established;
    private bool _initiator;
    private uint _localVerificationTag;
    private uint _peerVerificationTag;
    private uint _nextLocalTsn;
    private uint _peerCumulativeTsn; // highest in-order TSN received

    public SctpAssociation(ushort localPort = 5000, ushort remotePort = 5000)
    {
        _localPort = localPort;
        _remotePort = remotePort;
    }

    /// <summary>True once the four-way handshake has completed.</summary>
    public bool IsEstablished => _established;

    /// <summary>Raised when the peer opens a data channel (DCEP DATA_CHANNEL_OPEN).</summary>
    public event Action<SctpDataChannel>? ChannelOpened;

    /// <summary>Raised for an inbound application message: (streamId, PPID, payload).</summary>
    public event Action<ushort, uint, byte[]>? MessageReceived;

    /// <summary>Processes one inbound SCTP packet; returns the SCTP packets to send back (may be empty).</summary>
    public IReadOnlyList<byte[]> HandlePacket(ReadOnlySpan<byte> packetBytes)
    {
        if (!SctpPacket.TryParse(packetBytes, out var packet))
            return NoPackets;

        var responses = new List<byte[]>();
        foreach (var chunk in packet.Chunks)
        {
            switch (chunk.Type)
            {
                case SctpChunkType.Init:
                    HandleInit(chunk, responses);
                    break;
                case SctpChunkType.InitAck when _initiator:
                    HandleInitAck(chunk, packet.VerificationTag, responses);
                    break;
                case SctpChunkType.CookieEcho:
                    HandleCookieEcho(chunk, packet.VerificationTag, responses);
                    break;
                case SctpChunkType.CookieAck when _initiator && packet.VerificationTag == _localVerificationTag:
                    _established = true;
                    break;
                case SctpChunkType.Data when _established && packet.VerificationTag == _localVerificationTag:
                    HandleData(chunk, responses);
                    break;
                case SctpChunkType.Sack when _established && packet.VerificationTag == _localVerificationTag:
                    HandleSack(chunk);
                    break;
                case SctpChunkType.Heartbeat when _established:
                    responses.Add(BuildPacket(_peerVerificationTag, new SctpChunk { Type = SctpChunkType.HeartbeatAck, Value = chunk.Value }));
                    break;
                // COOKIE_ACK / SHUTDOWN etc. are not needed by the responder's minimal path.
            }
        }
        return responses;
    }

    /// <summary>Sends an application message on a stream; returns the SCTP packet(s) to transmit.</summary>
    public IReadOnlyList<byte[]> SendMessage(ushort streamId, uint ppid, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (!_established)
            return NoPackets;

        var sequence = _outboundStreamSequence.GetValueOrDefault(streamId);
        _outboundStreamSequence[streamId] = (ushort)(sequence + 1);

        var tsn = _nextLocalTsn++;
        var body = new DataChunk(tsn, streamId, sequence, ppid, data).Encode();
        var chunk = new SctpChunk
        {
            Type = SctpChunkType.Data,
            Flags = DataChunk.FlagBeginning | DataChunk.FlagEnding, // single-chunk message
            Value = body,
        };
        var packet = BuildPacket(_peerVerificationTag, chunk);
        _unacknowledged.Add((tsn, packet));
        return [packet];
    }

    /// <summary>
    /// Begins the association as the <b>active/initiator</b> side (the generic-library counterpart to the passive
    /// path). Returns the INIT packet to send; the handshake then completes as INIT-ACK / COOKIE-ECHO / COOKIE-ACK
    /// flow through <see cref="HandlePacket"/>. (A WebRTC node serving browsers is usually the responder, not this.)
    /// </summary>
    public IReadOnlyList<byte[]> Associate()
    {
        _initiator = true;
        _localVerificationTag = NonZeroTag();
        _nextLocalTsn = RandomTsn();
        var init = new InitData(_localVerificationTag, LocalReceiverWindow, MaxStreams, MaxStreams, _nextLocalTsn).Encode();
        // INIT is sent with verification tag 0.
        return [BuildPacket(0, new SctpChunk { Type = SctpChunkType.Init, Value = init })];
    }

    private void HandleInitAck(SctpChunk chunk, uint headerVerificationTag, List<byte[]> responses)
    {
        if (headerVerificationTag != _localVerificationTag)
            return;
        var initAck = InitData.Decode(chunk.Value);
        if (initAck.StateCookie is null)
            return;

        _peerVerificationTag = initAck.InitiateTag;
        _peerCumulativeTsn = initAck.InitialTsn - 1;
        // COOKIE-ECHO carries the peer's verification tag; echoes the state cookie verbatim.
        responses.Add(BuildPacket(_peerVerificationTag, new SctpChunk { Type = SctpChunkType.CookieEcho, Value = initAck.StateCookie }));
    }

    private void HandleInit(SctpChunk chunk, List<byte[]> responses)
    {
        var init = InitData.Decode(chunk.Value);

        // Stateless: choose our tag/TSN, seal everything we'll need into the cookie, keep no state until COOKIE-ECHO.
        var localTag = NonZeroTag();
        var localTsn = RandomTsn();
        var cookie = BuildCookie(peerTag: init.InitiateTag, peerTsn: init.InitialTsn, localTag, localTsn);

        var initAck = new InitData(localTag, LocalReceiverWindow, MaxStreams, MaxStreams, localTsn, cookie).Encode();
        // INIT-ACK is sent with the verification tag = the peer's Initiate Tag.
        responses.Add(BuildPacket(init.InitiateTag, new SctpChunk { Type = SctpChunkType.InitAck, Value = initAck }));
    }

    private void HandleCookieEcho(SctpChunk chunk, uint headerVerificationTag, List<byte[]> responses)
    {
        if (!TryOpenCookie(chunk.Value, out var peerTag, out var peerTsn, out var localTag, out var localTsn))
            return;
        if (headerVerificationTag != localTag)
            return; // COOKIE-ECHO must carry our tag

        _peerVerificationTag = peerTag;
        _localVerificationTag = localTag;
        _nextLocalTsn = localTsn;
        _peerCumulativeTsn = peerTsn - 1; // we've received everything up to just before their first TSN
        _established = true;

        responses.Add(BuildPacket(_peerVerificationTag, new SctpChunk { Type = SctpChunkType.CookieAck }));
    }

    private void HandleData(SctpChunk chunk, List<byte[]> responses)
    {
        var data = DataChunk.Decode(chunk.Value);

        if (data.Tsn == _peerCumulativeTsn + 1) // in order (minimal: gaps aren't buffered)
        {
            _peerCumulativeTsn = data.Tsn;
            Deliver(data, responses);
        }

        // Acknowledge up to the cumulative TSN.
        responses.Add(BuildPacket(_peerVerificationTag,
            new SctpChunk { Type = SctpChunkType.Sack, Value = new SackChunk(_peerCumulativeTsn, LocalReceiverWindow).Encode() }));
    }

    private void Deliver(DataChunk data, List<byte[]> responses)
    {
        if (data.Ppid == Dcep.Ppid)
        {
            var open = Dcep.TryParseOpen(data.UserData);
            if (open is not null)
            {
                responses.AddRange(SendMessage(data.StreamId, Dcep.Ppid, Dcep.BuildAck())); // DATA_CHANNEL_ACK
                ChannelOpened?.Invoke(new SctpDataChannel(data.StreamId, open.Label, open.Protocol));
            }
            // A DATA_CHANNEL_ACK from the peer needs no action here.
        }
        else
        {
            MessageReceived?.Invoke(data.StreamId, data.Ppid, data.UserData);
        }
    }

    private void HandleSack(SctpChunk chunk)
    {
        var sack = SackChunk.Decode(chunk.Value);
        _unacknowledged.RemoveAll(entry => SerialLessOrEqual(entry.Tsn, sack.CumulativeTsnAck));
    }

    private byte[] BuildPacket(uint verificationTag, SctpChunk chunk)
    {
        var packet = new SctpPacket { SourcePort = _localPort, DestinationPort = _remotePort, VerificationTag = verificationTag };
        packet.Chunks.Add(chunk);
        return packet.Encode();
    }

    // Cookie = [peerTag, peerTsn, localTag, localTsn] + HMAC-SHA256(secret, that)[..16]. Stateless handshake.
    private byte[] BuildCookie(uint peerTag, uint peerTsn, uint localTag, uint localTsn)
    {
        var cookie = new byte[16 + 16];
        BinaryPrimitives.WriteUInt32BigEndian(cookie.AsSpan(0), peerTag);
        BinaryPrimitives.WriteUInt32BigEndian(cookie.AsSpan(4), peerTsn);
        BinaryPrimitives.WriteUInt32BigEndian(cookie.AsSpan(8), localTag);
        BinaryPrimitives.WriteUInt32BigEndian(cookie.AsSpan(12), localTsn);
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(_cookieSecret, cookie.AsSpan(0, 16), mac);
        mac[..16].CopyTo(cookie.AsSpan(16));
        return cookie;
    }

    private bool TryOpenCookie(byte[] cookie, out uint peerTag, out uint peerTsn, out uint localTag, out uint localTsn)
    {
        peerTag = peerTsn = localTag = localTsn = 0;
        if (cookie.Length != 32)
            return false;
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(_cookieSecret, cookie.AsSpan(0, 16), mac);
        if (!CryptographicOperations.FixedTimeEquals(mac[..16], cookie.AsSpan(16, 16)))
            return false;

        peerTag = BinaryPrimitives.ReadUInt32BigEndian(cookie.AsSpan(0));
        peerTsn = BinaryPrimitives.ReadUInt32BigEndian(cookie.AsSpan(4));
        localTag = BinaryPrimitives.ReadUInt32BigEndian(cookie.AsSpan(8));
        localTsn = BinaryPrimitives.ReadUInt32BigEndian(cookie.AsSpan(12));
        return true;
    }

    private static uint NonZeroTag()
    {
        uint tag;
        do { tag = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4)); }
        while (tag == 0);
        return tag;
    }

    private static uint RandomTsn() => BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));

    // RFC 1982 serial-number arithmetic for 32-bit TSNs: a <= b.
    private static bool SerialLessOrEqual(uint a, uint b) => (int)(b - a) >= 0;
}
