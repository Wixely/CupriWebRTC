using System.Security.Cryptography;
using CupriWebRTC.Dtls;
using CupriWebRTC.Dtls13.Crypto;
using Org.BouncyCastle.Tls;

namespace CupriWebRTC.Dtls13;

/// <summary>A DTLS 1.3 handshake or connection failure, carrying the alert (if any) that caused or was sent for it.</summary>
public sealed class Dtls13Exception(string message, byte alertDescription = 0, Exception? inner = null)
    : Exception(message, inner)
{
    /// <summary>The alert description involved, or 0 if the failure was local.</summary>
    public byte AlertDescription { get; } = alertDescription;
}

/// <summary>
/// One peer's DTLS 1.3 connection, server side: it runs the handshake over a datagram transport and then <em>is</em>
/// the secured transport that SCTP runs over.
///
/// <para>The handshake is the RFC 9147 server flow — ClientHello (optionally answered by a HelloRetryRequest carrying
/// a stateless cookie), then ServerHello in the clear followed by an encrypted flight of EncryptedExtensions,
/// CertificateRequest, Certificate, CertificateVerify and Finished, then the client's encrypted flight, then an ACK.
/// After that, application records flow at epoch 3.</para>
///
/// <para>Threading mirrors the BouncyCastle path this replaces: <see cref="Handshake"/> blocks on the calling thread
/// until the connection is up, after which <see cref="Receive"/> (one reader) and <see cref="Send"/> (any thread) are
/// safe to use concurrently — everything that touches record state runs under one lock, with only the blocking wait
/// for a datagram outside it.</para>
/// </summary>
internal sealed class Dtls13ServerConnection : ISecureDatagramTransport
{
    /// <summary>The AEAD tag + inner content type + unified header a protected record costs.</summary>
    private const int CiphertextOverhead = 5 + 1 + 16;

    /// <summary>How recently we can have sent a flight and still ignore a peer retransmission as "crossed in flight"
    /// rather than lost. A quarter of the initial retransmit timeout, the same ratio RFC 9147 §7.1 uses for ACKs.</summary>
    private const long MinRetransmitInterval = 250;

    private readonly DatagramTransport _transport;
    private readonly Dtls13ServerOptions _options;
    private readonly IDtls13Signer _signer;
    private readonly IDtls13Crypto _crypto;
    private readonly Dtls13RecordLayer _records;
    private readonly Dtls13HandshakeReassembler _reassembler = new();
    private readonly Queue<byte[]> _applicationData = new();
    private readonly List<(ulong Epoch, ulong SequenceNumber)> _pendingAck = [];
    private readonly byte[] _cookieSecret = new byte[32];
    private readonly byte[] _receiveBuffer;
    private readonly Lock _gate = new();

    private Dtls13CipherSuite _suite = Dtls13CipherSuite.Aes128GcmSha256;
    private Dtls13KeySchedule? _schedule;
    private IDtls13Hash? _hash;
    private IDtls13RunningHash? _transcript;
    private IDtls13KeyExchange? _keyExchange;
    private Dtls13OutgoingFlight? _flight;
    private byte[]? _handshakeSecret;
    private byte[]? _clientHandshakeTrafficSecret;
    private byte[]? _serverHandshakeTrafficSecret;
    private byte[]? _clientApplicationTrafficSecret;
    private byte[]? _serverApplicationTrafficSecret;
    private byte[]? _clientHello1Hash;
    private byte[] _clientRandom = [];
    private ushort _nextSendMessageSeq;
    private long _lastTransmit;
    private ushort _clientKeyUpdateEpoch = Dtls13Epoch.Application;
    private ushort _serverKeyUpdateEpoch = Dtls13Epoch.Application;
    private State _state = State.ExpectClientHello;
    private bool _closed;

    public Dtls13ServerConnection(DatagramTransport transport, IDtls13Signer signer, Dtls13ServerOptions options)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _crypto = options.Crypto;
        _records = new Dtls13RecordLayer(_crypto);
        _receiveBuffer = new byte[Math.Max(2048, _transport.GetReceiveLimit())];
        _crypto.GetRandom(_cookieSecret);
    }

    /// <summary>The DTLS version this connection speaks — always 1.3; this type has no other role.</summary>
    public string ProtocolVersion => "DTLS 1.3";

    /// <summary>The suite that was negotiated (valid once the handshake has completed).</summary>
    public Dtls13CipherSuite NegotiatedCipherSuite => _suite;

    /// <summary>The named group the ECDHE ran over (valid once the handshake has completed).</summary>
    public ushort NegotiatedGroup => _keyExchange?.NamedGroup ?? 0;

    /// <summary>The peer's certificate chain as presented, unverified — WebRTC authenticates above this channel.</summary>
    public IReadOnlyList<byte[]> PeerCertificateChain { get; private set; } = [];

    /// <summary>
    /// Runs the server handshake to completion on the calling thread, retransmitting our flight on a doubling timer
    /// until the peer answers or acknowledges it.
    /// </summary>
    public void Handshake()
    {
        var buffer = _receiveBuffer;
        var deadline = Environment.TickCount64 + (long)_options.HandshakeTimeout.TotalMilliseconds;
        var retransmitTimeout = (long)_options.InitialRetransmitTimeout.TotalMilliseconds;
        var maxRetransmitTimeout = (long)_options.MaxRetransmitTimeout.TotalMilliseconds;
        var nextRetransmit = long.MaxValue; // nothing to retransmit until we have sent a flight

        while (true)
        {
            lock (_gate)
                if (_state == State.Established)
                    return;

            var now = Environment.TickCount64;
            if (now >= deadline)
                throw new Dtls13Exception($"DTLS 1.3 handshake did not complete within {_options.HandshakeTimeout}");

            var wait = (int)Math.Max(1, Math.Min(deadline, nextRetransmit) - now);
            var received = _transport.Receive(buffer, 0, buffer.Length, wait);
            if (received > 0)
            {
                lock (_gate)
                {
                    ProcessDatagram(buffer.AsSpan(0, received));
                    if (_flight is not null && !_flight.IsEmpty && !_flight.IsFullyAcknowledged)
                        nextRetransmit = Environment.TickCount64 + retransmitTimeout;
                }
                continue;
            }

            if (Environment.TickCount64 < nextRetransmit)
                continue;

            lock (_gate)
            {
                if (_flight is null || _flight.IsEmpty || _flight.IsFullyAcknowledged)
                {
                    nextRetransmit = long.MaxValue;
                    continue;
                }
                TransmitFlight(onlyUnacknowledged: true);
            }
            retransmitTimeout = Math.Min(retransmitTimeout * 2, maxRetransmitTimeout);
            nextRetransmit = Environment.TickCount64 + retransmitTimeout;
        }
    }

    // ---------------------------------------------------------------- record dispatch

    private void ProcessDatagram(ReadOnlySpan<byte> datagram)
    {
        foreach (var record in _records.ReadDatagram(datagram))
        {
            switch (record.ContentType)
            {
                case Dtls13ContentType.Handshake:
                    HandleHandshakeRecord(record);
                    break;
                case Dtls13ContentType.Ack:
                    HandleAck(record.Fragment);
                    break;
                case Dtls13ContentType.ApplicationData:
                    if (record.Fragment.Length > 0)
                        _applicationData.Enqueue(record.Fragment);
                    break;
                case Dtls13ContentType.Alert:
                    HandleAlert(record.Fragment, record.Epoch);
                    break;
                case Dtls13ContentType.ChangeCipherSpec:
                    break; // DTLS 1.3 never sends one; ignore a stray middlebox-compatibility record
            }
        }
        FlushAck();
    }

    private void HandleHandshakeRecord(Dtls13IncomingRecord record)
    {
        Dtls13ReassemblyResult result;
        try
        {
            result = _reassembler.Add(record.Fragment);
        }
        catch (Dtls13DecodeException ex)
        {
            throw Fatal(Dtls13Alert.DecodeError, ex.Message);
        }

        if (_reassembler.SawRetransmission)
        {
            _reassembler.ClearRetransmissionFlag();
            if (_state != State.Established)
            {
                // The peer is resending a flight we have already consumed, which usually means our answer never
                // arrived. Resending our flight is the fix (RFC 9147 §5.8.1); an ACK would only tell it to stop
                // asking while still leaving it without our messages. The guard is for the common case where the two
                // simply crossed in flight — browsers retransmit aggressively (~50ms), so without it every handshake
                // sends its second flight twice for nothing.
                if (_flight is { IsEmpty: false } && Environment.TickCount64 - _lastTransmit >= MinRetransmitInterval)
                    TransmitFlight(onlyUnacknowledged: true);
                return;
            }
            // Once established there is nothing left to resend, and the client's final flight must be ACKed — that
            // ACK is the only thing that stops it retransmitting (RFC 9147 §7.1).
            _pendingAck.Add((record.Epoch, record.SequenceNumber));
        }

        // Flights before the client's last one are implicitly acknowledged by the flight we send in reply, so ACKing
        // them would be noise — and an ACK for a ClientHello would go out at an epoch the client cannot yet read.
        if (result.Acknowledgeable && _state is State.ExpectClientFlight or State.Established)
            _pendingAck.Add((record.Epoch, record.SequenceNumber));

        foreach (var message in result.Delivered)
            HandleHandshakeMessage(message);
    }

    private void HandleAck(byte[] body)
    {
        var reader = new Dtls13Reader(body);
        var list = new Dtls13Reader(reader.ReadVector16());
        while (!list.IsEmpty)
        {
            var epoch = list.ReadUInt64();
            var sequence = list.ReadUInt64();
            _flight?.Acknowledge(epoch, sequence);
        }
    }

    private void HandleAlert(byte[] body, ushort epoch)
    {
        if (body.Length < 2)
            return;
        var (level, description) = (body[0], body[1]);
        if (description == Dtls13Alert.CloseNotify)
        {
            _closed = true;
            return;
        }
        if (level == Dtls13Alert.Fatal)
        {
            // The epoch narrows the fault a long way: an epoch-0 alert means the peer rejected our ServerHello or
            // HelloRetryRequest outright, while an epoch-2 one means it read our handshake keys fine and objected to
            // something inside the encrypted flight.
            throw new Dtls13Exception(
                $"peer sent a fatal alert at epoch {epoch} in state {_state}: {Dtls13Alert.Describe(description)}",
                description);
        }
    }

    // ---------------------------------------------------------------- handshake state machine

    private void HandleHandshakeMessage(Dtls13HandshakeMessage message)
    {
        switch (_state)
        {
            case State.ExpectClientHello when message.Type == Dtls13HandshakeType.ClientHello:
                HandleClientHello(message, second: false);
                break;
            case State.ExpectSecondClientHello when message.Type == Dtls13HandshakeType.ClientHello:
                HandleClientHello(message, second: true);
                break;
            case State.ExpectClientFlight:
                HandleClientFlightMessage(message);
                break;
            case State.Established when message.Type == Dtls13HandshakeType.KeyUpdate:
                HandleKeyUpdate(message);
                break;
            case State.Established:
                break; // a retransmission of the client's final flight; the ACK we queue for the record is the answer
            default:
                throw Fatal(Dtls13Alert.UnexpectedMessage,
                    $"unexpected handshake message {message.Type} in state {_state}");
        }
    }

    private void HandleClientHello(Dtls13HandshakeMessage message, bool second)
    {
        Dtls13ClientHello hello;
        try
        {
            hello = Dtls13ClientHello.Parse(message.Body);
        }
        catch (Dtls13DecodeException ex)
        {
            throw Fatal(Dtls13Alert.DecodeError, $"malformed ClientHello: {ex.Message}");
        }

        if (!hello.OffersDtls13)
            throw Fatal(Dtls13Alert.ProtocolVersion, "client does not offer DTLS 1.3");
        if (hello.LegacyCookie.Length != 0)
            throw Fatal(Dtls13Alert.IllegalParameter, "a DTLS 1.3 ClientHello must leave legacy_cookie empty");
        _clientRandom = hello.Random; // the key-log line's session identifier

        var suite = SelectCipherSuite(hello)
            ?? throw Fatal(Dtls13Alert.HandshakeFailure, "no cipher suite in common");

        if (!second)
        {
            _suite = suite;
            _records.SetCipherSuite(suite);
            _hash = _crypto.GetHash(suite.Hash);
            _schedule = new Dtls13KeySchedule(_hash);
            _transcript = _hash.CreateRunningHash();
        }
        else if (suite.Id != _suite.Id)
        {
            throw Fatal(Dtls13Alert.IllegalParameter, "the second ClientHello changed the cipher suite");
        }

        var clientShare = SelectKeyShare(hello);

        if (!second && _options.CookieExchange)
        {
            SendHelloRetryRequest(message, clientShare is null ? SelectGroupForRetry(hello) : null);
            return;
        }
        if (second)
        {
            var cookie = hello.Cookie ?? throw Fatal(Dtls13Alert.IllegalParameter, "the second ClientHello carries no cookie");
            if (!VerifyCookie(cookie))
                throw Fatal(Dtls13Alert.IllegalParameter, "the HelloRetryRequest cookie did not verify");
            if (clientShare is null)
                throw Fatal(Dtls13Alert.HandshakeFailure, "the second ClientHello still offers no usable key_share");
        }
        if (clientShare is null)
        {
            // Cookies are off, so this is our only chance to ask for a group we can actually do.
            SendHelloRetryRequest(message, SelectGroupForRetry(hello));
            return;
        }

        _transcript!.Update(message.ToTranscriptBytes());
        SendServerFlight(clientShare);
    }

    private void HandleClientFlightMessage(Dtls13HandshakeMessage message)
    {
        switch (message.Type)
        {
            case Dtls13HandshakeType.Certificate:
                // Accept any client certificate, including an empty one: in WebRTC the peer's identity is verified
                // above this channel (CupriNet's Noise handshake), and the browser's cert is self-signed anyway.
                PeerCertificateChain = ParseCertificateChain(message.Body);
                _transcript!.Update(message.ToTranscriptBytes());
                break;

            case Dtls13HandshakeType.CertificateVerify:
                // Deliberately not verified — see the Certificate case. The Finished MAC below still proves the peer
                // holds the ECDHE secret, so this is about identity only, and identity is not ours to judge here.
                _transcript!.Update(message.ToTranscriptBytes());
                break;

            case Dtls13HandshakeType.Finished:
                var expected = _schedule!.FinishedMac(_clientHandshakeTrafficSecret!, _transcript!.Snapshot());
                if (!CryptographicOperations.FixedTimeEquals(expected, message.Body))
                    throw Fatal(Dtls13Alert.DecryptError, "the client's Finished MAC did not verify");
                _transcript.Update(message.ToTranscriptBytes());
                _state = State.Established;
                _flight?.AcknowledgeAll(); // the client's flight implicitly acknowledges ours (RFC 9147 §7.1)
                // The epoch-2 receive keys are deliberately kept: if our ACK is lost the client retransmits its
                // final flight at epoch 2, and we must still be able to read it in order to ACK it again.
                break;

            default:
                throw Fatal(Dtls13Alert.UnexpectedMessage, $"unexpected message {message.Type} in the client's flight");
        }
    }

    /// <summary>
    /// Minimal KeyUpdate handling (RFC 9147 §8). A browser will not send one over a short-lived DataChannel, but if
    /// it does, silently ignoring it would leave us unable to read anything the peer sends afterwards.
    /// </summary>
    private void HandleKeyUpdate(Dtls13HandshakeMessage message)
    {
        if (message.Body.Length != 1)
            throw Fatal(Dtls13Alert.DecodeError, "malformed KeyUpdate");

        _clientApplicationTrafficSecret = _schedule!.ExpandLabel(_clientApplicationTrafficSecret!, "traffic upd", ReadOnlySpan<byte>.Empty, _schedule.HashLength);
        _clientKeyUpdateEpoch++;
        _records.SetReceiveKeys(_clientKeyUpdateEpoch, _schedule.TrafficKeys(_clientApplicationTrafficSecret, _suite));

        if (message.Body[0] != 1)
            return; // update_not_requested — the peer rotated its own keys and wants nothing back

        // update_requested: answer with our own KeyUpdate, sent under the *old* keys (the peer cannot read the new
        // ones until it has seen this message), and only then rotate our sending epoch.
        var reply = new Dtls13HandshakeMessage(Dtls13HandshakeType.KeyUpdate, _nextSendMessageSeq++, [0]);
        _flight = new Dtls13OutgoingFlight();
        _flight.Add(reply, _serverKeyUpdateEpoch);
        TransmitFlight(onlyUnacknowledged: false);

        _serverApplicationTrafficSecret = _schedule.ExpandLabel(_serverApplicationTrafficSecret!, "traffic upd", ReadOnlySpan<byte>.Empty, _schedule.HashLength);
        _serverKeyUpdateEpoch++;
        _records.SetSendKeys(_serverKeyUpdateEpoch, _schedule.TrafficKeys(_serverApplicationTrafficSecret, _suite));
    }

    // ---------------------------------------------------------------- flights

    private void SendHelloRetryRequest(Dtls13HandshakeMessage clientHello, ushort? selectedGroup)
    {
        // RFC 8446 §4.4.1: with an HRR in play, ClientHello1 is replaced in the transcript by a synthetic
        // "message_hash" message carrying only its hash. That is also exactly what makes a stateless cookie possible.
        _clientHello1Hash = _hash!.Hash(clientHello.ToTranscriptBytes());
        var seed = new byte[4 + _clientHello1Hash.Length];
        seed[0] = Dtls13HandshakeType.MessageHash;
        seed[3] = (byte)_clientHello1Hash.Length;
        _clientHello1Hash.CopyTo(seed.AsSpan(4));
        _transcript!.Restart(seed);

        var body = Dtls13ServerMessages.HelloRetryRequest(_suite.Id, selectedGroup, BuildCookie(_clientHello1Hash));
        var message = new Dtls13HandshakeMessage(Dtls13HandshakeType.ServerHello, _nextSendMessageSeq++, body);
        _transcript.Update(message.ToTranscriptBytes());

        _flight = new Dtls13OutgoingFlight();
        _flight.Add(message, Dtls13Epoch.Initial);
        TransmitFlight(onlyUnacknowledged: false);
        _state = State.ExpectSecondClientHello;
    }

    private void SendServerFlight(Dtls13KeyShareEntry clientShare)
    {
        _keyExchange = _crypto.GenerateKeyExchange(clientShare.NamedGroup);
        var sharedSecret = _keyExchange.Agree(clientShare.KeyExchange)
            ?? throw Fatal(Dtls13Alert.IllegalParameter, "the client's key_share is not a valid point on its group");

        var random = new byte[32];
        _crypto.GetRandom(random);
        var serverHelloBody = Dtls13ServerMessages.ServerHello(
            random, _suite.Id, new Dtls13KeyShareEntry(_keyExchange.NamedGroup, _keyExchange.PublicKey));
        var serverHello = new Dtls13HandshakeMessage(Dtls13HandshakeType.ServerHello, _nextSendMessageSeq++, serverHelloBody);
        _transcript!.Update(serverHello.ToTranscriptBytes());

        // RFC 8446 §7.1, with DTLS 1.3's "dtls13" label prefix: no PSK and no 0-RTT, so the early secret is an
        // extract over zeros and the handshake secret folds in the ECDHE output.
        var zeros = new byte[_schedule!.HashLength];
        var earlySecret = _schedule.Extract(zeros, zeros);
        var derived = _schedule.DeriveSecretOfEmpty(earlySecret, "derived");
        _handshakeSecret = _schedule.Extract(derived, sharedSecret);

        var afterServerHello = _transcript.Snapshot();
        _clientHandshakeTrafficSecret = _schedule.DeriveSecret(_handshakeSecret, "c hs traffic", afterServerHello);
        _serverHandshakeTrafficSecret = _schedule.DeriveSecret(_handshakeSecret, "s hs traffic", afterServerHello);
        _records.SetSendKeys(Dtls13Epoch.Handshake, _schedule.TrafficKeys(_serverHandshakeTrafficSecret, _suite));
        _records.SetReceiveKeys(Dtls13Epoch.Handshake, _schedule.TrafficKeys(_clientHandshakeTrafficSecret, _suite));
        Dtls13KeyLog.Write("CLIENT_HANDSHAKE_TRAFFIC_SECRET", _clientRandom, _clientHandshakeTrafficSecret);
        Dtls13KeyLog.Write("SERVER_HANDSHAKE_TRAFFIC_SECRET", _clientRandom, _serverHandshakeTrafficSecret);

        _flight = new Dtls13OutgoingFlight();
        _flight.Add(serverHello, Dtls13Epoch.Initial);
        AddEncryptedHandshakeMessage(Dtls13HandshakeType.EncryptedExtensions, Dtls13ServerMessages.EncryptedExtensions());
        if (_options.RequestClientCertificate)
            AddEncryptedHandshakeMessage(Dtls13HandshakeType.CertificateRequest,
                Dtls13ServerMessages.CertificateRequest(_options.AcceptedSignatureSchemes));
        AddEncryptedHandshakeMessage(Dtls13HandshakeType.Certificate,
            Dtls13ServerMessages.Certificate(_signer.CertificateChain));

        var signature = _signer.Sign(Dtls13ServerMessages.CertificateVerifyContent(server: true, _transcript.Snapshot()));
        AddEncryptedHandshakeMessage(Dtls13HandshakeType.CertificateVerify,
            Dtls13ServerMessages.CertificateVerify(_signer.SignatureScheme, signature));

        var verifyData = _schedule.FinishedMac(_serverHandshakeTrafficSecret, _transcript.Snapshot());
        AddEncryptedHandshakeMessage(Dtls13HandshakeType.Finished, Dtls13ServerMessages.Finished(verifyData));

        // Application traffic secrets are fixed by the transcript through our Finished, so both directions' epoch-3
        // keys exist before the client's flight arrives — which is why an early SCTP INIT never has to be buffered.
        var afterServerFinished = _transcript.Snapshot();
        var masterSecret = _schedule.Extract(_schedule.DeriveSecretOfEmpty(_handshakeSecret, "derived"), zeros);
        _clientApplicationTrafficSecret = _schedule.DeriveSecret(masterSecret, "c ap traffic", afterServerFinished);
        _serverApplicationTrafficSecret = _schedule.DeriveSecret(masterSecret, "s ap traffic", afterServerFinished);
        _records.SetSendKeys(Dtls13Epoch.Application, _schedule.TrafficKeys(_serverApplicationTrafficSecret, _suite));
        _records.SetReceiveKeys(Dtls13Epoch.Application, _schedule.TrafficKeys(_clientApplicationTrafficSecret, _suite));
        Dtls13KeyLog.Write("CLIENT_TRAFFIC_SECRET_0", _clientRandom, _clientApplicationTrafficSecret);
        Dtls13KeyLog.Write("SERVER_TRAFFIC_SECRET_0", _clientRandom, _serverApplicationTrafficSecret);

        TransmitFlight(onlyUnacknowledged: false);
        _state = State.ExpectClientFlight;
    }

    private void AddEncryptedHandshakeMessage(byte type, byte[] body)
    {
        var message = new Dtls13HandshakeMessage(type, _nextSendMessageSeq++, body);
        _transcript!.Update(message.ToTranscriptBytes());
        _flight!.Add(message, Dtls13Epoch.Handshake);
    }

    /// <summary>
    /// Serialises the current flight into records, packing as many as fit into each datagram, and notes which record
    /// carried which message bytes so an ACK can retire them.
    /// </summary>
    private void TransmitFlight(bool onlyUnacknowledged)
    {
        var maxFragment = _options.MaxDatagramSize - CiphertextOverhead - Dtls13HandshakeMessage.DtlsHeaderLength;
        var datagram = new List<byte>(_options.MaxDatagramSize);
        foreach (var (fragment, epoch, piece) in _flight!.BuildFragments(maxFragment, onlyUnacknowledged))
        {
            var record = epoch == Dtls13Epoch.Initial
                ? _records.WritePlaintextRecord(Dtls13ContentType.Handshake, fragment, out var sequence)
                : _records.WriteCiphertextRecord(epoch, Dtls13ContentType.Handshake, fragment, out sequence);
            _flight.RecordSent(epoch, sequence, [piece]);

            if (datagram.Count > 0 && datagram.Count + record.Length > _options.MaxDatagramSize)
            {
                SendDatagram(datagram);
                datagram.Clear();
            }
            datagram.AddRange(record);
        }
        if (datagram.Count > 0)
            SendDatagram(datagram);
        _lastTransmit = Environment.TickCount64;
    }

    private void SendDatagram(List<byte> datagram)
    {
        var bytes = datagram.ToArray();
        _transport.Send(bytes, 0, bytes.Length);
    }

    /// <summary>Emits an ACK for every handshake record processed since the last flush (RFC 9147 §7).</summary>
    private void FlushAck()
    {
        if (_pendingAck.Count == 0)
            return;
        _pendingAck.Sort((a, b) => a.Epoch != b.Epoch ? a.Epoch.CompareTo(b.Epoch) : a.SequenceNumber.CompareTo(b.SequenceNumber));
        var body = Dtls13ServerMessages.Ack(_pendingAck.Select(r => (r.Epoch, r.SequenceNumber)));
        _pendingAck.Clear();

        // "During the handshake, ACK records MUST be sent with an epoch which is equal to or higher than the record
        // being acknowledged" — the highest epoch we can send at always satisfies that.
        var epoch = _records.CurrentSendEpoch;
        if (epoch == Dtls13Epoch.Initial)
            return; // nothing to acknowledge before we have keys: the ClientHello is answered by our flight instead
        var record = _records.WriteCiphertextRecord(epoch, Dtls13ContentType.Ack, body, out _);
        _transport.Send(record, 0, record.Length);
    }

    // ---------------------------------------------------------------- negotiation helpers

    private Dtls13CipherSuite? SelectCipherSuite(Dtls13ClientHello hello)
    {
        foreach (var candidate in Dtls13CipherSuite.Supported) // our preference order, not the client's
            if (hello.CipherSuites.Contains(candidate.Id))
                return candidate;
        return null;
    }

    private Dtls13KeyShareEntry? SelectKeyShare(Dtls13ClientHello hello)
    {
        foreach (var group in _options.SupportedGroups)
            foreach (var share in hello.KeyShares)
                if (share.NamedGroup == group && _crypto.SupportsGroup(group))
                    return share;
        return null;
    }

    private ushort? SelectGroupForRetry(Dtls13ClientHello hello)
    {
        foreach (var group in _options.SupportedGroups)
            if (hello.SupportedGroups.Contains(group) && _crypto.SupportsGroup(group))
                return group;
        throw Fatal(Dtls13Alert.HandshakeFailure, "no named group in common");
    }

    // ---------------------------------------------------------------- stateless cookie

    /// <summary>
    /// A stateless return-routability cookie: a timestamp plus an HMAC binding it to this exact ClientHello, under a
    /// secret only this endpoint knows — the same shape as the SCTP layer's INIT cookie. Nothing is remembered on our
    /// side beyond the hash we already keep for the transcript.
    /// </summary>
    private byte[] BuildCookie(byte[] clientHelloHash)
    {
        var cookie = new byte[8 + 32];
        var timestamp = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        for (var i = 0; i < 8; i++)
            cookie[i] = (byte)(timestamp >> (8 * (7 - i)));
        CookieMac(cookie.AsSpan(0, 8), clientHelloHash).CopyTo(cookie.AsSpan(8));
        return cookie;
    }

    private bool VerifyCookie(byte[] cookie)
    {
        if (cookie.Length != 40 || _clientHello1Hash is null)
            return false;
        ulong timestamp = 0;
        for (var i = 0; i < 8; i++)
            timestamp = (timestamp << 8) | cookie[i];
        var age = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (long)timestamp;
        if (age < 0 || age > (long)_options.CookieLifetime.TotalMilliseconds)
            return false;
        return CryptographicOperations.FixedTimeEquals(CookieMac(cookie.AsSpan(0, 8), _clientHello1Hash), cookie.AsSpan(8));
    }

    private byte[] CookieMac(ReadOnlySpan<byte> timestamp, ReadOnlySpan<byte> clientHelloHash)
    {
        var input = new byte[timestamp.Length + clientHelloHash.Length];
        timestamp.CopyTo(input);
        clientHelloHash.CopyTo(input.AsSpan(timestamp.Length));
        return _crypto.GetHash(Dtls13HashKind.Sha256).Hmac(_cookieSecret, input);
    }

    private static IReadOnlyList<byte[]> ParseCertificateChain(byte[] body)
    {
        try
        {
            var reader = new Dtls13Reader(body);
            reader.ReadVector8(); // certificate_request_context
            var list = new Dtls13Reader(reader.ReadVector24());
            var chain = new List<byte[]>();
            while (!list.IsEmpty)
            {
                chain.Add(list.ReadVector24().ToArray());
                list.ReadVector16(); // per-entry extensions
            }
            return chain;
        }
        catch (Dtls13DecodeException)
        {
            return []; // an unparseable chain is still an accepted one — we never look at it
        }
    }

    // ---------------------------------------------------------------- ISecureDatagramTransport

    public int GetReceiveLimit() => _transport.GetReceiveLimit() - CiphertextOverhead;

    public int GetSendLimit() => Math.Min(_options.MaxDatagramSize, _transport.GetSendLimit()) - CiphertextOverhead;

    public int Receive(byte[] buffer, int offset, int length, int waitMillis)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        lock (_gate)
            if (TryDequeue(buffer, offset, length, out var ready))
                return ready;

        var deadline = Environment.TickCount64 + Math.Max(0, waitMillis);
        while (true)
        {
            var remaining = (int)(deadline - Environment.TickCount64);
            if (remaining <= 0)
                return -1;
            var received = _transport.Receive(_receiveBuffer, 0, _receiveBuffer.Length, remaining);
            if (received <= 0)
                continue;
            lock (_gate)
            {
                ProcessDatagram(_receiveBuffer.AsSpan(0, received));
                if (TryDequeue(buffer, offset, length, out var ready))
                    return ready;
                // A close_notify from the peer ends the association. Throwing (rather than returning 0) is what the
                // BouncyCastle transport this replaces does, and it is what unwinds the SCTP receive loop.
                if (_closed)
                    throw new Dtls13Exception("the peer closed the DTLS 1.3 connection");
            }
        }
    }

    private bool TryDequeue(byte[] buffer, int offset, int length, out int written)
    {
        if (!_applicationData.TryDequeue(out var payload))
        {
            written = 0;
            return false;
        }
        written = Math.Min(length, payload.Length);
        payload.AsSpan(0, written).CopyTo(buffer.AsSpan(offset));
        return true;
    }

    public void Send(byte[] buffer, int offset, int length)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        lock (_gate)
        {
            if (_closed)
                throw new Dtls13Exception("the DTLS 1.3 connection is closed");
            var record = _records.WriteCiphertextRecord(
                _serverKeyUpdateEpoch, Dtls13ContentType.ApplicationData, buffer.AsSpan(offset, length), out _);
            _transport.Send(record, 0, record.Length);
        }
    }

    public void Close()
    {
        lock (_gate)
        {
            if (!_closed)
            {
                _closed = true;
                TrySendAlert(Dtls13Alert.Warning, Dtls13Alert.CloseNotify);
            }
        }
        try { _transport.Close(); }
        catch (Exception) { /* the transport may already be gone */ }
    }

    public void Dispose() => Close();

    // ---------------------------------------------------------------- alerts

    /// <summary>Sends a fatal alert (best-effort) and produces the exception to abandon the connection with.</summary>
    private Dtls13Exception Fatal(byte description, string message)
    {
        TrySendAlert(Dtls13Alert.Fatal, description);
        return new Dtls13Exception($"{message} (sent {Dtls13Alert.Describe(description)})", description);
    }

    private void TrySendAlert(byte level, byte description)
    {
        try
        {
            byte[] alert = [level, description];
            var epoch = _records.CurrentSendEpoch;
            var record = epoch == Dtls13Epoch.Initial
                ? _records.WritePlaintextRecord(Dtls13ContentType.Alert, alert, out _)
                : _records.WriteCiphertextRecord(epoch, Dtls13ContentType.Alert, alert, out _);
            _transport.Send(record, 0, record.Length);
        }
        catch (Exception)
        {
            // Alerts are not retransmitted and must never mask the real failure (RFC 9147 §5.10).
        }
    }

    private enum State
    {
        ExpectClientHello,
        ExpectSecondClientHello,
        ExpectClientFlight,
        Established,
    }
}
