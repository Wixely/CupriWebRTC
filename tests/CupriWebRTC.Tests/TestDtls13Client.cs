using CupriWebRTC.Dtls;
using CupriWebRTC.Dtls13;
using CupriWebRTC.Dtls13.Crypto;
using Org.BouncyCastle.Tls;

namespace CupriWebRTC.Tests;

/// <summary>
/// A deliberately minimal DTLS 1.3 <b>client</b>, for tests only. CupriWebRTC ships a server role only (a browser
/// always initiates), so this exists purely to drive that server over a loopback transport: ClientHello, an optional
/// HelloRetryRequest round, then the encrypted flights, then application data.
///
/// <para>It is built from the same internal record layer and key schedule as the server, so on its own it proves
/// self-consistency rather than interoperability — which is exactly why it is not the last word: the real gates are
/// the browser probe and a reference implementation. What it does buy is a fast, deterministic, offline check of the
/// whole handshake, including the cookie exchange and both epochs of record protection.</para>
/// </summary>
internal sealed class TestDtls13Client(DatagramTransport transport, bool requireHelloRetry = false) : ISecureDatagramTransport
{
    private static readonly IDtls13Crypto Crypto = BouncyCastleDtls13Crypto.Instance;

    private readonly DatagramTransport _transport = transport;
    private readonly Dtls13RecordLayer _records = new(Crypto);
    private readonly Dtls13HandshakeReassembler _reassembler = new();
    private readonly List<byte[]> _pendingTranscript = [];
    private readonly Queue<byte[]> _applicationData = new();
    private readonly byte[] _random = new byte[32];

    private Dtls13CipherSuite? _suite;
    private Dtls13KeySchedule? _schedule;
    private IDtls13RunningHash? _transcript;
    private IDtls13KeyExchange _keyExchange = Crypto.GenerateKeyExchange(Dtls13NamedGroup.X25519);
    private byte[]? _clientHandshakeTrafficSecret;
    private byte[]? _serverHandshakeTrafficSecret;
    private ushort _messageSeq;
    private bool _sawHelloRetryRequest;
    private bool _done;

    /// <summary>The server's certificate chain as presented (used to check the fingerprint the peer published).</summary>
    public IReadOnlyList<byte[]> ServerCertificateChain { get; private set; } = [];

    /// <summary>The suite that was negotiated.</summary>
    public Dtls13CipherSuite NegotiatedCipherSuite => _suite ?? throw new InvalidOperationException("no handshake yet");

    /// <summary>True if the server made us do a cookie round trip.</summary>
    public bool SawHelloRetryRequest => _sawHelloRetryRequest;

    /// <summary>Runs the client handshake to completion, or throws.</summary>
    public void Handshake(TimeSpan timeout)
    {
        Crypto.GetRandom(_random);
        SendClientHello(cookie: null);

        var buffer = new byte[4096];
        var deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
        while (!_done)
        {
            var remaining = (int)(deadline - Environment.TickCount64);
            if (remaining <= 0)
                throw new TimeoutException("the test client's DTLS 1.3 handshake timed out");
            var received = _transport.Receive(buffer, 0, buffer.Length, remaining);
            if (received > 0)
                ProcessDatagram(buffer.AsSpan(0, received));
        }
        if (requireHelloRetry && !_sawHelloRetryRequest)
            throw new InvalidOperationException("expected the server to send a HelloRetryRequest");
    }

    /// <summary>Sends one application datagram at epoch 3.</summary>
    public void Send(ReadOnlySpan<byte> payload)
    {
        var record = _records.WriteCiphertextRecord(Dtls13Epoch.Application, Dtls13ContentType.ApplicationData, payload, out _);
        _transport.Send(record, 0, record.Length);
    }

    /// <summary>Receives one application datagram, or null on timeout.</summary>
    public byte[]? Receive(TimeSpan timeout)
    {
        if (_applicationData.TryDequeue(out var ready))
            return ready;
        var buffer = new byte[4096];
        var deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
        while (Environment.TickCount64 < deadline)
        {
            var received = _transport.Receive(buffer, 0, buffer.Length, (int)(deadline - Environment.TickCount64));
            if (received <= 0)
                continue;
            ProcessDatagram(buffer.AsSpan(0, received));
            if (_applicationData.TryDequeue(out var payload))
                return payload;
        }
        return null;
    }

    // -------------------------------------------------- ISecureDatagramTransport (so SCTP can run over this client)

    public string ProtocolVersion => "DTLS 1.3";

    public int GetReceiveLimit() => 1200;

    public int GetSendLimit() => 1200;

    public int Receive(byte[] buffer, int offset, int length, int waitMillis)
    {
        var payload = Receive(TimeSpan.FromMilliseconds(waitMillis));
        if (payload is null)
            return -1;
        var n = Math.Min(length, payload.Length);
        payload.AsSpan(0, n).CopyTo(buffer.AsSpan(offset));
        return n;
    }

    public void Send(byte[] buffer, int offset, int length) => Send(buffer.AsSpan(offset, length));

    public void Close() => _transport.Close();

    public void Dispose() => Close();

    // ------------------------------------------------------------------ receive

    private void ProcessDatagram(ReadOnlySpan<byte> datagram)
    {
        foreach (var record in _records.ReadDatagram(datagram))
        {
            switch (record.ContentType)
            {
                case Dtls13ContentType.Handshake:
                    foreach (var message in _reassembler.Add(record.Fragment).Delivered)
                        HandleHandshakeMessage(message);
                    break;
                case Dtls13ContentType.ApplicationData:
                    _applicationData.Enqueue(record.Fragment);
                    break;
                case Dtls13ContentType.Alert:
                    throw new InvalidOperationException(
                        $"server sent alert level={record.Fragment[0]} {Dtls13AlertName(record.Fragment[1])}");
            }
        }
    }

    private static string Dtls13AlertName(byte description) => description switch
    {
        0 => "close_notify",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        47 => "illegal_parameter",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        80 => "internal_error",
        _ => $"alert({description})",
    };

    private void HandleHandshakeMessage(Dtls13HandshakeMessage message)
    {
        switch (message.Type)
        {
            case Dtls13HandshakeType.ServerHello:
                var (random, cipherSuite, extensions) = ParseServerHello(message.Body);
                if (random.SequenceEqual(Dtls13ServerMessages.HelloRetryRequestRandom))
                    HandleHelloRetryRequest(message, cipherSuite, extensions);
                else
                    HandleServerHello(message, cipherSuite, extensions);
                break;

            case Dtls13HandshakeType.EncryptedExtensions:
            case Dtls13HandshakeType.CertificateRequest:
            case Dtls13HandshakeType.CertificateVerify:
                _transcript!.Update(message.ToTranscriptBytes());
                break;

            case Dtls13HandshakeType.Certificate:
                ServerCertificateChain = ParseCertificateChain(message.Body);
                _transcript!.Update(message.ToTranscriptBytes());
                break;

            case Dtls13HandshakeType.Finished:
                var expected = _schedule!.FinishedMac(_serverHandshakeTrafficSecret!, _transcript!.Snapshot());
                if (!expected.SequenceEqual(message.Body))
                    throw new InvalidOperationException("the server's Finished MAC did not verify");
                _transcript.Update(message.ToTranscriptBytes());
                CompleteHandshake();
                break;

            default:
                throw new InvalidOperationException($"unexpected handshake message {message.Type}");
        }
    }

    private void HandleHelloRetryRequest(Dtls13HandshakeMessage message, ushort cipherSuite, List<Dtls13Extension> extensions)
    {
        if (_sawHelloRetryRequest)
            throw new InvalidOperationException("the server sent a second HelloRetryRequest");
        _sawHelloRetryRequest = true;
        SelectSuite(cipherSuite);

        // RFC 8446 §4.4.1: ClientHello1 becomes a synthetic message_hash message in the transcript.
        var hash = Crypto.GetHash(_suite!.Hash);
        var clientHello1 = hash.Hash(_pendingTranscript[0]);
        var seed = new byte[4 + clientHello1.Length];
        seed[0] = Dtls13HandshakeType.MessageHash;
        seed[3] = (byte)clientHello1.Length;
        clientHello1.CopyTo(seed.AsSpan(4));
        _transcript = hash.CreateRunningHash();
        _transcript.Restart(seed);
        _transcript.Update(message.ToTranscriptBytes());

        byte[]? cookie = null;
        foreach (var extension in extensions)
        {
            var reader = new Dtls13Reader(extension.Data);
            if (extension.Type == Dtls13ExtensionType.Cookie)
                cookie = reader.ReadVector16().ToArray();
            else if (extension.Type == Dtls13ExtensionType.KeyShare)
            {
                var group = reader.ReadUInt16();
                _keyExchange.Dispose();
                _keyExchange = Crypto.GenerateKeyExchange(group);
            }
        }
        SendClientHello(cookie);
    }

    private void HandleServerHello(Dtls13HandshakeMessage message, ushort cipherSuite, List<Dtls13Extension> extensions)
    {
        SelectSuite(cipherSuite);
        if (_transcript is null)
        {
            _transcript = Crypto.GetHash(_suite!.Hash).CreateRunningHash();
            foreach (var pending in _pendingTranscript)
                _transcript.Update(pending);
        }
        _transcript.Update(message.ToTranscriptBytes());

        byte[]? serverShare = null;
        foreach (var extension in extensions)
        {
            if (extension.Type != Dtls13ExtensionType.KeyShare)
                continue;
            var reader = new Dtls13Reader(extension.Data);
            var group = reader.ReadUInt16();
            if (group != _keyExchange.NamedGroup)
                throw new InvalidOperationException("the server chose a group we did not offer a share for");
            serverShare = reader.ReadVector16().ToArray();
        }
        var shared = _keyExchange.Agree(serverShare ?? throw new InvalidOperationException("ServerHello has no key_share"))
            ?? throw new InvalidOperationException("the server's key_share is invalid");

        var zeros = new byte[_schedule!.HashLength];
        var earlySecret = _schedule.Extract(zeros, zeros);
        var handshakeSecret = _schedule.Extract(_schedule.DeriveSecretOfEmpty(earlySecret, "derived"), shared);
        var afterServerHello = _transcript.Snapshot();
        _clientHandshakeTrafficSecret = _schedule.DeriveSecret(handshakeSecret, "c hs traffic", afterServerHello);
        _serverHandshakeTrafficSecret = _schedule.DeriveSecret(handshakeSecret, "s hs traffic", afterServerHello);
        _records.SetSendKeys(Dtls13Epoch.Handshake, _schedule.TrafficKeys(_clientHandshakeTrafficSecret, _suite!));
        _records.SetReceiveKeys(Dtls13Epoch.Handshake, _schedule.TrafficKeys(_serverHandshakeTrafficSecret, _suite!));
        _handshakeSecret = handshakeSecret;
    }

    private byte[]? _handshakeSecret;

    private void CompleteHandshake()
    {
        // Application traffic secrets are fixed by the transcript through the server's Finished.
        var zeros = new byte[_schedule!.HashLength];
        var afterServerFinished = _transcript!.Snapshot();
        var master = _schedule.Extract(_schedule.DeriveSecretOfEmpty(_handshakeSecret!, "derived"), zeros);
        var clientApplication = _schedule.DeriveSecret(master, "c ap traffic", afterServerFinished);
        var serverApplication = _schedule.DeriveSecret(master, "s ap traffic", afterServerFinished);

        // Our flight: an (unverified, per the WebRTC profile) certificate, its CertificateVerify, and Finished.
        var certificate = DtlsCertificate.GenerateSelfSigned();
        var signer = new Dtls13CertificateSigner(certificate);
        SendHandshakeMessage(Dtls13HandshakeType.Certificate, Dtls13ServerMessages.Certificate(signer.CertificateChain));
        var signature = signer.Sign(Dtls13ServerMessages.CertificateVerifyContent(server: false, _transcript.Snapshot()));
        SendHandshakeMessage(Dtls13HandshakeType.CertificateVerify,
            Dtls13ServerMessages.CertificateVerify(signer.SignatureScheme, signature));
        SendHandshakeMessage(Dtls13HandshakeType.Finished,
            _schedule.FinishedMac(_clientHandshakeTrafficSecret!, _transcript.Snapshot()));

        _records.SetSendKeys(Dtls13Epoch.Application, _schedule.TrafficKeys(clientApplication, _suite!));
        _records.SetReceiveKeys(Dtls13Epoch.Application, _schedule.TrafficKeys(serverApplication, _suite!));
        _done = true;
    }

    private void SelectSuite(ushort cipherSuite)
    {
        var suite = Dtls13CipherSuite.Find(cipherSuite)
            ?? throw new InvalidOperationException($"the server chose an unknown suite 0x{cipherSuite:x4}");
        if (_suite is null)
        {
            _suite = suite;
            _records.SetCipherSuite(suite);
            _schedule = new Dtls13KeySchedule(Crypto.GetHash(suite.Hash));
        }
        else if (_suite.Id != suite.Id)
        {
            throw new InvalidOperationException("the server changed cipher suite between flights");
        }
    }

    // ------------------------------------------------------------------ send

    private void SendClientHello(byte[]? cookie)
    {
        var body = BuildClientHello(cookie);
        var message = new Dtls13HandshakeMessage(Dtls13HandshakeType.ClientHello, _messageSeq++, body);
        if (_transcript is null)
            _pendingTranscript.Add(message.ToTranscriptBytes());
        else
            _transcript.Update(message.ToTranscriptBytes());

        var fragment = BuildFragment(message);
        var record = _records.WritePlaintextRecord(Dtls13ContentType.Handshake, fragment, out _);
        _transport.Send(record, 0, record.Length);
    }

    private void SendHandshakeMessage(byte type, byte[] body)
    {
        var message = new Dtls13HandshakeMessage(type, _messageSeq++, body);
        _transcript!.Update(message.ToTranscriptBytes());
        var fragment = BuildFragment(message);
        var record = _records.WriteCiphertextRecord(Dtls13Epoch.Handshake, Dtls13ContentType.Handshake, fragment, out _);
        _transport.Send(record, 0, record.Length);
    }

    private static byte[] BuildFragment(Dtls13HandshakeMessage message)
    {
        var fragment = new byte[Dtls13HandshakeMessage.DtlsHeaderLength + message.Body.Length];
        fragment[0] = message.Type;
        fragment[1] = (byte)(message.Body.Length >> 16);
        fragment[2] = (byte)(message.Body.Length >> 8);
        fragment[3] = (byte)message.Body.Length;
        fragment[4] = (byte)(message.MessageSeq >> 8);
        fragment[5] = (byte)message.MessageSeq;
        fragment[9] = (byte)(message.Body.Length >> 16);
        fragment[10] = (byte)(message.Body.Length >> 8);
        fragment[11] = (byte)message.Body.Length;
        message.Body.CopyTo(fragment.AsSpan(Dtls13HandshakeMessage.DtlsHeaderLength));
        return fragment;
    }

    private byte[] BuildClientHello(byte[]? cookie)
    {
        var writer = new Dtls13Writer();
        writer.WriteUInt16(0xFEFD); // legacy_version = DTLS 1.2
        writer.WriteBytes(_random);
        writer.WriteVector8(ReadOnlySpan<byte>.Empty); // legacy_session_id
        writer.WriteVector8(ReadOnlySpan<byte>.Empty); // legacy_cookie — must be empty for DTLS 1.3
        writer.WriteUInt16(6);
        writer.WriteUInt16(Dtls13CipherSuite.TlsAes128GcmSha256);
        writer.WriteUInt16(Dtls13CipherSuite.TlsAes256GcmSha384);
        writer.WriteUInt16(Dtls13CipherSuite.TlsChaCha20Poly1305Sha256);
        writer.WriteVector8([0]); // legacy_compression_methods

        var extensions = writer.BeginVector16();

        writer.WriteUInt16(43); // supported_versions
        var supportedVersions = writer.BeginVector16();
        writer.WriteUInt8(2);
        writer.WriteUInt16(0xFEFC); // DTLS 1.3
        writer.EndVector(supportedVersions);

        writer.WriteUInt16(10); // supported_groups
        var groups = writer.BeginVector16();
        writer.WriteUInt16(4);
        writer.WriteUInt16(Dtls13NamedGroup.X25519);
        writer.WriteUInt16(Dtls13NamedGroup.Secp256r1);
        writer.EndVector(groups);

        writer.WriteUInt16(13); // signature_algorithms
        var schemes = writer.BeginVector16();
        writer.WriteUInt16(2);
        writer.WriteUInt16(Dtls13SignatureScheme.EcdsaSecp256r1Sha256);
        writer.EndVector(schemes);

        writer.WriteUInt16(51); // key_share
        var keyShare = writer.BeginVector16();
        var shares = writer.BeginVector16();
        writer.WriteUInt16(_keyExchange.NamedGroup);
        writer.WriteVector16(_keyExchange.PublicKey);
        writer.EndVector(shares);
        writer.EndVector(keyShare);

        if (cookie is not null)
        {
            writer.WriteUInt16(44); // cookie
            var cookieExtension = writer.BeginVector16();
            writer.WriteVector16(cookie);
            writer.EndVector(cookieExtension);
        }

        writer.EndVector(extensions);
        return writer.ToArray();
    }

    private static (byte[] Random, ushort CipherSuite, List<Dtls13Extension> Extensions) ParseServerHello(byte[] body)
    {
        var reader = new Dtls13Reader(body);
        reader.ReadUInt16();                 // legacy_version
        var random = reader.ReadBytes(32).ToArray();
        reader.ReadVector8();                // legacy_session_id_echo
        var cipherSuite = reader.ReadUInt16();
        reader.ReadUInt8();                  // legacy_compression_method
        return (random, cipherSuite, Dtls13ClientHello.ParseExtensions(reader.ReadVector16()));
    }

    private static List<byte[]> ParseCertificateChain(byte[] body)
    {
        var reader = new Dtls13Reader(body);
        reader.ReadVector8();
        var list = new Dtls13Reader(reader.ReadVector24());
        var chain = new List<byte[]>();
        while (!list.IsEmpty)
        {
            chain.Add(list.ReadVector24().ToArray());
            list.ReadVector16();
        }
        return chain;
    }
}
