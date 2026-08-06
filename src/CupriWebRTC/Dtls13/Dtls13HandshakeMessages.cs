using System.Text;

namespace CupriWebRTC.Dtls13;

/// <summary>A TLS extension as it appears in a hello: its code point and its opaque body.</summary>
internal sealed record Dtls13Extension(ushort Type, byte[] Data);

/// <summary>One entry of a <c>key_share</c> extension: a named group and a public share for it.</summary>
internal sealed record Dtls13KeyShareEntry(ushort NamedGroup, byte[] KeyExchange);

/// <summary>
/// A parsed ClientHello (RFC 9147 §5.3). Only the fields a DTLS 1.3 server needs are surfaced; unknown extensions are
/// kept in <see cref="Extensions"/> but otherwise ignored, which is what lets a browser send us its full complement of
/// TLS extensions (ALPN, session tickets, <c>use_srtp</c>, …) without us having to understand any of them.
/// </summary>
internal sealed class Dtls13ClientHello
{
    private Dtls13ClientHello() { }

    /// <summary>The client's 32 random bytes.</summary>
    public byte[] Random { get; private init; } = [];

    /// <summary>The legacy session id. A DTLS 1.3 server MUST NOT echo it (RFC 9147 §5).</summary>
    public byte[] LegacySessionId { get; private init; } = [];

    /// <summary>The DTLS 1.2 <c>legacy_cookie</c> field, which a DTLS 1.3 client must leave empty.</summary>
    public byte[] LegacyCookie { get; private init; } = [];

    /// <summary>Offered cipher suites, in the client's preference order.</summary>
    public IReadOnlyList<ushort> CipherSuites { get; private init; } = [];

    /// <summary>Every extension, in wire order — including ones we do not understand.</summary>
    public IReadOnlyList<Dtls13Extension> Extensions { get; private init; } = [];

    /// <summary>Versions from <c>supported_versions</c>, in the client's preference order.</summary>
    public IReadOnlyList<ushort> SupportedVersions { get; private init; } = [];

    /// <summary>Groups from <c>supported_groups</c>, in the client's preference order.</summary>
    public IReadOnlyList<ushort> SupportedGroups { get; private init; } = [];

    /// <summary>Schemes from <c>signature_algorithms</c>, in the client's preference order.</summary>
    public IReadOnlyList<ushort> SignatureSchemes { get; private init; } = [];

    /// <summary>Shares from <c>key_share</c>, in the client's preference order.</summary>
    public IReadOnlyList<Dtls13KeyShareEntry> KeyShares { get; private init; } = [];

    /// <summary>The <c>cookie</c> extension, present only on a ClientHello answering a HelloRetryRequest.</summary>
    public byte[]? Cookie { get; private init; }

    /// <summary>True if the client offers DTLS 1.3 — the whole reason this stack exists.</summary>
    public bool OffersDtls13 => SupportedVersions.Contains(Dtls13Version.Dtls13);

    /// <summary>Parses a ClientHello body (the bytes after the handshake header).</summary>
    public static Dtls13ClientHello Parse(ReadOnlySpan<byte> body)
    {
        var reader = new Dtls13Reader(body);
        var legacyVersion = reader.ReadUInt16();
        if (legacyVersion is not (Dtls13Version.Dtls12 or 0xFEFF))
            throw new Dtls13DecodeException($"unexpected ClientHello legacy_version 0x{legacyVersion:x4}");

        var random = reader.ReadBytes(32).ToArray();
        var sessionId = reader.ReadVector8().ToArray();
        var legacyCookie = reader.ReadVector8().ToArray();

        var suites = ReadUInt16List(reader.ReadVector16(), "cipher_suites");

        var compression = reader.ReadVector8();
        if (compression.IndexOf((byte)0) < 0)
            throw new Dtls13DecodeException("client does not offer the null compression method");

        var extensions = reader.IsEmpty ? [] : ParseExtensions(reader.ReadVector16());

        var versions = new List<ushort>();
        var groups = new List<ushort>();
        var schemes = new List<ushort>();
        var shares = new List<Dtls13KeyShareEntry>();
        byte[]? cookie = null;

        foreach (var extension in extensions)
        {
            var extensionReader = new Dtls13Reader(extension.Data);
            switch (extension.Type)
            {
                case Dtls13ExtensionType.SupportedVersions:
                    versions.AddRange(ReadUInt16List(extensionReader.ReadVector8(), "supported_versions"));
                    break;
                case Dtls13ExtensionType.SupportedGroups:
                    groups.AddRange(ReadUInt16List(extensionReader.ReadVector16(), "supported_groups"));
                    break;
                case Dtls13ExtensionType.SignatureAlgorithms:
                    schemes.AddRange(ReadUInt16List(extensionReader.ReadVector16(), "signature_algorithms"));
                    break;
                case Dtls13ExtensionType.KeyShare:
                    var shareReader = new Dtls13Reader(extensionReader.ReadVector16());
                    while (!shareReader.IsEmpty)
                        shares.Add(new Dtls13KeyShareEntry(shareReader.ReadUInt16(), shareReader.ReadVector16().ToArray()));
                    break;
                case Dtls13ExtensionType.Cookie:
                    cookie = extensionReader.ReadVector16().ToArray();
                    break;
            }
        }

        return new Dtls13ClientHello
        {
            Random = random,
            LegacySessionId = sessionId,
            LegacyCookie = legacyCookie,
            CipherSuites = suites,
            Extensions = extensions,
            SupportedVersions = versions,
            SupportedGroups = groups,
            SignatureSchemes = schemes,
            KeyShares = shares,
            Cookie = cookie,
        };
    }

    /// <summary>Parses an <c>Extension extensions&lt;…&gt;</c> body (the bytes inside the outer length prefix).</summary>
    public static List<Dtls13Extension> ParseExtensions(ReadOnlySpan<byte> data)
    {
        var extensions = new List<Dtls13Extension>();
        var reader = new Dtls13Reader(data);
        while (!reader.IsEmpty)
            extensions.Add(new Dtls13Extension(reader.ReadUInt16(), reader.ReadVector16().ToArray()));
        return extensions;
    }

    private static ushort[] ReadUInt16List(ReadOnlySpan<byte> data, string what)
    {
        if (data.Length % 2 != 0)
            throw new Dtls13DecodeException($"{what} is not a whole number of 16-bit values");
        var values = new ushort[data.Length / 2];
        for (var i = 0; i < values.Length; i++)
            values[i] = (ushort)((data[i * 2] << 8) | data[(i * 2) + 1]);
        return values;
    }
}

/// <summary>
/// Builders for the handshake messages a DTLS 1.3 server sends. Each returns the message <em>body</em> — the bytes
/// after the handshake header — because the header (and any fragmentation of it) belongs to
/// <see cref="Dtls13HandshakeFlight"/>, and the transcript is computed over the TLS-style header + body, never over
/// DTLS's fragment fields (RFC 9147 §5.2).
/// </summary>
internal static class Dtls13ServerMessages
{
    /// <summary>SHA-256("HelloRetryRequest") — the ServerHello random that marks a message as an HRR (RFC 8446 §4.1.3).</summary>
    public static readonly byte[] HelloRetryRequestRandom =
    [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ];

    /// <summary>The CertificateVerify content prefix for a server signature (RFC 8446 §4.4.3). DTLS 1.3 keeps the
    /// TLS 1.3 context string verbatim — only the HKDF label prefix differs between the two protocols.</summary>
    private static readonly byte[] ServerCertificateVerifyContext =
        Encoding.ASCII.GetBytes("TLS 1.3, server CertificateVerify");

    /// <summary>The client's counterpart context string, for verifying a client CertificateVerify.</summary>
    private static readonly byte[] ClientCertificateVerifyContext =
        Encoding.ASCII.GetBytes("TLS 1.3, client CertificateVerify");

    /// <summary>
    /// ServerHello (RFC 9147 §5.4): a TLS 1.3 ServerHello with <c>legacy_version</c> = DTLS 1.2 and — unlike TLS —
    /// an <b>empty</b> <c>legacy_session_id_echo</c>, because DTLS 1.3 does not use TLS's middlebox compatibility mode
    /// and RFC 9147 §5 forbids echoing the client's session id.
    /// </summary>
    public static byte[] ServerHello(ReadOnlySpan<byte> random, ushort cipherSuite, Dtls13KeyShareEntry serverShare)
    {
        var writer = new Dtls13Writer();
        writer.WriteUInt16(Dtls13Version.Dtls12);
        writer.WriteBytes(random);
        writer.WriteVector8(ReadOnlySpan<byte>.Empty);
        writer.WriteUInt16(cipherSuite);
        writer.WriteUInt8(0); // legacy_compression_method

        var extensions = writer.BeginVector16();
        WriteSupportedVersion(writer);
        WriteExtension(writer, Dtls13ExtensionType.KeyShare, inner =>
        {
            inner.WriteUInt16(serverShare.NamedGroup);
            inner.WriteVector16(serverShare.KeyExchange);
        });
        writer.EndVector(extensions);
        return writer.ToArray();
    }

    /// <summary>
    /// HelloRetryRequest: structurally a ServerHello carrying <see cref="HelloRetryRequestRandom"/>. It asks the
    /// client to come back with a <paramref name="cookie"/> (proving it can receive at its claimed address) and, if
    /// its first <c>key_share</c> was for a group we do not do, with a share for <paramref name="selectedGroup"/>.
    /// </summary>
    public static byte[] HelloRetryRequest(ushort cipherSuite, ushort? selectedGroup, ReadOnlySpan<byte> cookie)
    {
        var writer = new Dtls13Writer();
        writer.WriteUInt16(Dtls13Version.Dtls12);
        writer.WriteBytes(HelloRetryRequestRandom);
        writer.WriteVector8(ReadOnlySpan<byte>.Empty);
        writer.WriteUInt16(cipherSuite);
        writer.WriteUInt8(0);

        var extensions = writer.BeginVector16();
        WriteSupportedVersion(writer);
        if (selectedGroup is { } group)
            WriteExtension(writer, Dtls13ExtensionType.KeyShare, inner => inner.WriteUInt16(group));
        var cookieBytes = cookie.ToArray();
        WriteExtension(writer, Dtls13ExtensionType.Cookie, inner => inner.WriteVector16(cookieBytes));
        writer.EndVector(extensions);
        return writer.ToArray();
    }

    /// <summary>EncryptedExtensions — the first encrypted message of the server's flight. WebRTC needs nothing in it
    /// (no ALPN, no SNI, no <c>use_srtp</c> for a data channel), so it carries an empty extension list.</summary>
    public static byte[] EncryptedExtensions()
    {
        var writer = new Dtls13Writer(4);
        writer.WriteUInt16(0);
        return writer.ToArray();
    }

    /// <summary>
    /// CertificateRequest. WebRTC peers are mutually certificated, and browsers expect to be asked; we ask, and then
    /// accept whatever arrives without verifying it — the peer's identity is authenticated above this channel.
    /// </summary>
    public static byte[] CertificateRequest(IReadOnlyList<ushort> signatureSchemes)
    {
        var writer = new Dtls13Writer();
        writer.WriteVector8(ReadOnlySpan<byte>.Empty); // certificate_request_context — empty in the main handshake
        var extensions = writer.BeginVector16();
        WriteExtension(writer, Dtls13ExtensionType.SignatureAlgorithms, inner =>
        {
            var list = inner.BeginVector16();
            foreach (var scheme in signatureSchemes)
                inner.WriteUInt16(scheme);
            inner.EndVector(list);
        });
        writer.EndVector(extensions);
        return writer.ToArray();
    }

    /// <summary>Certificate: our chain, end-entity first, each entry with an empty extension list.</summary>
    public static byte[] Certificate(IReadOnlyList<byte[]> chain)
    {
        var writer = new Dtls13Writer(1024);
        writer.WriteVector8(ReadOnlySpan<byte>.Empty); // certificate_request_context
        var list = writer.BeginVector24();
        foreach (var certificate in chain)
        {
            writer.WriteVector24(certificate);
            writer.WriteUInt16(0); // per-entry extensions
        }
        writer.EndVector(list);
        return writer.ToArray();
    }

    /// <summary>CertificateVerify: the signature scheme, then the signature over <see cref="CertificateVerifyContent"/>.</summary>
    public static byte[] CertificateVerify(ushort signatureScheme, ReadOnlySpan<byte> signature)
    {
        var writer = new Dtls13Writer(signature.Length + 8);
        writer.WriteUInt16(signatureScheme);
        writer.WriteVector16(signature);
        return writer.ToArray();
    }

    /// <summary>
    /// The bytes a CertificateVerify signs (RFC 8446 §4.4.3): 64 spaces, the context string, a zero byte, then the
    /// transcript hash. The leading spaces exist so that a signature can never be confused with one made over a
    /// different protocol's data.
    /// </summary>
    public static byte[] CertificateVerifyContent(bool server, ReadOnlySpan<byte> transcriptHash)
    {
        var context = server ? ServerCertificateVerifyContext : ClientCertificateVerifyContext;
        var content = new byte[64 + context.Length + 1 + transcriptHash.Length];
        content.AsSpan(0, 64).Fill(0x20);
        context.CopyTo(content.AsSpan(64));
        content[64 + context.Length] = 0x00;
        transcriptHash.CopyTo(content.AsSpan(64 + context.Length + 1));
        return content;
    }

    /// <summary>Finished: just the verify_data MAC.</summary>
    public static byte[] Finished(ReadOnlySpan<byte> verifyData) => verifyData.ToArray();

    /// <summary>An ACK record body: the record numbers being acknowledged, in increasing order (RFC 9147 §7).</summary>
    public static byte[] Ack(IEnumerable<(ulong Epoch, ulong SequenceNumber)> recordNumbers)
    {
        var writer = new Dtls13Writer();
        var list = writer.BeginVector16();
        foreach (var (epoch, sequence) in recordNumbers)
        {
            writer.WriteUInt64(epoch);
            writer.WriteUInt64(sequence);
        }
        writer.EndVector(list);
        return writer.ToArray();
    }

    private static void WriteSupportedVersion(Dtls13Writer writer) =>
        WriteExtension(writer, Dtls13ExtensionType.SupportedVersions, inner => inner.WriteUInt16(Dtls13Version.Dtls13));

    private static void WriteExtension(Dtls13Writer writer, ushort type, Action<Dtls13Writer> body)
    {
        writer.WriteUInt16(type);
        var length = writer.BeginVector16();
        body(writer);
        writer.EndVector(length);
    }
}
