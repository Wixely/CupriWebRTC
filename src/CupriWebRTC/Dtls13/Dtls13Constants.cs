namespace CupriWebRTC.Dtls13;

/// <summary>Record content types (RFC 8446 §5.1 plus DTLS 1.3's <c>ack</c>).</summary>
internal static class Dtls13ContentType
{
    public const byte ChangeCipherSpec = 20; // never sent in DTLS 1.3; only recognised so it can be dropped
    public const byte Alert = 21;
    public const byte Handshake = 22;
    public const byte ApplicationData = 23;
    public const byte Ack = 26;
}

/// <summary>Handshake message types (RFC 9147 Appendix A.2).</summary>
internal static class Dtls13HandshakeType
{
    public const byte ClientHello = 1;
    public const byte ServerHello = 2;
    public const byte NewSessionTicket = 4;
    public const byte EncryptedExtensions = 8;
    public const byte Certificate = 11;
    public const byte CertificateRequest = 13;
    public const byte CertificateVerify = 15;
    public const byte Finished = 20;
    public const byte KeyUpdate = 24;
    public const byte MessageHash = 254;
}

/// <summary>Extension type code points we read or write.</summary>
internal static class Dtls13ExtensionType
{
    public const ushort SupportedGroups = 10;
    public const ushort SignatureAlgorithms = 13;
    public const ushort UseSrtp = 14;
    public const ushort PreSharedKey = 41;
    public const ushort EarlyData = 42;
    public const ushort SupportedVersions = 43;
    public const ushort Cookie = 44;
    public const ushort PskKeyExchangeModes = 45;
    public const ushort KeyShare = 51;
}

/// <summary>TLS named groups (the ECDHE curves) we support.</summary>
public static class Dtls13NamedGroup
{
    /// <summary>secp256r1 / NIST P-256 — uncompressed point, 65 bytes.</summary>
    public const ushort Secp256r1 = 0x0017;

    /// <summary>X25519 — 32-byte u-coordinate. Browsers prefer this.</summary>
    public const ushort X25519 = 0x001D;
}

/// <summary>TLS SignatureScheme code points we can produce or advertise.</summary>
public static class Dtls13SignatureScheme
{
    public const ushort RsaPkcs1Sha256 = 0x0401;
    public const ushort EcdsaSecp256r1Sha256 = 0x0403;
    public const ushort RsaPssRsaeSha256 = 0x0804;
    public const ushort Ed25519 = 0x0807;
}

/// <summary>Alert levels and the descriptions this implementation can send.</summary>
internal static class Dtls13Alert
{
    public const byte Warning = 1;
    public const byte Fatal = 2;

    public const byte CloseNotify = 0;
    public const byte UnexpectedMessage = 10;
    public const byte BadRecordMac = 20;
    public const byte HandshakeFailure = 40;
    public const byte IllegalParameter = 47;
    public const byte DecodeError = 50;
    public const byte DecryptError = 51;
    public const byte ProtocolVersion = 70;
    public const byte InsufficientSecurity = 71;
    public const byte InternalError = 80;
    public const byte MissingExtension = 109;
    public const byte UnsupportedExtension = 110;
    public const byte NoApplicationProtocol = 120;

    public static string Describe(byte description) => description switch
    {
        CloseNotify => "close_notify",
        UnexpectedMessage => "unexpected_message",
        BadRecordMac => "bad_record_mac",
        HandshakeFailure => "handshake_failure",
        IllegalParameter => "illegal_parameter",
        DecodeError => "decode_error",
        DecryptError => "decrypt_error",
        ProtocolVersion => "protocol_version",
        InsufficientSecurity => "insufficient_security",
        InternalError => "internal_error",
        MissingExtension => "missing_extension",
        UnsupportedExtension => "unsupported_extension",
        NoApplicationProtocol => "no_application_protocol",
        _ => $"alert({description})",
    };
}

/// <summary>Protocol version code points, on the wire (DTLS versions are one's-complement, so they descend).</summary>
internal static class Dtls13Version
{
    /// <summary>DTLS 1.2 — <c>legacy_version</c>/<c>legacy_record_version</c> for every DTLS 1.3 record.</summary>
    public const ushort Dtls12 = 0xFEFD;

    /// <summary>DTLS 1.3, only ever seen inside <c>supported_versions</c>.</summary>
    public const ushort Dtls13 = 0xFEFC;
}

/// <summary>Epoch numbers DTLS 1.3 assigns to the phases of a connection (RFC 9147 §6.1).</summary>
internal static class Dtls13Epoch
{
    public const ushort Initial = 0;      // ClientHello / ServerHello / HelloRetryRequest — unencrypted
    public const ushort EarlyData = 1;    // 0-RTT — not supported here
    public const ushort Handshake = 2;    // [sender]_handshake_traffic_secret
    public const ushort Application = 3;  // [sender]_application_traffic_secret_0
}
