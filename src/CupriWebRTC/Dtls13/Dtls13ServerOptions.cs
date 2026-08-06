using CupriWebRTC.Dtls13.Crypto;

namespace CupriWebRTC.Dtls13;

/// <summary>
/// The DTLS 1.3 server's policy — the 1.3 counterpart of the BouncyCastle <c>TlsServer</c> object the 1.2 path uses.
/// The defaults are the WebRTC profile: all three TLS 1.3 suites, x25519 first (browsers prefer it), a client
/// certificate requested but never verified, and a cookie exchange on by default per RFC 9147 §5.1.
/// </summary>
public sealed class Dtls13ServerOptions
{
    /// <summary>Where the primitives come from. Swap this to move off BouncyCastle without touching the protocol.</summary>
    public IDtls13Crypto Crypto { get; init; } = BouncyCastleDtls13Crypto.Instance;

    /// <summary>
    /// Send a HelloRetryRequest carrying a stateless cookie before doing any expensive work, so a spoofed source
    /// address cannot make us sign or amplify (RFC 9147 §5.1). RFC 9147 permits turning this off where bidirectional
    /// connectivity is already proven — which ICE does — at the cost of one extra round trip when it is on.
    /// </summary>
    public bool CookieExchange { get; init; } = true;

    /// <summary>Ask the peer for a certificate. WebRTC browsers always have one and expect to be asked; we never
    /// verify what arrives (see the class remarks on <see cref="Dtls13Server"/>).</summary>
    public bool RequestClientCertificate { get; init; } = true;

    /// <summary>Named groups we will do ECDHE over, in preference order.</summary>
    public IReadOnlyList<ushort> SupportedGroups { get; init; } = [Dtls13NamedGroup.X25519, Dtls13NamedGroup.Secp256r1];

    /// <summary>Signature schemes advertised in our CertificateRequest (what we will accept from the peer).</summary>
    public IReadOnlyList<ushort> AcceptedSignatureSchemes { get; init; } =
    [
        Dtls13SignatureScheme.EcdsaSecp256r1Sha256,
        Dtls13SignatureScheme.Ed25519,
        Dtls13SignatureScheme.RsaPssRsaeSha256,
        Dtls13SignatureScheme.RsaPkcs1Sha256,
    ];

    /// <summary>How long the whole handshake may take before it is abandoned.</summary>
    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>The first retransmission timeout; it doubles on each expiry (RFC 9147 §5.8.2 recommends 1s).</summary>
    public TimeSpan InitialRetransmitTimeout { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>The retransmission timeout ceiling.</summary>
    public TimeSpan MaxRetransmitTimeout { get; init; } = TimeSpan.FromSeconds(8);

    /// <summary>
    /// The largest datagram we will emit. 1200 bytes is the conservative floor WebRTC stacks assume, comfortably
    /// inside any path MTU, so handshake flights fragment rather than risk IP fragmentation or a black hole.
    /// </summary>
    public int MaxDatagramSize { get; init; } = 1200;

    /// <summary>How long a HelloRetryRequest cookie stays valid.</summary>
    public TimeSpan CookieLifetime { get; init; } = TimeSpan.FromSeconds(60);
}
