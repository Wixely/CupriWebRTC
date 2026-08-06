using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace CupriWebRTC.Dtls;

/// <summary>
/// The DTLS 1.2 server role for a WebRTC endpoint. It presents a self-signed ECDSA certificate and — crucially —
/// <b>accepts any client certificate</b>: WebRTC is mutual-auth, but here the client's identity is authenticated
/// <em>above</em> the DataChannel (e.g. by CupriNet's Noise handshake), so verifying the client's cert fingerprint is
/// intentionally left to the caller, not enforced in DTLS. The server's own fingerprint is what the peer verifies,
/// and it is published in the signed connection link.
/// </summary>
internal sealed class CupriTlsServer(BcTlsCrypto crypto, DtlsCertificate certificate) : DefaultTlsServer(crypto)
{
    private readonly BcTlsCrypto _crypto = crypto;
    private readonly DtlsCertificate _certificate = certificate;

    // DTLS 1.2 only: BouncyCastle 2.6.2's DtlsServerProtocol does not support the DTLS 1.3 server role (negotiating
    // 1.3 throws internal_error in NegotiatedVersionDtlsServer). Modern browsers offer 1.3 but fall back to 1.2.
    protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.DTLSv12.Only();

    protected override int[] GetSupportedCipherSuites() =>
    [
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    ];

    protected override TlsCredentialedSigner GetECDsaSignerCredentials()
    {
        var tlsCertificate = new BcTlsCertificate(_crypto, _certificate.Certificate.GetEncoded());
        var chain = new Certificate([tlsCertificate]);
        var signatureAndHash = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa);
        return new BcDefaultTlsCredentialedSigner(
            new TlsCryptoParameters(m_context), _crypto, _certificate.PrivateKey, chain, signatureAndHash);
    }

    /// <summary>Request a client certificate (WebRTC sends one) but do not constrain or later verify it.</summary>
    public override CertificateRequest GetCertificateRequest()
    {
        var signatureAlgorithms = new List<SignatureAndHashAlgorithm>
        {
            new(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa),
            new(HashAlgorithm.sha256, SignatureAlgorithm.rsa),
        };
        return new CertificateRequest(
            [ClientCertificateType.ecdsa_sign, ClientCertificateType.rsa_sign],
            signatureAlgorithms,
            certificateAuthorities: null);
    }

    /// <summary>Accept any client certificate (including none) — see the class summary.</summary>
    public override void NotifyClientCertificate(Certificate clientCertificate)
    {
        // Intentionally no verification.
    }
}
