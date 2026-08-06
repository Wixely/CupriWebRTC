using CupriWebRTC.Dtls;
using CupriWebRTC.Dtls13.Crypto;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CupriWebRTC.Dtls13;

/// <summary>
/// Signs the CertificateVerify with the endpoint's DTLS certificate key, and carries the chain the peer will pin by
/// fingerprint. The signature scheme follows the key: an ECDSA P-256 key signs <c>ecdsa_secp256r1_sha256</c> (the
/// safest default, and what every browser has exercised for years), an Ed25519 key signs <c>ed25519</c>.
/// </summary>
internal sealed class Dtls13CertificateSigner : IDtls13Signer
{
    private readonly AsymmetricKeyParameter _privateKey;
    private readonly string _algorithm;

    public Dtls13CertificateSigner(DtlsCertificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        _privateKey = certificate.PrivateKey;
        CertificateChain = [certificate.Certificate.GetEncoded()];
        (SignatureScheme, _algorithm) = _privateKey switch
        {
            ECPrivateKeyParameters => (Dtls13SignatureScheme.EcdsaSecp256r1Sha256, "SHA-256withECDSA"),
            Ed25519PrivateKeyParameters => (Dtls13SignatureScheme.Ed25519, "Ed25519"),
            _ => throw new NotSupportedException($"DTLS 1.3 cannot sign with a {_privateKey.GetType().Name} key"),
        };
    }

    public ushort SignatureScheme { get; }

    public IReadOnlyList<byte[]> CertificateChain { get; }

    public byte[] Sign(ReadOnlySpan<byte> content)
    {
        var signer = SignerUtilities.GetSigner(_algorithm);
        signer.Init(forSigning: true, _privateKey);
        signer.BlockUpdate(content);
        return signer.GenerateSignature();
    }
}
