using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CupriWebRTC.Dtls;

/// <summary>
/// A self-signed certificate + key pair for the DTLS handshake, and its fingerprint. WebRTC endpoints use ephemeral
/// self-signed certs (there is no CA); the certificate's <b>fingerprint</b> is what a peer verifies — CupriNet
/// publishes it in the signed link, so a browser can check it. An ECDSA P-256 cert is used (WebRTC's common choice).
/// </summary>
public sealed class DtlsCertificate
{
    /// <summary>The X.509 certificate.</summary>
    public X509Certificate Certificate { get; }

    /// <summary>The certificate's private key.</summary>
    public AsymmetricKeyParameter PrivateKey { get; }

    /// <summary>The raw SHA-256 fingerprint of the DER-encoded certificate (32 bytes).</summary>
    public byte[] Fingerprint { get; }

    /// <summary>The fingerprint hash algorithm, as used in SDP / the WebRTC endpoint block.</summary>
    public string FingerprintAlgorithm => "sha-256";

    private DtlsCertificate(X509Certificate certificate, AsymmetricKeyParameter privateKey)
    {
        Certificate = certificate;
        PrivateKey = privateKey;
        Fingerprint = SHA256.HashData(certificate.GetEncoded());
    }

    /// <summary>The SDP-style fingerprint, upper-case hex bytes joined by colons (e.g. <c>AB:CD:…</c>).</summary>
    public string FingerprintSdp()
    {
        var hex = Convert.ToHexString(Fingerprint);
        var sb = new StringBuilder(hex.Length + (hex.Length / 2) - 1);
        for (var i = 0; i < hex.Length; i += 2)
        {
            if (i > 0)
                sb.Append(':');
            sb.Append(hex[i]).Append(hex[i + 1]);
        }
        return sb.ToString();
    }

    /// <summary>Generates a fresh, self-signed ECDSA P-256 certificate for a DTLS endpoint.</summary>
    public static DtlsCertificate GenerateSelfSigned(SecureRandom? random = null)
    {
        random ??= new SecureRandom();

        // The domain parameters MUST carry the curve's OID (ECNamedDomainParameters), not just its arithmetic.
        // Without it BouncyCastle writes the SubjectPublicKeyInfo with *explicit* curve parameters — the prime, a, b,
        // the base point, the order — instead of the named-curve OID. That is legal X.509 but RFC 5480 §2.1.1
        // forbids it for TLS, and BoringSSL (so: every Chromium browser) rejects such a certificate outright with a
        // decode_error alert, killing the handshake. It stayed hidden while browsers never got far enough to parse
        // our certificate at all.
        var oid = ECNamedCurveTable.GetOid("secp256r1");
        var x9 = ECNamedCurveTable.GetByOid(oid);
        var domain = new ECNamedDomainParameters(oid, x9);
        var keyGen = new ECKeyPairGenerator("ECDSA");
        keyGen.Init(new ECKeyGenerationParameters(domain, random));
        var keyPair = keyGen.GenerateKeyPair();

        var name = new X509Name("CN=CupriWebRTC");
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ProbablePrime(120, random));
        generator.SetIssuerDN(name);
        generator.SetSubjectDN(name);
        generator.SetNotBefore(DateTime.UtcNow.AddMinutes(-5));
        generator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        generator.SetPublicKey(keyPair.Public);

        var signatureFactory = new Asn1SignatureFactory("SHA256withECDSA", keyPair.Private, random);
        var certificate = generator.Generate(signatureFactory);
        return new DtlsCertificate(certificate, keyPair.Private);
    }
}
