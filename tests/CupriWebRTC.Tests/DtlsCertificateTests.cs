using CupriWebRTC.Dtls;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Xunit;

namespace CupriWebRTC.Tests;

public class DtlsCertificateTests
{
    [Fact]
    public void GenerateSelfSigned_ProducesSha256Fingerprint()
    {
        var cert = DtlsCertificate.GenerateSelfSigned();

        Assert.Equal("sha-256", cert.FingerprintAlgorithm);
        Assert.Equal(32, cert.Fingerprint.Length);

        // SDP form: 32 upper-case hex bytes joined by 31 colons = 95 chars, e.g. "AB:CD:...".
        var sdp = cert.FingerprintSdp();
        Assert.Equal(95, sdp.Length);
        Assert.Equal(31, sdp.Split(':').Length - 1);
        Assert.All(sdp.Split(':'), part => Assert.Equal(2, part.Length));
    }

    [Fact]
    public void GenerateSelfSigned_IsUniquePerCall()
    {
        Assert.NotEqual(DtlsCertificate.GenerateSelfSigned().Fingerprint,
                        DtlsCertificate.GenerateSelfSigned().Fingerprint);
    }

    /// <summary>
    /// The public key must name its curve by OID, not spell the curve out as explicit parameters. RFC 5480 §2.1.1
    /// requires <c>namedCurve</c> for TLS, and BoringSSL — so every Chromium browser — answers an explicit-parameter
    /// certificate with a <c>decode_error</c> alert and drops the connection. This is invisible in every test that
    /// does not involve a real browser, which is exactly why it is pinned here.
    /// </summary>
    [Fact]
    public void GenerateSelfSigned_NamesItsCurveByOid_AsBrowsersRequire()
    {
        var certificate = DtlsCertificate.GenerateSelfSigned();
        var publicKeyInfo = SubjectPublicKeyInfo.GetInstance(certificate.Certificate.CertificateStructure.SubjectPublicKeyInfo);

        Assert.Equal(X9ObjectIdentifiers.IdECPublicKey, publicKeyInfo.Algorithm.Algorithm);
        var parameters = X962Parameters.GetInstance(publicKeyInfo.Algorithm.Parameters);
        Assert.True(parameters.IsNamedCurve, "the certificate spells its curve out instead of naming it");
        Assert.Equal(X9ObjectIdentifiers.Prime256v1, // 1.2.840.10045.3.1.7 (secp256r1 / P-256)
            Assert.IsAssignableFrom<DerObjectIdentifier>(parameters.Parameters));
    }
}
