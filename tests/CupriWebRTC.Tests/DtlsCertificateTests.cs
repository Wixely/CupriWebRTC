using CupriWebRTC.Dtls;
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
}
