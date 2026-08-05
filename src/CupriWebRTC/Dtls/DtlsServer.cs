using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace CupriWebRTC.Dtls;

/// <summary>
/// Runs the DTLS server handshake for a WebRTC endpoint and yields the secured datagram transport that SCTP (the
/// DataChannel) then runs over. Presents <see cref="DtlsCertificate"/> and accepts any client certificate (see
/// <see cref="CupriTlsServer"/>). The handshake is driven over a BouncyCastle <see cref="DatagramTransport"/> — an
/// in-memory one in tests, or one bridged to the ICE UDP flow in production.
/// </summary>
public sealed class DtlsServer(DtlsCertificate certificate)
{
    private readonly DtlsCertificate _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));

    /// <summary>The raw SHA-256 fingerprint of our certificate (publish this in the connection link).</summary>
    public byte[] Fingerprint => _certificate.Fingerprint;

    /// <summary>The SDP-style fingerprint (<c>AB:CD:…</c>).</summary>
    public string FingerprintSdp => _certificate.FingerprintSdp();

    /// <summary>Blocks running the DTLS server handshake over <paramref name="transport"/>; returns the secured transport.</summary>
    public DtlsTransport Accept(DatagramTransport transport)
    {
        ArgumentNullException.ThrowIfNull(transport);
        var crypto = new BcTlsCrypto(new SecureRandom());
        var server = new CupriTlsServer(crypto, _certificate);
        return new DtlsServerProtocol().Accept(server, transport);
    }
}
