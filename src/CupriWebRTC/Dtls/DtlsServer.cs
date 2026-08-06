using CupriWebRTC.Dtls13;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace CupriWebRTC.Dtls;

/// <summary>
/// Runs the DTLS server handshake for a WebRTC endpoint and yields the secured datagram transport that SCTP (the
/// DataChannel) then runs over. Presents <see cref="DtlsCertificate"/> and accepts any client certificate.
///
/// <para>It is <b>dual-version</b>. Every current browser offers DTLS 1.3 first and refuses to fall back to 1.2, so
/// the first datagram is sniffed (<see cref="Dtls13Peek"/>): a ClientHello offering DTLS 1.3 goes to the managed
/// <see cref="Dtls13ServerConnection"/> in <c>CupriWebRTC.Dtls13</c>; anything else goes to BouncyCastle's DTLS 1.2
/// server, which is kept for 1.2-only peers. Either way the caller gets an
/// <see cref="ISecureDatagramTransport"/> and cannot tell which ran.</para>
/// </summary>
public sealed class DtlsServer
{
    private readonly DtlsCertificate _certificate;
    private readonly Dtls13ServerOptions _options13;

    public DtlsServer(DtlsCertificate certificate, Dtls13ServerOptions? options13 = null)
    {
        _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        _options13 = options13 ?? new Dtls13ServerOptions();
    }

    /// <summary>The raw SHA-256 fingerprint of our certificate (publish this in the connection link).</summary>
    public byte[] Fingerprint => _certificate.Fingerprint;

    /// <summary>The SDP-style fingerprint (<c>AB:CD:…</c>).</summary>
    public string FingerprintSdp => _certificate.FingerprintSdp();

    /// <summary>Blocks running the DTLS server handshake over <paramref name="transport"/>; returns the secured
    /// transport, whose <see cref="ISecureDatagramTransport.ProtocolVersion"/> says which version ran.</summary>
    public ISecureDatagramTransport Accept(DatagramTransport transport)
    {
        ArgumentNullException.ThrowIfNull(transport);

        var (first, offersDtls13) = PeekFirstDatagram(transport);
        var flow = new PushbackDatagramTransport(transport, first is null ? [] : [first]);

        if (offersDtls13)
        {
            var connection = new Dtls13ServerConnection(flow, new Dtls13CertificateSigner(_certificate), _options13);
            connection.Handshake();
            return connection;
        }

        var crypto = new BcTlsCrypto(new SecureRandom());
        var server = new CupriTlsServer(crypto, _certificate);
        return new BouncyCastleSecureDatagramTransport(new DtlsServerProtocol().Accept(server, flow));
    }

    /// <summary>
    /// Waits for the peer's first datagram and decides which DTLS version to run. The datagram is handed back so the
    /// chosen server still sees it; a peer that never speaks leaves this returning nothing, and the 1.2 path's own
    /// timeout takes over.
    /// </summary>
    private static (byte[]? Datagram, bool OffersDtls13) PeekFirstDatagram(DatagramTransport transport)
    {
        var buffer = new byte[Math.Max(1500, transport.GetReceiveLimit())];
        var received = transport.Receive(buffer, 0, buffer.Length, 60_000);
        if (received <= 0)
            return (null, false);
        var datagram = buffer.AsSpan(0, received).ToArray();
        return (datagram, Dtls13Peek.OffersDtls13(datagram));
    }
}
