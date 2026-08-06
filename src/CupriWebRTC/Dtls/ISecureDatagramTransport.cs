namespace CupriWebRTC.Dtls;

/// <summary>
/// A datagram transport whose payloads are already protected — what a completed DTLS handshake hands upward, and all
/// that SCTP (and therefore the DataChannel) needs to know about DTLS. Both DTLS versions in this stack implement it:
/// the BouncyCastle 1.2 path via <see cref="BouncyCastleSecureDatagramTransport"/>, and the managed 1.3 path
/// directly. The shape deliberately mirrors BouncyCastle's <c>DtlsTransport</c>, which is what the SCTP layer used
/// before the 1.3 work, so nothing above had to change.
/// </summary>
public interface ISecureDatagramTransport : IDisposable
{
    /// <summary>The DTLS version that was negotiated, for diagnostics (e.g. <c>"DTLS 1.3"</c>).</summary>
    string ProtocolVersion { get; }

    /// <summary>The largest application datagram this transport can deliver.</summary>
    int GetReceiveLimit();

    /// <summary>The largest application datagram this transport can send.</summary>
    int GetSendLimit();

    /// <summary>
    /// Receives one application datagram into <paramref name="buffer"/>, waiting at most
    /// <paramref name="waitMillis"/>. Returns the byte count, or a non-positive value on timeout.
    /// </summary>
    int Receive(byte[] buffer, int offset, int length, int waitMillis);

    /// <summary>Sends one application datagram.</summary>
    void Send(byte[] buffer, int offset, int length);

    /// <summary>Closes the transport (idempotent).</summary>
    void Close();
}
