using Org.BouncyCastle.Tls;

namespace CupriWebRTC.Dtls;

/// <summary>Presents a BouncyCastle DTLS 1.2 <see cref="DtlsTransport"/> as an <see cref="ISecureDatagramTransport"/>,
/// so the 1.2 fallback and the managed 1.3 path look identical to everything above them.</summary>
internal sealed class BouncyCastleSecureDatagramTransport(DtlsTransport transport) : ISecureDatagramTransport
{
    private readonly DtlsTransport _transport = transport ?? throw new ArgumentNullException(nameof(transport));

    public string ProtocolVersion => "DTLS 1.2";

    public int GetReceiveLimit() => _transport.GetReceiveLimit();

    public int GetSendLimit() => _transport.GetSendLimit();

    public int Receive(byte[] buffer, int offset, int length, int waitMillis) =>
        _transport.Receive(buffer, offset, length, waitMillis);

    public void Send(byte[] buffer, int offset, int length) => _transport.Send(buffer, offset, length);

    public void Close() => _transport.Close();

    public void Dispose()
    {
        try { _transport.Close(); }
        catch (Exception) { /* already closed or the peer went away */ }
    }
}
