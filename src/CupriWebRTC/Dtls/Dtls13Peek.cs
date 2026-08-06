using CupriWebRTC.Dtls13;
using Org.BouncyCastle.Tls;

namespace CupriWebRTC.Dtls;

/// <summary>
/// The version sniffer for the dual-stack dispatch: given the peer's very first datagram, decide whether to hand the
/// connection to the managed DTLS 1.3 server or to the BouncyCastle 1.2 one. It looks for a ClientHello's
/// <c>supported_versions</c> extension containing DTLS 1.3 (0xfefc) — the <c>legacy_version</c> field says nothing,
/// since every DTLS 1.3 ClientHello pins it to DTLS 1.2 for middlebox compatibility.
///
/// <para>Deliberately permissive: anything it cannot parse is reported as "not 1.3", so a malformed or non-hello
/// datagram falls through to the old path rather than failing here.</para>
/// </summary>
internal static class Dtls13Peek
{
    private const byte HandshakeContentType = 22;
    private const int PlaintextHeaderLength = 13;
    private const int DtlsHandshakeHeaderLength = 12;

    /// <summary>True if <paramref name="datagram"/> holds a ClientHello offering DTLS 1.3.</summary>
    public static bool OffersDtls13(ReadOnlySpan<byte> datagram)
    {
        try
        {
            return TryFindClientHello(datagram, out var body) && Dtls13ClientHello.Parse(body).OffersDtls13;
        }
        catch (Exception ex) when (ex is Dtls13DecodeException or ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static bool TryFindClientHello(ReadOnlySpan<byte> datagram, out ReadOnlySpan<byte> body)
    {
        body = default;
        var at = 0;
        while (at + PlaintextHeaderLength <= datagram.Length)
        {
            if (datagram[at] != HandshakeContentType)
                return false; // an encrypted or non-handshake first record is not a fresh ClientHello
            var length = (datagram[at + 11] << 8) | datagram[at + 12];
            var fragmentStart = at + PlaintextHeaderLength;
            if (fragmentStart + length > datagram.Length)
                return false;

            var fragment = datagram.Slice(fragmentStart, length);
            if (fragment.Length >= DtlsHandshakeHeaderLength && fragment[0] == 1) // client_hello
            {
                var messageLength = (fragment[1] << 16) | (fragment[2] << 8) | fragment[3];
                var fragmentOffset = (fragment[6] << 16) | (fragment[7] << 8) | fragment[8];
                var fragmentLength = (fragment[9] << 16) | (fragment[10] << 8) | fragment[11];
                // Only an unfragmented ClientHello can be sniffed; a fragmented one is vanishingly rare here (a
                // browser's hello is a few hundred bytes) and falls through to the 1.2 path.
                if (fragmentOffset != 0 || fragmentLength != messageLength ||
                    DtlsHandshakeHeaderLength + fragmentLength > fragment.Length)
                    return false;
                body = fragment.Slice(DtlsHandshakeHeaderLength, fragmentLength);
                return true;
            }
            at = fragmentStart + length;
        }
        return false;
    }
}

/// <summary>
/// A <see cref="DatagramTransport"/> that replays datagrams already taken off the wire before delegating to the real
/// one. Version dispatch has to read the first datagram to decide which DTLS server to build — this hands that
/// datagram back so the chosen server sees an untouched flow.
/// </summary>
internal sealed class PushbackDatagramTransport(DatagramTransport inner, IEnumerable<byte[]> pushback) : DatagramTransport
{
    private readonly DatagramTransport _inner = inner;
    private readonly Queue<byte[]> _pushback = new(pushback);

    public int GetReceiveLimit() => _inner.GetReceiveLimit();

    public int GetSendLimit() => _inner.GetSendLimit();

    public int Receive(byte[] buf, int off, int len, int waitMillis) => Receive(buf.AsSpan(off, len), waitMillis);

    public int Receive(Span<byte> buffer, int waitMillis)
    {
        if (_pushback.TryDequeue(out var datagram))
        {
            var n = Math.Min(buffer.Length, datagram.Length);
            datagram.AsSpan(0, n).CopyTo(buffer);
            return n;
        }
        return _inner.Receive(buffer, waitMillis);
    }

    public void Send(byte[] buf, int off, int len) => _inner.Send(buf.AsSpan(off, len));

    public void Send(ReadOnlySpan<byte> buffer) => _inner.Send(buffer);

    public void Close() => _inner.Close();
}
