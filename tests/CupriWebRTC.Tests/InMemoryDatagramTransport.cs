using Org.BouncyCastle.Tls;

namespace CupriWebRTC.Tests;

/// <summary>An in-memory, reliable, ordered datagram pair (BouncyCastle <see cref="DatagramTransport"/>) for tests.</summary>
internal sealed class InMemoryDatagramTransport : DatagramTransport
{
    private const int Mtu = 1500;
    private readonly System.Collections.Concurrent.BlockingCollection<byte[]> _inbound;
    private readonly System.Collections.Concurrent.BlockingCollection<byte[]> _outbound;

    private InMemoryDatagramTransport(
        System.Collections.Concurrent.BlockingCollection<byte[]> inbound,
        System.Collections.Concurrent.BlockingCollection<byte[]> outbound)
    {
        _inbound = inbound;
        _outbound = outbound;
    }

    public static (InMemoryDatagramTransport A, InMemoryDatagramTransport B) CreatePair()
    {
        var toA = new System.Collections.Concurrent.BlockingCollection<byte[]>();
        var toB = new System.Collections.Concurrent.BlockingCollection<byte[]>();
        return (new InMemoryDatagramTransport(toA, toB), new InMemoryDatagramTransport(toB, toA));
    }

    public int GetReceiveLimit() => Mtu;
    public int GetSendLimit() => Mtu;

    public int Receive(byte[] buf, int off, int len, int waitMillis) => Receive(buf.AsSpan(off, len), waitMillis);

    public int Receive(Span<byte> buffer, int waitMillis)
    {
        if (!_inbound.TryTake(out var datagram, waitMillis))
            return -1; // timeout
        var n = Math.Min(buffer.Length, datagram.Length);
        datagram.AsSpan(0, n).CopyTo(buffer);
        return n;
    }

    public void Send(byte[] buf, int off, int len) => Send(buf.AsSpan(off, len));

    public void Send(ReadOnlySpan<byte> buffer)
    {
        var copy = buffer.ToArray();
        try { _outbound.Add(copy); }
        catch (InvalidOperationException) { /* closed */ }
    }

    public void Close()
    {
        try { _outbound.CompleteAdding(); }
        catch (ObjectDisposedException) { }
    }
}
