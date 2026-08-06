using System.Net;

namespace CupriWebRTC.Dtls;

/// <summary>
/// An env-gated tap that writes every DTLS datagram, both directions, to a libpcap file so the handshake can be
/// decoded with Wireshark/tshark. Set <c>CUPRIWEBRTC_PCAP</c> to a path to switch it on; leave it unset and this
/// costs one null check per datagram.
///
/// <para>It exists because loopback cannot be captured without a packet driver on Windows, and the DTLS failure mode
/// this whole 1.3 effort was built to fix — a browser silently rejecting our flight — is invisible from inside the
/// process. Decoding the actual bytes is how you tell "our record is malformed" from "the peer didn't like our
/// version". Datagrams are wrapped in a synthetic IPv4+UDP header (LINKTYPE_RAW) so that
/// <c>tshark -d udp.port==&lt;port&gt;,dtls</c> dissects them as DTLS.</para>
/// </summary>
internal sealed class DtlsPcapTap : IDisposable
{
    private const uint MagicMicroseconds = 0xA1B2C3D4;
    private const uint LinkTypeRaw = 101; // LINKTYPE_RAW — the payload starts at the IP header

    private readonly FileStream _file;
    private readonly Lock _gate = new();
    private bool _disposed;

    private DtlsPcapTap(FileStream file)
    {
        _file = file;
        Span<byte> header = stackalloc byte[24];
        WriteUInt32(header, 0, MagicMicroseconds);
        WriteUInt16(header, 4, 2);          // version major
        WriteUInt16(header, 6, 4);          // version minor
        WriteUInt32(header, 8, 0);          // this zone
        WriteUInt32(header, 12, 0);         // sigfigs
        WriteUInt32(header, 16, 65535);     // snaplen
        WriteUInt32(header, 20, LinkTypeRaw);
        _file.Write(header);
        _file.Flush();
    }

    /// <summary>
    /// The one tap for this process if <c>CUPRIWEBRTC_PCAP</c> names a writable path, otherwise null. It is a
    /// singleton on purpose: every peer's datagrams belong in one capture file, and a per-session tap would truncate
    /// the file each time a peer reconnected — losing exactly the failed handshake you were trying to look at.
    /// </summary>
    public static DtlsPcapTap? Shared => LazyShared.Value;

    private static readonly Lazy<DtlsPcapTap?> LazyShared = new(() =>
    {
        var path = Environment.GetEnvironmentVariable("CUPRIWEBRTC_PCAP");
        if (string.IsNullOrWhiteSpace(path))
            return null;
        try
        {
            return new DtlsPcapTap(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null; // diagnostics must never break the data path
        }
    });

    /// <summary>Records one datagram travelling from <paramref name="source"/> to <paramref name="destination"/>.</summary>
    public void Write(ReadOnlySpan<byte> datagram, IPEndPoint source, IPEndPoint destination)
    {
        if (_disposed || datagram.Length > 65000)
            return;

        var udpLength = 8 + datagram.Length;
        var ipLength = 20 + udpLength;
        var packet = new byte[ipLength];

        packet[0] = 0x45;                                  // IPv4, 20-byte header
        WriteUInt16BigEndian(packet, 2, (ushort)ipLength);
        packet[8] = 64;                                    // TTL
        packet[9] = 17;                                    // UDP
        WriteAddress(packet, 12, source);
        WriteAddress(packet, 16, destination);
        WriteUInt16BigEndian(packet, 20, (ushort)source.Port);
        WriteUInt16BigEndian(packet, 22, (ushort)destination.Port);
        WriteUInt16BigEndian(packet, 24, (ushort)udpLength);
        // The UDP checksum is left zero, which IPv4 explicitly permits and Wireshark accepts.
        datagram.CopyTo(packet.AsSpan(28));

        var now = DateTimeOffset.UtcNow;
        Span<byte> record = stackalloc byte[16];
        WriteUInt32(record, 0, (uint)now.ToUnixTimeSeconds());
        WriteUInt32(record, 4, (uint)(now.ToUnixTimeMilliseconds() % 1000 * 1000));
        WriteUInt32(record, 8, (uint)packet.Length);
        WriteUInt32(record, 12, (uint)packet.Length);

        lock (_gate)
        {
            if (_disposed)
                return;
            try
            {
                _file.Write(record);
                _file.Write(packet);
                _file.Flush();
            }
            catch (IOException)
            {
                // A full or vanished disk must not take the connection down with it.
            }
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
                return;
            _disposed = true;
            _file.Dispose();
        }
    }

    private static void WriteAddress(Span<byte> buffer, int offset, IPEndPoint endPoint)
    {
        var address = endPoint.Address.IsIPv4MappedToIPv6 ? endPoint.Address.MapToIPv4() : endPoint.Address;
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            address.TryWriteBytes(buffer.Slice(offset, 4), out _);
        else
            buffer.Slice(offset, 4).Clear(); // an IPv6 peer is recorded as 0.0.0.0; the ports still identify the flow
    }

    private static void WriteUInt32(Span<byte> buffer, int offset, uint value)
    {
        buffer[offset] = (byte)value;
        buffer[offset + 1] = (byte)(value >> 8);
        buffer[offset + 2] = (byte)(value >> 16);
        buffer[offset + 3] = (byte)(value >> 24);
    }

    private static void WriteUInt16(Span<byte> buffer, int offset, ushort value)
    {
        buffer[offset] = (byte)value;
        buffer[offset + 1] = (byte)(value >> 8);
    }

    private static void WriteUInt16BigEndian(Span<byte> buffer, int offset, ushort value)
    {
        buffer[offset] = (byte)(value >> 8);
        buffer[offset + 1] = (byte)value;
    }
}
