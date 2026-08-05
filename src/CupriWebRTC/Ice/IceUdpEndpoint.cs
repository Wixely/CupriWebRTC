using System.Net;
using System.Net.Sockets;

namespace CupriWebRTC.Ice;

/// <summary>
/// Binds a UDP port and runs the ICE-lite side of a WebRTC endpoint: it demultiplexes incoming datagrams (RFC 7983 —
/// STUN vs. DTLS by the first byte), answers STUN connectivity checks via an <see cref="IceLiteResponder"/>, and
/// hands DTLS datagrams to a subscriber (the DTLS layer plugs in here). It learns the peer's address from the checks
/// (<see cref="SelectedRemote"/>). No candidate gathering, no trickle — the "reachable server" side.
/// </summary>
public sealed class IceUdpEndpoint : IAsyncDisposable
{
    private readonly UdpClient _udp;
    private readonly IceLiteResponder _responder;

    public IceUdpEndpoint(IceCredentials local, IPEndPoint bind)
    {
        ArgumentNullException.ThrowIfNull(bind);
        _responder = new IceLiteResponder(local);
        _udp = new UdpClient(bind);
    }

    /// <summary>The bound local endpoint (host + the actual port, useful when binding to port 0).</summary>
    public IPEndPoint LocalEndPoint => (IPEndPoint)_udp.Client.LocalEndPoint!;

    /// <summary>The fixed ICE credentials this endpoint answers to (publish these ahead of time).</summary>
    public IceCredentials LocalCredentials => _responder.LocalCredentials;

    /// <summary>The peer address learned from a successful connectivity check, if any.</summary>
    public IPEndPoint? SelectedRemote { get; private set; }

    /// <summary>Raised for non-STUN (DTLS) datagrams on this port — the DTLS layer subscribes here.</summary>
    public event Action<ReadOnlyMemory<byte>, IPEndPoint>? DtlsDatagramReceived;

    /// <summary>Raised when a STUN connectivity check is answered: (the peer's own ICE ufrag, its source address).
    /// The ufrag is unique per peer, so a listener keys sessions by it and migrates the address on a NAT rebind.</summary>
    public event Action<string, IPEndPoint>? ConnectivityCheck;

    /// <summary>Sends a datagram from this port (used by the DTLS layer to reply on the same flow).</summary>
    public ValueTask<int> SendAsync(ReadOnlyMemory<byte> datagram, IPEndPoint remote, CancellationToken cancellationToken = default)
        => _udp.SendAsync(datagram, remote, cancellationToken);

    /// <summary>Receive loop: runs until cancelled. Answers STUN checks itself; forwards DTLS datagrams.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            UdpReceiveResult result;
            try
            {
                result = await _udp.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException)
            {
                continue; // transient (e.g. ICMP port-unreachable surfaced on the socket) — keep serving
            }

            var buffer = result.Buffer;
            if (buffer.Length == 0)
                continue;

            var first = buffer[0];
            if (first <= 3) // STUN
            {
                var response = _responder.Handle(buffer, result.RemoteEndPoint, out var outcome, out var remoteUfrag);
                if (outcome == IceLiteResponder.Outcome.Responded && response is not null)
                {
                    SelectedRemote = result.RemoteEndPoint;
                    await _udp.SendAsync(response, result.RemoteEndPoint, cancellationToken).ConfigureAwait(false);
                    if (remoteUfrag is not null)
                        ConnectivityCheck?.Invoke(remoteUfrag, result.RemoteEndPoint);
                }
            }
            else if (first is >= 20 and <= 63) // DTLS
            {
                DtlsDatagramReceived?.Invoke(buffer, result.RemoteEndPoint);
            }
            // else: RTP/RTCP or unknown — ignored (this endpoint carries no media).
        }
    }

    public ValueTask DisposeAsync()
    {
        _udp.Dispose();
        return ValueTask.CompletedTask;
    }
}
