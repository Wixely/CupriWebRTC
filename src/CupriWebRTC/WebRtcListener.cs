using System.Net;
using CupriWebRTC.Dtls;
using CupriWebRTC.Ice;
using CupriWebRTC.Sctp;

namespace CupriWebRTC;

/// <summary>
/// A complete managed WebRTC DataChannel endpoint (the server/answerer side). It assembles the stack on one UDP
/// socket: <see cref="IceUdpEndpoint"/> answers ICE checks and demultiplexes DTLS, an <see cref="EndpointDatagramTransport"/>
/// bridges DTLS to the socket, <see cref="DtlsServer"/> secures it, and an <see cref="SctpAssociation"/> (responder)
/// runs the DataChannel over the secured transport. It runs from static, pre-published parameters
/// (<see cref="Parameters"/>) — ICE-lite, fixed credentials, accept-any client cert — so a browser can connect with
/// no signalling server. Not media (no SRTP).
/// </summary>
public sealed class WebRtcListener : IAsyncDisposable
{
    private readonly IceUdpEndpoint _ice;
    private readonly DtlsServer _dtls;
    private readonly DtlsCertificate _certificate;
    private readonly object _gate = new();

    private EndpointDatagramTransport? _bridge;
    private SctpTransport? _sctp;

    public WebRtcListener(IPEndPoint bind, IceCredentials? credentials = null, DtlsCertificate? certificate = null)
    {
        ArgumentNullException.ThrowIfNull(bind);
        _certificate = certificate ?? DtlsCertificate.GenerateSelfSigned();
        _dtls = new DtlsServer(_certificate);
        _ice = new IceUdpEndpoint(credentials ?? IceCredentials.Generate(), bind);
        _ice.DtlsDatagramReceived += OnDtlsDatagram;
    }

    /// <summary>The bound local endpoint (host + actual port).</summary>
    public IPEndPoint LocalEndPoint => _ice.LocalEndPoint;

    /// <summary>The static parameters to publish so a peer can dial this endpoint with no signalling.</summary>
    public WebRtcEndpointParameters Parameters => new(
        _ice.LocalCredentials.Ufrag,
        _ice.LocalCredentials.Password,
        _certificate.FingerprintAlgorithm,
        _certificate.Fingerprint,
        _ice.LocalEndPoint.Port);

    /// <summary>Raised when the peer opens a data channel.</summary>
    public event Action<SctpDataChannel>? ChannelOpened;

    /// <summary>Raised for an inbound application message: (streamId, PPID, payload).</summary>
    public event Action<ushort, uint, byte[]>? MessageReceived;

    /// <summary>Runs the endpoint (ICE receive loop) until cancelled.</summary>
    public Task RunAsync(CancellationToken cancellationToken) => _ice.RunAsync(cancellationToken);

    /// <summary>Sends an application message once a channel is up.</summary>
    public void SendMessage(ushort streamId, uint ppid, byte[] data)
    {
        SctpTransport? sctp;
        lock (_gate)
            sctp = _sctp;
        sctp?.SendMessage(streamId, ppid, data);
    }

    // First DTLS datagram from a peer starts the DTLS handshake (then SCTP) over a bridge fed by later datagrams.
    private void OnDtlsDatagram(ReadOnlyMemory<byte> data, IPEndPoint remote)
    {
        EndpointDatagramTransport bridge;
        lock (_gate)
        {
            if (_bridge is null)
            {
                _bridge = new EndpointDatagramTransport(_ice, remote);
                StartDtlsThenSctp(_bridge);
            }
            bridge = _bridge;
        }
        bridge.Enqueue(data);
    }

    private void StartDtlsThenSctp(EndpointDatagramTransport bridge)
    {
        var thread = new Thread(() =>
        {
            try
            {
                var secured = _dtls.Accept(bridge); // blocks until the DTLS handshake completes
                var sctp = new SctpTransport(secured, new SctpAssociation());
                sctp.ChannelOpened += channel => ChannelOpened?.Invoke(channel);
                sctp.MessageReceived += (stream, ppid, payload) => MessageReceived?.Invoke(stream, ppid, payload);
                lock (_gate)
                    _sctp = sctp;
                sctp.Start();
            }
            catch
            {
                // Handshake failed / peer went away — the endpoint keeps serving; a fresh peer can retry.
            }
        })
        { IsBackground = true, Name = "cupriwebrtc-dtls" };
        thread.Start();
    }

    public async ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            _sctp?.Dispose();
            _bridge?.Close();
        }
        await _ice.DisposeAsync().ConfigureAwait(false);
    }
}
