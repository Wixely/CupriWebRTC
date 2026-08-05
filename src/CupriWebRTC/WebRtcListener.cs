using System.Net;
using CupriWebRTC.Dtls;
using CupriWebRTC.Ice;
using CupriWebRTC.Sctp;

namespace CupriWebRTC;

/// <summary>
/// A complete managed WebRTC DataChannel endpoint (the server/answerer side), serving <b>many</b> peers on one UDP
/// socket. <see cref="IceUdpEndpoint"/> answers ICE checks and demultiplexes DTLS; each distinct peer address gets its
/// own session — an <see cref="EndpointDatagramTransport"/> bridge, a <see cref="DtlsServer"/> handshake, and an
/// <see cref="SctpAssociation"/> (responder) running its DataChannel — so N browsers run N independent Noise-ready
/// channels over the shared port, keyed by source address. It runs from static, pre-published parameters
/// (<see cref="Parameters"/>) — ICE-lite, fixed credentials, accept-any client cert — so a browser can connect with
/// no signalling server. Not media (no SRTP).
/// </summary>
public sealed class WebRtcListener : IAsyncDisposable
{
    /// <summary>Default cap on concurrent peer sessions — a Ward against a public endpoint being swamped.</summary>
    public const int DefaultMaxSessions = 256;

    private readonly IceUdpEndpoint _ice;
    private readonly DtlsServer _dtls;
    private readonly DtlsCertificate _certificate;
    private readonly int _maxSessions;
    private readonly object _gate = new();
    private readonly Dictionary<IPEndPoint, PeerSession> _sessions = new();
    private bool _disposed;

    public WebRtcListener(IPEndPoint bind, IceCredentials? credentials = null, DtlsCertificate? certificate = null, int maxSessions = DefaultMaxSessions)
    {
        ArgumentNullException.ThrowIfNull(bind);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxSessions, 1);
        _certificate = certificate ?? DtlsCertificate.GenerateSelfSigned();
        _dtls = new DtlsServer(_certificate);
        _maxSessions = maxSessions;
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

    /// <summary>The number of live peer sessions.</summary>
    public int SessionCount { get { lock (_gate) return _sessions.Count; } }

    /// <summary>Raised when any peer opens a data channel, carrying a self-contained <see cref="WebRtcChannel"/>.</summary>
    public event Action<WebRtcChannel>? ChannelOpened;

    /// <summary>Runs the endpoint (ICE receive loop) until cancelled.</summary>
    public Task RunAsync(CancellationToken cancellationToken) => _ice.RunAsync(cancellationToken);

    // Routes an inbound DTLS datagram to its peer's session (by source address), spinning up a new session on first
    // contact. Invoked serially from the single ICE receive loop, so the session map isn't racing itself here.
    private void OnDtlsDatagram(ReadOnlyMemory<byte> data, IPEndPoint remote)
    {
        PeerSession? session;
        lock (_gate)
        {
            if (_disposed)
                return;
            if (!_sessions.TryGetValue(remote, out session))
            {
                if (_sessions.Count >= _maxSessions)
                    return; // at capacity — drop first contact from a new peer (a Ward); existing peers keep serving
                session = new PeerSession(remote, _ice);
                _sessions[remote] = session;
                StartSession(session);
            }
        }
        session.Bridge.Enqueue(data);
    }

    private void StartSession(PeerSession session)
    {
        var thread = new Thread(() =>
        {
            SctpTransport sctp;
            try
            {
                var secured = _dtls.Accept(session.Bridge); // blocks until the DTLS handshake completes (or times out)
                sctp = new SctpTransport(secured, new SctpAssociation());
            }
            catch
            {
                Evict(session); // handshake failed / peer went away — free the slot
                return;
            }

            sctp.ChannelOpened += ch => session.OnChannelOpened(ch, ChannelOpened);
            sctp.MessageReceived += session.OnMessage;
            sctp.Closed += () => Evict(session);
            session.Attach(sctp);
            sctp.Start();
        })
        { IsBackground = true, Name = "cupriwebrtc-session" };
        thread.Start();
    }

    // Removes a session if it's still the current one for its remote (a reconnect may have replaced it), and closes it.
    private void Evict(PeerSession session)
    {
        bool removed;
        lock (_gate)
            removed = _sessions.TryGetValue(session.Remote, out var current)
                      && ReferenceEquals(current, session)
                      && _sessions.Remove(session.Remote);
        if (removed)
            session.Close();
    }

    public async ValueTask DisposeAsync()
    {
        PeerSession[] sessions;
        lock (_gate)
        {
            _disposed = true;
            sessions = [.. _sessions.Values];
            _sessions.Clear();
        }
        foreach (var session in sessions)
            session.Close();
        await _ice.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>One peer's session: its DTLS/SCTP bridge, its association, and the channels open within it.</summary>
    private sealed class PeerSession
    {
        private readonly Dictionary<ushort, WebRtcChannel> _channels = new();
        private SctpTransport? _sctp;
        private int _closed;

        public PeerSession(IPEndPoint remote, IceUdpEndpoint ice)
        {
            Remote = remote;
            Bridge = new EndpointDatagramTransport(ice, remote);
        }

        public IPEndPoint Remote { get; }
        public EndpointDatagramTransport Bridge { get; }

        public void Attach(SctpTransport sctp) => _sctp = sctp;

        public void OnChannelOpened(SctpDataChannel opened, Action<WebRtcChannel>? sink)
        {
            var channel = new WebRtcChannel(Remote, opened.StreamId, opened.Label, opened.Protocol,
                (stream, ppid, data) => _sctp?.SendMessage(stream, ppid, data));
            lock (_channels)
                _channels[opened.StreamId] = channel;
            sink?.Invoke(channel);
        }

        public void OnMessage(ushort streamId, uint ppid, byte[] payload)
        {
            WebRtcChannel? channel;
            lock (_channels)
                _channels.TryGetValue(streamId, out channel);
            channel?.RaiseMessage(ppid, payload);
        }

        public void Close()
        {
            if (Interlocked.Exchange(ref _closed, 1) != 0)
                return; // idempotent — evicted and disposed can both reach here
            WebRtcChannel[] channels;
            lock (_channels)
            {
                channels = [.. _channels.Values];
                _channels.Clear();
            }
            foreach (var channel in channels)
                channel.RaiseClosed();
            _sctp?.Dispose();
            Bridge.Close();
        }
    }
}
