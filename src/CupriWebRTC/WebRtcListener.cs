using System.Net;
using CupriWebRTC.Dtls;
using CupriWebRTC.Dtls13;
using CupriWebRTC.Ice;
using CupriWebRTC.Sctp;

namespace CupriWebRTC;

/// <summary>
/// A complete managed WebRTC DataChannel endpoint (the server/answerer side), serving <b>many</b> peers on one UDP
/// socket. <see cref="IceUdpEndpoint"/> answers ICE checks and demultiplexes DTLS; each distinct peer gets its own
/// session — an <see cref="EndpointDatagramTransport"/> bridge, a <see cref="DtlsServer"/> handshake, and an
/// <see cref="SctpAssociation"/> (responder) running its DataChannel — so N browsers run N independent Noise-ready
/// channels over the shared port. Sessions are keyed by the peer's <b>ICE ufrag</b> (unique per peer, carried in every
/// connectivity check), which lets a session survive a <b>NAT rebinding</b>: when the same peer's checks arrive from a
/// new address, the session migrates rather than being treated as a new peer. Idle sessions are evicted on a timer, and
/// the whole set is bounded by a concurrent-session cap. It runs from static, pre-published parameters
/// (<see cref="Parameters"/>) — ICE-lite, fixed credentials, accept-any client cert — so a browser can connect with no
/// signalling server. Not media (no SRTP).
/// </summary>
public sealed class WebRtcListener : IAsyncDisposable
{
    /// <summary>Default cap on concurrent peer sessions — a Ward against a public endpoint being swamped.</summary>
    public const int DefaultMaxSessions = 256;

    /// <summary>Default idle timeout: a live browser sends ICE consent checks every ~5s (RFC 7675), so this evicts a
    /// peer that has gone silent (no checks and no data) without cutting off a healthy-but-quiet channel.</summary>
    public static readonly TimeSpan DefaultIdleTimeout = TimeSpan.FromSeconds(30);

    private readonly IceUdpEndpoint _ice;
    private readonly DtlsServer _dtls;
    private readonly DtlsCertificate _certificate;
    private readonly int _maxSessions;
    private readonly long _idleTimeoutMs;
    private readonly object _gate = new();
    private readonly Dictionary<string, PeerSession> _byUfrag = new();     // the peer's ICE ufrag → its session
    private readonly Dictionary<IPEndPoint, PeerSession> _byAddress = new(); // current source address → its session
    private readonly Timer _idleTimer;
    private bool _disposed;

    public WebRtcListener(
        IPEndPoint bind,
        IceCredentials? credentials = null,
        DtlsCertificate? certificate = null,
        int maxSessions = DefaultMaxSessions,
        TimeSpan? sessionIdleTimeout = null,
        Dtls13ServerOptions? dtls13Options = null)
    {
        ArgumentNullException.ThrowIfNull(bind);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxSessions, 1);
        var idle = sessionIdleTimeout ?? DefaultIdleTimeout;
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(idle, TimeSpan.Zero);

        _certificate = certificate ?? DtlsCertificate.GenerateSelfSigned();
        _dtls = new DtlsServer(_certificate, dtls13Options);
        _maxSessions = maxSessions;
        _idleTimeoutMs = (long)idle.TotalMilliseconds;
        _ice = new IceUdpEndpoint(credentials ?? IceCredentials.Generate(), bind);
        _ice.ConnectivityCheck += OnConnectivityCheck;
        _ice.DtlsDatagramReceived += OnDtlsDatagram;

        var sweep = TimeSpan.FromMilliseconds(Math.Max(250, _idleTimeoutMs / 2));
        _idleTimer = new Timer(_ => SweepIdle(), null, sweep, sweep);
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
    public int SessionCount { get { lock (_gate) return _byUfrag.Count; } }

    /// <summary>Raised when any peer opens a data channel, carrying a self-contained <see cref="WebRtcChannel"/>.</summary>
    public event Action<WebRtcChannel>? ChannelOpened;

    /// <summary>Raised when a peer's session fails to establish (e.g. the DTLS handshake), with the peer address and
    /// the cause — for observability/diagnostics. The session is evicted regardless.</summary>
    public event Action<IPEndPoint, Exception>? SessionFaulted;

    /// <summary>Raised when a peer's DTLS handshake completes, with the peer address and the negotiated version
    /// (<c>"DTLS 1.3"</c> for browsers, <c>"DTLS 1.2"</c> for the BouncyCastle fallback) — the counterpart to
    /// <see cref="SessionFaulted"/>, and the quickest way to see which path a peer actually took.</summary>
    public event Action<IPEndPoint, string>? SessionSecured;

    /// <summary>Runs the endpoint (ICE receive loop) until cancelled.</summary>
    public Task RunAsync(CancellationToken cancellationToken) => _ice.RunAsync(cancellationToken);

    // A STUN connectivity check identifies its peer by ufrag. First check for a ufrag creates the session (and starts
    // its DTLS handshake, which blocks until the peer's ClientHello arrives); a later check from a new address for a
    // known ufrag is a NAT rebinding — migrate the session's address. Invoked serially from the one ICE receive loop.
    private void OnConnectivityCheck(string ufrag, IPEndPoint remote)
    {
        PeerSession? started = null;
        lock (_gate)
        {
            if (_disposed)
                return;
            if (_byUfrag.TryGetValue(ufrag, out var session))
            {
                if (!session.Remote.Equals(remote)) // NAT rebinding: same peer, new address
                {
                    _byAddress.Remove(session.Remote);
                    session.Migrate(remote);
                    _byAddress[remote] = session;
                }
                session.Touch();
                return;
            }
            if (_byUfrag.Count >= _maxSessions)
                return; // at capacity — a Ward; existing peers keep serving
            session = new PeerSession(ufrag, remote, _ice);
            _byUfrag[ufrag] = session;
            _byAddress[remote] = session;
            session.Touch();
            started = session;
        }
        if (started is not null)
            StartSession(started);
    }

    // Route an inbound DTLS datagram to its peer's session by source address (the session was created on the ICE check
    // that preceded DTLS). A datagram from an unmapped address is dropped.
    private void OnDtlsDatagram(ReadOnlyMemory<byte> data, IPEndPoint remote)
    {
        PeerSession? session;
        lock (_gate)
        {
            if (_disposed)
                return;
            _byAddress.TryGetValue(remote, out session);
        }
        if (session is null)
            return;
        session.Touch();
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
                SessionSecured?.Invoke(session.Remote, secured.ProtocolVersion);
                sctp = new SctpTransport(secured, new SctpAssociation());
            }
            catch (Exception ex)
            {
                SessionFaulted?.Invoke(session.Remote, ex); // handshake failed / peer went away
                Evict(session); // free the slot
                return;
            }

            sctp.ChannelOpened += ch => session.OnChannelOpened(ch, ChannelOpened);
            sctp.MessageReceived += session.OnMessage;
            session.Attach(sctp);
            try
            {
                sctp.RunReceiveLoop(); // one thread owns the whole session: handshake above, then the SCTP loop here
            }
            finally
            {
                Evict(session);
            }
        })
        { IsBackground = true, Name = "cupriwebrtc-session" };
        thread.Start();
    }

    // Removes a session from both maps if it's still the current one for its ufrag (a rebinding only moved its
    // address; a full reconnect would have a fresh ufrag), then closes it. Idempotent.
    private void Evict(PeerSession session)
    {
        bool removed;
        lock (_gate)
        {
            removed = _byUfrag.TryGetValue(session.Ufrag, out var current) && ReferenceEquals(current, session);
            if (removed)
                RemoveLocked(session);
        }
        if (removed)
            session.Close();
    }

    private void SweepIdle()
    {
        var now = Environment.TickCount64;
        List<PeerSession>? idle = null;
        lock (_gate)
        {
            foreach (var session in _byUfrag.Values)
                if (now - session.LastActivity > _idleTimeoutMs)
                    (idle ??= []).Add(session);
            if (idle is not null)
                foreach (var session in idle)
                    RemoveLocked(session);
        }
        if (idle is not null)
            foreach (var session in idle)
                session.Close(); // closing the bridge also unblocks a session still stuck in its DTLS handshake
    }

    // Caller holds _gate. Removes the session's ufrag key and its address entry (if still pointing at it).
    private void RemoveLocked(PeerSession session)
    {
        _byUfrag.Remove(session.Ufrag);
        if (_byAddress.TryGetValue(session.Remote, out var atAddress) && ReferenceEquals(atAddress, session))
            _byAddress.Remove(session.Remote);
    }

    public async ValueTask DisposeAsync()
    {
        await _idleTimer.DisposeAsync().ConfigureAwait(false);
        PeerSession[] sessions;
        lock (_gate)
        {
            _disposed = true;
            sessions = [.. _byUfrag.Values];
            _byUfrag.Clear();
            _byAddress.Clear();
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
        private long _lastActivity;

        public PeerSession(string ufrag, IPEndPoint remote, IceUdpEndpoint ice)
        {
            Ufrag = ufrag;
            Remote = remote;
            Bridge = new EndpointDatagramTransport(ice, remote);
            _lastActivity = Environment.TickCount64;
        }

        public string Ufrag { get; }
        public IPEndPoint Remote { get; private set; } // mutated only under the listener's _gate
        public EndpointDatagramTransport Bridge { get; }
        public long LastActivity => Volatile.Read(ref _lastActivity);

        public void Touch() => Volatile.Write(ref _lastActivity, Environment.TickCount64);

        public void Migrate(IPEndPoint remote)
        {
            Remote = remote;
            Bridge.UpdateRemote(remote); // DTLS/SCTP state is unchanged — it just flows over the new 5-tuple now
        }

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
                return; // idempotent — eviction, the idle sweep, and disposal can all reach here
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
