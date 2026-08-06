using System.Net;
using System.Text;
using CupriWebRTC;
using CupriWebRTC.Ice;
using CupriWebRTC.Sctp;

// A CupriWebRTC endpoint on loopback that a real browser can dial with NO signalling server: it prints its published
// static parameters, and the accompanying probe.html synthesises an SDP answer from them, opens a DataChannel, and
// sends a message. The host echoes every message back — so a round-trip proves ICE → DTLS → SCTP → DataChannel interop
// against the browser's real WebRTC stack (the SCTP layer being the riskiest).

var port = args.Length > 0 && int.TryParse(args[0], out var p) ? p : 45820;

var credentials = IceCredentials.Generate();
await using var listener = new WebRtcListener(new IPEndPoint(IPAddress.Loopback, port), credentials);

listener.SessionFaulted += (remote, ex) =>
    Console.WriteLine($"SESSION_FAULTED from={remote}: {ex.GetType().Name}: {ex.Message}\n{ex}");

listener.ChannelOpened += channel =>
{
    Console.WriteLine($"CHANNEL_OPENED label='{channel.Label}' stream={channel.StreamId} from={channel.Remote}");
    channel.MessageReceived += (ppid, data) =>
    {
        var text = Encoding.UTF8.GetString(data);
        Console.WriteLine($"RECEIVED (ppid={ppid}): {text}");
        var reply = Encoding.UTF8.GetBytes("echo:" + text);
        channel.Send(Dcep.PpidString, reply);
        Console.WriteLine($"ECHOED: echo:{text}");
    };
    channel.Closed += () => Console.WriteLine("CHANNEL_CLOSED");
};

var pr = listener.Parameters;
var hex = Convert.ToHexString(pr.Fingerprint); // "AABBCC…" (uppercase, no separators)
var fpColonHex = string.Join(":", Enumerable.Range(0, hex.Length / 2).Select(i => hex.Substring(i * 2, 2)));

Console.WriteLine("=== CupriWebRTC browser-interop probe ===");
Console.WriteLine($"PROBE ufrag={pr.IceUfrag} pwd={pr.IcePassword} fpalg={pr.FingerprintAlgorithm} fp={fpColonHex} port={pr.Port}");
Console.WriteLine("Open probe.html with these as the URL fragment, e.g.:");
Console.WriteLine($"  probe.html#ufrag={pr.IceUfrag}&pwd={pr.IcePassword}&fp={fpColonHex}&port={pr.Port}&ip=127.0.0.1");
Console.WriteLine("Listening. Ctrl+C to stop (auto-exits after 10 min).");

using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(10));
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
try { await listener.RunAsync(cts.Token); }
catch (OperationCanceledException) { }
Console.WriteLine("Probe stopped.");
