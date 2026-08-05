# CupriWebRTC

**A minimal, generic, 100% managed WebRTC data-channel library for C#/.NET.**

CupriWebRTC lets a .NET process be the *other end* of a browser's WebRTC connection: it implements just enough of the
WebRTC stack — **ICE, DTLS, and SCTP** — to accept a browser's **DataChannel** and exchange messages over it. It does
**not** do media (no SRTP/audio/video): its scope is the reliable, ordered **data** path.

> **Status: the full stack is implemented and proven end-to-end.** Every wire layer is validated (STUN against the
> RFC 5769 vector; CRC-32/CRC-32C against their standard check values), and a full-stack loopback test drives
> **ICE → DTLS → SCTP** against the listener over real UDP and delivers a message. Remaining: validation against a
> real browser, and reliability hardening (see [ROADMAP.md](ROADMAP.md)).

## Why it exists

It was written for [CupriNet](https://github.com/Wixely/CupriNet), which needs a node to accept browser WebRTC clients
in a specific, **non-standard mode**: a **static, pre-published endpoint** — fixed ICE credentials, **ICE-lite**, and a
known certificate fingerprint — that a browser can dial with **no signalling server**, accepting **any client
certificate** because the peer is authenticated *above* the channel. General-purpose managed WebRTC stacks are large,
built around the standard offer/answer flow, and don't cleanly support this static / blind-accept mode. CupriWebRTC is
a small, fully-controlled, purpose-built alternative that does exactly this — and is a **generic library** any .NET app
can use. See [docs/comparison-sipsorcery.md](docs/comparison-sipsorcery.md) for how it compares to the main managed
WebRTC library. CupriNet consumes it through a thin binding, the same way it consumes CupriTor.

## Scope

**In scope** (the data path a browser needs):

- **STUN** (RFC 5389/8489) — MESSAGE-INTEGRITY (HMAC-SHA1), FINGERPRINT (CRC-32), XOR-MAPPED-ADDRESS.
- **ICE-lite responder** — bind a UDP port, answer connectivity checks, learn the remote peer-reflexively. No
  candidate gathering, no trickle, no controlling role — the "reachable server" side of ICE.
- **DTLS** (server role) over the ICE flow (BouncyCastle). Publishes a certificate fingerprint; accepts any client
  cert by default (the caller re-authenticates above the channel).
- **SCTP** association + the **DataChannel Establishment Protocol (DCEP)** — the reliable, ordered message duplex a
  browser's `RTCDataChannel` talks to. Both the passive (responder) and active (initiator) roles.
- A top-level **`WebRtcListener`** that assembles the stack on one socket and serves **many** peers at once —
  inbound datagrams are demultiplexed to a per-peer session (keyed by the peer's ICE ufrag, so a session **survives a
  NAT rebinding** by migrating to the new address), each browser is its own `WebRtcChannel` (with its own messages),
  idle sessions are evicted on a timer, and the whole set is bounded by a concurrent-session cap. Plus the static
  **`WebRtcEndpointParameters`** to publish.

**Out of scope:** SRTP / media, the full `RTCPeerConnection` offer/answer machinery, TURN relaying, and trickle ICE. A
design goal is that the endpoint runs from **pre-published static parameters** (fixed ICE ufrag/pwd, known fingerprint,
ICE-lite) so it needs **no live signalling** — which is what CupriNet's "the signed link is the signalling" model
wants, and is a legitimate generic mode (cf. WHIP-style static endpoints).

## Usage (sketch)

```csharp
await using var listener = new WebRtcListener(new IPEndPoint(IPAddress.Any, 0));
_ = listener.RunAsync(cancellationToken);

// Publish these so a browser can dial the endpoint with no signalling server.
WebRtcEndpointParameters p = listener.Parameters; // ufrag, password, fingerprint, port

// One event per opened DataChannel — each WebRtcChannel is scoped to the peer that opened it, so many
// browsers on the one socket never cross-talk.
listener.ChannelOpened += channel =>
{
    Console.WriteLine($"channel opened by {channel.Remote}: {channel.Label}");
    channel.MessageReceived += (ppid, data) => { /* handle inbound message from this peer */ };
    channel.Closed += () => { /* peer went away */ };
    // channel.Send(Dcep.PpidBinary, bytes);
};
```

## Design notes

- **Managed + minimal.** BCL where possible; **BouncyCastle** for the DTLS handshake — the same crypto CupriNet
  already uses. No native interop.
- **Correctness to spec.** Wire layers are validated against RFC test vectors where they exist (STUN RFC 5769; the
  CRC-32 and CRC-32C standard check values), and the whole stack is proven end-to-end over real UDP.
- **Small surface.** Each layer (STUN → ICE → DTLS → SCTP → DataChannel) is independently testable.
- **Minimal SCTP profile (first cut):** in-order single-chunk messages, cumulative SACK, no congestion control or
  fragmentation yet — enough for DCEP and small messages over the low-loss DTLS channel; hardened later.

## Layout

```
CupriWebRTC/
  src/CupriWebRTC/
    Stun/            # STUN codec
    Ice/             # ICE-lite responder + UDP endpoint
    Dtls/            # DTLS server (BouncyCastle) + self-signed cert/fingerprint
    Sctp/            # SCTP packet/chunks, association (both roles), DCEP, transport driver
    WebRtcListener.cs, WebRtcEndpointParameters.cs   # the assembled endpoint
  tests/CupriWebRTC.Tests/    # xUnit tests, incl. the full-stack UDP loopback
  docs/comparison-sipsorcery.md
```

## Building

```
dotnet test CupriWebRTC.slnx
```

Targets .NET 10. The only dependency is BouncyCastle (for the DTLS handshake).

## License

See [LICENSE](LICENSE).
