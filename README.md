# CupriWebRTC

**A minimal, generic, 100% managed WebRTC data-channel library for C#/.NET — MIT-licensed.**

CupriWebRTC lets a .NET process be the *other end* of a browser's WebRTC connection: it implements just enough of the
WebRTC stack — **ICE, DTLS, and SCTP** — to accept a browser's **DataChannel** and exchange messages over it. It does
**not** do media (no SRTP/audio/video): its scope is the reliable, ordered **data** path.

> **Status: early scaffolding.** The STUN layer is implemented and tested; ICE-lite, DTLS, and SCTP are next. See
> [ROADMAP.md](ROADMAP.md).

## Why it exists

It was written for [CupriNet](https://github.com/Wixely/CupriNet) — which needs a node to accept browser WebRTC
clients while staying **100% managed and permissively licensed**. The obvious managed option (SIPSorcery) carries a
non-standard field-of-use licence restriction that is incompatible with a clean MIT dependency graph, and there is no
other well-known *truly-permissive, pure-managed* C# WebRTC stack. So CupriWebRTC is a first-party, MIT alternative.

It is deliberately built as a **generic library**, not a CupriNet component: any .NET app that needs a managed WebRTC
DataChannel endpoint can use it. CupriNet consumes it through a thin binding, the same way it consumes CupriTor.

## Scope

**In scope** (the data path a browser needs):

- **STUN** (RFC 5389/8489) message codec — MESSAGE-INTEGRITY (HMAC-SHA1), FINGERPRINT (CRC-32), XOR-MAPPED-ADDRESS.
- **ICE-lite responder** — bind a UDP port, answer connectivity checks, learn the remote peer-reflexively. No
  candidate gathering, no trickle, no controlling role — the "reachable server" side of ICE.
- **DTLS** (server role) over the ICE flow, via **BouncyCastle** (managed). Publishes a certificate fingerprint;
  callers decide whether to verify the client's (CupriNet does not — it re-authenticates above the channel).
- **SCTP** association over DTLS + the **DataChannel Establishment Protocol (DCEP)** — the reliable, ordered message
  duplex a browser's `RTCDataChannel` talks to.
- A small top-level API that emits opened DataChannels as a `SendAsync(bytes)` / `ReceiveAsync() -> bytes?` duplex.

**Out of scope:** SRTP / media, the full `RTCPeerConnection` offer/answer machinery, TURN relaying, trickle ICE, and
the ICE *controlling* (full) agent role. A design goal is that the endpoint can be driven from **pre-published static
parameters** (fixed ICE ufrag/pwd, known fingerprint, ICE-lite) so it needs no live signalling — which is exactly what
CupriNet's "the signed link is the signalling" model wants, and is a legitimate generic mode (cf. WHIP-style static
endpoints).

## Design notes

- **Managed + permissive only.** BCL where possible; **BouncyCastle** (MIT-X) for DTLS crypto — the same choice
  CupriNet already makes. No native interop, no restrictive licences.
- **Correctness to spec.** Wire layers are validated against RFC test vectors where they exist, then against a real
  browser end to end.
- **Small surface.** Each layer (STUN → ICE → DTLS → SCTP → DataChannel) is independently testable.

## Layout

```
CupriWebRTC/
  src/CupriWebRTC/            # the library
    Stun/                     # STUN codec (done)
    Ice/                      # ICE-lite responder (next)
    Dtls/                     # DTLS server over UDP (BouncyCastle) (next)
    Sctp/                     # SCTP association + DCEP DataChannel (next)
  tests/CupriWebRTC.Tests/    # xUnit tests
```

## License

MIT — see [LICENSE](LICENSE).
