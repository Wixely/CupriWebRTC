# CupriWebRTC roadmap

A managed WebRTC **DataChannel** endpoint, built bottom-up. Each layer is implemented and tested before the next
stacks on it. The target first milestone: **a browser opens a DataChannel to a CupriWebRTC endpoint and exchanges
messages**, with the endpoint driven from static, pre-published parameters (no live signalling).

## Phase 0 — Scaffolding ✅
- Repo, Wixely identity, solution + projects, this roadmap.

## Phase 1 — STUN codec ✅
- Message encode/decode; MESSAGE-INTEGRITY (HMAC-SHA1) add + verify; FINGERPRINT (CRC-32) add + verify;
  XOR-MAPPED-ADDRESS (IPv4/IPv6). Validated against the official **RFC 5769** sample vector (our code verifies the
  RFC's real integrity + fingerprint) plus self-consistent round-trip tests.

## Phase 2 — ICE-lite responder
- **Responder logic ✅** — `IceLiteResponder`: verifies an incoming Binding Request's USERNAME (`ourUfrag:theirUfrag`)
  + MESSAGE-INTEGRITY (our password) + FINGERPRINT, and produces a Binding Success carrying the peer's reflexive
  XOR-MAPPED-ADDRESS. Fixed, caller-supplied `IceCredentials` (publishable ahead of time). No trickle, no gathering,
  never initiates checks. Pure logic, unit-tested.
- **Next:** the UDP socket loop that binds the port, demultiplexes STUN vs. DTLS, drives the responder, and tracks the
  selected peer address — lands with the DTLS layer (they share the socket).

## Phase 3 — DTLS server (BouncyCastle) ✅ (core)
- `DtlsCertificate`: self-signed ECDSA P-256 cert + sha-256 fingerprint (raw + SDP `AB:CD:…`).
- `CupriTlsServer` / `DtlsServer`: DTLS 1.2 server (ECDHE-ECDSA AES-GCM) that **accepts any client certificate**
  (identity is authenticated above the channel). **Proven:** a full handshake completes against a BouncyCastle DTLS
  client over an in-memory transport, and application data flows both ways.
- **Next:** bridge the BouncyCastle `DatagramTransport` to the ICE UDP flow (they share the port) — lands with the
  top-level listener.

## Phase 4 — SCTP + DataChannel ✅ (core)
- **Wire codec** — `SctpPacket` (common header + CRC-32C checksum, RFC 3309, validated against the standard check
  value) and `SctpChunk` (generic TLV with 4-byte padding).
- **Chunk bodies** — INIT/INIT-ACK (with State Cookie parameter), DATA, SACK, plus DCEP (RFC 8832) open/ack + the
  WebRTC data PPIDs.
- **Association** (`SctpAssociation`) — the four-way handshake with a **stateless HMAC state cookie**, ordered DATA
  delivery + cumulative SACK, DCEP channel open→ack, and message send. Both the **passive (responder)** and
  **active (initiator)** roles. Pure "packet in → packets out + events" model.
- **Driver** (`SctpTransport`) — runs an association over a datagram transport (the DTLS channel), serialising the
  state machine and pumping a background receive loop.
- Tests: CRC-32C vs the standard check value; chunk/packet round-trips; the full responder flow (handshake → DCEP →
  data both ways) driven with crafted packets; a two-association loopback; and two drivers exchanging a message over
  an in-memory datagram pair.
- *Minimal profile (deferred): fragmentation/reassembly, gap-ack/selective retransmit, and congestion control —
  enough for DCEP + small messages over the low-loss DTLS channel; hardened later.*

## Phase 5 — Top-level API ✅ / browser interop (next)
- **`WebRtcListener` ✅** — assembles the whole stack on one UDP socket: ICE answers checks + demuxes DTLS, an
  `EndpointDatagramTransport` bridges DTLS to the socket, `DtlsServer` secures it, and `SctpAssociation` (responder)
  runs the DataChannel over the secured transport. Exposes the static `WebRtcEndpointParameters` (ufrag/pwd,
  fingerprint, port) to publish, plus `ChannelOpened` / `MessageReceived` / `SendMessage`.
- **Full-stack loopback test ✅** — a real UDP client drives ICE → DTLS → SCTP against the listener, verifies the
  published fingerprint matches the served cert, and delivers a message. Everything a browser does, minus the browser.
- **Next:** validate against a **real Chromium** (browser automation) — the static-parameter / ICE-lite /
  accept-any-cert mode against the actual browser WebRTC stack; then the CupriNet binding + fragmentation/reliability
  hardening.

## Explicitly out of scope
- Media (SRTP/audio/video), TURN, trickle ICE, the ICE controlling role, and the full RTCPeerConnection SDP engine.
