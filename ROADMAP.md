# CupriWebRTC roadmap

A managed WebRTC **DataChannel** endpoint, built bottom-up. Each layer is implemented and tested before the next
stacks on it. The target first milestone: **a browser opens a DataChannel to a CupriWebRTC endpoint and exchanges
messages**, with the endpoint driven from static, pre-published parameters (no live signalling).

## Phase 0 — Scaffolding ✅
- Repo, MIT licence, Wixely identity, solution + projects, this roadmap.

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

## Phase 4 — SCTP + DataChannel
- Minimal **SCTP** association over DTLS (the hard part: INIT/COOKIE handshake, DATA/SACK, ordered reliable delivery),
  then **DCEP** (DATA_CHANNEL_OPEN/ACK) to establish a channel. Surface it as a message duplex.

## Phase 5 — Top-level API + browser interop
- `WebRtcListener` tying the layers together, emitting opened DataChannels. Validate end to end against a real
  Chromium (browser automation), including the static-parameter / ICE-lite / accept-any-cert mode.

## Explicitly out of scope
- Media (SRTP/audio/video), TURN, trickle ICE, the ICE controlling role, and the full RTCPeerConnection SDP engine.
