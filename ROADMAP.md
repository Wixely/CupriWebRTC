# CupriWebRTC roadmap

A managed WebRTC **DataChannel** endpoint, built bottom-up. Each layer is implemented and tested before the next
stacks on it. The target first milestone: **a browser opens a DataChannel to a CupriWebRTC endpoint and exchanges
messages**, with the endpoint driven from static, pre-published parameters (no live signalling).

## Phase 0 — Scaffolding ✅
- Repo, MIT licence, Wixely identity, solution + projects, this roadmap.

## Phase 1 — STUN codec ✅
- Message encode/decode; MESSAGE-INTEGRITY (HMAC-SHA1) add + verify; FINGERPRINT (CRC-32) add + verify;
  XOR-MAPPED-ADDRESS (IPv4/IPv6). Self-consistent round-trip tests.
- **TODO:** add the official **RFC 5769** sample-vector tests for cross-implementation certainty.

## Phase 2 — ICE-lite responder
- Bind a UDP socket; parse incoming STUN **Binding Requests**; verify USERNAME (`ourUfrag:theirUfrag`) +
  MESSAGE-INTEGRITY with our password; reply with a **Binding Success** carrying XOR-MAPPED-ADDRESS + our
  MESSAGE-INTEGRITY + FINGERPRINT. Learn the peer's address peer-reflexively; demultiplex STUN vs. DTLS on the port.
- Fixed, caller-supplied **ufrag/password** (so they can be published ahead of time). No trickle, no gathering.

## Phase 3 — DTLS server (BouncyCastle)
- DTLS server handshake over the ICE-selected UDP flow, using a self-signed cert; expose its **fingerprint**
  (sha-256). Pluggable client-certificate policy (default: accept any — the caller authenticates above the channel).

## Phase 4 — SCTP + DataChannel
- Minimal **SCTP** association over DTLS (the hard part: INIT/COOKIE handshake, DATA/SACK, ordered reliable delivery),
  then **DCEP** (DATA_CHANNEL_OPEN/ACK) to establish a channel. Surface it as a message duplex.

## Phase 5 — Top-level API + browser interop
- `WebRtcListener` tying the layers together, emitting opened DataChannels. Validate end to end against a real
  Chromium (browser automation), including the static-parameter / ICE-lite / accept-any-cert mode.

## Explicitly out of scope
- Media (SRTP/audio/video), TURN, trickle ICE, the ICE controlling role, and the full RTCPeerConnection SDP engine.
