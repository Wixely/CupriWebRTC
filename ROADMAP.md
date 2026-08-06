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

## Phase 3 — DTLS 1.2 server (BouncyCastle) ✅ (core) — superseded for browsers by Phase 6
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
  fingerprint, port) to publish, plus a per-channel `ChannelOpened` → `WebRtcChannel` (its own `MessageReceived` /
  `Send` / `Closed`).
- **Multi-client ✅ (0.1.1)** — one UDP socket serves **many** peers: inbound datagrams are demultiplexed to a
  per-peer session (bridge → DTLS → SCTP), bounded by a concurrent-session cap (a Ward). Each peer is an independent
  channel.
- **Session lifecycle hardening ✅ (0.1.2)**:
  - *NAT rebinding* — sessions are keyed by the peer's **ICE ufrag** (unique per peer, in every connectivity check),
    not its address, so when a peer's checks arrive from a new address the session **migrates** (its DTLS/SCTP state is
    untouched — it just flows over the new 5-tuple) instead of being seen as a new peer.
    (`IceLiteResponder` now surfaces the remote ufrag; `EndpointDatagramTransport.UpdateRemote` repoints sends.)
  - *Idle eviction by timer* — a thread-pool sweep evicts sessions with no activity (no ICE consent, no data) past an
    idle timeout; ICE consent checks (~every 5s, RFC 7675) keep a healthy-but-quiet channel alive. Closing an idle
    session also unblocks one still stuck in its DTLS handshake.
  - *One thread per session* — the DTLS handshake and the SCTP receive loop now run on a single session thread
    (`SctpTransport.RunReceiveLoop`) instead of two; the whole set stays bounded by the session cap.
- **Full-stack loopback tests ✅** — a real UDP client drives ICE → DTLS → SCTP against the listener, verifies the
  published fingerprint, opens a DataChannel and delivers a message; a **two-client** test asserts each is demuxed to
  its own peer; a **rebinding** test asserts a same-ufrag check from a new address migrates (one session, not two);
  and an **idle** test asserts a silent session is evicted and its channel closed. 30 pass.

## Phase 6 — DTLS 1.3 + real-browser interop ✅ (0.2.0)
Browser automation against the endpoint found the blocker the previous phase was heading for: **every current browser
enables DTLS 1.3 by default, offers it first, and refuses our 1.2 fallback**, aborting with `decode_error`
(Chromium issue 382915276). BouncyCastle has no DTLS 1.3 *server* role (`// TODO[dtls13]`, still true on 2.7.0) and no
managed .NET one existed, so the fix was to write one. Full detail in **[docs/dtls-1.3.md](docs/dtls-1.3.md)**.

- **Managed DTLS 1.3 server ✅** (`CupriWebRTC.Dtls13`, RFC 9147 over RFC 8446), scoped to the WebRTC profile:
  server role only, no 0-RTT, resumption, PSK, client role or Connection ID.
  - *Record layer* — the unified header, AEAD protection, **record-sequence-number encryption**, epochs, a sliding
    anti-replay window, and ACK records.
  - *Key schedule* — RFC 8446 §7 with RFC 9147 §5.9's `"dtls13"` label prefix; transcript hashing over TLS-style
    messages, Finished, CertificateVerify.
  - *Handshake* — ClientHello → HelloRetryRequest with a **stateless HMAC cookie** → ServerHello →
    {EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify, Finished} → the client's flight → ACK,
    with fragmentation/reassembly, flight retransmission and ACK-driven retirement. Accept-any client certificate,
    as the 1.2 path always did. A minimal KeyUpdate responder.
  - *Primitives behind one seam* (`IDtls13Crypto`) — BouncyCastle today, swappable without touching the protocol.
    Only the raw ChaCha20 block function is implemented locally, because no library exposes a keystream block at a
    caller-chosen counter, which the record-number mask needs.
- **Dual-version dispatch ✅** — `DtlsServer` sniffs the first ClientHello and runs the 1.3 server or the
  BouncyCastle 1.2 one; both return an `ISecureDatagramTransport`, so SCTP and above are version-agnostic. The 1.2
  path is unchanged and still passes its tests. `WebRtcListener.SessionSecured` reports which ran.
- **Certificate fix ✅** — the self-signed certificate encoded P-256 as *explicit* curve parameters instead of the
  named-curve OID. RFC 5480 §2.1.1 forbids that for TLS and BoringSSL rejects it outright — a latent bug no test
  without a real TLS peer could see. Now fixed and pinned.
- **Verification ✅** — RFC 5869 / 8439 / 7748 vectors for the primitives; the **RFC 8448** "Simple 1-RTT Handshake"
  trace reproduced end to end for the key schedule; record-layer round trips, replay and tamper tests; an in-process
  DTLS 1.3 handshake driven by a minimal test client (with and without the cookie exchange); a full-stack UDP test
  (ICE → DTLS 1.3 → SCTP → DCEP); and — the real gate — **real Chromium opens a DataChannel and round-trips a
  message**, with Wireshark showing a clean DTLS 1.3 exchange, no alerts and nothing malformed. 70 tests pass.
- **Diagnostics ✅** — opt-in `CUPRIWEBRTC_PCAP` (libpcap capture of the DTLS flow) and `CUPRIWEBRTC_SSLKEYLOG`
  (NSS key log), which together make the encrypted flight readable in Wireshark.
- **Next:** a **Firefox** and ideally Safari pass (Firefox's WebRTC never reached the endpoint on the development
  machine — an environment problem before DTLS is involved, so it is untested rather than failing); **reference-client
  interop** (pion/dtls or `openssl s_client -dtls1_3`) as a CI gate that needs no GUI browser; then SCTP
  fragmentation/reliability hardening.
- **Before production: an external security review of the DTLS 1.3 code.** Hand-rolling the TLS 1.3 protocol is
  security-critical, and this has had none.

## Explicitly out of scope
- Media (SRTP/audio/video), TURN, trickle ICE, the ICE controlling role, and the full RTCPeerConnection SDP engine.
