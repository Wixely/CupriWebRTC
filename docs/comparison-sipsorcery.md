# CupriWebRTC vs. SIPSorcery

There is one mature, widely-used managed WebRTC implementation for .NET: **SIPSorcery**. It is a large,
capable library and, for most WebRTC use, it is the right tool. CupriWebRTC exists because CupriNet's
requirement is a narrow, unusual slice of WebRTC that a full-stack library isn't shaped to expose. This
document compares the two on **scope, API fit, footprint, and control** — so the choice is made on merits,
not by default.

**Short version:** use SIPSorcery for general WebRTC (media, the standard offer/answer flow, SIP/VoIP
interop). Use CupriWebRTC when you need a *tiny, fully-owned, DataChannel-only endpoint* driven from
*static, pre-published parameters* with *no signalling server* — which is exactly what CupriNet's
"the signed link is the signalling" model requires.

## 1. Scope

| | SIPSorcery | CupriWebRTC |
|---|---|---|
| Media (audio/video, SRTP) | Yes — a primary focus | No (out of scope by design) |
| SIP / VoIP stack | Yes — the library's origin | No |
| DataChannel (SCTP/DCEP) | Yes | Yes — **the only** focus |
| ICE | Full agent (host/srflx/relay, trickle, roles) | ICE-**lite** responder only |
| DTLS | Yes | Server role only |
| Offer/answer (SDP) engine | Full `RTCPeerConnection` | None — static parameters instead |

SIPSorcery aims to be a complete WebRTC + SIP + VoIP platform. CupriWebRTC deliberately implements **only**
the reliable data path (STUN → ICE-lite → DTLS → SCTP → DataChannel) and nothing else. That's not a
feature gap to apologise for — it's the point. A smaller surface is easier to read, audit, and reason
about when the whole library is a dependency of a security-sensitive P2P stack.

## 2. The mode CupriNet needs

CupriNet's design (see its Intonation-as-signalling notes) requires a node to publish **static** WebRTC
parameters inside its signed link, so a browser can dial it with **no signalling exchange at all**:

- **Fixed, caller-chosen ICE credentials** (ufrag/pwd), published ahead of time.
- **ICE-lite**: the node never gathers candidates or initiates checks — it answers on a known host
  candidate and learns the peer reflexively.
- **A known DTLS certificate fingerprint**, published in the link, so the browser verifies the node.
- **Accept-any client certificate**, because the real peer authentication happens *above* the channel
  (Noise / Consecration), not in the DTLS layer.

This is a legitimate, generic pattern (it's essentially how WHIP-style "static endpoint" servers work),
but it is the *opposite* of the standard interactive `RTCPeerConnection` flow that a full library is built
around. The friction isn't about capability — it's about which knobs are exposed:

- **ICE credentials are internally generated.** SIPSorcery's ICE session produces its own ufrag/pwd; the
  whole API is built to *exchange* them via SDP, not to *accept* a fixed pair you published earlier. Making
  a node answer to pre-published credentials means fighting the grain of the API.
- **No first-class ICE-lite "reachable server" switch.** The ICE agent is designed to be a full peer that
  gathers and negotiates. The "I am a fixed, always-passive endpoint" mode isn't the shape it presents.
- **DTLS fingerprint verification is internal.** Verification is wired to the fingerprint carried in the
  remote SDP. Our model has *no* SDP and wants to accept any client cert (authenticating above the
  channel) while publishing our *own* fingerprint out-of-band — again, cutting across the intended flow.

None of these are defects in SIPSorcery; they're the natural consequences of being a general
`RTCPeerConnection`. But to get CupriNet's mode we would be routing around the high-level API and depending
on internals — which is fragile and hard to keep correct across upstream changes.

## 3. Footprint & dependencies

CupriWebRTC is a few thousand lines across five small layers, with a **single** dependency (BouncyCastle,
for the DTLS handshake — the same crypto CupriNet already carries). No media codecs, no SIP, no native
interop. For a library whose entire job is "let a browser open a data channel to a node," that footprint
is the feature: less to build, less to audit, less to ship, less attack surface.

SIPSorcery necessarily carries the weight of everything it supports — media, SIP, the full ICE agent — even
when a consumer only wants a data channel.

## 4. Control & correctness

Because CupriWebRTC is first-party and small, CupriNet controls every wire decision that matters to it:
the exact ICE-lite acceptance rules, the accept-any-cert policy, the SCTP/DCEP profile, and how the static
parameters are produced and published. The wire layers are validated against RFC test vectors (STUN
RFC 5769; the CRC-32 / CRC-32C check values) and the whole stack is proven end-to-end over real UDP. When
we need to change behaviour for the Intonation model, we change our own code rather than petitioning an
upstream API to expose an internal.

## 5. When to use which

**Use SIPSorcery when you want:**
- Audio/video (media) over WebRTC, or SIP/VoIP interop.
- A standard `RTCPeerConnection` with the normal offer/answer signalling flow.
- A full ICE agent (candidate gathering, trickle, controlling role, TURN relays).
- A mature, broadly-tested, batteries-included library and you don't mind the size.

**Use CupriWebRTC when you want:**
- A **DataChannel only** — no media, no SIP.
- A **static, pre-published endpoint** a browser can dial with **no signalling server** (fixed ICE
  credentials, ICE-lite, known fingerprint).
- To **accept any client certificate** and authenticate the peer above the channel.
- A **tiny, fully-owned, single-dependency** managed library you can read end-to-end and control.

CupriWebRTC is not a replacement for SIPSorcery and doesn't try to be. It's a purpose-built alternative for
one specific job that a general-purpose library isn't shaped to do cleanly.
