# DTLS 1.3 in CupriWebRTC

CupriWebRTC contains a **managed DTLS 1.3 server** (RFC 9147), written because browsers left us no alternative. This
is the map of what it is, where it lives, how it is verified, and how to debug it.

## Why it exists

Chrome/Edge (BoringSSL), Firefox (NSS) and Safari now **enable DTLS 1.3 by default and offer it first** — Chromium
issue 382915276. A DTLS-1.2-only server does not get a graceful downgrade: the browser ignores the 1.2 ServerHello,
retransmits its ClientHello, and eventually aborts with a `decode_error` alert. BouncyCastle has no DTLS 1.3 **server**
role — the path is commented out behind `// TODO[dtls13]`, still true on 2.7.0 — and no other mature 100%-managed
.NET implementation exists. So the browser data path was blocked upstream, and the only fix was to write the server.

The scope is deliberately the WebRTC profile and nothing else: **server role only**, no 0-RTT, no resumption or PSK,
no client role, no Connection ID, no post-handshake client auth. Every feature not implemented is attack surface not
present.

## Layout

```
src/CupriWebRTC/Dtls13/
  Crypto/
    IDtls13Crypto.cs              # the primitives seam: AEAD, hash/HMAC, running transcript, ECDHE, signer
    BouncyCastleDtls13Crypto.cs   # the default implementation — pure managed, no native interop
    ChaCha20Block.cs              # the one primitive implemented here, and why (see below)
  Dtls13Constants.cs              # content/handshake/extension/alert/version/epoch code points
  Dtls13CipherSuite.cs            # the three TLS 1.3 suites and their derived lengths
  Dtls13Codec.cs                  # bounds-checked reader / length-prefix-backfilling writer
  Dtls13KeySchedule.cs            # RFC 8446 §7 with RFC 9147 §5.9's "dtls13" label prefix
  Dtls13RecordLayer.cs            # unified header, AEAD, record-number encryption, epochs, anti-replay
  Dtls13HandshakeMessages.cs      # ClientHello parsing; the server's message builders
  Dtls13HandshakeFraming.cs       # fragmentation, reassembly, flight/ACK bookkeeping
  Dtls13ServerConnection.cs       # the state machine, and the secured transport it becomes
  Dtls13ServerOptions.cs          # the policy object (the 1.3 counterpart of CupriTlsServer)
  Dtls13CertificateSigner.cs      # CertificateVerify signing from the endpoint's DTLS certificate
  Dtls13KeyLog.cs                 # opt-in NSS key log, for Wireshark
src/CupriWebRTC/Dtls/
  ISecureDatagramTransport.cs     # what a completed handshake hands to SCTP, either version
  DtlsServer.cs                   # dual-version dispatch (1.3 vs BouncyCastle 1.2)
  Dtls13Peek.cs                   # the ClientHello sniffer + a pushback transport
  DtlsPcapTap.cs                  # opt-in libpcap capture of the DTLS flow
```

## Where the crypto comes from

The protocol never touches a crypto library directly; it asks an `IDtls13Crypto`. The shipped implementation is
**BouncyCastle** throughout — AES-GCM, ChaCha20-Poly1305, SHA-256/384, HMAC, X25519 and P-256 ECDHE, ECDSA/Ed25519
signing — which keeps the stack 100% managed with no OS or native interop. Swapping in the BCL's `AesGcm`/`HKDF`
(OS-backed, faster) or a curve library is another implementation of that one interface.

> The original spec suggested sourcing x25519 and Ed25519 from **CupriCurve**. CupriCurve 0.2.0 ships Ed25519 only —
> it has no X25519 — so ECDHE comes from BouncyCastle for now. The seam is where that swap would happen if CupriCurve
> grows X25519.

**One primitive is implemented here rather than sourced:** the raw ChaCha20 block function
(`Crypto/ChaCha20Block.cs`). DTLS 1.3's record-number mask for the ChaCha20 suite is `ChaCha20(sn_key, counter, nonce)`
at a counter taken from the ciphertext, and neither BouncyCastle nor the BCL exposes a keystream block at a
caller-chosen counter — their stream ciphers only start at zero and step forward. ChaCha20's core is a fixed public
permutation of add/xor/rotate with no secret-dependent branch or table lookup, so it is constant-time by construction,
and RFC 8439 §2.3.2 pins it with a byte-exact vector in the tests.

## How it hangs off the existing stack

`DtlsServer.Accept` is unchanged in shape but now **dispatches on version**. It reads the peer's first datagram,
sniffs it for a ClientHello offering DTLS 1.3 (`Dtls13Peek`), hands the datagram back through a
`PushbackDatagramTransport` so the chosen server sees an untouched flow, and runs either the managed 1.3 server or the
BouncyCastle 1.2 one. Both return an `ISecureDatagramTransport`, so `SctpTransport` — and everything above it — cannot
tell which ran. `WebRtcListener.SessionSecured` reports the version per peer.

The DTLS 1.2 path is kept, untouched, for 1.2-only peers.

## Protocol notes worth knowing

Three details cause most DTLS 1.3 implementation bugs, and each is commented where it lives:

- **The AEAD's additional data is the unified header carrying the _unmasked_ sequence number.** It cannot be
  otherwise: the mask that hides the sequence number is derived from the record's own ciphertext, which depends on the
  additional data.
- **The AEAD nonce is built from the 64-bit sequence number alone — the epoch is excluded**, a deliberate change from
  DTLS 1.2 (RFC 9147 §4, erratum 8141).
- **The HKDF label prefix is `"dtls13"`, not `"tls13 "`** (RFC 9147 §5.9) — no trailing space, so the label still fits
  one hash block. The key schedule takes the prefix as a parameter purely so the tests can reproduce the RFC 8448
  traces, which are TLS.

Also: DTLS 1.3 has no middlebox compatibility mode, so the server must **not** echo `legacy_session_id` and must never
send ChangeCipherSpec; the transcript hashes TLS-style handshake messages, without DTLS's `message_seq`/fragment
fields; and a HelloRetryRequest replaces ClientHello1 in the transcript with a synthetic `message_hash` message.

## Verification

Bottom-up, all in `tests/CupriWebRTC.Tests/`:

| Layer | How it is pinned |
|---|---|
| HKDF | RFC 5869 test cases 1–3 |
| ChaCha20 block, ChaCha20-Poly1305 | RFC 8439 §2.3.2 and §2.8.2 |
| AES-GCM | NIST GCM vector |
| X25519 | RFC 7748 §6.1 (Alice/Bob), plus small-order rejection |
| Key schedule, transcript, Finished | **RFC 8448** "Simple 1-RTT Handshake" reproduced end to end — every secret, key and IV |
| Record layer | Round trips for all three suites, header bits, masked sequence numbers, multi-record datagrams, tamper rejection, replay window, sequence reconstruction |
| Handshake | A minimal DTLS 1.3 client (`TestDtls13Client`) completes the handshake with and without the cookie exchange, with and without a client certificate, and round-trips data |
| Full stack | A real UDP peer does ICE → DTLS 1.3 → SCTP → DCEP against a live `WebRtcListener` |
| Certificate | The public key must name its curve by OID — see below |
| Regression | The DTLS 1.2 path and all pre-existing tests stay green |

**The real gate is the browser**, and it is the only thing that catches what none of the above can. See
`probe/CupriWebRTC.BrowserProbe/`:

```
dotnet run --project probe/CupriWebRTC.BrowserProbe
# then open the printed probe.html#… fragment in a real browser
```

`PROBE:SUCCESS` on the page, plus `SESSION_SECURED … version=DTLS 1.3`, `CHANNEL_OPENED` and `RECEIVED` in the host
log, is the pass. Changing only the URL fragment does not reload the page — navigate to `about:blank` first.

### The bug only a browser could find

The first browser run failed with `decode_error` **after** Chrome had accepted our ServerHello and derived matching
handshake keys — it decrypted our flight and rejected a message inside it. The cause was not in the DTLS code at all:
`DtlsCertificate` built its key pair from bare `ECDomainParameters`, which loses the curve's OID, so BouncyCastle
wrote the certificate's `SubjectPublicKeyInfo` with **explicit** curve parameters (the prime, a, b, the base point,
the order) instead of the named-curve OID. RFC 5480 §2.1.1 requires `namedCurve` for TLS, and BoringSSL — so every
Chromium browser — rejects such a certificate outright.

This had been latent since the certificate was written. It was invisible because browsers never got far enough to
parse the certificate, and no test that lacks a real TLS peer can see it. It is now pinned by
`DtlsCertificateTests.GenerateSelfSigned_NamesItsCurveByOid_AsBrowsersRequire`.

## Debugging tools

Both are opt-in via environment variable and cost nothing when unset.

```
CUPRIWEBRTC_PCAP=<path>       # write every DTLS datagram, both directions, to a libpcap file
CUPRIWEBRTC_SSLKEYLOG=<path>  # write the handshake's traffic secrets in the NSS key-log format
```

Together they make the encrypted half of the handshake readable:

```
tshark -r <file.pcap> -d udp.port==<PORT>,dtls -o tls.keylog_file:<keys.log> -Y dtls \
       -T fields -e frame.number -e udp.srcport -e dtls.handshake.type
tshark -r <file.pcap> -d udp.port==<PORT>,dtls -o tls.keylog_file:<keys.log> -Y "frame.number==N" -V
```

A healthy handshake reads: ClientHello → HelloRetryRequest+cookie → ClientHello+cookie → ServerHello,
{EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify, Finished} → {Certificate,
CertificateVerify, Finished} → ACK → application data, with **no alert and nothing flagged malformed**.

**The key log is the session's live keys.** Anything written there deprotects the whole connection; it exists for a
developer's machine and nowhere else.

The probe host also honours `CUPRIWEBRTC_NO_COOKIE=1` and `CUPRIWEBRTC_NO_CERTREQ=1`, so a failing browser handshake
can be bisected feature by feature without a rebuild.

## Configuration

`Dtls13ServerOptions` is the 1.3 policy object, passed to `WebRtcListener` or `DtlsServer`:

- `CookieExchange` (default **on**) — a HelloRetryRequest carrying a stateless HMAC cookie before any expensive work,
  so a spoofed source address cannot make the endpoint sign or amplify (RFC 9147 §5.1). RFC 9147 permits turning it
  off where bidirectional connectivity is already proven — which ICE does — at the cost of one round trip when on.
- `RequestClientCertificate` (default **on**) — browsers always have one and expect to be asked. What arrives is
  **never verified**: in WebRTC the peer's identity is authenticated above this channel (CupriNet's Noise handshake),
  which is the same accept-any policy the 1.2 path has always had.
- `SupportedGroups`, `AcceptedSignatureSchemes`, timeouts, `MaxDatagramSize` (1200 by default — the conservative floor
  WebRTC stacks assume), `CookieLifetime`, and the `Crypto` seam.

## Status and limits

Verified: real Chromium (Chrome 147 engine) opens a DataChannel and round-trips a message; Wireshark shows a clean
DTLS 1.3 exchange with no alerts; RFC vectors, the in-process handshake and the full stack all pass.

Not yet verified, and honest about it:

- **Firefox and Safari.** Firefox's WebRTC would not reach the endpoint at all on the development machine (no ICE
  check ever arrived, headless or headed, with `media.peerconnection.ice.loopback` set) — an environment problem
  before DTLS is involved, so it says nothing about the implementation either way. It needs a run on a normal desktop.
- **Reference-client interop** (pion/dtls, `openssl s_client -dtls1_3`, `bssl client`). OpenSSL 3.5+ or a Go toolchain
  is needed and neither was available; this is the natural CI gate, since it needs no GUI browser.
- **KeyUpdate** is implemented as a minimal responder and has not been exercised by a real peer.

**This code has not had an external security review.** Hand-rolling the TLS 1.3 protocol is security-critical work —
transcript hashing, the key schedule, nonce construction, downgrade protection, constant-time comparison — and the
repo roadmap already mandates a review before production use.
