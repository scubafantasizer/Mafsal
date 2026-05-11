# Mafsal — Technical Reference

## Architectural Overview

```
[Firefox ESR 115+]
  │  SOCKS5 → 127.0.0.1:1080
  │  failover_direct = false  ← KILL-SWITCH
  │  WebRTC completely disabled
  ↓
[mafsal_client.py]  (kiosk — RAM / tmpfs)
  │  X25519 Ephemeral Key Exchange
  │  Session Key = HKDF(DH_secret, epoch)
  │  AES-256-GCM + per-packet HKDF sub-key
  │  ReplayGuard (64-bit sliding window)
  │  Traffic Shaping: Padding + Jitter + Decoy
  │  WebSocket (wss://)
  ↓
[Cloudflare Tunnel]  (trycloudflare.com)
  ↓
[mafsal_server.py]  (Google Colab)
  │  X25519 counterpart
  │  Same session key derivation
  │  HTTP CONNECT tunnel or plain HTTP forward
  │  Decoy packet detection and silent discard
  ↓
[Target Internet Host]
```

---

## v4 Handshake Protocol — X25519 Forward Secrecy

### Flow Diagram

```
Client                                     Server
  │                                           │
  │  1. Generate ephemeral key pair           │
  │     (client_priv, client_pub)             │
  │                                           │
  │──── HELLO ───────────────────────────────→│
  │     {type:"hello",                        │
  │      pub: b64(client_pub),                │
  │      mac: HMAC(SHARED_KEY, client_pub)}   │
  │                                           │
  │                     2. Verify client MAC  │
  │                     3. epoch = urandom(8) │
  │                     4. Ephemeral key pair  │
  │                        (server_priv, pub) │
  │                     5. DH(server_priv,    │
  │                           client_pub)     │
  │                        → shared_secret   │
  │                     6. session_key =      │
  │                        HKDF(shared_secret,│
  │                             epoch_bytes)  │
  │                                           │
  │←─── EPOCH ───────────────────────────────│
  │     {type:"epoch",                        │
  │      epoch: N,                            │
  │      pub: b64(server_pub),                │
  │      mac: HMAC(SHARED_KEY,                │
  │                epoch_bytes+server_pub)}   │
  │                                           │
  │  7. Verify server MAC                     │
  │  8. DH(client_priv, server_pub)           │
  │     → shared_secret (identical!)          │
  │  9. session_key =                         │
  │     HKDF(shared_secret, epoch_bytes)      │
  │ 10. Scrub client_priv + shared_secret     │
  │                                    scrub  │
  │                                           │
  │════════ ALL TRAFFIC USES session_key ═════│
```

### Why This Matters

| Scenario | Without X25519 | Mafsal v4 (X25519 + HKDF) |
|----------|----------------|----------------------------|
| SHARED_KEY stolen, no traffic recorded | Safe | Safe |
| SHARED_KEY stolen, traffic recorded | **Decryptable** | Safe ✓ |
| Session key stolen | That session only | That session only |
| Both sides on hostile network | Encrypted | Encrypted |

`SHARED_KEY` is used **only for HMAC authentication**.
Encryption runs entirely on the ephemeral `session_key`.
Once the session ends, both sides scrub it — past traffic is safe even
if the server is later compromised.

---

## Packet Wire Format

```
┌──────────┬──────────┬───────────┬───────────┬──────────────────┐
│ salt(8 B)│epoch(8 B)│counter(8 B)│ nonce(12 B)│  ct + tag (≥17 B)│
└──────────┴──────────┴───────────┴───────────┴──────────────────┘
│◄─────────────────── AAD (integrity-protected) ─────────────────►│
```

- **Overhead:** 52 bytes/packet — negligible
- **AAD:** salt + epoch + counter — header manipulation breaks the GCM tag
- **Sub-key derivation:** `HKDF(session_key, salt, info="mafsal-v4:{dir}:{epoch}:{ctr}")`
- **Per packet:** independent salt + nonce + sub-key

---

## Traffic Shaping

### Padding

Appended to each plaintext before encryption:

```
[original_data] [random_pad] [pad_len (2 B, big-endian)]
```

- `padding_min` / `padding_max` (default 16–128 bytes) control the range.
- The receiver reads the last 2 bytes to recover `pad_len` and strips it.
- Padding content is `os.urandom` — does not compress.

### Jitter

Each packet transmission is preceded by a delay sampled from a
**log-normal distribution**:

```
delay = exp(gauss(jitter_mean, jitter_sigma))
        clamped to [jitter_min_s, jitter_max_s]
```

Default parameters `(mean=-3.0, sigma=1.2)` yield:

| Percentile | Delay |
|-----------|-------|
| p25 | ~18 ms (fast click) |
| p50 | ~50 ms (normal) |
| p75 | ~135 ms (reading pause) |
| p95 | ~400 ms (long read) |

### Decoy Traffic

When `decoy_enabled = True`, the client runs a background coroutine
(`run_decoy_sender`) that periodically sends random-sized, authentically
encrypted packets tagged `{"type": "decoy", ...}`.

The server calls `is_decoy_frame()` before decryption and silently
discards these packets — they are never forwarded to the target.

A passive observer on the wire sees:
- Packets of varying size (padding)
- Irregular inter-packet timing (jitter)
- Continuous traffic during idle periods (decoy)

All three signals are indistinguishable from real user activity.

---

## Security Layers — Full Table

| # | Layer | Mechanism | Threat | Status |
|---|-------|-----------|--------|--------|
| 1 | Encryption | AES-256-GCM | Passive eavesdropping | ✓ v3+ |
| 2 | Key isolation | HKDF per-packet | Sub-key leakage | ✓ v3+ |
| 3 | Forward Secrecy | X25519 ephemeral | Master key + recording | ✓ **v4** |
| 4 | Authentication | HMAC-SHA256 | MITM, rogue server | ✓ v3.1+ |
| 5 | Replay protection | 64-bit sliding window | Packet replay, gap injection | ✓ v3.1+ |
| 6 | Kill-switch | failover_direct=false | Direct leak on proxy crash | ✓ v3+ |
| 7 | WebRTC block | peerconnection=false | Real IP via WebRTC | ✓ v3+ |
| 8 | IPv6 block | disableIPv6=true | IPv6 IP leak | ✓ v3+ |
| 9 | DNS isolation | SOCKS remote DNS + DoH | DNS leak | ✓ v3+ |
| 10 | No disk writes | cache=false, tmpfs | Disk forensics | ✓ v3+ |
| 11 | Shutdown cleanup | shred -n3, unset | Disk remnants | ✓ v3+ |
| 12 | Memory safety | bytearray + scrub_key | RAM scraping | ✓ v3.1+ |
| 13 | Session monitor | InternalMonitor (RAM) | — | ✓ v3.1+ |
| 14 | Fingerprint resistance | resistFingerprinting | Browser fingerprint | ✓ v3+ |
| 15 | Traffic shaping | Padding + Jitter + Decoy | Traffic analysis | ✓ **v4** |

---

## ReplayGuard — RFC 4303 Style Sliding Window

```
Window size: 64 packets
high_water:  highest counter received so far

Rules:
  ctr > high_water          → Accept; advance window
  ctr <= high_water - 64    → Reject (too old; outside window)
  In range + bit set        → Reject (duplicate = replay)
  In range + bit clear      → Accept (out-of-order but new)
```

**Improvement over naive `ctr <= last`:** A simple check only catches
backward replay. An attacker could inject a packet with a very high counter
(gap injection). The bitmap prevents this.

---

## InternalMonitor

- All metrics are stored in RAM only (`SessionMetrics` dataclass)
- No file writes, no network calls, no syslog
- Kill-switch thresholds: `replay_attempts >= 3` or `decrypt_failures >= 5`
- On session close: prints a summary to stdout, then calls `clear()`

---

## Memory Safety — Layered Approach

```
SHARED_KEY     → bytearray (GC cannot cache; zeroed in place)
session_key    → bytearray (scrub_bytearray on session end)
sub_key        → bytearray (scrubbed immediately after use + del)
HKDF output    → bytes (C layer) → scrub_bytes_ctypes → del
DH shared_sec. → bytes → scrub_bytes_ctypes → del
X25519 priv    → C layer; reference dropped + gc.collect()
```

**Documented limitation:** `X25519PrivateKey` is held in the
`cryptography` library's C extension. The Python API does not expose a
manual scrub method; the reference is dropped and GC is triggered.
This is an accepted limitation given the key's short lifetime.

---

## Dependencies

**Kiosk (client):**
```
Python 3.9+
pip install websockets cryptography
Firefox ESR 115+
```

**Colab (server):**
```
pip install websockets cryptography
cloudflared (pre-installed in Colab)
```

---

## Known Limitations

| Limitation | Description | Risk |
|------------|-------------|------|
| X25519 priv scrub | C layer; left to GC | Low — ephemeral, short-lived |
| Colab session length | Free tier ~12 hours | Operational; mitigated by key rotation |
| Cloudflare URL | Changes per Colab session | Operational |
| `scrub_bytes_ctypes` | CPython internal layout | May silently fail on non-CPython; bytearray path preferred |
| No mutual TLS | Server certificate not pinned | Mitigated by HMAC authentication |

---

## Version History

| Version | Change |
|---------|--------|
| v3.0 | AES-256-GCM, HKDF, epoch, kill-switch, WebRTC block |
| v3.1 | ReplayGuard, epoch HMAC, bytearray scrub, InternalMonitor |
| v4.0 | X25519 ephemeral key exchange → real Forward Secrecy |
| v4.1 | Traffic shaping integrated (padding + jitter + decoy); English codebase; GPL-3.0 |
