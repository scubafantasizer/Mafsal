#!/usr/bin/env python3
"""
Mafsal — Server (Google Colab side)
mafsal_server.py

Copyright (C) 2026  Mafsal Contributors
SPDX-License-Identifier: GPL-3.0-or-later

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Architecture:
    [Firefox ESR] → SOCKS5:1080 → [mafsal_client] → Cloudflare Tunnel
    → [mafsal_server on Colab] → Target Internet Host

Security (v4):
    X25519 Ephemeral Key Exchange → real Forward Secrecy
    AES-256-GCM + per-packet HKDF sub-key
    HMAC-SHA256 handshake authentication
    64-bit sliding-window ReplayGuard (RFC 4303 style)
    Decoy packet detection and silent discard

Environment variables:
    RELAY_KEY        — shared secret, minimum 64 hex characters
    TARGET_HOST      — default forwarding host (default: httpbin.org)
    TARGET_PORT      — default forwarding port (default: 443)
"""

import asyncio
import base64
import gc
import json
import logging
import os
import sys
import struct
import ctypes
import hmac as _hmac
import hashlib
import http.client

try:
    import websockets
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey,
    )
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("[ERROR] Missing dependencies: pip install websockets cryptography")
    sys.exit(1)

from traffic_shaping import (
    TrafficShapingConfig,
    DEFAULT_CONFIG as TS_CONFIG,
    add_padding,
    strip_padding,
    is_decoy_frame,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8765

RELAY_KEY_HEX = os.environ.get("RELAY_KEY", "")
if not RELAY_KEY_HEX or len(RELAY_KEY_HEX) < 64:
    print("[ERROR] RELAY_KEY is missing or too short (minimum 64 hex characters).")
    sys.exit(1)

try:
    SHARED_KEY: bytearray = bytearray(bytes.fromhex(RELAY_KEY_HEX))
except ValueError:
    print("[ERROR] RELAY_KEY is not valid hexadecimal.")
    sys.exit(1)

os.environ.pop("RELAY_KEY", None)
del RELAY_KEY_HEX

DEFAULT_TARGET_HOST = os.environ.get("TARGET_HOST", "httpbin.org")
DEFAULT_TARGET_PORT = int(os.environ.get("TARGET_PORT", "443"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("mafsal-server")

# ---------------------------------------------------------------------------
# Memory Safety
# ---------------------------------------------------------------------------

def scrub_bytearray(data: bytearray) -> None:
    """Overwrite a bytearray with zeros in place."""
    for i in range(len(data)):
        data[i] = 0


def scrub_bytes_ctypes(data: bytes) -> None:
    """
    Best-effort zero-fill of an immutable bytes object via ctypes.
    CPython-specific; silently skips on failure.
    """
    try:
        import sys as _sys
        sz = len(data)
        if sz == 0:
            return
        header = _sys.getsizeof(b"") - 1
        buf = (ctypes.c_char * sz).from_address(id(data) + header)
        ctypes.memset(buf, 0, sz)
    except Exception:
        pass


def scrub_key(key: bytearray) -> None:
    scrub_bytearray(key)
    gc.collect()

# ---------------------------------------------------------------------------
# ReplayGuard — RFC 4303 style 64-bit sliding window
# ---------------------------------------------------------------------------

REPLAY_WINDOW = 64


class ReplayGuard:
    """
    Duplicate / replay packet detector.

    Uses a bitmap sliding window identical in spirit to RFC 4303 §3.4.3.
    Accepts out-of-order packets within the window but rejects duplicates
    and packets outside the window (too old).
    """

    def __init__(self) -> None:
        self._high: int = -1
        self._bitmap: int = 0

    def check_and_advance(self, ctr: int) -> bool:
        """
        Return True if *ctr* is a new, acceptable counter value.
        Return False if it is a replay or outside the window.
        """
        if self._high == -1:
            self._high = ctr
            self._bitmap = 1
            return True
        if ctr > self._high:
            shift = ctr - self._high
            self._bitmap = (
                ((self._bitmap << shift) | 1) if shift < REPLAY_WINDOW else 1
            )
            self._bitmap &= (1 << REPLAY_WINDOW) - 1
            self._high = ctr
            return True
        diff = self._high - ctr
        if diff >= REPLAY_WINDOW:
            return False   # too old
        bit = 1 << diff
        if self._bitmap & bit:
            return False   # already seen
        self._bitmap |= bit
        return True

# ---------------------------------------------------------------------------
# Cryptography
# ---------------------------------------------------------------------------

def derive_packet_key(
    session_key: bytearray,
    salt: bytes,
    epoch: int,
    counter: int,
    direction: str,
) -> bytearray:
    """
    Derive a per-packet AES-256 sub-key from the ephemeral session key.

    Inputs: session_key (X25519 + HKDF), salt (8 random bytes),
            epoch, counter, direction ("C2S" or "S2C").
    SHARED_KEY is never passed to this function.
    """
    info = f"mafsal-v4:{direction}:{epoch}:{counter}".encode()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend(),
    )
    raw: bytes = hkdf.derive(bytes(session_key))
    result = bytearray(raw)
    scrub_bytes_ctypes(raw)
    return result


def encrypt_packet(
    plaintext: bytes,
    session_key: bytearray,
    epoch: int,
    counter: int,
    direction: str,
) -> bytes:
    """
    Encrypt *plaintext* and return the Mafsal wire packet.

    Wire format:
        salt(8 B) | epoch(8 B BE) | counter(8 B BE) | nonce(12 B) | ct+tag
    AAD: salt + epoch + counter  →  header integrity under GCM.
    """
    salt    = os.urandom(8)
    sub_key = derive_packet_key(session_key, salt, epoch, counter, direction)
    nonce   = os.urandom(12)
    aad     = salt + struct.pack(">QQ", epoch, counter)
    ct      = AESGCM(bytes(sub_key)).encrypt(nonce, plaintext, aad)
    scrub_bytearray(sub_key)
    del sub_key
    return salt + struct.pack(">QQ", epoch, counter) + nonce + ct


def decrypt_packet(
    data: bytes,
    session_key: bytearray,
    expected_epoch: int,
    expected_direction: str,
) -> tuple[bytes, int]:
    """
    Decrypt a Mafsal wire packet.
    Returns (plaintext, counter).
    Raises ValueError on format errors or epoch mismatch.
    AESGCM.decrypt raises InvalidTag on authentication failure.
    """
    MIN_LEN = 8 + 8 + 8 + 12 + 17
    if len(data) < MIN_LEN:
        raise ValueError(f"Packet too short: {len(data)} B")
    salt    = data[:8]
    epoch   = struct.unpack(">Q", data[8:16])[0]
    counter = struct.unpack(">Q", data[16:24])[0]
    nonce   = data[24:36]
    ct      = data[36:]
    aad     = salt + struct.pack(">QQ", epoch, counter)
    if epoch != expected_epoch:
        raise ValueError(f"Epoch mismatch: got {epoch}, expected {expected_epoch}")
    sub_key = derive_packet_key(session_key, salt, epoch, counter, expected_direction)
    try:
        pt = AESGCM(bytes(sub_key)).decrypt(nonce, ct, aad)
    finally:
        scrub_bytearray(sub_key)
        del sub_key
    return pt, counter

# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

def frame(payload: bytes) -> str:
    """Encode an encrypted binary payload as a JSON WebSocket message."""
    return json.dumps({
        "v": 4,
        "data": base64.b64encode(payload).decode(),
        "size": len(payload),
    })


def error_frame(msg: str) -> str:
    return json.dumps({"type": "error", "message": msg})


def unframe(message: str) -> bytes:
    """Decode a JSON WebSocket message back to encrypted binary payload."""
    obj = json.loads(message)
    if obj.get("type") == "error":
        raise RuntimeError(f"Client error: {obj.get('message')}")
    return base64.b64decode(obj["data"])

# ---------------------------------------------------------------------------
# X25519 Handshake (server side)
# ---------------------------------------------------------------------------
#
# Flow:
#   1.  Receive HELLO + client_pub + HMAC(SHARED_KEY, client_pub)
#   2.  Verify client HMAC
#   3.  Generate epoch (8 random bytes) and server ephemeral key pair
#   4.  shared_secret = X25519(server_priv, client_pub)
#   5.  session_key   = HKDF(shared_secret, salt=epoch_bytes,
#                            info="mafsal-v4-session")
#   6.  Send epoch + server_pub + HMAC(SHARED_KEY, epoch_bytes + server_pub)
#   7.  Scrub server_priv and shared_secret from memory

async def do_handshake(ws) -> tuple[bytearray, int]:
    """
    Perform X25519 key exchange with the client.
    Returns (session_key, epoch).
    """
    # 1. Receive HELLO
    raw_hello = await asyncio.wait_for(ws.recv(), timeout=10)
    obj = json.loads(raw_hello)
    if obj.get("type") != "hello":
        raise RuntimeError(f"Unexpected handshake message: {obj}")

    client_pub_bytes = base64.b64decode(obj["pub"])
    client_mac       = obj.get("mac", "")

    # 2. Verify client MAC
    expected_client_mac = _hmac.new(
        bytes(SHARED_KEY),
        client_pub_bytes,
        hashlib.sha256,
    ).hexdigest()
    if not client_mac or not _hmac.compare_digest(expected_client_mac, client_mac):
        raise RuntimeError("Client HMAC invalid — unauthorised connection attempt")

    # 3. Generate epoch and server ephemeral key pair
    epoch            = int.from_bytes(os.urandom(8), "big")
    epoch_bytes      = struct.pack(">Q", epoch)
    server_priv      = X25519PrivateKey.generate()
    server_pub_bytes: bytes = server_priv.public_key().public_bytes_raw()

    # 4. DH shared secret
    client_pub    = X25519PublicKey.from_public_bytes(client_pub_bytes)
    shared_secret: bytes = server_priv.exchange(client_pub)

    # 5. Derive session key
    session_key_raw: bytes = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=epoch_bytes,
        info=b"mafsal-v4-session",
        backend=default_backend(),
    ).derive(shared_secret)
    session_key = bytearray(session_key_raw)

    # 6. Send epoch + server_pub + HMAC(SHARED_KEY, epoch_bytes + server_pub)
    server_mac = _hmac.new(
        bytes(SHARED_KEY),
        epoch_bytes + server_pub_bytes,
        hashlib.sha256,
    ).hexdigest()

    await ws.send(json.dumps({
        "v": 4,
        "type": "epoch",
        "epoch": epoch,
        "pub": base64.b64encode(server_pub_bytes).decode(),
        "mac": server_mac,
    }))

    # 7. Scrub ephemeral private key and shared secret
    scrub_bytes_ctypes(shared_secret)
    scrub_bytes_ctypes(session_key_raw)
    del server_priv, shared_secret, session_key_raw
    gc.collect()

    log.info(f"Handshake complete — X25519 ✓ | epoch={epoch} | HMAC ✓")
    return session_key, epoch

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def sniff_http_host(raw: bytes):
    """Extract Host header from a raw HTTP request."""
    try:
        header_section = raw.split(b"\r\n\r\n")[0].decode(errors="replace")
        for line in header_section.splitlines():
            if line.lower().startswith("host:"):
                host_val = line.split(":", 1)[1].strip()
                if ":" in host_val:
                    h, p = host_val.rsplit(":", 1)
                    return h, int(p), int(p) == 443
                return host_val, 443, True
    except Exception:
        pass
    return DEFAULT_TARGET_HOST, DEFAULT_TARGET_PORT, True


def is_connect_method(raw: bytes) -> tuple[bool, str, int]:
    """Return (is_connect, host, port) for HTTP CONNECT requests."""
    try:
        first_line = raw.split(b"\r\n")[0].decode(errors="replace")
        parts = first_line.split()
        if parts and parts[0].upper() == "CONNECT":
            hp = parts[1]
            if ":" in hp:
                h, p = hp.rsplit(":", 1)
                return True, h, int(p)
            return True, hp, 443
    except Exception:
        pass
    return False, "", 0

# ---------------------------------------------------------------------------
# TCP tunnel
# ---------------------------------------------------------------------------

async def tunnel_raw_tcp(
    ws,
    host: str,
    port: int,
    epoch: int,
    send_ctr: list,
    recv_guard: ReplayGuard,
    session_key: bytearray,
    ts_cfg: TrafficShapingConfig = TS_CONFIG,
) -> None:
    """Bidirectional relay between the WebSocket and a raw TCP connection."""
    use_ssl = (port == 443)
    reader, writer = await asyncio.open_connection(host, port, ssl=use_ssl)

    async def ws_to_tcp():
        async for msg in ws:
            if is_decoy_frame(msg):
                log.debug("Decoy packet discarded")
                continue
            raw_enc = unframe(msg)
            padded, ctr = decrypt_packet(raw_enc, session_key, epoch, "C2S")
            if not recv_guard.check_and_advance(ctr):
                log.warning(f"CRITICAL_SECURITY_EVENT: Replay (tcp): ctr={ctr}")
                continue
            original = strip_padding(padded, ts_cfg)
            writer.write(original)
            await writer.drain()
        writer.close()

    async def tcp_to_ws():
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            padded = add_padding(chunk, ts_cfg)
            ctr = send_ctr[0]
            enc = encrypt_packet(padded, session_key, epoch, ctr, "S2C")
            send_ctr[0] += 1
            await ws.send(frame(enc))

    done, pending = await asyncio.wait(
        [asyncio.create_task(ws_to_tcp()),
         asyncio.create_task(tcp_to_ws())],
        return_when=asyncio.FIRST_COMPLETED,
    )
    for t in pending:
        t.cancel()

# ---------------------------------------------------------------------------
# HTTP single-request forward
# ---------------------------------------------------------------------------

async def forward_http(
    ws,
    raw: bytes,
    host: str,
    port: int,
    use_tls: bool,
    epoch: int,
    send_ctr: list,
    session_key: bytearray,
    ts_cfg: TrafficShapingConfig = TS_CONFIG,
) -> None:
    """Forward a single plain HTTP request to the target host and return the response."""
    log.info(f"HTTP → {host}:{port}")
    try:
        ConnCls = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
        conn = ConnCls(host, port, timeout=15)
        hdr_raw, _, body = raw.partition(b"\r\n\r\n")
        req_line, _, hdrs_raw = hdr_raw.partition(b"\r\n")
        parts = req_line.decode(errors="replace").split(None, 2)
        method = parts[0] if parts else "GET"
        path   = parts[1] if len(parts) > 1 else "/"
        hdrs: dict = {}
        for hline in hdrs_raw.split(b"\r\n"):
            if b":" in hline:
                k, _, v = hline.partition(b":")
                key = k.decode(errors="replace").strip()
                if key.lower() not in ("host", "connection", "proxy-connection"):
                    hdrs[key] = v.decode(errors="replace").strip()
        hdrs["Connection"] = "close"
        conn.request(method, path, body=body or None, headers=hdrs)
        resp = conn.getresponse()
        sl   = f"HTTP/1.1 {resp.status} {resp.reason}\r\n"
        rh   = "".join(f"{k}: {v}\r\n" for k, v in resp.getheaders())
        rb   = resp.read()
        full = (sl + rh + "\r\n").encode() + rb
        padded = add_padding(full, ts_cfg)
        ctr    = send_ctr[0]
        enc    = encrypt_packet(padded, session_key, epoch, ctr, "S2C")
        send_ctr[0] += 1
        await ws.send(frame(enc))
        log.info(f"← HTTP {resp.status} ({len(full)} B)")
        conn.close()
    except Exception as exc:
        log.error(f"HTTP forward error: {exc}")
        await ws.send(error_frame(str(exc)))

# ---------------------------------------------------------------------------
# WebSocket handler
# ---------------------------------------------------------------------------

async def bridge_handler(ws) -> None:
    """Handle one WebSocket connection: handshake → relay loop → cleanup."""
    peer = ws.remote_address
    log.info(f"New connection: {peer}")

    session_key: bytearray | None = None
    try:
        session_key, epoch = await do_handshake(ws)
    except Exception as exc:
        log.error(f"Handshake failed ({peer}): {exc}")
        return

    send_ctr     = [0]
    recv_guard   = ReplayGuard()
    connect_done = False

    try:
        async for message in ws:
            # Silently discard decoy packets from the client
            if is_decoy_frame(message):
                log.debug("Decoy packet discarded (bridge)")
                continue

            try:
                padded, ctr = decrypt_packet(unframe(message), session_key, epoch, "C2S")
            except Exception as exc:
                log.error(f"CRITICAL_SECURITY_EVENT: Decryption error: {exc}")
                await ws.send(error_frame(str(exc)))
                continue

            if not recv_guard.check_and_advance(ctr):
                log.warning(f"CRITICAL_SECURITY_EVENT: Replay (bridge): ctr={ctr}")
                continue

            plaintext = strip_padding(padded, TS_CONFIG)

            is_conn, c_host, c_port = is_connect_method(plaintext)
            if is_conn and not connect_done:
                ack   = b"HTTP/1.1 200 Connection Established\r\n\r\n"
                padded_ack = add_padding(ack, TS_CONFIG)
                ctr_s = send_ctr[0]
                enc   = encrypt_packet(padded_ack, session_key, epoch, ctr_s, "S2C")
                send_ctr[0] += 1
                await ws.send(frame(enc))
                connect_done = True
                log.info(f"CONNECT → {c_host}:{c_port}")
                await tunnel_raw_tcp(
                    ws, c_host, c_port, epoch,
                    send_ctr, recv_guard, session_key, TS_CONFIG,
                )
                return
            elif not connect_done:
                host, port, use_tls = sniff_http_host(plaintext)
                await forward_http(
                    ws, plaintext, host, port, use_tls,
                    epoch, send_ctr, session_key, TS_CONFIG,
                )

    except websockets.exceptions.ConnectionClosedOK:
        log.info(f"Client disconnected cleanly: {peer}")
    except websockets.exceptions.ConnectionClosedError as exc:
        log.warning(f"Connection lost: {peer} — {exc}")
    except Exception as exc:
        log.error(f"Handler error ({peer}): {exc}")
    finally:
        if session_key is not None:
            scrub_bytearray(session_key)
            del session_key
            gc.collect()
        log.info(f"Session closed: {peer}")

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    log.info("=" * 62)
    log.info("  Mafsal — Server (Colab)")
    log.info(f"  Listen         : {SERVER_HOST}:{SERVER_PORT}")
    log.info(f"  Cipher         : AES-256-GCM + HKDF (per-packet)")
    log.info(f"  Key exchange   : X25519 Ephemeral (Forward Secrecy ✓)")
    log.info(f"  Auth           : HMAC-SHA256 (SHARED_KEY)")
    log.info(f"  Replay guard   : 64-bit sliding window (RFC 4303)")
    log.info(f"  Padding        : {'enabled' if TS_CONFIG.padding_enabled else 'disabled'}")
    log.info(f"  Decoy discard  : active")
    log.info("=" * 62)

    async with websockets.serve(
        bridge_handler,
        SERVER_HOST,
        SERVER_PORT,
        max_size=10 * 1024 * 1024,
        ping_interval=20,
        ping_timeout=10,
    ):
        log.info(f"Server ready → ws://{SERVER_HOST}:{SERVER_PORT}")
        try:
            await asyncio.Future()
        finally:
            log.info("Scrubbing SHARED_KEY from memory...")
            scrub_key(SHARED_KEY)
            log.info("Cleanup complete.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Server stopped by user.")
