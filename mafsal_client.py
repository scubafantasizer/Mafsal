#!/usr/bin/env python3
"""
Mafsal — Client (kiosk side)
mafsal_client.py

Copyright (C) 2026  Mafsal Contributors
SPDX-License-Identifier: GPL-3.0-or-later

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

What it does:
    Opens a SOCKS5 proxy on localhost:1080.
    Firefox (ZeroTrustProfile) routes all traffic through this proxy.
    Each connection is forwarded over an encrypted WebSocket to the
    Mafsal server running on Google Colab.

Security layers (v4):
    AES-256-GCM | HKDF per-packet sub-key | X25519 Forward Secrecy
    HMAC-SHA256 handshake auth | ReplayGuard (RFC 4303) | Kill-switch
    bytearray scrub | InternalMonitor (RAM-only)
    Traffic shaping: randomized padding + human-like jitter + decoy traffic

Environment variables:
    RELAY_KEY        — shared secret, minimum 64 hex characters
    COLAB_WS_URL     — wss://xxxx.trycloudflare.com/bridge
"""

import asyncio
import base64
import gc
import json
import os
import hmac as _hmac
import hashlib
import logging
import sys
import struct
import ctypes
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

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
    print("[ERROR] Missing packages: pip install websockets cryptography")
    sys.exit(1)

from traffic_shaping import (
    TrafficShapingConfig,
    DEFAULT_CONFIG as TS_CONFIG,
    add_padding,
    strip_padding,
    apply_jitter,
    run_decoy_sender,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOCAL_HOST  = "127.0.0.1"
LOCAL_PORT  = 1080
BUFFER_SIZE = 65536

COLAB_WS_URL = os.environ.get("COLAB_WS_URL", "")
if not COLAB_WS_URL:
    print("[ERROR] COLAB_WS_URL is not set.")
    print('  export COLAB_WS_URL="wss://xxxx.trycloudflare.com/bridge"')
    sys.exit(1)

RELAY_KEY_HEX = os.environ.get("RELAY_KEY", "")
if not RELAY_KEY_HEX or len(RELAY_KEY_HEX) < 64:
    print("[ERROR] RELAY_KEY is missing or too short (minimum 64 hex characters).")
    sys.exit(1)

try:
    # bytearray: cannot be interned by the GC; can be zeroed in place.
    SHARED_KEY: bytearray = bytearray(bytes.fromhex(RELAY_KEY_HEX))
except ValueError:
    print("[ERROR] RELAY_KEY is not valid hexadecimal.")
    sys.exit(1)

os.environ.pop("RELAY_KEY", None)
del RELAY_KEY_HEX

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("mafsal-client")

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
        sz = len(data)
        if sz == 0:
            return
        import sys as _sys
        header = _sys.getsizeof(b"") - 1
        buf = (ctypes.c_char * sz).from_address(id(data) + header)
        ctypes.memset(buf, 0, sz)
    except Exception:
        pass


def scrub_key(key: bytearray) -> None:
    scrub_bytearray(key)
    gc.collect()

# ---------------------------------------------------------------------------
# InternalMonitor — RAM-only session security tracker
# ---------------------------------------------------------------------------

@dataclass
class SessionMetrics:
    start_time: float = field(default_factory=time.monotonic)
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    replay_attempts: int = 0
    decrypt_failures: int = 0
    kill_switch_triggered: bool = False
    handshake_ok: bool = False
    fs_ok: bool = False          # X25519 complete?
    epoch: Optional[int] = None
    events: deque = field(default_factory=lambda: deque(maxlen=50))


class InternalMonitor:
    """
    RAM-only session security monitor.
    No data is ever written to disk or sent over the network.
    Prints a summary to stdout when the session ends, then clears itself.
    """

    def __init__(self) -> None:
        self._m = SessionMetrics()

    def record_sent(self, n: int) -> None:
        self._m.bytes_sent += n
        self._m.packets_sent += 1

    def record_recv(self, n: int) -> None:
        self._m.bytes_recv += n
        self._m.packets_recv += 1

    def record_replay(self, ctr: int) -> None:
        self._m.replay_attempts += 1
        self._m.events.append(f"REPLAY ctr={ctr} t={time.monotonic():.2f}")

    def record_decrypt_fail(self, reason: str) -> None:
        self._m.decrypt_failures += 1
        self._m.events.append(f"DECRYPT_FAIL reason={reason[:80]}")

    def record_kill_switch(self) -> None:
        self._m.kill_switch_triggered = True
        self._m.events.append(f"KILL_SWITCH t={time.monotonic():.2f}")

    def set_handshake(self, epoch: int, fs: bool) -> None:
        self._m.handshake_ok = True
        self._m.fs_ok = fs
        self._m.epoch = epoch

    def should_kill(self) -> bool:
        return self._m.replay_attempts >= 3 or self._m.decrypt_failures >= 5

    def print_summary(self) -> None:
        elapsed = time.monotonic() - self._m.start_time
        sep = "=" * 62
        print(f"\n{sep}")
        print("  SESSION SECURITY SUMMARY  (InternalMonitor — RAM only)")
        print(sep)
        print(f"  Duration        : {elapsed:.1f} s")
        print(f"  Handshake       : {'✓ OK' if self._m.handshake_ok else '✗ FAILED'}")
        print(f"  Forward Secrecy : {'✓ X25519 active' if self._m.fs_ok else '✗ NONE'}")
        if self._m.epoch:
            print(f"  Epoch           : {self._m.epoch}")
        print(f"  Sent            : {self._m.packets_sent} packets / {self._m.bytes_sent} B")
        print(f"  Received        : {self._m.packets_recv} packets / {self._m.bytes_recv} B")
        print(f"  Replay attempts : {self._m.replay_attempts}")
        print(f"  Decrypt errors  : {self._m.decrypt_failures}")
        print(f"  Kill-switch     : {'⚠ TRIGGERED' if self._m.kill_switch_triggered else '— none'}")
        if self._m.events:
            print(f"\n  Security events ({len(self._m.events)}):")
            for ev in self._m.events:
                print(f"    ⚠ {ev}")
        print(sep)
        print("  [No data was sent outside this process.]\n")

    def clear(self) -> None:
        self._m.events.clear()
        self._m.epoch = None
        self._m = SessionMetrics()
        gc.collect()

# ---------------------------------------------------------------------------
# ReplayGuard — RFC 4303 style 64-bit sliding window
# ---------------------------------------------------------------------------

REPLAY_WINDOW = 64


class ReplayGuard:
    """
    Duplicate / replay packet detector.

    Accepts out-of-order packets within a 64-packet window, but rejects
    duplicates and packets that fall outside the window (too old).
    """

    def __init__(self) -> None:
        self._high: int = -1
        self._bitmap: int = 0

    def check_and_advance(self, ctr: int) -> bool:
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
            return False
        bit = 1 << diff
        if self._bitmap & bit:
            return False
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

    SHARED_KEY is never passed to this function.  The session_key is the
    X25519 + HKDF result; an attacker who obtains SHARED_KEY cannot
    derive any session_key (Forward Secrecy guarantee).
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
    Overhead: 52 B/packet.
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
        raise ValueError(f"Epoch mismatch: expected={expected_epoch} got={epoch}")
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
    return json.dumps({
        "v": 4,
        "data": base64.b64encode(payload).decode(),
        "size": len(payload),
    })


def unframe(message: str) -> bytes:
    obj = json.loads(message)
    if obj.get("type") == "error":
        raise RuntimeError(f"Server error: {obj.get('message')}")
    return base64.b64decode(obj["data"])

# ---------------------------------------------------------------------------
# X25519 Handshake (client side)
# ---------------------------------------------------------------------------
#
# Flow:
#   1.  Generate ephemeral X25519 key pair (client_priv, client_pub)
#   2.  Send HELLO: client_pub + HMAC(SHARED_KEY, client_pub)
#   3.  Receive epoch + server_pub + HMAC(SHARED_KEY, epoch_bytes + server_pub)
#   4.  Verify server HMAC
#   5.  shared_secret = X25519(client_priv, server_pub)
#   6.  session_key   = HKDF(shared_secret, salt=epoch_bytes,
#                            info="mafsal-v4-session")
#   7.  Scrub client_priv and shared_secret from memory
#
# Result: SHARED_KEY was used only for HMAC authentication.
#         Encryption runs entirely on the ephemeral session_key.
#         Compromising SHARED_KEY cannot decrypt any recorded session.

async def do_handshake(ws, monitor: InternalMonitor) -> tuple[bytearray, int]:
    """
    Perform X25519 key exchange with the server.
    Returns (session_key, epoch).
    """
    # 1. Generate ephemeral key pair
    client_priv = X25519PrivateKey.generate()
    client_pub_bytes: bytes = client_priv.public_key().public_bytes_raw()

    # 2. Send HELLO
    client_mac = _hmac.new(
        bytes(SHARED_KEY),
        client_pub_bytes,
        hashlib.sha256,
    ).hexdigest()

    await ws.send(json.dumps({
        "v": 4,
        "type": "hello",
        "pub": base64.b64encode(client_pub_bytes).decode(),
        "mac": client_mac,
    }))

    # 3. Receive epoch + server_pub + MAC
    raw = await asyncio.wait_for(ws.recv(), timeout=10)
    obj = json.loads(raw)
    if obj.get("type") != "epoch":
        raise RuntimeError(f"Handshake: unexpected response: {obj}")

    epoch            = int(obj["epoch"])
    epoch_bytes      = struct.pack(">Q", epoch)
    server_pub_bytes = base64.b64decode(obj["pub"])
    server_mac       = obj.get("mac", "")

    # 4. Verify server MAC: HMAC(SHARED_KEY, epoch_bytes + server_pub)
    expected_mac = _hmac.new(
        bytes(SHARED_KEY),
        epoch_bytes + server_pub_bytes,
        hashlib.sha256,
    ).hexdigest()

    if not server_mac or not _hmac.compare_digest(expected_mac, server_mac):
        raise RuntimeError("Handshake: server HMAC invalid — possible MITM attack")

    # 5. X25519 DH
    server_pub    = X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared_secret: bytes = client_priv.exchange(server_pub)

    # 6. Derive session key
    session_key_raw: bytes = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=epoch_bytes,
        info=b"mafsal-v4-session",
        backend=default_backend(),
    ).derive(shared_secret)
    session_key = bytearray(session_key_raw)

    # 7. Scrub ephemeral material
    scrub_bytes_ctypes(shared_secret)
    scrub_bytes_ctypes(session_key_raw)
    # client_priv is held in the cryptography library's C extension;
    # dropping the reference lets the GC reclaim it (documented limitation).
    del client_priv, shared_secret, session_key_raw
    gc.collect()

    monitor.set_handshake(epoch, fs=True)
    log.info(f"Handshake complete — X25519 ✓ | epoch={epoch} | HMAC ✓")
    return session_key, epoch

# ---------------------------------------------------------------------------
# TCP client handler
# ---------------------------------------------------------------------------

async def handle_tcp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Handle one local SOCKS5 connection: connect to server → relay loop."""
    peer    = writer.get_extra_info("peername")
    monitor = InternalMonitor()
    log.info(f"New connection: {peer}")

    send_counter = 0
    recv_guard   = ReplayGuard()
    session_key: Optional[bytearray] = None
    decoy_stop   = asyncio.Event()

    try:
        async with websockets.connect(
            COLAB_WS_URL,
            ping_interval=20,
            ping_timeout=10,
            max_size=10 * 1024 * 1024,
            open_timeout=15,
        ) as ws:

            try:
                session_key, epoch = await do_handshake(ws, monitor)
            except Exception as exc:
                log.error(f"Handshake failed: {exc} → kill-switch")
                monitor.record_kill_switch()
                return

            log.info(f"Tunnel active | epoch={epoch} | FS=X25519")

            # Shared mutable counter list so decoy sender and real sender
            # both advance the same counter (no gaps in sequence).
            send_ctr_ref = [send_counter]

            async def local_to_remote() -> None:
                while True:
                    chunk = await reader.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    # 1. Human-like send delay
                    await apply_jitter(TS_CONFIG)
                    # 2. Randomize packet size signature
                    padded = add_padding(chunk, TS_CONFIG)
                    # 3. Encrypt (padding is inside GCM protection)
                    ctr = send_ctr_ref[0]
                    enc = encrypt_packet(padded, session_key, epoch, ctr, "C2S")
                    send_ctr_ref[0] += 1
                    await ws.send(frame(enc))
                    monitor.record_sent(len(chunk))
                    log.debug(f"→ {len(chunk)} B ctr={ctr}")

            async def remote_to_local() -> None:
                async for msg in ws:
                    try:
                        raw = unframe(msg)
                        padded, ctr = decrypt_packet(raw, session_key, epoch, "S2C")
                    except Exception as exc:
                        monitor.record_decrypt_fail(str(exc))
                        log.warning(f"⚠ Decryption error: {exc}")
                        if monitor.should_kill():
                            log.critical(
                                "CRITICAL_SECURITY_EVENT: threshold exceeded → kill-switch"
                            )
                            monitor.record_kill_switch()
                            raise RuntimeError("Kill-switch triggered")
                        continue

                    if not recv_guard.check_and_advance(ctr):
                        monitor.record_replay(ctr)
                        log.warning(
                            f"CRITICAL_SECURITY_EVENT: Replay/gap ctr={ctr}"
                        )
                        if monitor.should_kill():
                            log.critical(
                                "CRITICAL_SECURITY_EVENT: replay threshold → kill-switch"
                            )
                            monitor.record_kill_switch()
                            raise RuntimeError("Kill-switch: replay threshold")
                        continue

                    plaintext = strip_padding(padded, TS_CONFIG)
                    writer.write(plaintext)
                    await writer.drain()
                    monitor.record_recv(len(plaintext))
                    log.debug(f"← {len(plaintext)} B ctr={ctr}")

            # Start decoy sender as a background task
            decoy_task = asyncio.create_task(
                run_decoy_sender(
                    ws, session_key, epoch,
                    send_ctr_ref, TS_CONFIG,
                    encrypt_packet, decoy_stop,
                )
            )

            try:
                done, pending = await asyncio.wait(
                    [asyncio.create_task(local_to_remote()),
                     asyncio.create_task(remote_to_local())],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for t in pending:
                    t.cancel()
            finally:
                decoy_stop.set()
                decoy_task.cancel()
                try:
                    await decoy_task
                except (asyncio.CancelledError, Exception):
                    pass

    except (
        websockets.exceptions.ConnectionClosedError,
        websockets.exceptions.InvalidURI,
        OSError,
        asyncio.TimeoutError,
    ) as exc:
        log.warning(f"⚠ Tunnel error — kill-switch: {exc}")
        monitor.record_kill_switch()
    except Exception as exc:
        log.error(f"Error: {exc}")
    finally:
        if session_key is not None:
            scrub_bytearray(session_key)
            del session_key
            gc.collect()
        monitor.print_summary()
        monitor.clear()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        log.info(f"Session closed: {peer}")

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    log.info("=" * 62)
    log.info("  Mafsal — Client")
    log.info(f"  Port           : {LOCAL_HOST}:{LOCAL_PORT}")
    log.info(f"  Colab URL      : {COLAB_WS_URL}")
    log.info(f"  Cipher         : AES-256-GCM + HKDF (per-packet)")
    log.info(f"  Key exchange   : X25519 Ephemeral (Forward Secrecy ✓)")
    log.info(f"  Auth           : HMAC-SHA256 (SHARED_KEY)")
    log.info(f"  Replay guard   : 64-bit sliding window (RFC 4303)")
    log.info(f"  Monitor        : InternalMonitor (RAM-only)")
    log.info(f"  Padding        : {'enabled' if TS_CONFIG.padding_enabled else 'disabled'}")
    log.info(f"  Jitter         : {'enabled' if TS_CONFIG.jitter_enabled else 'disabled'}")
    log.info(f"  Decoy traffic  : {'enabled' if TS_CONFIG.decoy_enabled else 'disabled'}")
    log.info("=" * 62)

    server = await asyncio.start_server(handle_tcp_client, LOCAL_HOST, LOCAL_PORT)
    async with server:
        log.info(f"TCP proxy ready → {LOCAL_HOST}:{LOCAL_PORT}")
        try:
            await server.serve_forever()
        finally:
            log.info("Scrubbing SHARED_KEY from memory...")
            scrub_key(SHARED_KEY)
            log.info("Cleanup complete.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Stopped by user.")
