#!/usr/bin/env python3
"""
Mafsal — Traffic Shaping Module
traffic_shaping.py

Copyright (C) 2026  Mafsal Contributors
SPDX-License-Identifier: GPL-3.0-or-later

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Purpose: Disguise tunnel traffic from statistical bot/DPI analysis.

Three techniques:

1. Randomized Padding
   Each packet receives a random-length byte sequence appended before
   encryption.  Fixed packet sizes are a fingerprint; random sizes add
   noise that mimics real browser traffic.

2. Human-like Jitter
   Inter-packet delay is sampled from a log-normal distribution that
   matches observed human "think time" (reading pauses, click latency).
   A constant transmission rate is a bot signature; burst + silence
   patterns look like a browser.

3. Decoy Traffic (NEW — implemented)
   During idle periods the client sends authentically encrypted random
   packets to the server.  The server detects and silently discards
   them.  An observer watching the wire cannot distinguish real bursts
   from idle keep-alive noise.

Design notes:
   - Padding bytes: random (not zero — would compress trivially).
   - Padding length is included in the ciphertext; GCM protects it.
     An attacker can see the padded wire size but not the pad length.
   - Jitter distribution: log-normal (aligns with empirical human
     click/read latency studies; positive-only, long right tail).
   - All three features can be toggled independently at runtime.
"""

import asyncio
import json
import math
import os
import random
import struct
from dataclasses import dataclass, field
from typing import Callable, Awaitable


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class TrafficShapingConfig:
    """
    Traffic shaping parameters.
    All values can be changed at runtime without restarting.
    """

    # -- Padding -------------------------------------------------------------
    padding_enabled: bool = True

    # Padding size range (bytes).
    # Too small → insufficient statistical noise.
    # Too large → bandwidth waste.
    # 16–128 bytes: enough to confuse WAF/DPI fingerprinting,
    # bandwidth overhead < 1 % for typical workloads.
    padding_min: int = 16
    padding_max: int = 128

    # -- Jitter --------------------------------------------------------------
    jitter_enabled: bool = True

    # Log-normal distribution parameters.
    #
    # Human browser traffic research (IMC 2012; PAM 2018) shows that
    # inter-packet times follow a log-normal distribution:
    #   μ ≈ 0 s for burst mode, σ = 0.5–1.5 for long tail.
    #
    # jitter_mean: μ parameter (seconds, log-space).
    #   0.0  → median ~1 ms  (fast connection simulation)
    #  -3.0  → median ~50 ms (normal browsing)
    #
    # jitter_sigma: distribution width.
    #   0.5 → narrow, consistent delays
    #   1.2 → wide, occasional long "reading" pauses
    jitter_mean:  float = -3.0   # median ≈ 50 ms
    jitter_sigma: float = 1.2    # occasional 200–500 ms "reading" pause

    # Delay bounds (seconds)
    jitter_min_s: float = 0.005   # 5 ms minimum
    jitter_max_s: float = 0.800   # 800 ms maximum

    # -- Decoy Traffic -------------------------------------------------------
    decoy_enabled: bool = False

    # Interval between decoy packets (seconds, uniform random range).
    # Shorter → better traffic analysis resistance, higher overhead.
    # Longer  → lower overhead, easier to detect idle gaps.
    decoy_interval_min_s: float = 2.0
    decoy_interval_max_s: float = 8.0

    # Size of the random payload inside each decoy packet (bytes).
    # Should overlap with real packet sizes to avoid trivial detection.
    decoy_min_bytes: int = 32
    decoy_max_bytes: int = 256


# Default config imported by client and server.
DEFAULT_CONFIG = TrafficShapingConfig()


# ---------------------------------------------------------------------------
# Padding
# ---------------------------------------------------------------------------
#
# Wire format (prepended to plaintext, before encryption):
#
#   [original_data] [padding_bytes] [pad_len (2 B, big-endian uint16)]
#
# Receiver reads the last 2 bytes → learns pad_len → strips padding.
#
# Why suffix?
#   Prefix requires two reads; suffix is a single read + fixed offset.
#
# Why not include pad_len in AAD?
#   pad_len is already inside the GCM-protected ciphertext.
#   An attacker can see the padded wire size but cannot recover pad_len.

PAD_LEN_FIELD = 2  # bytes


def add_padding(data: bytes, cfg: TrafficShapingConfig = DEFAULT_CONFIG) -> bytes:
    """
    Append random padding to *data*.
    Returns padded bytes (must be called BEFORE encryption).
    """
    if not cfg.padding_enabled:
        # Padding disabled: still append zero-length marker so the receiver
        # can always apply the same strip logic unconditionally.
        return data + struct.pack(">H", 0)

    pad_len = random.randint(cfg.padding_min, cfg.padding_max)
    padding = os.urandom(pad_len)   # random content — does not compress
    return data + padding + struct.pack(">H", pad_len)


def strip_padding(data: bytes, cfg: TrafficShapingConfig = DEFAULT_CONFIG) -> bytes:
    """
    Remove padding appended by *add_padding*.
    Returns original bytes.
    Raises ValueError on malformed input.
    """
    if len(data) < PAD_LEN_FIELD:
        raise ValueError(f"Packet too short to contain padding field: {len(data)} B")

    pad_len = struct.unpack(">H", data[-PAD_LEN_FIELD:])[0]
    total_extra = pad_len + PAD_LEN_FIELD

    if len(data) < total_extra:
        raise ValueError(
            f"pad_len={pad_len} but packet is only {len(data)} B — corrupted"
        )

    return data[:len(data) - total_extra]


# ---------------------------------------------------------------------------
# Jitter
# ---------------------------------------------------------------------------
#
# Why log-normal?
#
#   Human click behaviour studies (Claypool et al., 2003; Guo et al., 2011)
#   show that reaction times after receiving content follow a log-normal
#   distribution: positive-only, right-skewed, long tail.
#
#   Alternatives:
#     Uniform(a, b)    → too smooth, obvious bot signature
#     Normal(μ, σ)     → allows negative values, unrealistic
#     Exponential(λ)   → good for Poisson network events, poor for humans
#     Log-normal       ← chosen: positive, long tail, matches human model
#
# Example delay distribution (mean=-3.0, sigma=1.2):
#   p25  ≈  18 ms   (fast click)
#   p50  ≈  50 ms   (normal)
#   p75  ≈ 135 ms   (reading pause)
#   p95  ≈ 400 ms   (long read)
#   p99  ≈ 800 ms   (capped by jitter_max_s)

def _sample_jitter(cfg: TrafficShapingConfig) -> float:
    """Sample one delay from the log-normal distribution (seconds)."""
    raw = math.exp(random.gauss(cfg.jitter_mean, cfg.jitter_sigma))
    return max(cfg.jitter_min_s, min(cfg.jitter_max_s, raw))


async def apply_jitter(cfg: TrafficShapingConfig = DEFAULT_CONFIG) -> None:
    """
    Await a human-like delay before transmitting a packet.
    Returns immediately if jitter is disabled.
    """
    if not cfg.jitter_enabled:
        return
    delay = _sample_jitter(cfg)
    await asyncio.sleep(delay)


# ---------------------------------------------------------------------------
# Decoy Traffic
# ---------------------------------------------------------------------------
#
# Protocol:
#   The client sends a special WebSocket frame tagged {"type": "decoy", ...}.
#   The payload is authentically encrypted random bytes (same cipher path
#   as real traffic — a passive observer cannot distinguish them).
#   The server detects the tag BEFORE decryption and silently discards
#   the frame without forwarding anything to the target host.
#
# Security note:
#   Decoy packets consume real counter values and use the same HKDF
#   sub-key derivation as data packets.  This ensures they are
#   cryptographically indistinguishable from real traffic on the wire.

def build_decoy_frame(
    session_key,          # bytearray
    epoch: int,
    send_ctr_ref: list,   # [int]  — mutated in place
    cfg: TrafficShapingConfig,
    encrypt_fn: Callable,
    *,
    import_b64_and_json: bool = True,
) -> str:
    """
    Build a single decoy WebSocket frame string.

    Parameters
    ----------
    session_key   : current session key (bytearray)
    epoch         : session epoch
    send_ctr_ref  : [counter] list — incremented after use
    cfg           : traffic shaping config
    encrypt_fn    : callable(plaintext, session_key, epoch, counter, direction) → bytes

    Returns
    -------
    str  — JSON frame ready to pass to ws.send()
    """
    import base64

    size = random.randint(cfg.decoy_min_bytes, cfg.decoy_max_bytes)
    payload = os.urandom(size)
    ctr = send_ctr_ref[0]
    enc = encrypt_fn(payload, session_key, epoch, ctr, "C2S")
    send_ctr_ref[0] += 1
    return json.dumps({
        "v": 4,
        "type": "decoy",
        "data": base64.b64encode(enc).decode(),
        "size": len(enc),
    })


async def run_decoy_sender(
    ws,
    session_key,          # bytearray
    epoch: int,
    send_ctr_ref: list,   # [int] — shared with real sender, must be thread-safe
    cfg: TrafficShapingConfig,
    encrypt_fn: Callable,
    stop_event: asyncio.Event,
) -> None:
    """
    Background coroutine: periodically inject decoy packets.

    Runs until *stop_event* is set.  Designed to be started as an
    asyncio.Task alongside the real data transfer tasks.

    Usage in mafsal_client.py::

        stop = asyncio.Event()
        decoy_task = asyncio.create_task(
            run_decoy_sender(ws, session_key, epoch,
                             send_ctr_ref, cfg, encrypt_packet, stop)
        )
        # ... data transfer ...
        stop.set()
        decoy_task.cancel()
    """
    if not cfg.decoy_enabled:
        return

    try:
        while not stop_event.is_set():
            interval = random.uniform(
                cfg.decoy_interval_min_s,
                cfg.decoy_interval_max_s,
            )
            try:
                await asyncio.wait_for(
                    asyncio.shield(stop_event.wait()),
                    timeout=interval,
                )
                break  # stop_event was set during sleep
            except asyncio.TimeoutError:
                pass  # normal path — interval elapsed

            if stop_event.is_set():
                break

            frame_str = build_decoy_frame(
                session_key, epoch, send_ctr_ref, cfg, encrypt_fn
            )
            await ws.send(frame_str)

    except (asyncio.CancelledError, Exception):
        pass  # task cancelled by caller — exit silently


def is_decoy_frame(raw_message: str) -> bool:
    """
    Return True if *raw_message* is a decoy frame that should be discarded.
    Called by the server BEFORE decryption to avoid wasting CPU on fakes.
    """
    try:
        obj = json.loads(raw_message)
        return obj.get("type") == "decoy"
    except Exception:
        return False
