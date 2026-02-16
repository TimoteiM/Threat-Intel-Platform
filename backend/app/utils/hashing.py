"""
Hashing utilities for artifacts and favicon fingerprinting.
"""

from __future__ import annotations

import hashlib
import struct


def sha256_bytes(data: bytes) -> str:
    """SHA-256 hash of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_str(text: str) -> str:
    """SHA-256 hash of a string."""
    return sha256_bytes(text.encode("utf-8"))


def murmurhash3_32(data: bytes, seed: int = 0) -> int:
    """
    MurmurHash3 (32-bit) — used for favicon hashing.
    Compatible with the favicon hash used by Shodan.
    """
    length = len(data)
    n_blocks = length // 4

    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    h1 = seed

    # Body
    for i in range(n_blocks):
        k1 = struct.unpack_from("<I", data, i * 4)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    # Tail
    tail_idx = n_blocks * 4
    k1 = 0
    tail_size = length & 3

    if tail_size >= 3:
        k1 ^= data[tail_idx + 2] << 16
    if tail_size >= 2:
        k1 ^= data[tail_idx + 1] << 8
    if tail_size >= 1:
        k1 ^= data[tail_idx]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    # Finalization
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    return h1


def favicon_hash(data: bytes) -> str:
    """
    Compute favicon hash compatible with Shodan.
    Base64-encode the favicon data, then MurmurHash3 it.
    """
    import base64
    encoded = base64.encodebytes(data)
    return str(murmurhash3_32(encoded))
