"""RAR5 key derivation and password verification.

WinRAR derives a 32-byte key with PBKDF2-HMAC-SHA256 over the archive salt, then
stores the first 8 bytes of a folded check value in the header. Reproducing that
fold is enough to verify a guess without decrypting anything.
"""

from __future__ import annotations

import hashlib
import struct
import time

from .rar5 import Entry


def _iterations(log2: int) -> int:
    return (1 << log2) + 32


def derive(password: bytes, salt: bytes, log2: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, _iterations(log2), 32)


def check_from_key(key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("RAR5 key must be 32 bytes")
    w = struct.unpack("<8I", key)
    return struct.pack("<2I", w[0] ^ w[2] ^ w[4] ^ w[6], w[1] ^ w[3] ^ w[5] ^ w[7])


def pswcheck(password: str | bytes, salt: bytes, log2: int) -> bytes:
    if isinstance(password, str):
        password = password.encode("utf-8")
    return check_from_key(derive(password, salt, log2))


def verify(entry: Entry, password: str | bytes) -> bool:
    if not entry.encrypted:
        raise ValueError("entry %s has no encryption record" % entry.name)
    return pswcheck(password, entry.salt, entry.log2) == entry.check[:8]


def match(entry: Entry, password_hash: bytes) -> bool:
    """Compare a pre-computed check value, for hot loops."""
    return password_hash == entry.check[:8]


def benchmark(entry: Entry, rounds: int = 20) -> float:
    """Guesses per second for a single core on this machine."""
    password = b"benchmark"
    started = time.perf_counter()
    for _ in range(rounds):
        pswcheck(password, entry.salt, entry.log2)
    return rounds / max(time.perf_counter() - started, 1e-9)
