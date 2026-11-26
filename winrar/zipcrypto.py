"""ZipCrypto (PKWARE traditional encryption): cipher, verifier and a fast CPU engine.

ZipCrypto has no KDF: three 32-bit keys are advanced per password byte, so a guess costs
microseconds instead of milliseconds. That makes a Python engine competitive with hashcat
here, and lets masks and dictionary attacks run without any GPU.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import time
import zlib
from dataclasses import dataclass
from itertools import islice
from typing import Iterable, Iterator

CRC_TABLE: list[int] = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    CRC_TABLE.append(_c)


def crc32_byte(crc: int, byte: int) -> int:
    return ((crc >> 8) & 0x00FFFFFF) ^ CRC_TABLE[(crc ^ byte) & 0xFF]


def keys_from_password(password: bytes) -> tuple[int, int, int]:
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
    for byte in password:
        k0 = crc32_byte(k0, byte)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = crc32_byte(k2, (k1 >> 24) & 0xFF)
    return k0, k1, k2


def _keystream_byte(k2: int) -> int:
    temp = (k2 | 2) & 0xFFFF
    return ((temp * (temp ^ 1)) >> 8) & 0xFF


def decrypt(keys: tuple[int, int, int], data: bytes) -> bytes:
    k0, k1, k2 = keys
    out = bytearray(len(data))
    for index, value in enumerate(data):
        plain = value ^ _keystream_byte(k2)
        out[index] = plain
        k0 = crc32_byte(k0, plain)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = crc32_byte(k2, (k1 >> 24) & 0xFF)
    return bytes(out)


def check_byte(header12: bytes, keys: tuple[int, int, int]) -> int:
    """Last byte of the 12-byte encryption header, decrypted, is the password check."""
    k0, k1, k2 = keys
    plain = 0
    for value in header12[:11]:
        plain = value ^ _keystream_byte(k2)
        k0 = crc32_byte(k0, plain)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = crc32_byte(k2, (k1 >> 24) & 0xFF)
    return header12[11] ^ _keystream_byte(k2)


def plausible(header12: bytes, expected: int, password: str) -> bool:
    try:
        raw = password.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return check_byte(header12, keys_from_password(raw)) == expected


# ------------------------------------------------------------------ engine

_STATE: dict = {}


def _init_worker(spec: dict) -> None:
    _STATE.update(spec)


def _work(batch: list[str]) -> tuple[str | None, int]:
    header = _STATE["header"]
    expected = _STATE["expected"]
    full = _STATE.get("full")
    for password in batch:
        try:
            keys = keys_from_password(password.encode("utf-8"))
        except UnicodeEncodeError:
            continue
        if check_byte(header, keys) != expected:
            continue
        if full and not _verify_parts(**full, password=password):
            continue
        return password, len(batch)
    return None, len(batch)


@dataclass
class ZipResult:
    password: str | None
    tested: int
    elapsed: float

    @property
    def rate(self) -> float:
        return self.tested / max(self.elapsed, 1e-9)


class ZipCryptoEngine:
    """Same surface as engine.CpuEngine, different cipher."""

    def __init__(self, header12: bytes, expected: int, threads: int | None = None,
                 entry=None, path: str | None = None):
        self.header12 = header12
        self.expected = expected
        self.threads = threads or os.cpu_count() or 4
        self.full = None
        if entry is not None and path is not None:
            self.full = {
                "path": path,
                "data_offset": entry.data_offset,
                "comp_size": entry.comp_size,
                "method": entry.method,
                "crc": entry.crc,
                "header12": header12,
                "check": expected,
            }

    def crack(
        self,
        candidates: Iterable[str],
        total: int | None = None,
        label: str = "",
        quiet: bool = False,
    ) -> ZipResult:
        from . import ui

        started = time.monotonic()
        batch_size = max(self.threads * 4096, 8192)
        tested = 0
        progress = ui.Progress(total, label or "zipcrypto", stream=None) if not quiet else None

        pool = mp.Pool(
            processes=self.threads,
            initializer=_init_worker,
            initargs=({"header": self.header12, "expected": self.expected,
                       "full": self.full},),
        )
        try:
            for found, size in pool.imap_unordered(_work, self._batches(candidates, batch_size),
                                                   chunksize=1):
                tested += size
                if progress:
                    progress.update(min(tested, total) if total else tested)
                if found is not None:
                    pool.terminate()
                    return ZipResult(found, tested, time.monotonic() - started)
            pool.close()
        except KeyboardInterrupt:
            pool.terminate()
            if progress:
                progress.finish(ui.yellow("interrupted"))
            return ZipResult(None, tested, time.monotonic() - started)
        finally:
            pool.join()
        if progress:
            progress.finish()
        return ZipResult(None, tested, time.monotonic() - started)

    @staticmethod
    def _batches(stream: Iterable[str], size: int) -> Iterator[list[str]]:
        iterator = iter(stream)
        while True:
            batch = list(islice(iterator, size))
            if not batch:
                return
            yield batch


def benchmark(threads: int | None = None) -> float:
    """Guesses per second for this machine, ZipCrypto side."""
    header = bytes(range(12))
    engine = ZipCryptoEngine(header, 0xFF, threads=1)
    started = time.monotonic()
    count = 0
    while time.monotonic() - started < 0.3:
        keys_from_password(b"benchmark%d" % count)
        count += 1
    return count / (time.monotonic() - started)


def _verify_parts(path: str, data_offset: int, comp_size: int, method: int, crc: int,
                  header12: bytes, check: int, password: str) -> bool:
    """Header byte plus payload decrypt, inflate and CRC compare."""
    try:
        raw = password.encode("utf-8")
    except UnicodeEncodeError:
        return False
    keys = keys_from_password(raw)
    if check_byte(header12, keys) != check:
        return False
    try:
        with open(path, "rb") as fh:
            fh.seek(data_offset)
            blob = fh.read(comp_size)
    except OSError:
        return False
    if len(blob) < 12:
        return False
    plain = decrypt(keys, blob)[12:]
    try:
        if method == 0:
            data = plain
        elif method == 8:
            data = zlib.decompress(plain, -15)
        else:
            return False
    except zlib.error:
        return False
    return (zlib.crc32(data) & 0xFFFFFFFF) == crc


def verify_entry(path: str, entry, password: str, confirm: bool = True) -> bool:
    """Full check: header byte, then decrypt, inflate and compare the CRC.

    The header check alone is a 1-in-256 filter, so a hit is only accepted once the
    payload decompresses to the recorded CRC.
    """
    header12 = getattr(entry, "header12", b"")
    if len(header12) != 12:
        return False
    if not confirm:
        return plausible(header12, entry.check_byte, password)
    return _verify_parts(path, entry.data_offset, entry.comp_size, entry.method, entry.crc,
                         header12, entry.check_byte, password)


def inflate_and_check(payload: bytes, plain_crc: int, method: int) -> bool:
    """Second-stage confirmation: decrypt the body, inflate it, compare the CRC."""
    try:
        if method == 0:
            data = payload
        elif method == 8:
            data = zlib.decompress(payload, -15)
        else:
            return False
    except zlib.error:
        return False
    return (zlib.crc32(data) & 0xFFFFFFFF) == plain_crc
