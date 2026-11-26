"""Format sniffing and a uniform view over RAR5, ZIP and 7z archives."""

from __future__ import annotations

import os
from dataclasses import dataclass

from . import rar5, sevenzip, ziparchive
from .rar5 import ArchiveError

RAR5_SIG = b"Rar!\x1a\x07\x01\x00"
ZIP_SIG = b"PK\x03\x04"
SEVENZIP_SIG = b"7z\xbc\xaf\x27\x1c"

MODE_RAR5 = "13000"
MODE_SEVENZIP = "11600"
MODE_ZIP_AES = "13600"


def sniff(path: str) -> str:
    with open(path, "rb") as fh:
        head = fh.read(8)
    if head.startswith(RAR5_SIG):
        return "RAR5"
    if head.startswith(SEVENZIP_SIG):
        return "7Z"
    if head.startswith(ZIP_SIG):
        return "ZIP"
    return "unknown"


def open_archive(path: str):
    kind = sniff(path)
    if kind == "RAR5":
        return rar5.Archive.open(path)
    if kind == "7Z":
        return sevenzip.SevenZipArchive(path)
    if kind == "ZIP":
        return ziparchive.ZipArchive(path)
    raise ArchiveError("unsupported container: %s" % path)


def mode_for(archive) -> str | None:
    if isinstance(archive, rar5.Archive):
        return MODE_RAR5
    if isinstance(archive, sevenzip.SevenZipArchive):
        return MODE_SEVENZIP
    if isinstance(archive, ziparchive.ZipArchive):
        if archive.aes_target() is not None:
            return MODE_ZIP_AES
        return None          # ZipCrypto has no hashcat format we build here
    return None


def crypto_label(archive) -> str:
    if isinstance(archive, rar5.Archive):
        return "AES-256 RAR5 (PBKDF2-HMAC-SHA256)"
    if isinstance(archive, sevenzip.SevenZipArchive):
        target = archive.hash_target()
        if target and "unsupported" in target:
            return "7zAES (%s)" % target["unsupported"]
        return "7zAES (SHA-256 KDF)"
    if isinstance(archive, ziparchive.ZipArchive):
        return archive.declared_crypto()
    return "unknown"


def kdf_label(archive) -> str:
    if isinstance(archive, rar5.Archive):
        targets = archive.unique_targets()
        if not targets:
            return "-"
        entry = targets[0]
        return "%d iterations (log2=%d)" % (entry.iterations, entry.log2)
    if isinstance(archive, sevenzip.SevenZipArchive):
        target = archive.hash_target()
        if not target or "unsupported" in target:
            return "-"
        return "%d iterations (2^%d)" % (1 << target["cycles"], target["cycles"])
    if isinstance(archive, ziparchive.ZipArchive):
        entry = archive.aes_target() or archive.zipcrypto_target()
        if not entry:
            return "-"
        if entry.aes:
            return "PBKDF2-HMAC-SHA1, 1000 rounds (WinZip AES)"
        return "none (ZipCrypto has no KDF)"
    return "-"


def salt_label(archive) -> str:
    if isinstance(archive, rar5.Archive):
        targets = archive.unique_targets()
        return targets[0].salt.hex() if targets else "-"
    if isinstance(archive, sevenzip.SevenZipArchive):
        target = archive.hash_target()
        if not target or "unsupported" in target:
            return "-"
        return "none (7zAES uses IV + cycle count)"
    if isinstance(archive, ziparchive.ZipArchive):
        entry = archive.aes_target()
        return entry.salt.hex() if entry else "none"
    return "-"


def format_label(archive) -> str:
    if isinstance(archive, rar5.Archive):
        return "RAR5"
    if isinstance(archive, sevenzip.SevenZipArchive):
        return archive.format_label
    if isinstance(archive, ziparchive.ZipArchive):
        return "ZIP"
    return "unknown"


@dataclass
class Target:
    """One crackable thing, whatever the container."""

    archive: object
    entry: object | None
    mode: str | None
    hash_line: str | None
    kind: str          # rar5 | zipcrypto | zipaes | 7zip

    @property
    def name(self) -> str:
        entry = self.entry
        name = getattr(entry, "name", None) or os.path.basename(self.archive.path)
        return name

    @property
    def size(self) -> int:
        return getattr(self.entry, "size", 0)

    def supports_cpu(self) -> bool:
        return self.kind in ("rar5", "zipcrypto")


def pick_target(archive) -> Target | None:
    """Cheapest crackable target of an archive."""
    if isinstance(archive, rar5.Archive):
        entry = archive.smallest_target()
        if not entry:
            return None
        return Target(archive, entry, MODE_RAR5, entry.hashcat, "rar5")
    if isinstance(archive, sevenzip.SevenZipArchive):
        target = archive.hash_target()
        if not target or "unsupported" in target:
            return None
        line = archive.hashes()[0]
        return Target(archive, archive.smallest_target(), MODE_SEVENZIP, line, "7zip")
    if isinstance(archive, ziparchive.ZipArchive):
        crypto = archive.zipcrypto_target()
        if crypto is not None:
            return Target(archive, crypto, None, None, "zipcrypto")
        aes = archive.aes_target()
        if aes is not None:
            lines = archive.hashes()
            line = next((l for l in lines if aes.salt.hex() in l), lines[0] if lines else None)
            return Target(archive, aes, MODE_ZIP_AES, line, "zipaes")
    return None


def all_targets(archives: list) -> list[Target]:
    targets = []
    for archive in archives:
        target = pick_target(archive)
        if target is not None:
            targets.append(target)
    return targets
