"""Archive forensics: fingerprints, timeline, compression profile, duplicate detection."""

from __future__ import annotations

import hashlib
import os
import time
from collections import Counter
from dataclasses import dataclass, field

from . import formats, rar5


def _sha256_file(path: str, limit: int = 64 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        digest.update(fh.read(limit))
    return digest.hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class Report:
    path: str
    format: str
    bytes_total: int
    files: int
    bytes_unpacked: int
    byte_fingerprint: str
    payload_fingerprint: str
    crypto: str
    kdf: str
    salt: str
    headers_encrypted: bool = False
    modified: float = 0.0
    compression: dict[str, int] = field(default_factory=dict)
    timeline: dict | None = None
    notes: list[str] = field(default_factory=list)
    encrypted_files: int = 0
    largest: tuple[str, int] | None = None
    duplicates: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        payload = self.__dict__.copy()
        payload["modified"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(self.modified))
        return payload


def analyze(path: str) -> Report:
    archive = formats.open_archive(path)
    entries = [e for e in archive if not getattr(e, "is_dir", False)]
    names = sorted((getattr(e, "name", ""), getattr(e, "size", 0)) for e in entries)
    payload = _sha256_text("\n".join("%s:%d" % pair for pair in names))

    packed = sum(getattr(e, "data_size", 0) or 0 for e in entries)
    if packed == 0:
        packed = os.path.getsize(path)

    report = Report(
        path=path,
        format=formats.format_label(archive),
        bytes_total=os.path.getsize(path),
        files=len(entries),
        bytes_unpacked=archive.total_size,
        byte_fingerprint=_sha256_file(path),
        payload_fingerprint=payload,
        crypto=formats.crypto_label(archive),
        kdf=formats.kdf_label(archive),
        salt=formats.salt_label(archive),
        headers_encrypted=getattr(archive, "headers_encrypted", False),
        modified=os.path.getmtime(path),
        encrypted_files=len(archive.encrypted_entries),
        largest=max(names, key=lambda pair: pair[1]) if names else None,
    )

    methods = Counter(getattr(e, "method_name", "-") for e in entries)
    report.compression = dict(methods)

    if isinstance(archive, rar5.Archive):
        times = [e.mtime for e in entries if getattr(e, "mtime", None)]
        if times:
            report.timeline = {
                "earliest": time.strftime("%Y-%m-%d %H:%M", time.gmtime(min(times))),
                "latest": time.strftime("%Y-%m-%d %H:%M", time.gmtime(max(times))),
                "span_days": round((max(times) - min(times)) / 86400.0, 1),
            }
        if archive.volume:
            report.notes.append("multivolume archive")
        if archive.comment:
            report.notes.append("archive comment present")

    seen: dict[tuple[str, int], int] = {}
    for entry in entries:
        key = (getattr(entry, "name", ""), getattr(entry, "size", 0))
        seen[key] = seen.get(key, 0) + 1
    report.duplicates = ["%s (%d)" % (name, count) for (name, _), count in seen.items() if count > 1]

    encrypted = report.encrypted_files
    if encrypted and encrypted < len(entries):
        report.notes.append("mixed encryption: %d of %d files encrypted" % (encrypted, len(entries)))
    if encrypted and report.headers_encrypted:
        report.notes.append("file names are encrypted (header encryption on)")
    if not encrypted:
        report.notes.append("no encrypted entries")
    if report.files and report.bytes_unpacked == 0:
        report.notes.append("all entries are empty")

    return report


def compare(reports: list[Report]) -> dict:
    """Group reports by payload and by bytes to expose repacks and re-downloads."""
    by_payload: dict[str, list[str]] = {}
    by_bytes: dict[str, list[str]] = {}
    for report in reports:
        by_payload.setdefault(report.payload_fingerprint, []).append(report.path)
        by_bytes.setdefault(report.byte_fingerprint, []).append(report.path)
    return {
        "repacks": [group for group in by_payload.values() if len(group) > 1],
        "identical": [group for group in by_bytes.values() if len(group) > 1],
        "unique": [paths[0] for paths in by_payload.values() if len(paths) == 1],
    }
