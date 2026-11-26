"""RAR5 container parser: headers, extra records, encryption metadata.

Only the header chain is read. For `info` and `hash` the file is consumed up to the
first encrypted file header (a few kB), never the whole archive.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterator

RAR5_SIG = b"Rar!\x1a\x07\x01\x00"
RAR4_SIG = b"Rar!\x1a\x07\x00"
SEVENZIP_SIG = b"7z\xbc\xaf\x27\x1c"
ZIP_SIG = b"PK\x03\x04"

HDR_MAIN = 1
HDR_FILE = 2
HDR_SERVICE = 3
HDR_CRYPT = 4
HDR_END = 5

EX_CRYPT = 1
EX_HASH = 2
EX_HTIME = 3
EX_VERSION = 4
EX_REDIR = 5
EX_UOWNER = 6
EX_SUBDATA = 7

FLAG_EXTRA = 0x0001
FLAG_DATA = 0x0002

FILE_FLAG_DIRECTORY = 0x0001
FILE_FLAG_TIME = 0x0002
FILE_FLAG_CRC = 0x0004
FILE_FLAG_UNKNOWN_SIZE = 0x0008

METHOD_NAMES = {0: "store", 1: "fastest", 2: "fast", 3: "normal", 4: "good", 5: "best"}


class ArchiveError(Exception):
    """Raised for malformed containers or unsupported formats."""


def read_vint(buf: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ArchiveError("truncated variable-length integer")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


@dataclass
class Entry:
    name: str
    size: int
    is_dir: bool = False
    method: int = 0
    codec_version: int = 0
    mtime: int | None = None
    crc32: int | None = None
    data_size: int = 0
    log2: int | None = None
    salt: bytes = b""
    iv: bytes = b""
    check: bytes = b""

    @property
    def encrypted(self) -> bool:
        return bool(self.salt)

    @property
    def iterations(self) -> int:
        return 0 if self.log2 is None else (1 << self.log2) + 32

    @property
    def method_name(self) -> str:
        return METHOD_NAMES.get(self.method, "m%d" % self.method)

    @property
    def hashcat(self) -> str:
        if not self.encrypted:
            raise ArchiveError("entry is not encrypted: %s" % self.name)
        return "$rar5$16$%s$%02d$%s$8$%s" % (
            self.salt.hex(),
            self.log2,
            self.iv.hex(),
            self.check[:8].hex(),
        )


@dataclass
class Archive:
    path: str
    entries: list[Entry] = field(default_factory=list)
    headers_encrypted: bool = False
    header_salt: bytes = b""
    header_check: bytes = b""
    volume: bool = False
    solid: bool = False
    comment: str = ""

    # -- construction -----------------------------------------------------

    @classmethod
    def open(cls, path: str) -> "Archive":
        if not os.path.exists(path):
            raise ArchiveError("not found: %s" % path)
        if os.path.isdir(path):
            raise ArchiveError("is a directory: %s" % path)
        archive = cls(path=path)
        archive._parse()
        return archive

    def _parse(self) -> None:
        with open(self.path, "rb") as fh:
            head = fh.read(8)
            if head.startswith(RAR4_SIG):
                raise ArchiveError(
                    "%s is RAR4. Use hashcat mode 12500 and rar2john from john-jumbo."
                    % os.path.basename(self.path)
                )
            if head.startswith(SEVENZIP_SIG):
                raise ArchiveError(
                    "%s is 7z. Use hashcat mode 11600." % os.path.basename(self.path)
                )
            if head.startswith(ZIP_SIG):
                raise ArchiveError(
                    "%s is ZIP. ZipCrypto can be attacked with bkcrack (known plaintext), "
                    "AES with hashcat mode 13600." % os.path.basename(self.path)
                )
            if not head.startswith(RAR5_SIG):
                raise ArchiveError("not a RAR5 archive: %s" % self.path)
            fh.seek(len(RAR5_SIG))
            self._walk(fh)

    # -- block chain ------------------------------------------------------

    def _walk(self, fh) -> None:
        while True:
            if len(fh.read(4)) < 4:          # header crc32
                return
            block = self._read_block(fh)
            if block is None:
                return
            if self._handle(block) is False:
                return

    def _read_block(self, fh):
        header_size = self._read_vint(fh)
        if header_size is None:
            return None
        if not 0 < header_size <= (2 << 20):
            raise ArchiveError("corrupt header size %d in %s" % (header_size, self.path))
        data = fh.read(header_size)
        if len(data) < header_size:
            return None
        htype, pos = read_vint(data, 0)
        hflags, pos = read_vint(data, pos)
        extra_size = 0
        data_size = 0
        if hflags & FLAG_EXTRA:
            extra_size, pos = read_vint(data, pos)
        if hflags & FLAG_DATA:
            data_size, pos = read_vint(data, pos)
        body = data[pos:]
        if data_size:
            fh.seek(data_size, os.SEEK_CUR)
        return htype, hflags, body, extra_size, data_size

    @staticmethod
    def _read_vint(fh) -> int | None:
        first = fh.read(1)
        if not first:
            return None
        value = first[0] & 0x7F
        shift = 7
        while first[0] & 0x80:
            first = fh.read(1)
            if not first:
                return None
            value |= (first[0] & 0x7F) << shift
            shift += 7
        return value

    def _handle(self, block) -> bool | None:
        htype, hflags, body, extra_size, data_size = block
        if htype == HDR_END:
            return False
        if extra_size > len(body):
            return None
        main = body[: len(body) - extra_size] if extra_size else body
        extra = body[len(body) - extra_size:] if extra_size else b""

        if htype in (HDR_FILE, HDR_SERVICE):
            entry = self._parse_file(main, extra, data_size)
            if entry is not None:
                self.entries.append(entry)
            return None

        if htype == HDR_MAIN:
            if len(main) >= 2:
                self.volume = bool(main[1] & 0x0001)
            for rtype, rdata in iter_records(extra):
                if rtype == EX_CRYPT:
                    self.headers_encrypted = True
                    self.header_salt, self.header_check = parse_archive_crypt(rdata)
            return None

        if htype == HDR_CRYPT:
            self.headers_encrypted = True
            return False
        return None

    def _parse_file(self, main: bytes, extra: bytes, data_size: int) -> Entry | None:
        try:
            fflags, pos = read_vint(main, 0)
            usize, pos = read_vint(main, pos)
            _, pos = read_vint(main, pos)              # attributes
            mtime = None
            if fflags & FILE_FLAG_TIME:
                if pos + 4 > len(main):
                    return None
                mtime = int.from_bytes(main[pos:pos + 4], "little")
                pos += 4
            crc = None
            if fflags & FILE_FLAG_CRC:
                if pos + 4 > len(main):
                    return None
                crc = int.from_bytes(main[pos:pos + 4], "little")
                pos += 4
            comp, pos = read_vint(main, pos)
            method = (comp >> 7) & 0x0F
            version = comp & 0x3F
            solid = bool((comp >> 6) & 0x01)
            _, pos = read_vint(main, pos)              # host os
            name_len, pos = read_vint(main, pos)
            name = main[pos:pos + name_len].decode("utf-8", "replace")
        except (ArchiveError, IndexError):
            return None

        entry = Entry(
            name=name,
            size=usize,
            is_dir=bool(fflags & FILE_FLAG_DIRECTORY),
            method=method,
            codec_version=version,
            mtime=mtime,
            crc32=crc,
            data_size=data_size,
        )
        for rtype, rdata in iter_records(extra):
            if rtype == EX_CRYPT:
                try:
                    _, pos = read_vint(rdata, 0)       # version
                    _, pos = read_vint(rdata, pos)     # flags
                    entry.log2 = rdata[pos]
                    pos += 1
                    entry.salt = rdata[pos:pos + 16]
                    entry.iv = rdata[pos + 16:pos + 32]
                    entry.check = rdata[pos + 32:pos + 44]
                except (ArchiveError, IndexError):
                    entry.log2 = None
                break
        return entry

    # -- queries ----------------------------------------------------------

    @property
    def encrypted_entries(self) -> list[Entry]:
        return [e for e in self.entries if e.encrypted and not e.is_dir]

    def unique_targets(self) -> list[Entry]:
        """One entry per distinct KDF context (salt + cost)."""
        seen: set[tuple[bytes, int]] = set()
        targets: list[Entry] = []
        for entry in self.encrypted_entries:
            key = (entry.salt, entry.log2)
            if key in seen:
                continue
            seen.add(key)
            targets.append(entry)
        return targets

    def smallest_target(self) -> Entry | None:
        targets = self.encrypted_entries
        return min(targets, key=lambda e: (e.size, e.name)) if targets else None

    def hashes(self) -> list[str]:
        if self.headers_encrypted and not self.entries:
            raise ArchiveError(
                "header encryption is on: file names and per-file IVs are unavailable"
            )
        return [t.hashcat for t in self.unique_targets()]

    @property
    def total_size(self) -> int:
        return sum(e.size for e in self.entries if not e.is_dir)

    def __len__(self) -> int:
        return len([e for e in self.entries if not e.is_dir])

    def __iter__(self) -> Iterator[Entry]:
        return iter(self.entries)


def iter_records(extra: bytes) -> Iterator[tuple[int, bytes]]:
    pos = 0
    while pos < len(extra):
        try:
            size, pos = read_vint(extra, pos)
            rtype, pos = read_vint(extra, pos)
        except ArchiveError:
            return
        if pos + size > len(extra):
            return
        yield rtype, extra[pos:pos + size]
        pos += size


def parse_archive_crypt(rdata: bytes) -> tuple[bytes, bytes]:
    try:
        _, pos = read_vint(rdata, 0)
        _, pos = read_vint(rdata, pos)
        pos += 1                                   # kdf count
        salt = rdata[pos:pos + 16]
        check = rdata[pos + 16:pos + 28]
        return salt, check
    except (ArchiveError, IndexError):
        return b"", b""
