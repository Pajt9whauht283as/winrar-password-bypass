"""ZIP container support: central directory parsing, ZipCrypto and WinZip AES targets."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from .rar5 import ArchiveError

EOCD_SIG = b"PK\x05\x06"
CEN_SIG = b"PK\x01\x02"
LOC_SIG = b"PK\x03\x04"

AES_EXTRA_ID = 0x9901
MAX_AES_PAYLOAD = 4 << 20


@dataclass
class ZipEntry:
    name: str
    size: int
    comp_size: int
    crc: int
    method: int
    flags: int
    header_offset: int
    is_dir: bool = False
    aes: bool = False
    aes_mode: int = 0            # 1 = AES-128, 2 = AES-192, 3 = AES-256
    aes_method: int = 8
    data_offset: int = 0
    salt: bytes = b""
    pv: bytes = b""
    cipher_len: int = 0
    auth: bytes = b""
    header12: bytes = b""
    check_byte: int = 0

    @property
    def encrypted(self) -> bool:
        return bool(self.flags & 0x0001)

    @property
    def kind(self) -> str:
        if not self.encrypted:
            return "open"
        return "aes" if self.aes else "zipcrypto"


class ZipArchive:
    format = "ZIP"

    def __init__(self, path: str):
        self.path = path
        self.entries: list[ZipEntry] = []
        self.headers_encrypted = False
        self.comment = ""
        self._fh = None
        self._parse()

    # -- parsing ----------------------------------------------------------

    def _parse(self) -> None:
        size = os.path.getsize(self.path)
        if size < 22:
            raise ArchiveError("not a ZIP file: %s" % self.path)
        tail_len = min(size, 66 * 1024)
        with open(self.path, "rb") as fh:
            fh.seek(size - tail_len)
            tail = fh.read(tail_len)
            pos = tail.rfind(EOCD_SIG)
            if pos < 0:
                raise ArchiveError("no end-of-central-directory record: %s" % self.path)
            (_, _, _, _, total, cd_size, cd_offset, comment_len) = struct.unpack(
                "<4s4H2LH", tail[pos:pos + 22])
            self.comment = tail[pos + 22:pos + 22 + comment_len].decode("utf-8", "replace")
            if cd_offset == 0xFFFFFFFF or total == 0xFFFF:
                cd_offset, total = self._zip64_tail(fh, size, tail, pos)
            fh.seek(cd_offset)
            directory = fh.read(cd_size)
        self._walk_directory(directory, total)

    def _zip64_tail(self, fh, size, tail, eocd_pos):
        locator = tail.rfind(b"PK\x06\x07", 0, eocd_pos)
        if locator < 0:
            raise ArchiveError("zip64 locator missing")
        offset = struct.unpack("<Q", tail[locator + 8:locator + 16])[0]
        fh.seek(offset)
        record = fh.read(56)
        if not record.startswith(b"PK\x06\x06"):
            raise ArchiveError("zip64 end record missing")
        total = struct.unpack("<Q", record[32:40])[0]
        cd_offset = struct.unpack("<Q", record[48:56])[0]
        return cd_offset, total

    def _walk_directory(self, directory: bytes, total: int) -> None:
        pos = 0
        while pos + 46 <= len(directory) and len(self.entries) < total:
            if directory[pos:pos + 4] != CEN_SIG:
                break
            flags, method = struct.unpack("<HH", directory[pos + 8:pos + 12])
            crc, comp_size, size = struct.unpack("<LLL", directory[pos + 16:pos + 28])
            name_len, extra_len, comment_len = struct.unpack("<HHH", directory[pos + 28:pos + 34])
            (header_offset,) = struct.unpack("<L", directory[pos + 42:pos + 46])
            name_bytes = directory[pos + 46:pos + 46 + name_len]
            extra = directory[pos + 46 + name_len:pos + 46 + name_len + extra_len]
            name = name_bytes.decode("utf-8" if flags & 0x0800 else "cp437", "replace")
            aes_mode, aes_method = self._aes_extra(extra)
            entry = ZipEntry(
                name=name,
                size=size,
                comp_size=comp_size,
                crc=crc,
                method=method,
                flags=flags,
                header_offset=header_offset,
                is_dir=name.endswith("/"),
                aes=aes_mode > 0,
                aes_mode=aes_mode,
                aes_method=aes_method or method,
            )
            if entry.encrypted and not entry.is_dir:
                self._read_crypto_material(entry)
            self.entries.append(entry)
            pos += 46 + name_len + extra_len + comment_len

    @staticmethod
    def _aes_extra(extra: bytes) -> tuple[int, int]:
        pos = 0
        while pos + 4 <= len(extra):
            tag, size = struct.unpack("<HH", extra[pos:pos + 4])
            body = extra[pos + 4:pos + 4 + size]
            if tag == AES_EXTRA_ID and len(body) >= 7:
                strength = body[4]
                actual_method = struct.unpack("<H", body[5:7])[0]
                if strength in (1, 2, 3):
                    return strength, actual_method
            pos += 4 + size
        return 0, 0

    def _read_crypto_material(self, entry: ZipEntry) -> None:
        with open(self.path, "rb") as fh:
            fh.seek(entry.header_offset)
            local = fh.read(30)
            if len(local) < 30 or local[:4] != LOC_SIG:
                return
            name_len, extra_len = struct.unpack("<HH", local[26:30])
            entry.data_offset = entry.header_offset + 30 + name_len + extra_len
            fh.seek(entry.data_offset)
            if entry.aes:
                salt_len = {1: 8, 2: 12, 3: 16}.get(entry.aes_mode, 0)
                head = fh.read(salt_len + 2)
                entry.salt = head[:salt_len]
                entry.pv = head[salt_len:salt_len + 2]
                entry.cipher_len = max(entry.comp_size - salt_len - 2 - 10, 0)
                if entry.cipher_len > 0:
                    fh.seek(entry.data_offset + salt_len + 2 + entry.cipher_len)
                    entry.auth = fh.read(10)
            else:
                entry.header12 = fh.read(12)
                if len(entry.header12) == 12:
                    if entry.flags & 0x0008:
                        dos_time = struct.unpack("<H", local[10:12])[0]
                        entry.check_byte = (dos_time >> 8) & 0xFF
                    else:
                        entry.check_byte = (entry.crc >> 24) & 0xFF

    # -- queries ----------------------------------------------------------

    @property
    def encrypted_entries(self) -> list[ZipEntry]:
        return [e for e in self.entries if e.encrypted and not e.is_dir]

    @property
    def total_size(self) -> int:
        return sum(e.size for e in self.entries if not e.is_dir)

    def __len__(self) -> int:
        return len([e for e in self.entries if not e.is_dir])

    def __iter__(self):
        return iter(self.entries)

    def zipcrypto_target(self) -> ZipEntry | None:
        for entry in self.encrypted_entries:
            if not entry.aes and len(entry.header12) == 12:
                return entry
        return None

    def aes_target(self) -> ZipEntry | None:
        for entry in self.encrypted_entries:
            if entry.aes and entry.pv:
                return entry
        return None

    def hashes(self) -> list[str]:
        """hashcat mode 13600 lines for WinZip AES entries."""
        lines = []
        for entry in self.encrypted_entries:
            if not entry.aes or not entry.pv:
                continue
            data_hex = ""
            if 0 < entry.cipher_len <= MAX_AES_PAYLOAD:
                with open(self.path, "rb") as fh:
                    fh.seek(entry.data_offset + len(entry.salt) + 2)
                    data_hex = fh.read(entry.cipher_len).hex()
            lines.append("$zip2$*0*%d*0*%s*%s*%x*%s*%s*$/zip2$" % (
                entry.aes_mode,
                entry.salt.hex(),
                entry.pv.hex(),
                entry.comp_size,
                data_hex,
                entry.auth.hex(),
            ))
        return lines

    def smallest_target(self):
        crypto = [e for e in self.encrypted_entries if not e.aes and e.header12]
        aes = [e for e in self.encrypted_entries if e.aes]
        pool = crypto or aes
        return min(pool, key=lambda e: (e.size, e.name)) if pool else None

    def unique_targets(self):
        target = self.smallest_target()
        return [target] if target else []

    def declared_crypto(self) -> str:
        kinds = {e.kind for e in self.encrypted_entries}
        if not kinds:
            return "none"
        if kinds == {"zipcrypto"}:
            return "ZipCrypto (legacy, no KDF)"
        if kinds == {"aes"}:
            modes = sorted({e.aes_mode for e in self.encrypted_entries})
            return "WinZip AES-%s" % "/".join({1: "128", 2: "192", 3: "256"}[m] for m in modes)
        return "mixed ZipCrypto + AES"
