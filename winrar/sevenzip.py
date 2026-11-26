"""7-Zip container support: header parsing and hashcat mode 11600 ($7z$) emission.

Only the header chain is read. Compressed headers (kEncodedHeader) are inflated with the
stdlib lzma module, so no external 7z binary is needed for inspection or hashing.
"""

from __future__ import annotations

import lzma
import os
import struct
from dataclasses import dataclass, field

from .rar5 import ArchiveError

MAGIC = b"7z\xbc\xaf\x27\x1c"

END = 0x00
HEADER = 0x01
ARCHIVE_PROPERTIES = 0x02
ADD_STREAMS_INFO = 0x03
MAIN_STREAMS_INFO = 0x04
FILES_INFO = 0x05
PACK_INFO = 0x06
UNPACK_INFO = 0x07
SUBSTREAMS_INFO = 0x08
SIZE = 0x09
CRC = 0x0A
FOLDER = 0x0B
UNPACK_SIZE = 0x0C
NUM_UNPACK_STREAM = 0x0D
EMPTY_STREAM = 0x0E
EMPTY_FILE = 0x0F
ANTI = 0x10
NAME = 0x11
MTIME = 0x14
ENCODED_HEADER = 0x17
DUMMY = 0x19

AES_ID = b"\x06\xf1\x07\x01"
LZMA1_ID = b"\x03\x01\x01"
LZMA2_ID = b"\x21"
DEFLATE_ID = b"\x04\x01\x08"
COPY_ID = b"\x00"

CODER_KIND = {LZMA1_ID: 1, LZMA2_ID: 2, DEFLATE_ID: 7, COPY_ID: 0}
CODER_NAME = {1: "LZMA1", 2: "LZMA2", 7: "DEFLATE", 0: "copy"}

MAX_PACK_FOR_HASH = 8 << 20


class Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def peek(self) -> int:
        return self.data[self.pos] if self.pos < len(self.data) else -1

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise ArchiveError("7z header truncated")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def number(self) -> int:
        first = self.byte()
        mask = 0x80
        value = 0
        for index in range(8):
            if first & mask == 0:
                high = first & (mask - 1)
                return value | (high << (index * 8))
            value |= self.byte() << (index * 8)
            mask >>= 1
        return value

    def u32(self) -> int:
        raw = self.data[self.pos:self.pos + 4]
        if len(raw) < 4:
            raise ArchiveError("7z header truncated")
        self.pos += 4
        return struct.unpack("<L", raw)[0]

    def u64(self) -> int:
        raw = self.data[self.pos:self.pos + 8]
        if len(raw) < 8:
            raise ArchiveError("7z header truncated")
        self.pos += 8
        return struct.unpack("<Q", raw)[0]

    def bytes(self, count: int) -> bytes:
        raw = self.data[self.pos:self.pos + count]
        if len(raw) < count:
            raise ArchiveError("7z header truncated")
        self.pos += count
        return raw

    def bitvector(self, count: int) -> list[bool]:
        out = []
        value = 0
        mask = 0
        for _ in range(count):
            if mask == 0:
                value = self.byte()
                mask = 0x80
            out.append(bool(value & mask))
            mask >>= 1
        return out


@dataclass
class Coder:
    codec_id: bytes
    properties: bytes = b""
    num_in: int = 1
    num_out: int = 1


@dataclass
class Folder:
    coders: list[Coder] = field(default_factory=list)
    unpack_sizes: list[int] = field(default_factory=list)
    crc: int | None = None
    num_substreams: int = 1
    substream_sizes: list[int] = field(default_factory=list)
    substream_crcs: list[int | None] = field(default_factory=list)

    @property
    def unpack_size(self) -> int:
        return self.unpack_sizes[-1] if self.unpack_sizes else 0

    @property
    def total_out(self) -> int:
        return sum(c.num_out for c in self.coders)

    @property
    def total_in(self) -> int:
        return sum(c.num_in for c in self.coders)

    @property
    def aes(self) -> Coder | None:
        for coder in self.coders:
            if coder.codec_id == AES_ID:
                return coder
        return None

    @property
    def kind(self) -> str:
        return "aes" if self.aes else "open"


@dataclass
class Entry:
    name: str
    size: int = 0
    is_dir: bool = False
    encrypted: bool = False
    folder: int | None = None
    mtime: int | None = None

    @property
    def method_name(self) -> str:
        return "AES" if self.encrypted else "-"


def aes_properties(props: bytes) -> tuple[int, bytes, bytes]:
    """Return (num_cycles_power, salt, iv) from a 7zAES coder property blob."""
    if not props:
        return 19, b"", b"\x00" * 16
    first = props[0]
    cycles = first & 0x3F
    if first & 0xC0 == 0:
        return cycles, b"", b"\x00" * 16
    salt_len = (first >> 7) & 1
    iv_len = (first >> 6) & 1
    second = props[1] if len(props) > 1 else 0
    salt_len += second >> 4
    iv_len += second & 0x0F
    offset = 2
    salt = props[offset:offset + salt_len]
    offset += salt_len
    iv = props[offset:offset + iv_len].ljust(16, b"\x00")[:16]
    return cycles, salt, iv


class SevenZipArchive:
    format = "7Z"

    def __init__(self, path: str):
        self.path = path
        self.entries: list[Entry] = []
        self.folders: list[Folder] = []
        self.pack_sizes: list[int] = []
        self.pack_pos = 0
        self.position_after_header = 32
        self.headers_encrypted = False
        self.version = (0, 4)
        self._parse()

    # -- header -----------------------------------------------------------

    def _parse(self) -> None:
        with open(self.path, "rb") as fh:
            blob = fh.read()
        if not blob.startswith(MAGIC):
            raise ArchiveError("not a 7z archive: %s" % self.path)
        self.version = (blob[6], blob[7])
        next_offset, next_size, next_crc = struct.unpack("<QQI", blob[12:32])
        start = 32 + next_offset
        raw = blob[start:start + next_size]
        if len(raw) != next_size:
            raise ArchiveError("7z header out of bounds")
        reader = Reader(raw)
        if reader.peek() == ENCODED_HEADER:
            reader.byte()
            streams = self._parse_streams(reader, blob, start)
            raw = self._decode_header(streams, blob, start)
            reader = Reader(raw)
        self._parse_header(reader, blob, start)

    def _decode_header(self, streams, blob, base) -> bytes:
        folder = streams["unpack"][0]
        size = streams["pack_sizes"][0]
        offset = self.position_after_header + streams["pack_pos"]
        data = blob[offset:offset + size]
        coder = folder.coders[0]
        if coder.codec_id != LZMA1_ID:
            raise ArchiveError("encoded header uses unsupported coder")
        props = coder.properties
        if len(props) < 5:
            raise ArchiveError("lzma properties truncated")
        dict_size = int.from_bytes(props[1:5], "little") or (1 << 24)
        filters = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size,
                    "lc": props[0] % 9, "lp": (props[0] // 9) % 5, "pb": props[0] // 45}]
        expected = folder.unpack_sizes[-1] if folder.unpack_sizes else 0
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
        try:
            if expected:
                return decoder.decompress(data, max_length=expected)
            return decoder.decompress(data)
        except lzma.LZMAError:
            if decoder.eof or decoder.needs_input:
                raise ArchiveError("could not inflate the 7z header")
            return decoder.decompress(b"", max_length=expected or 1)

    def _parse_header(self, reader: Reader, blob: bytes, base: int) -> None:
        kind = reader.byte()
        if kind != HEADER:
            raise ArchiveError("unexpected 7z header marker 0x%02x" % kind)
        streams = None
        files = None
        while not reader.eof():
            marker = reader.peek()
            if marker == END:
                reader.byte()
                break
            if marker == ARCHIVE_PROPERTIES:
                reader.byte()
                while reader.peek() != END:
                    reader.number()
                    reader.bytes(reader.number())
                reader.byte()
            elif marker == ADD_STREAMS_INFO:
                reader.byte()
                self._parse_streams(reader, blob, base)
            elif marker == MAIN_STREAMS_INFO:
                reader.byte()
                streams = self._parse_streams(reader, blob, base)
            elif marker == FILES_INFO:
                reader.byte()
                files = self._parse_files(reader)
            else:
                reader.byte()
        if streams:
            self.folders = streams["unpack"]
            self.pack_sizes = streams["pack_sizes"]
            self.pack_pos = streams["pack_pos"]
        self._map_files(files or [])

    def _parse_streams(self, reader: Reader, blob: bytes, base: int) -> dict:
        result = {"pack_pos": 0, "pack_sizes": [], "unpack": []}
        while not reader.eof():
            marker = reader.peek()
            if marker == END:
                reader.byte()
                break
            if marker == PACK_INFO:
                reader.byte()
                result["pack_pos"] = reader.number()
                count = reader.number()
                while reader.peek() != END:
                    tag = reader.byte()
                    if tag == SIZE:
                        result["pack_sizes"] = [reader.number() for _ in range(count)]
                    elif tag == CRC:
                        self._read_digests(reader, count)
                    else:
                        raise ArchiveError("bad pack info tag 0x%02x" % tag)
                reader.byte()
            elif marker == UNPACK_INFO:
                reader.byte()
                if reader.byte() != FOLDER:
                    raise ArchiveError("missing kFolder")
                count = reader.number()
                external = reader.byte()
                if external:
                    raise ArchiveError("external folder definitions are not supported")
                for _ in range(count):
                    result["unpack"].append(self._parse_folder(reader))
                tag = reader.byte()
                if tag != UNPACK_SIZE:
                    raise ArchiveError("missing kCodersUnpackSize")
                for folder in result["unpack"]:
                    folder.unpack_sizes = [reader.number() for _ in range(folder.total_out)]
                tag = reader.peek()
                if tag == CRC:
                    reader.byte()
                    crcs = self._read_digests(reader, count)
                    for folder, value in zip(result["unpack"], crcs):
                        folder.crc = value
                if reader.byte() != END:
                    raise ArchiveError("bad unpack info tail")
            elif marker == SUBSTREAMS_INFO:
                reader.byte()
                self._parse_substreams(reader, result["unpack"])
            else:
                break
        return result

    def _parse_folder(self, reader: Reader) -> Folder:
        folder = Folder()
        coders = reader.number()
        for _ in range(coders):
            flags = reader.byte()
            id_size = flags & 0x0F
            is_complex = flags & 0x10
            has_props = flags & 0x20
            codec_id = reader.bytes(id_size)
            coder = Coder(codec_id=codec_id)
            if is_complex:
                coder.num_in = reader.number()
                coder.num_out = reader.number()
            if has_props:
                coder.properties = reader.bytes(reader.number())
            folder.coders.append(coder)
        bind_pairs = folder.total_out - 1
        for _ in range(bind_pairs):
            reader.number()
            reader.number()
        packed = folder.total_in - bind_pairs
        if packed > 1:
            for _ in range(packed):
                reader.number()
        return folder

    def _parse_substreams(self, reader: Reader, folders: list[Folder]) -> None:
        counts = [1] * len(folders)
        while not reader.eof():
            marker = reader.peek()
            if marker == END:
                reader.byte()
                break
            if marker == NUM_UNPACK_STREAM:
                reader.byte()
                counts = [reader.number() for _ in folders]
            elif marker == SIZE:
                reader.byte()
                for index, folder in enumerate(folders):
                    take = counts[index] - 1
                    folder.substream_sizes = [reader.number() for _ in range(max(take, 0))]
            elif marker == CRC:
                reader.byte()
                values = self._read_digests(reader, sum(counts))
                cursor = 0
                for index, folder in enumerate(folders):
                    folder.substream_crcs = values[cursor:cursor + counts[index]]
                    cursor += counts[index]
            else:
                break
        for index, folder in enumerate(folders):
            folder.num_substreams = counts[index]
            if len(folder.substream_sizes) < counts[index]:
                remaining = folder.unpack_size - sum(folder.substream_sizes)
                folder.substream_sizes.append(max(remaining, 0))

    @staticmethod
    def _read_digests(reader: Reader, count: int) -> list[int | None]:
        if count <= 0:
            return []
        all_defined = reader.byte()
        present = [True] * count if all_defined else reader.bitvector(count)
        return [reader.u32() if present[index] else None for index in range(count)]

    def _parse_files(self, reader: Reader) -> list[dict]:
        count = reader.number()
        files = [{"name": "", "empty": False} for _ in range(count)]
        empty_streams: list[bool] = []
        while not reader.eof():
            marker = reader.peek()
            if marker == END:
                reader.byte()
                break
            kind = reader.byte()
            size = reader.number()
            end = reader.pos + size
            if kind == EMPTY_STREAM:
                empty_streams = reader.bitvector(count)
                for index, value in enumerate(empty_streams):
                    files[index]["empty"] = value
            elif kind == EMPTY_FILE:
                flags = reader.bitvector(sum(1 for v in empty_streams if v))
                position = 0
                for index, is_empty_stream in enumerate(empty_streams):
                    if is_empty_stream:
                        files[index]["dir"] = not flags[position]
                        position += 1
            elif kind == NAME:
                external = reader.byte()
                if external:
                    raise ArchiveError("external names unsupported")
                blob = reader.bytes(end - reader.pos)
                names = blob.decode("utf-16-le", "replace").split("\x00")
                for index in range(count):
                    files[index]["name"] = names[index] if index < len(names) else ""
            reader.pos = end
        return files

    def _map_files(self, files: list[dict]) -> None:
        indices = [(i, f) for i, f in enumerate(files)]
        folder = 0
        substream = 0
        for _, info in indices:
            name = info.get("name") or ""
            entry = Entry(name=name, is_dir=bool(info.get("dir")), encrypted=False)
            if not info.get("empty") and folder < len(self.folders):
                current = self.folders[folder]
                sizes = current.substream_sizes or current.unpack_sizes[-1:]
                entry.size = sizes[substream] if substream < len(sizes) else 0
                entry.folder = folder
                entry.encrypted = current.aes is not None
                substream += 1
                if substream >= current.num_substreams:
                    folder += 1
                    substream = 0
            self.entries.append(entry)

    # -- queries ----------------------------------------------------------

    @property
    def encrypted_entries(self) -> list[Entry]:
        return [e for e in self.entries if e.encrypted and not e.is_dir]

    @property
    def total_size(self) -> int:
        return sum(e.size for e in self.entries if not e.is_dir)

    def __len__(self) -> int:
        return len([e for e in self.entries if not e.is_dir])

    def __iter__(self):
        return iter(self.entries)

    @property
    def format_label(self) -> str:
        label = "7Z %d.%d" % self.version
        kinds = {CODER_NAME.get(CODER_KIND.get(c.codec_id, -1), c.codec_id.hex())
                 for folder in self.folders for c in folder.coders}
        if kinds:
            label += " (" + ", ".join(sorted(kinds)) + ")"
        return label

    def aes_folder(self) -> tuple[int, Folder] | None:
        for index, folder in enumerate(self.folders):
            if folder.aes is not None and folder.unpack_sizes:
                return index, folder
        return None

    def hash_target(self) -> dict | None:
        """Everything needed to rebuild a $7z$ hash line, or None when unsupported."""
        found = self.aes_folder()
        if not found:
            return None
        index, folder = found
        aes = folder.aes
        cycles, salt, iv = aes_properties(aes.properties)
        if salt:
            return {"unsupported": "AES salt is set; hashcat mode 11600 expects saltless 7zAES"}
        if index >= len(self.pack_sizes):
            return {"unsupported": "pack sizes missing for the encrypted folder"}
        pack_size = self.pack_sizes[index] if index < len(self.pack_sizes) else 0
        if pack_size <= 0:
            pack_size = sum(self.pack_sizes) if len(self.pack_sizes) == 1 else 0
        if pack_size > MAX_PACK_FOR_HASH:
            return {"unsupported": "encrypted stream is %s, over the 8 MiB hashcat buffer"
                                   % _human(pack_size)}
        crc = None
        if folder.substream_crcs:
            crc = folder.substream_crcs[0]
        if crc is None:
            crc = folder.crc
        if crc is None:
            crc = 0
        compressors = [c for c in folder.coders if c.codec_id != AES_ID]
        data_type = 0
        coder_attributes = b""
        if compressors:
            main = compressors[0]
            data_type = CODER_KIND.get(main.codec_id, -1)
            if data_type < 0:
                return {"unsupported": "coder %s is not supported by mode 11600"
                                       % main.codec_id.hex()}
            coder_attributes = main.properties
        unpack_size = folder.unpack_sizes[-1] if folder.unpack_sizes else 0
        crc_len = folder.substream_sizes[0] if folder.substream_sizes else unpack_size
        return {
            "folder": index,
            "cycles": cycles,
            "iv": iv,
            "crc": crc,
            "pack_size": pack_size,
            "unpack_size": unpack_size,
            "data_type": data_type,
            "coder_attributes": coder_attributes,
            "crc_len": crc_len,
            "pack_offset": self.position_after_header + self.pack_pos,
        }

    def hashes(self) -> list[str]:
        target = self.hash_target()
        if not target:
            return []
        if "unsupported" in target:
            raise ArchiveError(target["unsupported"])
        with open(self.path, "rb") as fh:
            fh.seek(target["pack_offset"])
            payload = fh.read(target["pack_size"])
        line = "$7z$%d$%d$0$$%d$%s$%d$%d$%d$%s" % (
            target["data_type"],
            target["cycles"],
            len(target["iv"]),
            target["iv"].hex(),
            target["crc"],
            target["pack_size"],
            target["unpack_size"],
            payload.hex(),
        )
        if target["data_type"] != 0:
            line += "$%d$%s" % (target["crc_len"], target["coder_attributes"].hex())
        return [line]

    def smallest_target(self) -> Entry | None:
        pool = self.encrypted_entries
        return min(pool, key=lambda e: (e.size, e.name)) if pool else None

    def unique_targets(self) -> list[Entry]:
        target = self.smallest_target()
        return [target] if target else []


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return "%.0f %s" % (value, unit)
        value /= 1024.0
    return "%.1f TB" % value
