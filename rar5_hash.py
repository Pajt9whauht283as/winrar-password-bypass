#!/usr/bin/env python3
"""
rar5_hash.py - RAR5 hash extractor, verifier and wordlist cracker for WinRAR archives.

No dependencies. No WinRAR install required for `list`, `hash` and `verify`.

Commands
    list    <archive.rar>                 show what is inside without the password
    hash    <archive.rar> [-o file]       emit hashcat hashes (mode 13000)
    verify  <archive.rar> <password>      check a password locally, no GPU needed
    crack   <archive.rar> -w wordlist.txt crack a wordlist on the CPU (multiprocess)

The archive never has to be fully downloaded: `hash` only needs the headers, so a
range-request over the first few hundred KB is enough for remote files.
"""

import argparse
import hashlib
import os
import struct
import sys
import time

RAR5_SIG = b"Rar!\x1a\x07\x01\x00"
RAR4_SIG = b"Rar!\x1a\x07\x00"

HDR_MAIN = 1
HDR_FILE = 2
HDR_SERVICE = 3
HDR_CRYPT = 4
HDR_END = 5

EX_CRYPT = 1

FLAG_EXTRA = 0x0001
FLAG_DATA = 0x0002


class ArchiveError(Exception):
    pass


def vint(buf, pos):
    """Read a RAR5 variable-length integer."""
    value = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ArchiveError("truncated header")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


class Entry:
    __slots__ = ("name", "is_dir", "size", "log2", "salt", "iv", "check", "data_size")

    def __init__(self, name, is_dir, size, log2, salt, iv, check, data_size):
        self.name = name
        self.is_dir = is_dir
        self.size = size
        self.log2 = log2
        self.salt = salt
        self.iv = iv
        self.check = check
        self.data_size = data_size

    @property
    def hashcat(self):
        return "$rar5$16$%s$%02d$%s$8$%s" % (
            self.salt.hex(), self.log2, self.iv.hex(), self.check[:8].hex()
        )


class Archive:
    def __init__(self, path):
        self.path = path
        self.entries = []
        self.headers_encrypted = False
        self.salt = None
        self.check = None
        self._parse()

    def _parse(self):
        with open(self.path, "rb") as fh:
            head = fh.read(8)
            if head.startswith(RAR4_SIG):
                raise ArchiveError(
                    "RAR4 archive. This tool only speaks RAR5; use hashcat mode 12500 "
                    "and rar2john from john-jumbo for RAR3/RAR4."
                )
            if not head.startswith(RAR5_SIG):
                raise ArchiveError("not a RAR5 archive")
            fh.seek(len(RAR5_SIG))
            self._walk(fh)

    def _walk(self, fh):
        while True:
            crc = fh.read(4)
            if len(crc) < 4:
                return
            raw = self._read_block(fh)
            if raw is None:
                return
            self._handle(raw)

    def _read_block(self, fh):
        """Read one header block: returns (htype, hflags, body, extra) or None at EOF."""
        size_bytes = self._read_vint_stream(fh)
        if size_bytes is None:
            return None
        header_size = size_bytes[0]
        if header_size == 0 or header_size > 2 << 20:
            raise ArchiveError("corrupt header size %d" % header_size)
        data = fh.read(header_size)
        if len(data) < header_size:
            return None
        htype, p = vint(data, 0)
        hflags, p = vint(data, p)
        extra_size = 0
        data_size = 0
        if hflags & FLAG_EXTRA:
            extra_size, p = vint(data, p)
        if hflags & FLAG_DATA:
            data_size, p = vint(data, p)
        body = data[p:]
        if data_size:
            fh.seek(data_size, os.SEEK_CUR)
        return htype, hflags, body, extra_size, data_size

    def _read_vint_stream(self, fh):
        raw = b""
        first = fh.read(1)
        if not first:
            return None
        raw += first
        value = first[0] & 0x7F
        shift = 7
        while first[0] & 0x80:
            byte = fh.read(1)
            if not byte:
                return None
            raw += byte
            first = byte
            value |= (byte[0] & 0x7F) << shift
            shift += 7
        return value, raw

    def _handle(self, block):
        htype, hflags, body, extra_size, data_size = block
        if htype in (HDR_END,):
            return
        if extra_size > len(body):
            return
        main = body[: len(body) - extra_size]
        extra = body[len(body) - extra_size:]

        if htype in (HDR_FILE, HDR_SERVICE):
            entry = self._parse_file(main, extra, data_size)
            if entry is not None:
                self.entries.append(entry)
            return

        if htype in (HDR_MAIN, HDR_CRYPT):
            for rtype, rdata in self._records(extra):
                if rtype == EX_CRYPT and htype == HDR_CRYPT:
                    self.headers_encrypted = True
                    self._parse_archive_crypt(rdata)

    def _parse_archive_crypt(self, rdata):
        try:
            _, p = vint(rdata, 0)          # version
            _, p = vint(rdata, p)          # flags
            log2 = rdata[p]
            p += 1
            self.salt = rdata[p:p + 16]
            self.check = rdata[p + 16:p + 28]
        except (IndexError, ArchiveError):
            pass

    @staticmethod
    def _records(extra):
        pos = 0
        out = []
        while pos < len(extra):
            size, pos = vint(extra, pos)
            rtype, pos = vint(extra, pos)
            if size < 0 or pos + size > len(extra):
                break
            out.append((rtype, extra[pos:pos + size]))
            pos += size
        return out

    def _parse_file(self, main, extra, data_size):
        name_len_pos = 0
        try:
            fflags, p = vint(main, 0)
            usize, p = vint(main, p)
            _, p = vint(main, p)               # attributes
            if fflags & 0x0002:                # mtime
                p += 4
            if fflags & 0x0004:                # crc32
                p += 4
            _, p = vint(main, p)               # compression info
            _, p = vint(main, p)               # host os
            name_len, p = vint(main, p)
            name = main[p:p + name_len].decode("utf-8", "replace")
        except (ArchiveError, IndexError):
            return None
        is_dir = bool(fflags & 0x0001)

        crypt = None
        for rtype, rdata in self._records(extra):
            if rtype == EX_CRYPT:
                crypt = rdata
                break
        if crypt is None:
            return Entry(name, is_dir, usize, 0, b"", b"", b"", data_size)

        try:
            _, p = vint(crypt, 0)              # version
            _, p = vint(crypt, p)              # flags
            log2 = crypt[p]
            p += 1
            salt = crypt[p:p + 16]
            iv = crypt[p + 16:p + 32]
            check = crypt[p + 32:p + 44]
        except (ArchiveError, IndexError):
            return None
        return Entry(name, is_dir, usize, log2, salt, iv, check, data_size)

    # ------------------------------------------------------------------ output

    def unique_hashes(self):
        seen = set()
        out = []
        for e in self.entries:
            if not e.salt:
                continue
            key = (e.salt, e.log2)
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
        return out

    def smallest_encrypted(self):
        files = [e for e in self.entries if e.salt and not e.is_dir]
        if not files:
            return None
        return min(files, key=lambda e: (e.size, e.name))


# ------------------------------------------------------------------ crypto

def pswcheck(password, salt, log2):
    """Reproduce the RAR5 password check value from a password guess."""
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, (1 << log2) + 32, 32
    )
    w = struct.unpack("<8I", dk)
    return struct.pack("<2I", w[0] ^ w[2] ^ w[4] ^ w[6], w[1] ^ w[3] ^ w[5] ^ w[7])


def password_matches(entry, password):
    return pswcheck(password, entry.salt, entry.log2) == entry.check[:8]


# ------------------------------------------------------------------ commands

def cmd_list(archive, args):
    enc = archive.unique_hashes()
    if archive.headers_encrypted:
        print("headers: ENCRYPTED (file names are not readable without the password)")
    else:
        print("headers: readable")
    print("entries: %d   encrypted file headers: %d"
          % (len(archive.entries), len(enc)))
    if enc:
        print("kdf    : %d iterations (log2=%d), salt %s"
              % ((1 << enc[0].log2) + 32, enc[0].log2, enc[0].salt.hex()))
    print()
    print("%-10s %-12s %s" % ("encrypted", "size", "name"))
    for e in archive.entries:
        if e.is_dir:
            continue
        print("%-10s %-12d %s" % ("yes" if e.salt else "no", e.size, e.name))


def cmd_hash(archive, args):
    if archive.headers_encrypted:
        raise ArchiveError(
            "header encryption is on: only the archive-level salt is available, "
            "use it with hashcat mode 13000 anyway (see --archive-salt)"
        )
    targets = archive.unique_hashes()
    if not targets:
        raise ArchiveError("no encrypted entries found - the archive is not encrypted")
    lines = [e.hashcat for e in targets]
    if args.output:
        with open(args.output, "w", encoding="ascii") as fh:
            fh.write("\n".join(lines) + "\n")
        print("%d hash(es) written to %s" % (len(lines), args.output))
    for line in lines:
        print(line)


def cmd_verify(archive, args):
    targets = archive.unique_hashes()
    if not targets:
        raise ArchiveError("no encrypted entries found")
    entry = targets[0]
    started = time.time()
    ok = password_matches(entry, args.password)
    took = time.time() - started
    print("password %r -> %s (%.1f ms)" % (args.password, "MATCH" if ok else "no", took * 1000))
    return 0 if ok else 1


def _worker(job):
    password, salt, log2, check = job
    try:
        return password if pswcheck(password, salt, log2) == check else None
    except Exception:
        return None


def cmd_crack(archive, args):
    from itertools import islice
    from multiprocessing import Pool, cpu_count

    targets = archive.unique_hashes()
    if not targets:
        raise ArchiveError("no encrypted entries found")
    entry = targets[0]

    pool = Pool(cpu_count())
    started = time.time()
    tested = 0
    chunk = 400
    with open(args.wordlist, "r", encoding="utf-8", errors="replace") as fh:
        while True:
            batch = list(islice(fh, chunk))
            if not batch:
                break
            jobs = [(w.rstrip("\r\n"), entry.salt, entry.log2, entry.check[:8]) for w in batch]
            for result in pool.imap_unordered(_worker, jobs, chunksize=8):
                if result is not None:
                    pool.terminate()
                    print("FOUND: %s" % result)
                    print("tested %d in %.1fs (%.0f/s)"
                          % (tested, time.time() - started, tested / max(time.time() - started, 1e-9)))
                    return 0
            tested += len(batch)
            if args.verbose and tested % 4000 == 0:
                rate = tested / max(time.time() - started, 1e-9)
                print("%d tested, %.0f/s" % (tested, rate), file=sys.stderr)
    pool.terminate()
    print("not found after %d candidates (%.1fs)" % (tested, time.time() - started))
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="RAR5 hash extractor / verifier / cracker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    p_list = sub.add_parser("list", help="list entries without the password")
    p_list.add_argument("archive")

    p_hash = sub.add_parser("hash", help="emit hashcat mode 13000 hashes")
    p_hash.add_argument("archive")
    p_hash.add_argument("-o", "--output")

    p_verify = sub.add_parser("verify", help="verify a password locally")
    p_verify.add_argument("archive")
    p_verify.add_argument("password")

    p_crack = sub.add_parser("crack", help="crack a wordlist on the CPU")
    p_crack.add_argument("archive")
    p_crack.add_argument("-w", "--wordlist", required=True)
    p_crack.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2

    try:
        archive = Archive(args.archive)
    except (ArchiveError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    handler = {"list": cmd_list, "hash": cmd_hash,
               "verify": cmd_verify, "crack": cmd_crack}[args.command]
    try:
        return handler(archive, args) or 0
    except ArchiveError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
