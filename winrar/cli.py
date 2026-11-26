"""Command line interface: subcommands, attack staging, reporting."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Callable, Iterator

from . import attacks, batch, crypto, engine, extract, formats, forensics, gpu, rar5, ui, zipcrypto
from .formats import Target
from .rar5 import ArchiveError

POT_DIR = os.path.join(os.path.expanduser("~"), ".winrar-bypass")
POT_FILE = os.path.join(POT_DIR, "potfile")
DEFAULT_MASK_HOURS = 12.0
VERSION = "1.2.0"


# ------------------------------------------------------------------ potfile

def potfile_load() -> dict[str, str]:
    if not os.path.exists(POT_FILE):
        return {}
    return gpu.read_potfile(POT_FILE)


def potfile_add(hash_line: str, password: str) -> None:
    os.makedirs(POT_DIR, exist_ok=True)
    with open(POT_FILE, "a", encoding="utf-8") as fh:
        fh.write("%s:%s\n" % (hash_line, password))


# ------------------------------------------------------------------ helpers

def open_archives(paths: list[str]) -> list:
    found = []
    for path in paths:
        try:
            found.append(formats.open_archive(path))
        except ArchiveError as exc:
            ui.fail(str(exc))
        except OSError as exc:
            ui.fail("%s: %s" % (path, exc))
    return found


def resolve_gpu(args, required: bool = False) -> str | None:
    if not (args.gpu or args.hashcat or required):
        return None
    exe = gpu.find_hashcat(args.hashcat)
    if not exe:
        if required or args.gpu or args.hashcat:
            ui.warn("hashcat not found")
        return None
    if not gpu.check_layout(exe):
        ui.warn("hashcat at %s has no OpenCL folder" % exe)
        return None
    return exe


def gpu_speed(exe: str, mode: str) -> float:
    speed, _ = gpu.benchmark(exe, quiet=True, mode=mode)
    return speed


def target_matches(target: Target, password: str, sevenzip: str | None = None) -> bool:
    if target.kind == "rar5":
        return crypto.verify(target.entry, password)
    if target.kind == "zipcrypto":
        return zipcrypto.verify_entry(target.archive.path, target.entry, password)
    try:
        return extract.test_password(target.archive.path, password, sevenzip)
    except (RuntimeError, OSError):
        return False


# ------------------------------------------------------------------ stages

@dataclass
class Stage:
    label: str
    kind: str                                   # wordlist | stream | mask
    factory: Callable[[], Iterator[str]] | None = None
    path: str | None = None
    mask: str | None = None
    custom: list[str] | None = None
    rule: str | None = None
    total: int | None = None
    estimate: int | None = None


def build_stages(args, primary_path: str, other_names: list[str]) -> list[Stage]:
    stages: list[Stage] = []
    auto = args.auto or not (args.wordlist or args.mask)
    if auto:
        tokens = [t for name in other_names for t in attacks.tokens_from_path(name)]
        stages.append(Stage(
            label="targeted guesses",
            kind="stream",
            factory=lambda: attacks.targeted(primary_path, tokens),
        ))
        stages.append(Stage(
            label="built-in top passwords",
            kind="stream",
            factory=attacks.top_passwords,
            total=2000,
        ))
    for wordlist in args.wordlist or []:
        if not os.path.exists(wordlist):
            ui.fail("wordlist not found: %s" % wordlist)
            continue
        lines = attacks.count_lines(wordlist)
        stages.append(Stage(
            label="wordlist %s (%s)" % (os.path.basename(wordlist), ui.human_count(lines)),
            kind="wordlist",
            path=wordlist,
            rule=args.rule,
            total=lines,
            factory=(lambda p=wordlist: attacks.read_wordlist(p)),
        ))
        for level in range(1, (args.mutate or 0) + 1):
            estimate = lines * attacks.mutation_multiplier(level)
            stages.append(Stage(
                label="mutate L%d %s (%s)" % (level, os.path.basename(wordlist), ui.human_count(estimate)),
                kind="stream",
                factory=(lambda p=wordlist, lv=level: attacks.mutate(attacks.read_wordlist(p), lv)),
                estimate=estimate,
            ))
    for mask in args.mask or []:
        try:
            keyspace = attacks.mask_keyspace(mask, args.custom)
        except ValueError as exc:
            ui.fail(str(exc))
            continue
        stages.append(Stage(
            label="mask %s (%s)" % (mask, ui.human_count(keyspace)),
            kind="mask",
            mask=mask,
            custom=args.custom,
            total=keyspace,
        ))
    return stages


# ------------------------------------------------------------------ commands

def cmd_info(args) -> int:
    archives = open_archives(args.archives)
    if not archives:
        return 2
    payload = []
    for archive in archives:
        ui.title(os.path.basename(archive.path))
        entries = [e for e in archive if not getattr(e, "is_dir", False)]
        targets = archive.unique_targets() if hasattr(archive, "unique_targets") else []
        ui.kv("path", archive.path)
        ui.kv("format", formats.format_label(archive))
        ui.kv("files", "%d  (%s unpacked)" % (len(entries), ui.human_bytes(archive.total_size)))
        ui.kv("headers", ui.yellow("encrypted") if getattr(archive, "headers_encrypted", False)
               else "readable")
        ui.kv("crypto", formats.crypto_label(archive))
        if archive.encrypted_entries:
            ui.kv("kdf", formats.kdf_label(archive))
            ui.kv("salt", formats.salt_label(archive)[:64])
            ui.kv("targets", "%d encrypted file(s)" % len(archive.encrypted_entries))
        rows = []
        for entry in entries:
            marker = "yes" if getattr(entry, "encrypted", False) else "-"
            rows.append([
                marker,
                ui.human_bytes(getattr(entry, "size", 0)),
                getattr(entry, "method_name", "-"),
                getattr(entry, "name", "?"),
            ])
        limit = len(rows) if args.all else min(len(rows), args.limit)
        print()
        ui.table(["enc", "size", "method", "name"], rows[:limit], right=(1,))
        if limit < len(rows):
            print("  " + ui.dim("... %d more (use --all)" % (len(rows) - limit)))
        hashes = []
        try:
            hashes = archive.hashes()
        except ArchiveError as exc:
            ui.warn(str(exc))
        payload.append({
            "path": archive.path,
            "format": formats.format_label(archive),
            "files": len(entries),
            "bytes": archive.total_size,
            "headers_encrypted": getattr(archive, "headers_encrypted", False),
            "crypto": formats.crypto_label(archive),
            "kdf": formats.kdf_label(archive),
            "encrypted_entries": len(archive.encrypted_entries),
            "hashes": hashes,
        })
    if args.json:
        print(json.dumps(payload, indent=2))
    return 0


def cmd_hash(args) -> int:
    archives = open_archives(args.archives)
    if not archives:
        return 2
    lines: list[str] = []
    payload = []
    for archive in archives:
        try:
            hashes = archive.hashes()
        except ArchiveError as exc:
            ui.fail("%s: %s" % (os.path.basename(archive.path), exc))
            continue
        if not hashes:
            if isinstance(archive, type(archives[0])) and formats.crypto_label(archive).startswith("ZipCrypto"):
                ui.warn("%s is ZipCrypto: no hash needed, use `crack` (it runs on the CPU)"
                        % os.path.basename(archive.path))
            else:
                ui.warn("%s has no encrypted entries" % os.path.basename(archive.path))
        payload.append({"path": archive.path,
                        "mode": formats.mode_for(archive),
                        "hashes": hashes})
        for line in hashes:
            lines.append("%s\t%s" % (line, archive.path))
    if not lines:
        if args.json:
            print(json.dumps(payload, indent=2))
        return 1
    if args.output:
        with open(args.output, "w", encoding="ascii") as fh:
            for line in lines:
                fh.write(line.split("\t")[0] + "\n")
        ui.ok("%d hash(es) written to %s" % (len(lines), args.output))
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for line in lines:
            hash_part, path = line.split("\t", 1)
            print(hash_part)
            if args.verbose:
                print(ui.dim("  " + path))
    return 0


def cmd_verify(args) -> int:
    archives = open_archives([args.archive])
    if not archives:
        return 2
    target = formats.pick_target(archives[0])
    if target is None:
        ui.fail("nothing encrypted to verify against")
        return 1
    started = time.perf_counter()
    ok = target_matches(target, args.password, args.sevenzip)
    elapsed = time.perf_counter() - started
    label = ui.bold(repr(args.password))
    if ok:
        ui.ok("%s matches (%s, %s)" % (label, ui.human_time(elapsed), target.kind))
    else:
        ui.fail("%s does not match (%s, %s)" % (repr(args.password), ui.human_time(elapsed), target.kind))
    return 0 if ok else 1


def cmd_forensics(args) -> int:
    paths = batch.find_archives(args.path, recursive=not args.no_recursive) \
        if os.path.isdir(args.path) else [args.path]
    if not paths:
        ui.fail("no archives under %s" % args.path)
        return 1
    reports = []
    for path in paths:
        try:
            reports.append(forensics.analyze(path))
        except ArchiveError as exc:
            ui.fail("%s: %s" % (os.path.basename(path), exc))
    if not reports:
        return 1

    for report in reports:
        ui.title(os.path.basename(report.path))
        ui.kv("format", report.format)
        ui.kv("size", "%s on disk, %s unpacked, %d files"
              % (ui.human_bytes(report.bytes_total), ui.human_bytes(report.bytes_unpacked),
                 report.files))
        ui.kv("crypto", report.crypto)
        if report.encrypted_files:
            ui.kv("kdf", report.kdf)
            ui.kv("salt", report.salt[:64])
        if report.timeline:
            ui.kv("timeline", "%s .. %s (%.1f days)"
                  % (report.timeline["earliest"], report.timeline["latest"],
                     report.timeline["span_days"]))
        if report.largest:
            ui.kv("largest", "%s (%s)" % (report.largest[0][:44], ui.human_bytes(report.largest[1])))
        profile = ", ".join("%s x%d" % (name, count) for name, count in
                            sorted(report.compression.items(), key=lambda kv: -kv[1])[:4])
        if profile:
            ui.kv("methods", profile)
        ui.kv("bytes fp", report.byte_fingerprint[:32])
        ui.kv("payload fp", report.payload_fingerprint[:32])
        for note in report.notes:
            ui.warn(note)
        if report.duplicates:
            ui.warn("duplicate entries: " + ", ".join(report.duplicates[:4]))

    if len(reports) > 1:
        groups = forensics.compare(reports)
        print()
        ui.section("relationships")
        for group in groups["identical"]:
            print("  " + ui.green("identical bytes") + "  "
                  + ", ".join(os.path.basename(p) for p in group))
        for group in groups["repacks"]:
            print("  " + ui.yellow("same payload, different archive") + "  "
                  + ", ".join(os.path.basename(p) for p in group))

    if args.json:
        print(json.dumps([report.to_dict() for report in reports], indent=2))
    return 0


def cmd_scan(args) -> int:
    items = batch.scan(args.path, recursive=not args.no_recursive)
    if not items:
        ui.fail("no archives under %s" % args.path)
        return 1
    groups = batch.group_by_target(items)
    group_index = {}
    for index, group in enumerate(groups, start=1):
        for item in group.archives:
            group_index[item.path] = index

    ui.title("scan: %s" % args.path)
    rows = []
    for item in items:
        if item.ok:
            archive = item.archive
            rows.append([
                os.path.basename(item.path),
                str(group_index.get(item.path, "-")),
                "enc" if archive.encrypted_entries else "open",
                formats.format_label(archive),
                str(len(archive)),
                ui.human_bytes(archive.total_size),
            ])
        else:
            rows.append([os.path.basename(item.path), "-", "skip", "-", "-", item.error[:40]])
    ui.table(["archive", "group", "state", "format", "files", "size"], rows, right=(4, 5))

    if len(groups) > 1:
        print()
        ui.section("groups (one crack covers every archive in a group)")
        for index, group in enumerate(groups, start=1):
            names = ", ".join(os.path.basename(a.path) for a in group.archives[:4])
            more = "" if len(group.archives) <= 4 else " +%d" % (len(group.archives) - 4)
            print("  " + ui.bold("G%d" % index) + "  " + names + more)

    if args.json:
        print(json.dumps([{
            "path": item.path,
            "error": item.error,
            "format": formats.format_label(item.archive) if item.ok else None,
            "files": len(item.archive) if item.ok else None,
            "encrypted": item.encrypted if item.ok else None,
            "group": group_index.get(item.path),
            "hashes": item.hashes,
        } for item in items], indent=2))
    return 0


def cmd_bench(args) -> int:
    archives = open_archives([args.archive])
    if not archives:
        return 2
    archive = archives[0]
    target = formats.pick_target(archive)
    if target is None:
        ui.fail("nothing encrypted in %s" % args.archive)
        return 2

    ui.title("benchmark")
    cores = os.cpu_count() or 1
    if target.kind == "zipcrypto":
        single = zipcrypto.benchmark(threads=1)
        ui.kv("zipcrypto", "%.0f guesses/s per core" % single)
        ui.kv("cpu x%d" % cores, "%.0f guesses/s" % (single * cores))
        best = single * cores
    else:
        single = crypto.benchmark(target.entry, rounds=15)
        ui.kv("cpu core", "%.0f guesses/s" % single)
        ui.kv("cpu x%d" % cores, "%.0f guesses/s" % (single * cores))
        best = single * cores

    exe = resolve_gpu(argparse.Namespace(gpu=True, hashcat=args.hashcat))
    if exe and target.hash_line:
        mode = target.mode or formats.MODE_RAR5
        ui.kv("hashcat", "%s (%s, mode %s)" % (exe, gpu.version(exe), mode))
        gpu_rate = gpu_speed(exe, mode)
        ui.kv("gpu", "%.0f guesses/s" % gpu_rate)
        best = max(best, gpu_rate)

    print()
    ui.section("time to exhaustion at %s guesses/s" % ui.human_count(best))
    cases = [
        ("built-in 2000", 2000),
        ("rockyou (14.3M)", 14_344_384),
        ("top 100k + rules", 7_700_000),
        ("?l?l?l?l?l?l", 26 ** 6),
        ("?l?l?l?l?l?l?l?l", 26 ** 8),
        ("?l?l?l?l?l?l?d?d", 26 ** 6 * 100),
        ("?a?a?a?a?a?a?a?a", 95 ** 8),
    ]
    ui.table(
        ["keyspace", "candidates", "time"],
        [[name, ui.human_count(size), ui.human_time(size / max(best, 1e-9))]
         for name, size in cases],
        right=(1, 2),
    )
    return 0


def cmd_doctor(args) -> int:
    ui.title("doctor")
    ui.kv("python", "%s (%s)" % (sys.version.split()[0], sys.platform))
    ui.kv("cpu cores", str(os.cpu_count()))

    exe = resolve_gpu(argparse.Namespace(gpu=True, hashcat=args.hashcat))
    if exe:
        ui.kv("hashcat", gpu.version(exe))
        ui.kv("path", exe)
        ui.kv("layout", "ok" if gpu.check_layout(exe) else ui.yellow("missing OpenCL folder"))
        for device in gpu.devices(exe)[:4]:
            ui.kv("device", device)
    else:
        ui.kv("hashcat", ui.yellow("not found (CPU only)"))

    sevenzip = extract.find_7z(args.sevenzip)
    unrar = extract.find_unrar()
    ui.kv("7-zip", sevenzip or ui.yellow("not found"))
    ui.kv("unrar", unrar or ui.yellow("not found"))
    ui.kv("potfile", POT_FILE)
    try:
        count = sum(1 for _ in attacks.top_passwords())
    except OSError:
        count = 0
    ui.kv("builtin list", "%d passwords" % count)
    try:
        single = zipcrypto.benchmark(threads=1)
        ui.kv("zipcrypto", "%.0f guesses/s per core" % single)
    except Exception:
        pass
    return 0


def cmd_crack(args) -> int:
    archives = open_archives(args.archives)
    if not archives:
        return 2
    targets = formats.all_targets(archives)
    if not targets:
        ui.fail("no crackable encrypted entries in the given archives")
        return 1

    primary = min(targets, key=lambda t: (t.size or t.archive.total_size))
    started = time.monotonic()
    password: str | None = None
    tested = 0
    used_engine = "cpu"

    ui.title("crack: %s" % os.path.basename(primary.archive.path))
    ui.kv("target", primary.name)
    ui.kv("format", formats.format_label(primary.archive))
    ui.kv("crypto", formats.crypto_label(primary.archive))
    ui.kv("kdf", formats.kdf_label(primary.archive))
    ui.kv("archives", "%d given, %d encrypted" % (len(archives), len(targets)))

    from_cache = False
    if primary.hash_line:
        cached = potfile_load().get(primary.hash_line)
        if cached and target_matches(primary, cached, args.sevenzip):
            password = cached
            from_cache = True
            ui.ok("password already in potfile: %s" % ui.bold(cached))

    gpu_exe = None if password else resolve_gpu(args, required=not primary.supports_cpu())
    if not password and not primary.supports_cpu() and not gpu_exe:
        ui.fail("%s needs hashcat (mode %s): there is no local verifier for this format"
                % (primary.kind, primary.mode))
        return 2
    if gpu_exe:
        used_engine = "gpu"
        ui.kv("engine", "hashcat (%s, mode %s)" % (gpu.version(gpu_exe), primary.mode))

    if not password:
        stages = build_stages(args, primary.archive.path, [a.path for a in archives])
        if not stages:
            ui.fail("no attack sources: pass --wordlist, --mask or --auto")
            return 2

        threads = args.threads or os.cpu_count() or 1
        if gpu_exe:
            rate = gpu_speed(gpu_exe, primary.mode)
        elif primary.kind == "zipcrypto":
            rate = zipcrypto.benchmark(threads=1) * threads
            ui.kv("engine", "zipcrypto cpu x%d (~%s/s)" % (threads, ui.human_count(rate)))
        else:
            rate = crypto.benchmark(primary.entry, rounds=5) * threads
            ui.kv("engine", "cpu x%d (~%s/s)" % (threads, ui.human_count(rate)))

        cpu_engine = None
        if not gpu_exe:
            if primary.kind == "rar5":
                cpu_engine = engine.CpuEngine(primary.entry, args.threads,
                                             resume_path=args.resume)
            elif primary.kind == "zipcrypto":
                cpu_engine = zipcrypto.ZipCryptoEngine(
                    primary.entry.header12, primary.entry.check_byte, args.threads,
                    entry=primary.entry, path=primary.archive.path)

        for stage in stages:
            print()
            ui.section(stage.label)
            if stage.kind == "mask" and rate:
                keyspace = stage.total or 1
                hours = keyspace / rate / 3600.0
                if hours > args.max_mask_hours and not args.force:
                    ui.warn("mask needs ~%s, over the %.1fh guard (use --force)"
                            % (ui.human_time(keyspace / rate), args.max_mask_hours))
                    continue
                ui.kv("eta", ui.human_time(keyspace / rate))

            if gpu_exe and primary.hash_line:
                target_file = write_target_hash(primary.hash_line)
                if stage.kind == "wordlist":
                    _, pot = gpu.crack_wordlist(
                        gpu_exe, target_file, POT_FILE, stage.path, rule=stage.rule,
                        force=args.force, workload=args.workload, mode=primary.mode)
                elif stage.kind == "mask":
                    _, pot = gpu.crack_mask(
                        gpu_exe, target_file, POT_FILE, stage.mask, custom=stage.custom,
                        force=args.force, workload=args.workload, mode=primary.mode)
                else:
                    _, pot = gpu.crack_stream(
                        gpu_exe, target_file, POT_FILE, stage.factory(),
                        force=args.force, workload=args.workload, label=stage.label,
                        mode=primary.mode)
                password = pot.get(primary.hash_line)
                if password and not target_matches(primary, password, args.sevenzip):
                    password = None
            else:
                result = cpu_engine.crack(stage.factory(), total=stage.total,
                                          label=stage.label, quiet=args.quiet)
                tested += result.tested
                if result.password:
                    if target_matches(primary, result.password, args.sevenzip):
                        password = result.password
                        ui.ok("hit after %s candidates" % ui.human_count(result.tested))
                    else:
                        ui.warn("discarded false positive: %r" % result.password)

            if password:
                break
            ui.warn("exhausted %s" % stage.label)

    elapsed = time.monotonic() - started

    if not password:
        ui.title("result")
        ui.kv("password", ui.red("not recovered"))
        ui.kv("time", ui.human_time(elapsed))
        ui.kv("candidates", ui.human_count(tested))
        if args.json:
            print(json.dumps({"password": None, "archives": [a.path for a in archives],
                              "elapsed": elapsed, "tested": tested}, indent=2))
        return 1

    if primary.hash_line and not from_cache:
        potfile_add(primary.hash_line, password)
    verified = target_matches(primary, password, args.sevenzip)

    opened = []
    for archive in archives:
        target = formats.pick_target(archive)
        ok = bool(target and target_matches(target, password, args.sevenzip))
        opened.append((archive, ok))

    ui.title("result")
    ui.kv("password", ui.bold(ui.green(password)))
    ui.kv("verified", "yes" if verified else ui.red("no"))
    ui.kv("engine", used_engine)
    ui.kv("time", ui.human_time(elapsed))
    print()
    ui.table(
        ["archive", "opens", "files"],
        [[os.path.basename(a.path), "yes" if ok else "no", str(len(a))] for a, ok in opened],
        right=(2,),
    )

    extracted_to = None
    if args.extract:
        dest = args.output or os.path.join(
            os.path.dirname(os.path.abspath(primary.archive.path)),
            os.path.splitext(os.path.basename(primary.archive.path))[0] + "_extracted",
        )
        try:
            count = extract.extract(primary.archive.path, password, dest, args.sevenzip)
            extracted_to = dest
            ui.ok("extracted %d file(s) to %s" % (count, dest))
        except RuntimeError as exc:
            ui.fail(str(exc))

    if args.json:
        print(json.dumps({
            "password": password,
            "verified": verified,
            "engine": used_engine,
            "elapsed": elapsed,
            "tested": tested,
            "target_kind": primary.kind,
            "archives": [{"path": a.path, "opens": ok, "files": len(a)} for a, ok in opened],
            "extracted_to": extracted_to,
        }, indent=2))
    return 0


_TARGET_CACHE: dict[str, str] = {}


def write_target_hash(hash_line: str) -> str:
    """One-line hash file hashcat can consume, cached per process."""
    path = _TARGET_CACHE.get(hash_line)
    if path and os.path.exists(path):
        return path
    os.makedirs(POT_DIR, exist_ok=True)
    path = os.path.join(POT_DIR, "target-%s.hash" % abs(hash(hash_line)))
    with open(path, "w", encoding="ascii") as fh:
        fh.write(hash_line + "\n")
    _TARGET_CACHE[hash_line] = path
    return path


# ------------------------------------------------------------------ parser

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="WinRaR Password Bypass: RAR5, ZIP and 7z hash extraction, cracking and extraction.",
        epilog="examples:\n"
               "  main.py info pack.rar\n"
               "  main.py forensics D:\\Downloads\n"
               "  main.py crack pack.rar --auto --gpu --extract\n"
               "  main.py crack photos.zip --mask '?l?l?l?l?l?l'\n"
               "  main.py crack backup.7z -w rockyou.txt --gpu\n"
               "  main.py scan D:\\Downloads\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version="winrar-bypass " + VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    p_info = sub.add_parser("info", help="inspect an archive without the password")
    p_info.add_argument("archives", nargs="+")
    p_info.add_argument("--all", action="store_true", help="list every entry")
    p_info.add_argument("--limit", type=int, default=15)
    p_info.add_argument("--json", action="store_true")
    p_info.set_defaults(func=cmd_info)

    p_hash = sub.add_parser("hash", help="print hashcat hashes (13000 / 11600 / 13600)")
    p_hash.add_argument("archives", nargs="+")
    p_hash.add_argument("-o", "--output")
    p_hash.add_argument("-v", "--verbose", action="store_true")
    p_hash.add_argument("--json", action="store_true")
    p_hash.set_defaults(func=cmd_hash)

    p_verify = sub.add_parser("verify", help="check one password locally")
    p_verify.add_argument("archive")
    p_verify.add_argument("password")
    p_verify.add_argument("--sevenzip", metavar="PATH")
    p_verify.set_defaults(func=cmd_verify)

    p_forensics = sub.add_parser("forensics", help="fingerprints, timeline, duplicate detection")
    p_forensics.add_argument("path", help="archive or directory")
    p_forensics.add_argument("--no-recursive", action="store_true")
    p_forensics.add_argument("--json", action="store_true")
    p_forensics.set_defaults(func=cmd_forensics)

    p_scan = sub.add_parser("scan", help="find archives and group them by target")
    p_scan.add_argument("path")
    p_scan.add_argument("--no-recursive", action="store_true")
    p_scan.add_argument("--json", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    p_crack = sub.add_parser("crack", help="recover the password")
    p_crack.add_argument("archives", nargs="+")
    p_crack.add_argument("-w", "--wordlist", action="append", metavar="FILE")
    p_crack.add_argument("--rule", metavar="FILE", help="hashcat rule file for GPU wordlists")
    p_crack.add_argument("--mask", action="append", metavar="MASK")
    p_crack.add_argument("--charset", action="append", metavar="SET",
                         help="custom set for ?1..?4, repeatable")
    p_crack.add_argument("--mutate", type=int, choices=(0, 1, 2, 3), default=0,
                         help="apply built-in mutation levels to wordlists")
    p_crack.add_argument("--auto", action="store_true",
                         help="targeted guesses plus built-in password list")
    p_crack.add_argument("--gpu", action="store_true", help="use hashcat")
    p_crack.add_argument("--hashcat", metavar="PATH", help="hashcat binary, implies --gpu")
    p_crack.add_argument("--threads", type=int, help="CPU worker count")
    p_crack.add_argument("--workload", type=int, default=3, help="hashcat -w")
    p_crack.add_argument("--resume", metavar="FILE", help="CPU resume state file")
    p_crack.add_argument("--force", action="store_true", help="ignore mask guard, hashcat --force")
    p_crack.add_argument("--max-mask-hours", type=float, default=DEFAULT_MASK_HOURS)
    p_crack.add_argument("--extract", action="store_true")
    p_crack.add_argument("-o", "--output", metavar="DIR")
    p_crack.add_argument("--sevenzip", metavar="PATH")
    p_crack.add_argument("--json", action="store_true")
    p_crack.add_argument("-q", "--quiet", action="store_true")
    p_crack.set_defaults(func=cmd_crack)

    p_bench = sub.add_parser("bench", help="measure this machine against the archive's format")
    p_bench.add_argument("archive")
    p_bench.add_argument("--hashcat", metavar="PATH")
    p_bench.set_defaults(func=cmd_bench)

    p_doctor = sub.add_parser("doctor", help="check the environment")
    p_doctor.add_argument("--hashcat", metavar="PATH")
    p_doctor.add_argument("--sevenzip", metavar="PATH")
    p_doctor.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "no_color", False):
        ui.disable()
    if hasattr(args, "charset") and args.charset:
        args.custom = args.charset[:4]
    else:
        args.custom = None
    try:
        return args.func(args)
    except ArchiveError as exc:
        ui.fail(str(exc))
        return 2
    except KeyboardInterrupt:
        print()
        ui.warn("interrupted")
        return 130
