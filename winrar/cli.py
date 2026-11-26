"""Command line interface: subcommands, attack staging, reporting."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Iterator

from . import attacks, batch, crypto, engine, extract, gpu, rar5, ui
from .rar5 import Archive, ArchiveError

POT_DIR = os.path.join(os.path.expanduser("~"), ".winrar-bypass")
POT_FILE = os.path.join(POT_DIR, "potfile")
DEFAULT_MASK_HOURS = 12.0
VERSION = "1.1.0"


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

def open_archives(paths: list[str]) -> list[Archive]:
    found: list[Archive] = []
    for path in paths:
        try:
            found.append(Archive.open(path))
        except ArchiveError as exc:
            ui.fail(str(exc))
    return found


def encrypted_targets(archives: list[Archive]) -> list[tuple[Archive, rar5.Entry]]:
    pairs = []
    for archive in archives:
        entry = archive.smallest_target()
        if entry is not None:
            pairs.append((archive, entry))
    return pairs


def resolve_gpu(args) -> str | None:
    if not (args.gpu or args.hashcat):
        return None
    exe = gpu.find_hashcat(args.hashcat)
    if not exe:
        ui.warn("hashcat not found, staying on CPU")
        return None
    if not gpu.check_layout(exe):
        ui.warn("hashcat at %s has no OpenCL folder, staying on CPU" % exe)
        return None
    return exe


def gpu_speed(exe: str) -> float:
    speed, _ = gpu.benchmark(exe, quiet=True)
    return speed


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
        targets = archive.unique_targets()
        ui.kv("path", archive.path)
        ui.kv("format", "RAR5" + (" volume" if archive.volume else ""))
        ui.kv("files", "%d  (%s unpacked)" % (len(archive), ui.human_bytes(archive.total_size)))
        ui.kv("headers", ui.yellow("encrypted") if archive.headers_encrypted else "readable")
        if targets:
            entry = targets[0]
            ui.kv("encryption", "AES-256, %d iterations (log2=%d)" % (entry.iterations, entry.log2))
            ui.kv("salt", entry.salt.hex())
            ui.kv("targets", "%d distinct key context(s), %d encrypted file(s)"
                  % (len(targets), len(archive.encrypted_entries)))
        else:
            ui.kv("encryption", "none")
        rows = [[
            "yes" if e.encrypted else "-",
            ui.human_bytes(e.size),
            e.method_name,
            e.name,
        ] for e in archive if not e.is_dir]
        limit = len(rows) if args.all else min(len(rows), args.limit)
        print()
        ui.table(["enc", "size", "method", "name"], rows[:limit], right=(1,))
        if limit < len(rows):
            print("  " + ui.dim("... %d more (use --all)" % (len(rows) - limit)))
        payload.append({
            "path": archive.path,
            "files": len(archive),
            "bytes": archive.total_size,
            "headers_encrypted": archive.headers_encrypted,
            "encrypted_entries": len(archive.encrypted_entries),
            "hashes": archive.hashes() if not archive.headers_encrypted else [],
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
            ui.warn("%s has no encrypted entries" % os.path.basename(archive.path))
        payload.append({"path": archive.path, "hashes": hashes})
        for line in hashes:
            lines.append("%s\t%s" % (line, archive.path))
    if not lines:
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
    archive = archives[0]
    entry = archive.smallest_target()
    if entry is None:
        ui.fail("archive is not encrypted")
        return 1
    started = time.perf_counter()
    ok = crypto.verify(entry, args.password)
    elapsed = time.perf_counter() - started
    if ok:
        ui.ok("%s matches (%s)" % (ui.bold(repr(args.password)), ui.human_time(elapsed)))
    else:
        ui.fail("%s does not match (%s)" % (repr(args.password), ui.human_time(elapsed)))
    return 0 if ok else 1


def cmd_scan(args) -> int:
    items = batch.scan(args.path, recursive=not args.no_recursive)
    if not items:
        ui.fail("no .rar files under %s" % args.path)
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
                str(len(archive)),
                ui.human_bytes(archive.total_size),
                "hdr" if archive.headers_encrypted else "",
            ])
        else:
            rows.append([os.path.basename(item.path), "-", "skip", "-", "-", item.error[:40]])
    ui.table(["archive", "group", "state", "files", "size", "note"], rows, right=(3, 4))

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
            "files": len(item.archive) if item.ok else None,
            "encrypted": item.encrypted if item.ok else None,
            "group": group_index.get(item.path),
            "hashes": item.hashes,
        } for item in items], indent=2))
    return 0


def cmd_bench(args) -> int:
    archives = open_archives([args.archive]) if args.archive else []
    entry = archives[0].smallest_target() if archives else None
    if entry is None:
        ui.fail("give an encrypted archive: bench <archive.rar>")
        return 2
    ui.title("benchmark")
    single = crypto.benchmark(entry, rounds=15)
    cores = os.cpu_count() or 1
    ui.kv("cpu core", "%.0f guesses/s" % single)
    ui.kv("cpu x%d" % cores, "%.0f guesses/s" % (single * cores))

    exe = resolve_gpu(argparse.Namespace(gpu=True, hashcat=args.hashcat))
    gpu_rate = 0.0
    if exe:
        ui.kv("hashcat", "%s (%s)" % (exe, gpu.version(exe)))
        gpu_rate = gpu_speed(exe)
        ui.kv("gpu", "%.0f guesses/s" % gpu_rate)
    best = max(gpu_rate, single * cores) or 1.0

    print()
    ui.section("time to exhaustion at %.0f guesses/s" % best)
    cases = [
        ("rockyou (14.3M)", 14_344_384),
        ("top 100k + rules", 7_700_000),
        ("?l?l?l?l?l?l", 26 ** 6),
        ("?l?l?l?l?l?l?l?l", 26 ** 8),
        ("?l?l?l?l?l?l?d?d", 26 ** 6 * 100),
        ("?a?a?a?a?a?a?a?a", 95 ** 8),
    ]
    ui.table(
        ["keyspace", "candidates", "time"],
        [[name, ui.human_count(size), ui.human_time(size / best)] for name, size in cases],
        right=(1, 2),
    )
    return 0


def cmd_doctor(args) -> int:
    ui.title("doctor")
    ui.kv("python", "%s (%s)" % (sys.version.split()[0], sys.platform))
    ui.kv("cpu cores", str(os.cpu_count()))

    exe = argparse.Namespace(gpu=True, hashcat=args.hashcat)
    hashcat = resolve_gpu(exe)
    if hashcat:
        ui.kv("hashcat", gpu.version(hashcat))
        ui.kv("path", hashcat)
        ui.kv("layout", "ok" if gpu.check_layout(hashcat) else ui.yellow("missing OpenCL folder"))
        for device in gpu.devices(hashcat)[:4]:
            ui.kv("device", device)
    else:
        ui.kv("hashcat", ui.yellow("not found (CPU only)"))

    sevenzip = extract.find_7z(args.sevenzip)
    unrar = extract.find_unrar()
    ui.kv("7-zip", sevenzip or ui.yellow("not found"))
    ui.kv("unrar", unrar or ui.yellow("not found"))
    ui.kv("potfile", POT_FILE)
    top = attacks.top_passwords()
    try:
        count = sum(1 for _ in top)
    except OSError:
        count = 0
    ui.kv("builtin list", "%d passwords" % count)
    return 0


def cmd_crack(args) -> int:
    archives = open_archives(args.archives)
    if not archives:
        return 2
    targets = encrypted_targets(archives)
    if not targets:
        ui.fail("none of the given archives is encrypted")
        return 1

    primary_archive, primary_entry = min(targets, key=lambda pair: pair[1].size)
    target_hash = primary_entry.hashcat

    ui.title("crack: %s" % os.path.basename(primary_archive.path))
    ui.kv("target", primary_entry.name)
    ui.kv("kdf", "%d iterations, %d encrypted file(s)"
          % (primary_entry.iterations, len(primary_archive.encrypted_entries)))
    ui.kv("archives", "%d given, %d encrypted" % (len(archives), len(targets)))

    started = time.monotonic()
    password: str | None = None
    tested = 0
    used_engine = "cpu"

    cached = potfile_load().get(target_hash)
    from_cache = False
    if cached and crypto.verify(primary_entry, cached):
        password = cached
        from_cache = True
        ui.ok("password already in potfile: %s" % ui.bold(cached))

    gpu_exe = resolve_gpu(args) if not password else None
    if gpu_exe:
        used_engine = "gpu"
        ui.kv("engine", "hashcat (%s)" % gpu.version(gpu_exe))

    if not password:
        stages = build_stages(args, primary_archive.path,
                              [a.path for a in archives])
        if not stages:
            ui.fail("no attack sources: pass --wordlist, --mask or --auto")
            return 2

        rate = None
        if gpu_exe:
            rate = gpu_speed(gpu_exe)
        cpu_engine = None if gpu_exe else engine.CpuEngine(
            primary_entry, args.threads, resume_path=args.resume)
        if not gpu_exe:
            rate = crypto.benchmark(primary_entry, rounds=5) * (args.threads or os.cpu_count() or 1)
            used_engine = "cpu"
            ui.kv("engine", "cpu x%d (~%.0f/s)" % (args.threads or os.cpu_count() or 1, rate))

        for stage in stages:
            print()
            ui.section(stage.label)
            seconds = (stage.total / rate) if (stage.total and rate) else None
            if stage.kind == "mask":
                keyspace = stage.total or attacks.mask_keyspace(stage.mask, stage.custom)
                estimated_hours = keyspace / max(rate or 1, 1) / 3600.0
                if estimated_hours > args.max_mask_hours and not args.force:
                    ui.warn("mask needs ~%s, over the %.1fh guard (use --force)"
                            % (ui.human_time(keyspace / max(rate or 1, 1)), args.max_mask_hours))
                    continue
                if seconds:
                    ui.kv("eta", ui.human_time(seconds))

            if gpu_exe:
                if stage.kind == "wordlist":
                    _, pot = gpu.crack_wordlist(
                        gpu_exe, write_target_hash(target_hash), POT_FILE, stage.path,
                        rule=stage.rule, force=args.force, workload=args.workload,
                    )
                elif stage.kind == "mask":
                    _, pot = gpu.crack_mask(
                        gpu_exe, write_target_hash(target_hash), POT_FILE, stage.mask,
                        custom=stage.custom, force=args.force, workload=args.workload,
                    )
                else:
                    _, pot = gpu.crack_stream(
                        gpu_exe, write_target_hash(target_hash), POT_FILE, stage.factory(),
                        force=args.force, workload=args.workload, label=stage.label,
                    )
                password = pot.get(target_hash)
                if password and not crypto.verify(primary_entry, password):
                    password = None
            else:
                result = cpu_engine.crack(
                    stage.factory(), total=stage.total, label=stage.label, quiet=args.quiet)
                tested += result.tested
                if result.password:
                    password = result.password
                    ui.ok("hit after %s candidates" % ui.human_count(result.tested))

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

    if not from_cache:
        potfile_add(target_hash, password)
    verified = crypto.verify(primary_entry, password)
    opened = []
    for archive in archives:
        hit = None
        for entry in archive.encrypted_entries:
            if crypto.verify(entry, password):
                hit = entry
                break
        opened.append((archive, hit is not None))

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
            os.path.dirname(os.path.abspath(primary_archive.path)),
            os.path.splitext(os.path.basename(primary_archive.path))[0] + "_extracted",
        )
        try:
            count = extract.extract(primary_archive.path, password, dest, args.sevenzip)
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
        description="WinRaR password bypass toolkit: RAR5 hash extraction, cracking, extraction.",
        epilog="examples:\n"
               "  main.py info pack.rar\n"
               "  main.py crack pack.rar --auto --gpu --extract\n"
               "  main.py crack pack.rar -w rockyou.txt --mutate 2\n"
               "  main.py crack pack.rar --mask '?l?l?l?l?l?l' --gpu\n"
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

    p_hash = sub.add_parser("hash", help="print hashcat mode 13000 hashes")
    p_hash.add_argument("archives", nargs="+")
    p_hash.add_argument("-o", "--output")
    p_hash.add_argument("-v", "--verbose", action="store_true")
    p_hash.add_argument("--json", action="store_true")
    p_hash.set_defaults(func=cmd_hash)

    p_verify = sub.add_parser("verify", help="check one password locally")
    p_verify.add_argument("archive")
    p_verify.add_argument("password")
    p_verify.set_defaults(func=cmd_verify)

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

    p_bench = sub.add_parser("bench", help="measure this machine against RAR5")
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
