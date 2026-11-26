"""hashcat driver: locate the binary, stream candidates, parse live status."""

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from . import ui

MODE_RAR5 = "13000"

_SEARCH_ROOTS = [
    os.environ.get("HASHCAT_HOME", ""),
    r"C:\hashcat",
    r"C:\tools\hashcat",
    os.path.join(os.environ.get("ProgramFiles", ""), "hashcat"),
    os.path.join(os.environ.get("ProgramFiles(x86)", ""), "hashcat"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "hashcat"),
    os.path.join(os.environ.get("USERPROFILE", ""), "hashcat"),
    "/usr/local/bin",
    "/usr/bin",
    "/opt/hashcat",
]

_RE_PROGRESS = re.compile(r"^Progress\.+:\s*(\d+)/(\d+)")
_RE_SPEED = re.compile(r"^Speed\.#\d+\.+:\s*([\d.]+)\s*([kKmMgGtT]?)H/s")
_RE_RECOVERED = re.compile(r"^Recovered\.+:\s*(\d+)/(\d+)")
_RE_STATUS = re.compile(r"^Status\.+:\s*(.+)$")
_RE_MASK = re.compile(r"^Guess\.Mask\.+:\s*(.+)$")
_RE_ESTIMATE = re.compile(r"^Time\.Estimated\.+:\s*(.+)$")
_RE_RESTORE = re.compile(r"^Restore\.Point\.+:\s*(\d+)/(\d+)")
_RE_ERROR = re.compile(r"^(?:ERROR\b|No devices found|Cannot open|Hashfile .+ is empty)")

_SCALE = {"": 1.0, "k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12}


@dataclass
class Status:
    done: int = 0
    total: int = 0
    speed: float = 0.0
    recovered: int = 0
    state: str = ""
    mask: str = ""
    eta: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def percent(self) -> float:
        return 100.0 * self.done / self.total if self.total else 0.0


# ------------------------------------------------------------------ locating

def find_hashcat(explicit: str | None = None) -> str | None:
    if explicit:
        path = explicit if os.path.isfile(explicit) else shutil.which(explicit)
        if path and os.path.isfile(path):
            return os.path.abspath(path)
        return None
    for name in ("hashcat", "hashcat.exe"):
        found = shutil.which(name)
        if found:
            return found
    patterns = []
    for root in filter(None, _SEARCH_ROOTS):
        patterns.append(os.path.join(root, "hashcat.exe"))
        patterns.append(os.path.join(root, "hashcat"))
        patterns.append(os.path.join(root, "hashcat-*", "hashcat.exe"))
        patterns.append(os.path.join(root, "hashcat-*", "hashcat"))
    for pattern in patterns:
        for candidate in sorted(glob.glob(pattern), reverse=True):
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)
    return None


def check_layout(exe: str) -> bool:
    """hashcat resolves ./OpenCL and ./modules relative to its working directory."""
    return os.path.isdir(os.path.join(os.path.dirname(exe), "OpenCL"))


def version(exe: str) -> str:
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=20)
        return out.stdout.strip().splitlines()[0] if out.stdout.strip() else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def devices(exe: str) -> list[str]:
    """Parse `hashcat -I` into human readable device lines."""
    try:
        out = subprocess.run(
            [exe, "-I"], cwd=os.path.dirname(exe), capture_output=True, text=True, timeout=60
        )
    except (OSError, subprocess.SubprocessError):
        return []
    found = []
    current = None
    for line in out.stdout.splitlines():
        line = line.strip()
        if line.startswith("Backend Device ID #"):
            if current:
                found.append(current)
            current = {}
            continue
        if current is None:
            continue
        if line.startswith("Type...."):
            current["type"] = line.split(":", 1)[1].strip()
        elif line.startswith("Name...."):
            current["name"] = line.split(":", 1)[1].strip()
        elif line.startswith("Memory.Total"):
            current["memory"] = line.split(":", 1)[1].strip()
    if current:
        found.append(current)
    return ["%s (%s, %s)" % (d.get("name", "?"), d.get("type", "?"), d.get("memory", "?"))
            for d in found]


# ------------------------------------------------------------------ potfile

def read_potfile(path: str) -> dict[str, str]:
    result: dict[str, str] = {}
    if not os.path.exists(path):
        return result
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line:
                continue
            hash_part, _, password = line.partition(":")
            result[hash_part] = password
    return result


# ------------------------------------------------------------------ running

def _parse_speed(value: str, scale: str) -> float:
    try:
        return float(value) * _SCALE.get(scale.lower(), 1.0)
    except ValueError:
        return 0.0


def run(
    exe: str,
    args: list[str],
    stdin_lines: Iterable[str] | None = None,
    quiet: bool = False,
    label: str = "",
    force: bool = False,
    status_lines: bool = True,
) -> tuple[Status, str]:
    """Run hashcat, stream status into a progress bar, return (status, raw_output)."""
    cmd = [exe, "-m", MODE_RAR5, *args]
    if status_lines:
        cmd += ["--status", "--status-timer", "2"]
    if force:
        cmd.append("--force")

    status = Status()
    progress = None if quiet else ui.Progress(None, label or "gpu")
    output: list[str] = []
    proc = subprocess.Popen(
        cmd,
        cwd=os.path.dirname(exe),
        stdin=subprocess.PIPE if stdin_lines is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )

    def feed() -> None:
        assert proc.stdin is not None
        try:
            for line in stdin_lines:                      # type: ignore[union-attr]
                proc.stdin.write(line + "\n")
            proc.stdin.close()
        except (BrokenPipeError, ValueError, OSError):
            pass

    if stdin_lines is not None:
        import threading

        threading.Thread(target=feed, daemon=True).start()

    try:
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.rstrip("\r\n")
            output.append(line)
            if line.startswith("STATUS"):
                status.state = line[7:].strip()
                continue
            match = _RE_PROGRESS.match(line)
            if match:
                status.done, status.total = int(match.group(1)), int(match.group(2))
                if progress:
                    progress.update(status.done)
                continue
            match = _RE_SPEED.match(line)
            if match:
                status.speed = _parse_speed(match.group(1), match.group(2))
                if progress and status.speed:
                    progress.update(status.done)
                continue
            match = _RE_RECOVERED.match(line)
            if match:
                status.recovered = int(match.group(1))
                continue
            match = _RE_ESTIMATE.match(line)
            if match:
                status.eta = match.group(1).strip()
                continue
            match = _RE_MASK.match(line)
            if match:
                status.mask = match.group(1).strip()
                continue
            if _RE_ERROR.match(line) and "WARN" not in line:
                status.errors.append(line.strip())
                if not quiet:
                    ui.warn(line.strip())
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        if progress:
            progress.finish(ui.yellow("interrupted"))
        return status, "\n".join(output)

    if progress:
        progress.finish()
    return status, "\n".join(output)


def crack_wordlist(
    exe: str,
    hashfile: str,
    potfile: str,
    wordlist: str,
    rule: str | None = None,
    quiet: bool = False,
    force: bool = False,
    workload: int = 3,
) -> tuple[Status, dict[str, str]]:
    args = ["-a", "0", hashfile, wordlist, "--potfile-path", potfile, "-w", str(workload)]
    if rule:
        args += ["-r", rule]
    status, _ = run(exe, args, quiet=quiet, label="gpu wordlist", force=force)
    return status, read_potfile(potfile)


def crack_stream(
    exe: str,
    hashfile: str,
    potfile: str,
    lines: Iterable[str],
    quiet: bool = False,
    force: bool = False,
    workload: int = 3,
    label: str = "gpu stream",
) -> tuple[Status, dict[str, str]]:
    args = ["-a", "0", hashfile, "--stdin", "--potfile-path", potfile, "-w", str(workload)]
    status, _ = run(exe, args, stdin_lines=lines, quiet=quiet, label=label, force=force)
    return status, read_potfile(potfile)


def crack_mask(
    exe: str,
    hashfile: str,
    potfile: str,
    mask: str,
    custom: list[str] | None = None,
    quiet: bool = False,
    force: bool = False,
    workload: int = 3,
) -> tuple[Status, dict[str, str]]:
    args = ["-a", "3", hashfile, mask, "--potfile-path", potfile, "-w", str(workload)]
    for index, charset in enumerate(custom or [], start=1):
        args += ["-1" if index == 1 else "-%d" % index, charset]
    status, _ = run(exe, args, quiet=quiet, label="gpu mask", force=force)
    return status, read_potfile(potfile)


def benchmark(exe: str, quiet: bool = False) -> tuple[float, str]:
    status, output = run(exe, ["-b", "-m", MODE_RAR5], quiet=True, force=True, status_lines=False)
    combined = re.search(r"Speed\.#\*\.+:\s*([\d.]+)\s*([kKmMgGtT]?)H/s", output)
    if combined:
        return _parse_speed(*combined.groups()), output.strip()
    matches = re.findall(r"Speed\.#\S+\.+:\s*([\d.]+)\s*([kKmMgGtT]?)H/s", output)
    speeds = [_parse_speed(value, scale) for value, scale in matches]
    return (max(speeds) if speeds else 0.0), output.strip()
