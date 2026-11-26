"""Archive testing and extraction through 7-Zip or UnRAR."""

from __future__ import annotations

import os
import shutil
import subprocess

_CANDIDATES_7Z = [
    os.path.join(os.environ.get("ProgramFiles", ""), "7-Zip", "7z.exe"),
    os.path.join(os.environ.get("ProgramFiles(x86)", ""), "7-Zip", "7z.exe"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "7-Zip", "7z.exe"),
    "/usr/bin/7z", "/usr/bin/7za", "/usr/local/bin/7z",
]

_CANDIDATES_UNRAR = [
    os.path.join(os.environ.get("ProgramFiles", ""), "WinRAR", "UnRAR.exe"),
    os.path.join(os.environ.get("ProgramFiles(x86)", ""), "WinRAR", "UnRAR.exe"),
    "/usr/bin/unrar", "/usr/local/bin/unrar",
]


def _first_existing(paths: list[str]) -> str | None:
    for path in paths:
        if path and os.path.isfile(path):
            return path
    return None


def find_7z(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit if os.path.isfile(explicit) else shutil.which(explicit)
    return shutil.which("7z") or shutil.which("7z.exe") or _first_existing(_CANDIDATES_7Z)


def find_unrar(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit if os.path.isfile(explicit) else shutil.which(explicit)
    return shutil.which("unrar") or shutil.which("unrar.exe") or _first_existing(_CANDIDATES_UNRAR)


def test_password(archive: str, password: str, tool: str | None = None) -> bool:
    exe = tool or find_7z()
    if not exe:
        raise RuntimeError("no extraction tool found; install 7-Zip or pass --sevenzip")
    if os.path.basename(exe).lower().startswith("unrar"):
        code = subprocess.run(
            [exe, "t", "-p" + password, "-idq", archive],
            capture_output=True, text=True, errors="replace",
        ).returncode
        return code == 0
    code = subprocess.run(
        [exe, "t", "-p" + password, "-y", archive],
        capture_output=True, text=True, errors="replace",
    ).returncode
    return code == 0


def extract(archive: str, password: str, dest: str, tool: str | None = None) -> int:
    exe = tool or find_7z()
    if not exe:
        raise RuntimeError("no extraction tool found; install 7-Zip or pass --sevenzip")
    os.makedirs(dest, exist_ok=True)
    if os.path.basename(exe).lower().startswith("unrar"):
        proc = subprocess.run(
            [exe, "x", "-p" + password, "-o+", archive, dest + os.sep],
            capture_output=True, text=True, errors="replace",
        )
    else:
        proc = subprocess.run(
            [exe, "x", archive, "-p" + password, "-o" + dest, "-y"],
            capture_output=True, text=True, errors="replace",
        )
    if proc.returncode != 0:
        tail = "\n".join((proc.stdout or "").strip().splitlines()[-3:])
        raise RuntimeError("extraction failed: %s" % (tail or proc.stderr.strip()))
    total = 0
    for _, _, files in os.walk(dest):
        total += len(files)
    return total
