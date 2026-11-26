"""Batch discovery: find archives under a path and group them by KDF context."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .rar5 import Archive, ArchiveError

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}


@dataclass
class Discovered:
    path: str
    archive: Archive | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.archive is not None

    @property
    def encrypted(self) -> bool:
        return bool(self.archive and self.archive.encrypted_entries)

    @property
    def hashes(self) -> list[str]:
        if not self.archive:
            return []
        try:
            return self.archive.hashes()
        except ArchiveError:
            return []


@dataclass
class Group:
    hash_line: str
    archives: list[Discovered] = field(default_factory=list)


def find_archives(root: str, recursive: bool = True) -> list[str]:
    if os.path.isfile(root):
        return [root]
    found: list[str] = []
    if recursive:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name.lower().endswith((".rar", ".rev")):
                    found.append(os.path.join(dirpath, name))
    else:
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isfile(path) and name.lower().endswith((".rar", ".rev")):
                found.append(path)
    return sorted(found)


def scan(root: str, recursive: bool = True) -> list[Discovered]:
    items: list[Discovered] = []
    for path in find_archives(root, recursive):
        try:
            items.append(Discovered(path=path, archive=Archive.open(path)))
        except ArchiveError as exc:
            items.append(Discovered(path=path, error=str(exc)))
        except OSError as exc:
            items.append(Discovered(path=path, error=str(exc)))
    return items


def group_by_target(items: list[Discovered]) -> list[Group]:
    """Archives that share a salt and KDF cost share the same cracking target."""
    groups: dict[str, Group] = {}
    for item in items:
        for line in item.hashes:
            groups.setdefault(line, Group(hash_line=line)).archives.append(item)
    return sorted(groups.values(), key=lambda g: len(g.archives), reverse=True)
