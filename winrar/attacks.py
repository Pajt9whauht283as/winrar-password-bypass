"""Candidate generation: wordlists, mutations, masks, hybrids and targeted guesses."""

from __future__ import annotations

import os
import re
from typing import Iterable, Iterator

CHARSETS = {
    "l": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "d": "0123456789",
    "s": " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    "b": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "h": "0123456789abcdef",
    "H": "0123456789ABCDEF",
}
CHARSETS["a"] = CHARSETS["l"] + CHARSETS["u"] + CHARSETS["d"] + CHARSETS["s"]

LEET = str.maketrans({
    "a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7",
    "A": "4", "E": "3", "I": "1", "O": "0", "S": "5", "T": "7",
})

SUFFIX_1 = ["", "1", "12", "123", "1234", "12345", "!", "!!", "1!", "@", "#",
            "0", "01", "007", "69", "777", "321", "21", "11", "99", "000"]
YEARS = [str(y) for y in range(1990, 2028)]
COMMON_EXTRA = ["_", "-", ".", "$"]


# ------------------------------------------------------------------ wordlists

def read_wordlist(path: str) -> Iterator[str]:
    """Stream a wordlist, tolerating encodings and stray whitespace."""
    with open(path, "rb") as fh:
        raw = fh.read(3)
        if raw == b"\xef\xbb\xbf":
            fh.seek(3)
        elif raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
            fh.seek(0)
    errors = ["utf-8", "latin-1"]
    for encoding in errors:
        try:
            with open(path, "r", encoding=encoding, errors="strict") as fh:
                for line in fh:
                    word = line.rstrip("\r\n")
                    if word:
                        yield word
            return
        except UnicodeDecodeError:
            continue


def count_lines(path: str) -> int:
    total = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            total += chunk.count(b"\n")
    return total


# ------------------------------------------------------------------ mutations

def leet(word: str) -> str:
    return word.translate(LEET)


def variants(word: str) -> Iterator[str]:
    seen = set()
    for candidate in (word, word.lower(), word.capitalize(), word.upper(), leet(word)):
        if candidate and candidate not in seen:
            seen.add(candidate)
            yield candidate


def mutate(words: Iterable[str], level: int = 1) -> Iterator[str]:
    """Cheap rules baked into Python so no rule file is needed.

    level 1: case and leet variants
    level 2: level 1 plus the usual numeric and symbol suffixes
    level 3: level 2 plus every 4-digit suffix and underscore/hyphen joiners
    """
    emitted: set[str] = set()
    for word in words:
        for base in variants(word):
            for suffix in SUFFIX_1:
                candidate = base + suffix
                if candidate not in emitted:
                    emitted.add(candidate)
                    yield candidate
            if level >= 2:
                for year in YEARS:
                    for candidate in (base + year, base + "_" + year, base + "@" + year):
                        if candidate not in emitted:
                            emitted.add(candidate)
                            yield candidate
            if level >= 3:
                for sep in COMMON_EXTRA:
                    for year in ("2024", "2025", "2026"):
                        candidate = base + sep + year
                        if candidate not in emitted:
                            emitted.add(candidate)
                            yield candidate
                for i in range(1000):
                    candidate = "%s%03d" % (base, i)
                    if candidate not in emitted:
                        emitted.add(candidate)
                        yield candidate


def hybrid(words: Iterable[str], suffixes: Iterable[str]) -> Iterator[str]:
    for word in words:
        for suffix in suffixes:
            yield word + suffix


def mutation_multiplier(level: int) -> int:
    """Rough upper bound on candidates per source word for mutate()."""
    per_word = 5 * len(SUFFIX_1)
    if level >= 2:
        per_word += 5 * 3 * len(YEARS)
    if level >= 3:
        per_word += 5 * (9 + 1000)
    return per_word


# ------------------------------------------------------------------ masks

def parse_mask(mask: str, custom: list[str] | None = None) -> list[str]:
    """Split a hashcat-style mask into a list of character sets."""
    custom = custom or []
    sets: list[str] = []
    i = 0
    while i < len(mask):
        ch = mask[i]
        if ch == "?":
            if i + 1 >= len(mask):
                raise ValueError("mask ends with a lone '?'")
            token = mask[i + 1]
            if token == "?":
                sets.append("?")
                i += 2
                continue
            if token.isdigit():
                index = int(token)
                if not 1 <= index <= len(custom):
                    raise ValueError("mask uses ?%s but --charset%s was not given" % (token, token))
                sets.append(custom[index - 1])
                i += 2
                continue
            if token not in CHARSETS:
                raise ValueError("unknown mask token ?%s" % token)
            sets.append(CHARSETS[token])
            i += 2
            continue
        sets.append(ch)
        i += 1
    if not sets:
        raise ValueError("empty mask")
    return sets


def mask_keyspace(mask: str, custom: list[str] | None = None) -> int:
    total = 1
    for charset in parse_mask(mask, custom):
        total *= len(charset)
    return total


def mask_iter(mask: str, custom: list[str] | None = None) -> Iterator[str]:
    sets = parse_mask(mask, custom)
    indices = [0] * len(sets)
    while True:
        yield "".join(charset[i] for charset, i in zip(sets, indices))
        pos = len(sets) - 1
        while pos >= 0:
            indices[pos] += 1
            if indices[pos] < len(sets[pos]):
                break
            indices[pos] = 0
            pos -= 1
        if pos < 0:
            return


# ------------------------------------------------------------------ targeted

def tokens_from_path(path: str) -> list[str]:
    """Words a human would plausibly put in the password of this archive."""
    stem = os.path.splitext(os.path.basename(path))[0]
    parts = [p for p in re.split(r"[^0-9A-Za-z]+", stem) if p]
    tokens: list[str] = []
    for part in parts + [stem]:
        for candidate in (part, part.lower(), part.capitalize(), part.upper()):
            if len(candidate) > 1 and candidate not in tokens:
                tokens.append(candidate)
    return tokens


def targeted(path: str, extra_tokens: Iterable[str] = ()) -> Iterator[str]:
    """Index-free first pass: product names, years, leet and digit tails."""
    stems = tokens_from_path(path) + [t for t in extra_tokens if t]
    emitted: set[str] = set()
    for stem in stems:
        bases = list(variants(stem))
        for base in bases:
            combos = [base]
            for other in stems:
                if other != stem:
                    combos.append(base + other)
                    combos.append(base + "_" + other)
            for combo in combos:
                for suffix in SUFFIX_1 + YEARS:
                    candidate = combo + suffix
                    if candidate not in emitted:
                        emitted.add(candidate)
                        yield candidate
                if combos:
                    for candidate in (combo + "2025", combo + "2026", combo + "!"):
                        if candidate not in emitted:
                            emitted.add(candidate)
                            yield candidate


# ------------------------------------------------------------------ packaged data

def top_passwords() -> Iterator[str]:
    """Small built-in list so the tool is useful with no external wordlist."""
    path = os.path.join(os.path.dirname(__file__), "data", "top-passwords.txt")
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            word = line.rstrip("\r\n")
            if word:
                yield word
