"""Terminal output: colours, boxes, tables, progress bars, human units."""

from __future__ import annotations

import os
import shutil
import sys
import time

_TTY = sys.stdout.isatty()
_COLOR = _TTY and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"


def _sgr(code: str, text: str) -> str:
    if not _COLOR:
        return text
    return "\x1b[%sm%s\x1b[0m" % (code, text)


def disable() -> None:
    """Turn colours off at runtime (--no-color)."""
    global _COLOR
    _COLOR = False


def bold(text: str) -> str:
    return _sgr("1", text)


def dim(text: str) -> str:
    return _sgr("2", text)


def red(text: str) -> str:
    return _sgr("31", text)


def green(text: str) -> str:
    return _sgr("32", text)


def yellow(text: str) -> str:
    return _sgr("33", text)


def blue(text: str) -> str:
    return _sgr("34", text)


def magenta(text: str) -> str:
    return _sgr("35", text)


def cyan(text: str) -> str:
    return _sgr("36", text)


def width(default: int = 80) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except OSError:
        return default


def title(text: str) -> None:
    line = "─" * max(0, min(width(), 78) - len(text) - 4)
    print()
    print(cyan("┌─ ") + bold(text) + " " + cyan(line))


def section(text: str, pad: int = 2) -> None:
    print(" " * pad + dim("·") + " " + bold(text))


def kv(key: str, value: str, pad: int = 4) -> None:
    print(" " * pad + dim("%-12s" % key) + " " + value)


def warn(text: str) -> None:
    print(yellow("  ! ") + text)


def fail(text: str) -> None:
    print(red("  x ") + text, file=sys.stderr)


def ok(text: str) -> None:
    print(green("  + ") + text)


def table(headers: list[str], rows: list[list[str]], right: tuple[int, ...] = ()) -> None:
    if not rows:
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    header = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print("  " + dim(header))
    print("  " + dim("─" * len(header)))
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            cells.append(cell.rjust(widths[i]) if i in right else cell.ljust(widths[i]))
        print("  " + "  ".join(cells))


def human_time(seconds: float) -> str:
    if seconds < 0 or seconds != seconds or seconds == float("inf"):
        return "?"
    if seconds < 1:
        return "%.0f ms" % (seconds * 1000)
    if seconds < 60:
        return "%.1f s" % seconds
    if seconds < 3600:
        return "%d m %02d s" % divmod(int(seconds), 60)
    if seconds < 86400:
        hours, rest = divmod(int(seconds), 3600)
        return "%d h %02d m" % (hours, rest // 60)
    days, rest = divmod(int(seconds), 86400)
    return "%d d %02d h" % (days, rest // 3600)


def human_count(n: float) -> str:
    for unit in ("", "K", "M", "G", "T", "P"):
        if abs(n) < 1000:
            return ("%d%s" % (n, unit)) if unit == "" else ("%.1f%s" % (n, unit))
        n /= 1000.0
    return "%.1fE" % n


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return "%.0f %s" % (n, unit)
        n /= 1024.0
    return "%.1f TB" % n


class Progress:
    """Single-line progress bar with rate and ETA. Degrades to periodic lines."""

    def __init__(self, total: int | None, label: str = "", stream=None) -> None:
        self.total = total
        self.label = label
        self.stream = stream or sys.stdout
        self.started = time.monotonic()
        self.last_draw = 0.0
        self.last_count = 0
        self.last_time = self.started
        self._drawn = False

    def update(self, done: int, force: bool = False) -> None:
        now = time.monotonic()
        interval = 0.05 if self.total else 1.0
        if not force and now - self.last_draw < interval:
            return
        self.last_draw = now
        rate = 0.0
        if now - self.last_time >= 0.5:
            rate = (done - self.last_count) / max(now - self.last_time, 1e-9)
            self.last_count = done
            self.last_time = now
        if not _TTY:
            if force or now - self.last_draw >= 5:
                pct = ("%.1f%%" % (100.0 * done / self.total)) if self.total else ""
                print("  %s %s %s/s" % (self.label, human_count(done), human_count(rate)))
            return
        bar = ""
        if self.total:
            frac = min(done / self.total, 1.0) if self.total else 0.0
            cells = 24
            filled = int(frac * cells)
            bar = dim("[") + "#" * filled + dim("." * (cells - filled)) + dim("] ")
            bar += "%5.1f%%  " % (100 * frac)
        eta = ""
        if self.total and rate > 0:
            eta = "  eta " + human_time((self.total - done) / rate)
        line = "  %s%s%s  %s/s%s" % (bar, self.label, "", human_count(rate), eta)
        self.stream.write("\r" + line[: max(width() - 1, 20)] + "\x1b[K")
        self.stream.flush()
        self._drawn = True

    def finish(self, message: str = "") -> None:
        if _TTY and self._drawn:
            self.stream.write("\r\x1b[K")
            self.stream.flush()
        if message:
            print("  " + message)
