"""CPU cracking engine: multiprocess PBKDF2 with batching, progress and resume."""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import time
from dataclasses import dataclass
from itertools import islice
from typing import Iterable, Iterator

from . import crypto, ui
from .rar5 import Entry

_STATE: dict = {}


def _init_worker(salt: bytes, log2: int, check: bytes) -> None:
    _STATE["salt"] = salt
    _STATE["log2"] = log2
    _STATE["check"] = check


def _work(batch: list[str]) -> tuple[str | None, int]:
    salt = _STATE["salt"]
    log2 = _STATE["log2"]
    check = _STATE["check"]
    for password in batch:
        try:
            if crypto.pswcheck(password, salt, log2) == check:
                return password, len(batch)
        except (ValueError, UnicodeEncodeError):
            continue
    return None, len(batch)


@dataclass
class CrackResult:
    password: str | None
    tested: int
    elapsed: float

    @property
    def rate(self) -> float:
        return self.tested / max(self.elapsed, 1e-9)


class CpuEngine:
    def __init__(self, entry: Entry, threads: int | None = None, resume_path: str | None = None):
        if not entry.encrypted:
            raise ValueError("entry is not encrypted")
        self.entry = entry
        self.threads = threads or os.cpu_count() or 4
        self.resume_path = resume_path

    # -- resume -----------------------------------------------------------

    def _load_resume(self, stage: str) -> int:
        if not self.resume_path or not os.path.exists(self.resume_path):
            return 0
        try:
            with open(self.resume_path, "r", encoding="utf-8") as fh:
                state = json.load(fh)
            if state.get("stage") != stage:
                return 0
            return int(state.get("done", 0))
        except (OSError, ValueError):
            return 0

    def _save_resume(self, done: int, stage: str) -> None:
        if not self.resume_path:
            return
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.resume_path)), exist_ok=True)
            with open(self.resume_path, "w", encoding="utf-8") as fh:
                json.dump({"stage": stage, "done": done, "updated": time.time()}, fh)
        except OSError:
            pass

    # -- main loop --------------------------------------------------------

    def crack(
        self,
        candidates: Iterable[str],
        total: int | None = None,
        label: str = "",
        quiet: bool = False,
    ) -> CrackResult:
        started = time.monotonic()
        stream = iter(candidates)

        done = self._load_resume(label)
        if done:
            if not quiet:
                ui.warn("resuming after %s candidates" % ui.human_count(done))
            stream = islice(stream, done, None)

        batch_size = max(self.threads * 32, 256)
        tested = done
        progress = ui.Progress(total, label or "cracking", stream=None) if not quiet else None

        pool = mp.Pool(
            processes=self.threads,
            initializer=_init_worker,
            initargs=(self.entry.salt, self.entry.log2, self.entry.check[:8]),
        )
        try:
            batches = self._batches(stream, batch_size)
            for found, size in pool.imap_unordered(_work, batches, chunksize=1):
                tested += size
                if progress:
                    progress.update(min(tested, total) if total else tested)
                if found is not None:
                    pool.terminate()
                    elapsed = time.monotonic() - started
                    self._save_resume(tested, label)
                    return CrackResult(found, tested, elapsed)
            pool.close()
        except KeyboardInterrupt:
            pool.terminate()
            self._save_resume(tested, label)
            if progress:
                progress.finish(ui.yellow("interrupted, state saved"))
            return CrackResult(None, tested, time.monotonic() - started)
        finally:
            pool.join()

        elapsed = time.monotonic() - started
        if progress:
            progress.finish()
        self._save_resume(tested, label)
        return CrackResult(None, tested, elapsed)

    @staticmethod
    def _batches(stream: Iterator[str], size: int) -> Iterator[list[str]]:
        while True:
            batch = list(islice(stream, size))
            if not batch:
                return
            yield batch
