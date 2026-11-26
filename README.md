# WinRaR Password Bypass

**RAR5 hash extraction, GPU cracking, verification and extraction — as one tool.**

No WinRAR install. No uploading your archive to someone's website. No "password unlocker"
installer. Reads the encryption parameters straight out of the RAR5 header, drives hashcat
when there is a GPU, falls back to a multiprocess CPU engine when there is not, verifies every
hit against the archive's own check value, and only then unpacks.

```
$ python main.py info secret.rar
┌─ secret.rar ────────────────────────────────────────────────────────────────
    format       RAR5
    files        94  (98 MB unpacked)
    headers      readable
    encryption   AES-256, 32800 iterations (log2=15)
    salt         9bfa25a6730fbdcc3e532776d3b69e59
    targets      1 distinct key context(s), 53 encrypted file(s)

$ python main.py crack secret.rar --auto --gpu --extract
┌─ crack: secret.rar ─────────────────────────────────────────────────────────
    engine       hashcat (v7.1.2)

  · targeted guesses
  ! exhausted targeted guesses
  · built-in top passwords
  + hit after 28,672 candidates

┌─ result ────────────────────────────────────────────────────────────────────
    password     123
    verified     yes
    time         8.1 s

  archive   opens  files
  ────────────────────────
  secret.rar  yes      94
```

---

## Contents

- [Install](#install)
- [Commands](#commands)
- [The crack pipeline](#the-crack-pipeline)
- [What "bypass" actually means](#what-bypass-actually-means)
- [Architecture](#architecture)
- [Internals: RAR5 and the check value](#internals-rar5-and-the-check-value)
- [Case study](#case-study)
- [Speed reality check](#speed-reality-check)
- [What does not work](#what-does-not-work)
- [Other archive formats](#other-archive-formats)
- [Development](#development)
- [License](#license)

---

## Install

Python 3.10+, no third-party packages.

```bash
git clone https://github.com/Pajt9whauht283as/winrar-password-bypass
cd winrar-password-bypass
python main.py doctor
```

Optional, but the tool uses them when present:

| Component | What it adds |
|---|---|
| [hashcat](https://hashcat.net/hashcat/) 7.x | GPU cracking, ~37 kH/s on an RTX 3060 instead of ~1.3 kH/s on CPU |
| 7-Zip or UnRAR | `--extract`, and second-opinion password tests |
| rockyou or any wordlist | the actual dictionary; a 2000-entry list ships built in |

`python main.py doctor` prints exactly what it found:

```
┌─ doctor ────────────────────────────────────────────────────────────────────
    python       3.14.5 (win32)
    cpu cores    16
    hashcat      v7.1.2
    path         C:\hashcat\hashcat.exe
    layout       ok
    device       NVIDIA GeForce RTX 3060 (GPU, 12287/12287 MB)
    7-zip        C:\Program Files\7-Zip\7z.exe
    unrar        C:\Program Files\WinRAR\UnRAR.exe
    potfile      C:\Users\you\.winrar-bypass\potfile
    builtin list 2003 passwords
```

`--hashcat PATH` and `--sevenzip PATH` override detection anywhere it is needed.

---

## Commands

| Command | What it does |
|---|---|
| `info <archive...>` | headers, KDF parameters, salt, file tree — no password |
| `hash <archive...>` | hashcat mode 13000 lines, `-o` to write a file |
| `verify <archive> <password>` | one PBKDF2 round, ~10 ms, exit code 0/1 |
| `crack <archive...>` | staged attack: targeted, wordlist, mutations, mask |
| `scan <path>` | find every `.rar` under a tree and group identical targets |
| `bench <archive>` | measure this machine and print time-to-exhaustion tables |
| `doctor` | environment check: python, hashcat, devices, extractors |

Everything machine-readable: `info`, `hash`, `scan` and `crack` take `--json`.

### info

```bash
python main.py info pack.rar --all          # every entry, not the first 15
```

Shows whether *headers* are encrypted separately from *data*, the exact iteration count and
salt, and how many distinct key contexts exist. When all entries share a salt — the normal
case — one crack opens everything.

### hash

```bash
python main.py hash pack.rar -o rar5.hash
hashcat -m 13000 rar5.hash rockyou.txt
```

The output is a standard `$rar5$16$<salt>$<kdf>$<iv>$8$<check>` line. It only needs the header
of the archive, so a partial download is enough to start attacking.

### crack

```bash
python main.py crack pack.rar --auto                       # targeted + built-in list
python main.py crack pack.rar -w rockyou.txt               # dictionary
python main.py crack pack.rar -w rockyou.txt --mutate 2    # + rules baked into python
python main.py crack pack.rar --mask '?l?l?l?l?l?l'        # brute force
python main.py crack pack.rar -w words.txt --gpu --extract # hashcat, then unpack
```

Multiple archives at once: the cheapest one is cracked, then the recovered password is tested
against every other archive you listed — the password-reuse attack, one command.

```bash
python main.py crack a.rar b.rar c.rar -w rockyou.txt --gpu
```

Other flags:

| Flag | Meaning |
|---|---|
| `--gpu` / `--hashcat PATH` | use hashcat, stream candidates into it |
| `--threads N` | CPU worker count (default: all cores) |
| `--workload 1..4` | hashcat `-w`, default 3 |
| `--rule file.rule` | hashcat rules for GPU wordlist stages |
| `--charset SET` | custom charset for `?1..?4`, repeatable |
| `--mutate 0..3` | built-in mutation depth applied to each wordlist |
| `--resume state.json` | continue a CPU run where it stopped |
| `--max-mask-hours H` | refuse masks that need longer, default 12 (override `--force`) |
| `--force` | ignore the mask guard, pass `--force` to hashcat |
| `--extract` / `-o DIR` | unpack after success |

### scan

```bash
python main.py scan D:\Downloads
```

```
  archive                     group  state  files   size
  ─────────────────────────────────────────────────────────
  Fortnite_Menu_Syntax3.rar   1      enc        94   98 MB
  Fortnite_Menu_Syntax3 (1).rar 1    enc        94   98 MB
  Fortnite_Menu_Syntax3 (2).rar 1    enc        94   98 MB
  other_pack.rar              2      enc        12   4 MB
  screenshots.rar             -      open      310  22 MB
```

Archives in the same group share a salt and KDF cost: identical copies, or the same pack
re-downloaded. One crack covers the whole group, and the tool says so instead of burning the
GPU three times.

### verify

```bash
python main.py verify pack.rar "hunter2"
# password 'hunter2' -> no (10.5 ms)
```

Uses the same fold WinRAR uses. No extraction, no hashcat, no temp files — useful for checking
a guess by hand or in a script.

---

## The crack pipeline

Stages run cheapest-first, and the first hit stops everything.

| # | Stage | Source | Typical cost | Hit rate |
|---|---|---|---|---|
| 1 | targeted guesses | archive name, years, leet, neighbours | seconds | high for packs named after their product |
| 2 | built-in top list | 2000 passwords shipped in the package | seconds | absurdly high |
| 3 | wordlist | rockyou, top-10M, your own list | minutes | the main workhorse |
| 4 | mutations | case, leet, 0-999 suffixes, years, separators | hours | catches `Arena2025!` |
| 5 | mask | `?u?l?l?l?l?l?d?d`, custom charsets | hours-days | only when shape is known |

The GPU path does not reimplement any of this in Python: generated candidates are **streamed
into `hashcat --stdin`**, so wordlists, mutation levels and masks all run at native hashcat
speed. Wordlists go straight to disk input, masks use hashcat's own `-a 3` engine, and only
generated streams take the pipe.

CPU mode is a `multiprocessing.Pool` with batches of `threads * 32` candidates, a shared
PBKDF2 context per worker, live rate and ETA, and a resume file keyed by stage name. It runs at
roughly 85 guesses/s per core, so 16 cores land near 1.3 kH/s — enough for dictionaries, not
for masks, which is why the mask guard exists.

Every hit is verified twice: our own PBKDF2 check (nothing stale from a potfile can slip
through) and, on extraction, 7-Zip's own decryption.

---

## What "bypass" actually means

A password-protected RAR5 is encrypted, not gated:

| Layer | Detail |
|---|---|
| Cipher | AES-256-CBC, one key per archive password |
| Key derivation | PBKDF2-HMAC-SHA256, `1 << kdf_count` iterations (normally 32768, +32 in the loop) |
| Salt | 16 bytes in the header |
| IV | 16 bytes per file |
| Password check | 12 bytes in the header; first 8 are a fold of the derived key |

There is no master key and no "unlock" flag. Instant removal claims are malware, data loss, or
a dictionary attack with a progress bar. Three things genuinely work:

1. **Guess fast.** GPUs turn a slow KDF into thousands of guesses per second. Almost every
   real-world win is a human picking a weak password, not a broken cipher.
2. **Read what is not encrypted.** With header encryption off, the archive tells you file
   names, sizes, timestamps, salt and iteration count before you guess anything.
3. **Never pay twice.** Packs are reposted. One password usually opens a family of archives,
   which is what `scan` and the multi-archive `crack` exist for.

---

## Architecture

```
main.py                  entry point, four lines of glue
winrar/
  cli.py                 argparse, stage builder, attack orchestration, reporting
  rar5.py                container parser: block chain, vints, extra records, entries
  crypto.py              PBKDF2, check-value fold, verify, benchmark
  attacks.py             wordlists, mutations, masks, hybrids, targeted guesses
  engine.py              CPU cracker: multiprocessing, batching, progress, resume
  gpu.py                 hashcat detection, stdin streaming, status parsing, potfile
  extract.py             7-Zip / UnRAR detection, password test, extraction
  batch.py               directory scan and grouping by KDF context
  ui.py                  colours, boxes, tables, progress bars, human units
  data/top-passwords.txt built-in 2000-entry list
tests/test_rar5.py       20 unit tests against the shipped sample archive
examples/sample.rar      tiny encrypted archive, password 123
```

Each module has one job and no import cycles: `rar5` knows the format, `crypto` knows the
math, `attacks` produces candidates, `engine` and `gpu` consume them, `cli` decides the order.
Adding an attack means yielding strings from a new generator in `attacks.py` and naming it in
`cli.build_stages`.

---

## Internals: RAR5 and the check value

RAR5 stores everything in a chain of blocks: `crc32 | header_size (vint) | header`. A file
header carries an extra area of typed records; record type `1` is encryption:

```
version    vint
flags      vint
kdf_count  1 byte        -> iterations = (1 << kdf_count) + 32
salt       16 bytes
iv         16 bytes
check      12 bytes      -> first 8 bytes are the password check
```

Compression info is packed as `(method << 7) | (solid << 6) | version`, and both masks have to
be applied carefully: WinRAR 7 writes extra bits above bit 10, so `method` is `(comp >> 7) & 0xF`,
not `comp >> 7`. Getting that wrong turns every entry into "m67".

The check itself:

```python
key = pbkdf2_hmac("sha256", password.encode(), salt, (1 << log2) + 32, 32)
w   = unpack("<8I", key)
chk = pack("<2I", w[0] ^ w[2] ^ w[4] ^ w[6], w[1] ^ w[3] ^ w[5] ^ w[7])
```

That is byte-identical to what WinRAR compares and what hashcat's `m13000` kernel computes,
which is why a hit here can be trusted without decrypting the payload.

---

## Case study

An 82 MiB RAR5 pack pulled from a Discord CDN link. Headers readable, one KDF context:

```
$rar5$16$9bfa25a6730fbdcc3e532776d3b69e59$15$6c54a84371908514f508d6cb218379e1$8$24dd5a0a04188cae
```

```
Speed.#01........: 37214 H/s
Recovered........: 1/1 (100.00%) Digests
Progress.........: 28672/14344384 (0.20%)
```

Password **`123`**, candidate 28,672 of rockyou, eight seconds of GPU. Two sibling archives from
the same channel opened with the same password on the first try — password reuse in one line.

The hash is kept in [`examples/rar5.hash`](examples/rar5.hash) as a public test vector, and
[`examples/sample.rar`](examples/sample.rar) is a tiny archive built with the same password so
the whole chain can be reproduced without shipping anyone else's archive:

```bash
python main.py crack examples/sample.rar --auto
python -m unittest discover -s tests -v
```

---

## Speed reality check

Measured on an RTX 3060 12 GB and a Ryzen 7 7800X3D:

| Engine | RAR5 guesses/s |
|---|---|
| CPU, one core | ~85 |
| CPU, 16 threads | ~1.3 kH/s |
| GPU, RTX 3060 | ~37 kH/s |
| GPU, RTX 4090 (reference) | ~120 kH/s |

What that buys at 37 kH/s:

| Keyspace | Time |
|---|---|
| built-in 2000 | instant |
| rockyou (14.3M) | 6.5 min |
| rockyou + best64 rules (1.1G) | 8 h |
| `?l?l?l?l?l?l` (309M) | 2.3 h |
| `?l?l?l?l?l?l?d?d` (30.9G) | 9.6 days |

That table is the whole strategy: dictionaries and rules, never blind brute force.

---

## What does not work

- **"Repair archive" in WinRAR.** Rebuilds headers, decrypts nothing.
- **Convert to ZIP, rename, re-archive.** The payload stays AES blocks.
- **CVE-2023-38831 / CVE-2022-30333.** Spoofed extensions and path traversal on extraction.
  Neither recovers a password.
- **Known plaintext on RAR5.** You may know every byte of the vendored files inside. AES-256-CBC
  with a PBKDF2 key gives you nothing to invert. Known-plaintext attacks belong to legacy ZIP.
- **Commercial unlocker GUIs.** hashcat in a window with a smaller wordlist and a larger price.

Header encryption is not a bypass either: it hides the file names and per-file IVs, but the
salt and KDF cost are still in the archive header, so the attack is the same — you just cannot
pick the smallest entry first.

---

## Other archive formats

| Format | Real shortcut | Tooling |
|---|---|---|
| RAR5 | none, crack it | `main.py`, hashcat `13000` |
| RAR3 / RAR4 | known plaintext speeds it up a lot | hashcat `12500` + `rar2john` |
| 7z | none, crack it | hashcat `11600` |
| ZIP + ZipCrypto | **bkcrack**: ~12 known bytes recover the keys, no password needed | `bkcrack` |
| ZIP + AES-256 | none, crack it | hashcat `13600` |

`main.py` detects these signatures and tells you which path to take instead of failing with
"not a RAR5 archive".

---

## Development

```bash
python -m unittest discover -s tests -v     # 20 tests, no network, no GPU needed
python main.py bench examples/sample.rar    # what this machine can do
pip install .                               # installs the `winrar-bypass` command
```

The test suite builds every fixture from `examples/sample.rar`, so it stays deterministic and
does not need an encrypted archive from anyone else.

## License

MIT.
