# WinRaR Password Bypass

**One toolkit for password-protected archives: RAR5, ZIP (ZipCrypto and WinZip AES), and 7z.**

Reads the encryption parameters straight out of the container headers, drives hashcat when a
GPU is available, falls back to a multiprocess CPU engine when it is not, verifies every hit
against the archive itself, and only then unpacks. Plus a forensics mode that fingerprints
archives, builds a timeline, and spots re-packs and re-downloads.

No WinRAR install. No uploading your archive to someone's website. No "password unlocker"
installer.

```
$ python main.py info secret.rar
┌─ secret.rar ────────────────────────────────────────────────────────────────
    format       RAR5
    files        94  (98 MB unpacked)
    crypto       AES-256 RAR5 (PBKDF2-HMAC-SHA256)
    kdf          32800 iterations (log2=15)
    salt         9bfa25a6730fbdcc3e532776d3b69e59
    targets      53 encrypted file(s)

$ python main.py crack secret.rar --auto --gpu --extract
┌─ crack: secret.rar ─────────────────────────────────────────────────────────
    engine       hashcat (v7.1.2, mode 13000)

  · targeted guesses
  ! exhausted targeted guesses
  · built-in top passwords
  + hit after 28,672 candidates

┌─ result ────────────────────────────────────────────────────────────────────
    password     123
    verified     yes
    time         8.1 s
```

---

## Contents

- [Format support](#format-support)
- [Install](#install)
- [Commands](#commands)
- [Forensics](#forensics)
- [The crack pipeline](#the-crack-pipeline)
- [What "bypass" actually means](#what-bypass-actually-means)
- [Architecture](#architecture)
- [Internals](#internals)
- [Case study](#case-study)
- [Speed reality check](#speed-reality-check)
- [Limits and what does not work](#limits-and-what-does-not-work)
- [Development](#development)
- [License](#license)

---

## Format support

| Container | Detection | Crack engine | hashcat mode | Local verifier |
|---|---|---|---|---|
| RAR5 | header block chain | CPU or GPU | `13000` | PBKDF2 pswcheck, ~10 ms |
| ZIP + ZipCrypto | central directory | **CPU, ~2.5 M guesses/s** | — (no KDF to attack) | header byte + inflate + CRC |
| ZIP + WinZip AES | `0x9901` extra field | GPU | `13600` | 7-Zip test on the hit |
| 7z + 7zAES | header property tree | GPU | `11600` | 7-Zip test on the hit |

ZipCrypto has no key derivation function: three 32-bit keys advance per password byte, so a
pure-Python engine beats waiting for a GPU round-trip, and masks on short passwords become
realistic. RAR5 and 7z are deliberately slow by design, so they lean on hashcat.

RAR4 is detected and refused with the mode you actually want (`12500` + `rar2john`).

## Install

Python 3.10+, no third-party packages.

```bash
git clone https://github.com/Pajt9whauht283as/winrar-password-bypass
cd winrar-password-bypass
python main.py doctor
```

Optional, used when present:

| Component | What it adds |
|---|---|
| [hashcat](https://hashcat.net/hashcat/) 7.x | GPU cracking for RAR5, 7z and WinZip AES |
| 7-Zip or UnRAR | `--extract`, and the verifier for 7z / AES zip |
| rockyou or any wordlist | the dictionary; a 2000-entry list ships built in |

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
    zipcrypto    1.6M guesses/s per core
```

## Commands

| Command | What it does |
|---|---|
| `info <archive...>` | headers, crypto, KDF, salt, file tree — no password |
| `hash <archive...>` | hashcat lines for the format (`13000`, `11600`, `13600`) |
| `verify <archive> <password>` | one local check, exit code 0/1 |
| `crack <archive...>` | staged attack: targeted, wordlist, mutations, mask |
| `forensics <path>` | fingerprints, timeline, compression profile, duplicates |
| `scan <path>` | find every archive under a tree and group identical targets |
| `bench <archive>` | measure this machine and print time-to-exhaustion tables |
| `doctor` | environment check |

`info`, `hash`, `scan`, `forensics` and `crack` all take `--json`.

### Per format

```bash
# RAR5
python main.py crack pack.rar --auto --gpu --extract
python main.py crack pack.rar -w rockyou.txt --mutate 2 --hashcat C:\hashcat\hashcat.exe

# ZIP with ZipCrypto: no GPU needed, masks are cheap
python main.py crack photos.zip --auto
python main.py crack photos.zip --mask '?l?l?l?l?l?l'

# ZIP with WinZip AES, and 7z
python main.py crack vault.zip -w rockyou.txt --gpu
python main.py crack backup.7z -w rockyou.txt --gpu
```

Multiple archives at once: the cheapest one is cracked, then the password is tested against
every other archive — the reuse attack in one command.

```bash
python main.py crack a.rar b.rar c.7z -w rockyou.txt --gpu
```

Other flags: `--threads N`, `--workload 1..4`, `--rule file.rule`, `--charset SET`,
`--mutate 0..3`, `--resume state.json`, `--max-mask-hours H`, `--force`, `--extract`, `-o DIR`,
`--sevenzip PATH`, `-q`.

## Forensics

```bash
python main.py forensics D:\Downloads\packs
```

```
┌─ pack_v2.rar ───────────────────────────────────────────────────────────────
    format       RAR5
    size         82 MB on disk, 98 MB unpacked, 94 files
    crypto       AES-256 RAR5 (PBKDF2-HMAC-SHA256)
    kdf          32800 iterations (log2=15)
    salt         9bfa25a6730fbdcc3e532776d3b69e59
    timeline     2026-11-06 04:15 .. 2026-11-06 05:55 (0.1 days)
    largest      arena_showcase.mp4 (43.9 MB)
    methods      normal x91, store x3
    bytes fp     9a2de82278f9afb65344efb18b26ea37...
    payload fp   0b2ec97241e403fbbbcefa603fc55c10...

· relationships
  identical bytes                  pack.rar, pack (1).rar
  same payload, different archive  pack.rar, backup.7z
```

Two fingerprints, on purpose:

- **bytes fingerprint** — SHA-256 of the first 64 KiB. Identical means the same file, byte for
  byte: a re-download.
- **payload fingerprint** — SHA-256 over the sorted `name:size` list. Identical means the same
  content re-packed into a different container or a different compression method.

That distinction is what tells an analyst whether two archives are the same distribution or a
repack, and it is computed without the password.

## The crack pipeline

Stages run cheapest-first and the first verified hit stops everything.

| # | Stage | Source | Typical cost | Notes |
|---|---|---|---|---|
| 1 | targeted guesses | archive name, years, leet, sibling names | seconds | high hit rate on packs named after their product |
| 2 | built-in top list | 2000 passwords shipped in the package | seconds | absurdly high |
| 3 | wordlist | rockyou, top-10M, your own | minutes | the workhorse |
| 4 | mutations | case, leet, 0-999 suffixes, years, separators | hours | catches `Arena2025!` |
| 5 | mask | `?u?l?l?l?l?l?d?d`, custom charsets | hours-days | guarded by an ETA check |

GPU stages stream generated candidates into `hashcat --stdin`, so mutations and targeted
guesses run at native hashcat speed; wordlists go straight to disk input and masks use
hashcat's own `-a 3`.

CPU stages use a `multiprocessing.Pool` with batches of `threads * 32` candidates for PBKDF2
formats, `threads * 4096` for ZipCrypto, live rate and ETA, and per-stage resume.

Every hit is confirmed twice: locally against the container's own check (PBKDF2 pswcheck,
ZipCrypto header + inflate + CRC, or 7z/zip via the extraction tool), and again on extraction.

## What "bypass" actually means

A password-protected archive is encrypted, not gated:

| Format | Cipher | KDF | Verifier |
|---|---|---|---|
| RAR5 | AES-256-CBC, per-file IV | PBKDF2-HMAC-SHA256, 32768+ rounds | 8-byte fold of the key |
| ZIP AES | AES-128/192/256, CBC | PBKDF2-HMAC-SHA1, 1000 rounds | 2-byte password value + HMAC-SHA1 auth code |
| 7z | AES-256-CBC | SHA-256 chain, 2^19 rounds | CRC32 of the unpacked stream |
| ZIP ZipCrypto | custom 3-key stream | none | 1 byte of the 12-byte header |

There is no master key and no unlock flag. Three things genuinely work:

1. **Guess fast.** GPUs on the slow KDFs, raw Python on ZipCrypto which has no KDF at all.
2. **Read what is not encrypted.** With header encryption off, names, sizes, salts and cost are
   all readable before you guess anything.
3. **Never pay twice.** Packs are reposted; one password usually opens a family.

## Architecture

```
main.py                  entry point, four lines of glue
winrar/
  cli.py                 argparse, attack staging, reporting
  formats.py             signature sniffing, uniform view, target selection
  rar5.py                RAR5 block chain, extra records, RAR5 crypto metadata
  sevenzip.py            7z header property tree, 7zAES parameters, $7z$ emission
  ziparchive.py          ZIP central directory, AES extra field, $zip2$ emission
  zipcrypto.py           PKWARE cipher, full verifier, fast CPU engine
  crypto.py              RAR5 PBKDF2, check fold, verify, benchmark
  attacks.py             wordlists, mutations, masks, hybrids, targeted guesses
  engine.py              PBKDF2 CPU cracker: multiprocessing, batching, resume
  gpu.py                 hashcat detection, stdin streaming, status parsing, potfile
  forensics.py           fingerprints, timeline, compression profile, grouping
  extract.py             7-Zip / UnRAR detection, password test, extraction
  batch.py               directory scan and grouping by KDF context
  ui.py                  colours, boxes, tables, progress bars, human units
  data/top-passwords.txt built-in 2000-entry list
tests/                   35 unit tests over four shipped sample archives
examples/                tiny RAR5, ZipCrypto, AES zip and 7z archives, password 123
```

## Internals

**RAR5.** Blocks are `crc32 | header_size (vint) | header`; record type `1` in a file's extra
area is the encryption record (`version, flags, kdf_count, salt[16], iv[16], check[12]`). The
check is `w0^w2^w4^w6 ‖ w1^w3^w5^w7` over the first eight PBKDF2 words. Compression info packs
`(method << 7) | (solid << 6) | version`, and WinRAR 7 writes bits above bit 10, so the method
is `(comp >> 7) & 0xF`.

**ZipCrypto.** Keys start at `0x12345678, 0x23456789, 0x34567890`, each password byte updates
all three, and the keystream byte comes from `(k2 | 2) * ((k2 | 2) ^ 1) >> 8 & 0xFF`. The last
of the 12 header bytes must equal the high CRC byte (or the high time byte when a data
descriptor is used). That is a 1-in-256 filter, so the tool always re-decrypts the body,
inflates it and compares the CRC before accepting a hit.

**7z.** The header is a property tree (`kPackInfo`, `kUnPackInfo`, `kFilesInfo`) and is usually
LZMA-compressed itself — inflated here with the stdlib `lzma` module, no 7z binary needed. The
AES coder property byte packs `cycles` and the presence of salt/IV. Three details cost real
time to get right and are documented in the code:

- 7-Zip's KDF counter is a little-endian 64-bit value appended to the UTF-16LE password per
  iteration, not big-endian.
- The CRC that hashcat can verify is the **substream** (first file) CRC, not the folder CRC,
  with `crc_len` equal to that file's unpacked size.
- `kCRC` blobs start with a single `allAreDefined` byte, not two.

## Case study

An 82 MiB RAR5 pack pulled from a Discord CDN link. Headers readable, one KDF context:

```
$rar5$16$9bfa25a6730fbdcc3e532776d3b69e59$15$6c54a84371908514f508d6cb218379e1$8$24dd5a0a04188cae

Speed.#01........: 37214 H/s
Recovered........: 1/1 (100.00%) Digests
Progress.........: 28672/14344384 (0.20%)
```

Password **`123`**, candidate 28,672 of rockyou, eight seconds of GPU. Two sibling archives
from the same channel opened with the same password on the first try.

The hash is kept in [`examples/rar5.hash`](examples/rar5.hash); the four sample archives are
built with the same password so the whole chain reproduces:

```bash
python main.py crack examples/sample_zipcrypto.zip --auto
python main.py crack examples/sample_plain.7z -w wordlist.txt --gpu
python -m unittest discover -s tests -v
```

## Speed reality check

Measured on an RTX 3060 12 GB and a Ryzen 7 7800X3D:

| Format | Engine | Guesses/s |
|---|---|---|
| ZipCrypto | CPU, one core | ~1.6 M |
| ZipCrypto | CPU, 16 threads | ~2.5 M |
| RAR5 | CPU, one core | ~85 |
| RAR5 | CPU, 16 threads | ~1.3 K |
| RAR5 | GPU | ~37 K |
| 7z | GPU | ~40 K |
| WinZip AES | GPU | ~500 K |

What that buys at 37 kH/s for RAR5:

| Keyspace | Time |
|---|---|
| built-in 2000 | instant |
| rockyou (14.3M) | 6.5 min |
| rockyou + best64 rules (1.1G) | 8 h |
| `?l?l?l?l?l?l` (309M) | 2.3 h |
| `?l?l?l?l?l?l?d?d` (30.9G) | 9.6 days |

ZipCrypto at 2.5 M/s finishes `?l?l?l?l?l?l` in two minutes — that gap is why the format
matters more than the hardware.

## Limits and what does not work

Deliberate limits, reported instead of guessed at:

- 7z with an explicit **salt** in the AES properties cannot be expressed as a hashcat `$7z$`
  line; the tool says so and points at 7z2hashcat.
- 7z streams larger than 8 MiB, and AES zip entries larger than 4 MiB, exceed hashcat's hook
  buffers; the tool reports the size instead of emitting a hash that cannot verify.
- ZipCrypto has no hashcat format here: the CPU engine is faster anyway.
- RAR4 needs hashcat mode `12500` and `rar2john`.

Things that never work:

- "Repair archive" in WinRAR: rebuilds headers, decrypts nothing.
- Convert to ZIP, rename, re-archive: the payload stays AES blocks.
- CVE-2023-38831 / CVE-2022-30333: extension spoofing and path traversal on extraction.
- Known plaintext on RAR5/7z/AES: AES-256-CBC with a KDF key gives nothing to invert.
  Known-plaintext belongs to legacy ZipCrypto (`bkcrack`).
- Commercial unlocker GUIs: hashcat in a window with a smaller wordlist and a bigger price.

## Development

```bash
python -m unittest discover -s tests -v     # 35 tests, no network, no GPU needed
python main.py bench examples/sample.rar
pip install .                               # installs the `winrar-bypass` command
```

Every fixture is generated from the four shipped samples, so the suite is deterministic and
never needs anyone else's archive.

## License

MIT.
