# WinRaR Password Bypass

**A clean, dependency-free attack pipeline for password-protected WinRAR archives.**
Pulls the RAR5 hash straight out of the archive headers, hands it to hashcat, verifies the
result locally, and extracts. No WinRAR install, no sketchy "password unlocker" binaries,
no uploading your archive to somebody's website.

```
$ python rar5_hash.py hash secret.rar
$rar5$16$9bfa25a6730fbdcc3e532776d3b69e59$15$6c54a84371908514f508d6cb218379e1$8$24dd5a0a04188cae

$ hashcat -m 13000 hash.txt rockyou.txt
$rar5$16$9bfa25...$8$24dd5a0a04188cae:123
Status...........: Cracked
Time.Started.....: (8 secs)
```

---

## Contents

- [The honest version of "bypass"](#the-honest-version-of-bypass)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Case study: the archive this was built on](#case-study-the-archive-this-was-built-on)
- [Attack order that actually works](#attack-order-that-actually-works)
- [Speed reality check](#speed-reality-check)
- [What does not work](#what-does-not-work)
- [Other archive formats](#other-archive-formats)
- [How the extractor works](#how-the-extractor-works)
- [Repo layout](#repo-layout)
- [License](#license)

---

## The honest version of "bypass"

A RAR5 archive is not "protected by a password screen". It is encrypted:

| Layer | Detail |
|---|---|
| Cipher | AES-256-CBC, one key per archive password |
| Key derivation | PBKDF2-HMAC-SHA256, `1 << kdf_count` iterations (usually 32768, +32 in the spec loop) |
| Salt | 16 bytes stored in the header |
| IV | 16 bytes, per file |
| Password check | 12 bytes in the header, first 8 = `w0^w2^w4^w6 ‖ w1^w3^w5^w7` of the derived key |

There is no master key, no recovery key, no "unlock" byte to flip. Anything that claims to
remove a WinRAR password instantly is either lying, deleting your data, or running a
dictionary attack behind a progress bar. What you can actually do:

1. **Guess the password fast.** PBKDF2 is deliberately slow, but a GPU eats thousands of
   guesses per second. That is 99% of real-world wins, because humans pick `123`.
2. **Skip the crypto when you can.** If *file names are not encrypted*, the header tells you
   everything: file list, sizes, timestamps, KDF parameters, salt. The tool here reads all of
   that without the password.
3. **Stop paying the cost twice.** Password reuse across archives from the same pack, seller
   or Discord channel cracks whole batches for the price of one.

This repo automates 1 and 2, and gives you the primitives for 3.

---

## Quick start

Requirements: Python 3.8+, and for GPU work [hashcat](https://hashcat.net/hashcat/) plus a
working OpenCL/CUDA driver. `7z` or `UnRAR` only if you want the script to extract for you.

```bash
git clone https://github.com/Pajt9whauht283as/winrar-password-bypass
cd winrar-password-bypass
```

Look inside an archive with no password at all:

```bash
python rar5_hash.py list secret.rar
```

```
headers: readable
entries: 113   encrypted file headers: 1
kdf    : 32800 iterations (log2=15), salt 9bfa25a6730fbdcc3e532776d3b69e59

encrypted  size         name
yes        46           ship/.ship_generated
yes        26           ship/Arena/.gitignore
yes        938          ship/Arena/Arena.sln
...
```

Get the hashcat hash:

```bash
python rar5_hash.py hash secret.rar -o rar5.hash
```

Crack it on the GPU:

```bash
hashcat -m 13000 -a 0 rar5.hash rockyou.txt
```

Or run the whole chain, verify included, with extraction:

```powershell
.\winrar_crack.ps1 -Archive secret.rar -Wordlist rockyou.txt -Extract
.\winrar_crack.ps1 -Archive secret.rar -Mask "?l?l?l?l?l?l?d?d"
.\winrar_crack.ps1 -Archive secret.rar -Wordlist rockyou.txt -Rule rules\best64.rule
```

No GPU? `crack` runs a wordlist on the CPU across all cores:

```bash
python rar5_hash.py crack secret.rar -w wordlist.txt
```

Verify a single guess in ~10 ms, no hashcat, no archive rebuild:

```bash
python rar5_hash.py verify secret.rar "hunter2"
# password 'hunter2' -> no (10.5 ms)
```

---

## Commands

### `rar5_hash.py`

| Command | Purpose | Needs password | Needs GPU |
|---|---|---|---|
| `list <archive>` | file list, sizes, KDF, salt, which entries are encrypted | no | no |
| `hash <archive> [-o file]` | emit `$rar5$...` lines for hashcat mode 13000 | no | no |
| `verify <archive> <password>` | recompute the check value, confirm a guess | the guess | no |
| `crack <archive> -w file` | multiprocess CPU wordlist attack | — | no |

Only the first few hundred kilobytes matter for `list` / `hash`: both commands stop after the
header block. A partial download, a range request or a corrupted tail still yields the hash.

### `winrar_crack.ps1`

```
-Archive   archive to open (required)
-Wordlist  dictionary attack (-a 0)
-Mask      mask attack, e.g. "?u?l?l?l?l?d?d" (-a 3)
-Rule      hashcat rule file, e.g. rules\best64.rule
-Hashcat   path to hashcat.exe (default: from PATH)
-SevenZip  path to 7z.exe (default: %ProgramFiles%\7-Zip\7z.exe)
-Extract   extract after the password is confirmed
-OutDir    extraction target (default: next to the archive)
-Workload  hashcat -w value, default 3
```

It writes the hash to a temp folder, runs each attack against a private potfile, verifies the
hit with its own PBKDF2 implementation (so a false positive from a stale potfile cannot fool
it), and only then calls `7z x -p<password>`.

---

## Case study: the archive this was built on

A 82 MiB RAR5 pack from a Discord CDN link. Header encryption off, so the whole tree was
readable:

```
Type = Rar5
Method = v6:32M:m0:m3
Characteristics = Locator QuickOpen:85564054
```

`hash` returned one line, and the whole thing was over in eight seconds:

```
$rar5$16$9bfa25a6730fbdcc3e532776d3b69e59$15$6c54a84371908514f508d6cb218379e1$8$24dd5a0a04188cae

hashcat (v7.1.2) starting
Hash.Mode........: 13000 (RAR5)
Speed.#01........: 37214 H/s
Recovered........: 1/1 (100.00%) Digests
Progress.........: 28672/14344384 (0.20%)
```

```
$rar5$16$9bfa25...$8$24dd5a0a04188cae:123
```

Password: **`123`**. Candidate 28672 of rockyou. The exact hash is kept in
[`examples/rar5.hash`](examples/rar5.hash) as a test vector, and
[`examples/sample.rar`](examples/sample.rar) is a tiny archive built with the same password so
the whole toolchain can be tested end to end:

```bash
python rar5_hash.py list    examples/sample.rar
python rar5_hash.py hash    examples/sample.rar
python rar5_hash.py verify  examples/sample.rar 123
python rar5_hash.py crack   examples/sample.rar -w wordlist.txt
```

Two sibling archives from the same channel opened with the same password, which is the
password-reuse attack in one sentence: crack the cheapest archive, try the password everywhere.

---

## Attack order that actually works

Do not start with masks. Start with the cheapest thing that has a real hit rate.

1. **Targeted list (seconds).** Product name, brand, year, `!`, `@`, leet. `syntax2026`,
   `Arena2025`, `fortnite123`. A few thousand candidates, generated from what the archive is
   called and where it came from.
2. **rockyou / top-10M (minutes).** Our case: found at 0.2%.
3. **rockyou + rules (hours).** `best64.rule` multiplies 14M candidates by 77. `dive.rule` is
   stronger and slower. This is where `Arena2025!` and `Arena_2025` fall out.
4. **Mask with structure (hours to days).** Only when you have a reason to believe the shape:
   `?u?l?l?l?l?l?d?d`, `?l?l?l?l?l?l?l?l`. Blind full-space masks on 8+ characters are not a
   plan, they are a heater.
5. **Hybrid.** `-a 6` with a wordlist plus `?d?d` covers `word12` patterns cheaply.

Rules of thumb for this archive type: `-w 3`, `--force` only on Windows driver warnings, and
let hashcat autotune. Watch `Progress` vs `Speed` before committing a night to a mask.

---

## Speed reality check

RAR5 is one of the slower hashcat modes because every candidate runs the full PBKDF2 loop.

| GPU | Mode 13000 |
|---|---|
| RTX 3060 12 GB | ~37 kH/s (measured, driver 616.92) |
| RTX 4090 | ~120 kH/s |
| CPU, 8 cores, this Python tool | ~1 kH/s |

What that buys at 37 kH/s:

| Keyspace | Time |
|---|---|
| rockyou (14.3M) | 6.5 min |
| rockyou + best64 (1.1G) | 8 h |
| `?l?l?l?l?l?l` (309M) | 2.3 h |
| `?l?l?l?l?l?l?d?d` (2.1T) | 1.8 years |

That table is the whole strategy. Dictionaries and rules, not brute force.

---

## What does not work

Things people burn days on:

- **"Repair archive" in WinRAR.** Rebuilds headers, decrypts nothing.
- **Convert to ZIP / rename / re-archive.** The payload stays AES blocks; conversion fails
  without the key.
- **CVE-2023-38831 / CVE-2022-30333.** Real bugs (spoofed extensions, path traversal on
  extraction) — neither recovers a password.
- **Known-plaintext on RAR5.** You know `imgui.cpp` byte-for-byte inside the archive; it does
  not help, because AES-256-CBC with a secret key from PBKDF2 gives you nothing to invert.
  Known plaintext attacks belong to legacy ZIP, not to RAR5.
- **Commercial "unlocker" GUIs.** They wrap hashcat/john with a smaller wordlist and a bigger
  price tag. Every one of them that claims instant removal is malware or a refund scam.

If the archive also has **encrypted headers**, `list` cannot show names; you get the archive
salt only. The attack is identical, you just cannot pick the smallest entry or read the tree
first.

---

## Other archive formats

| Format | Real shortcut | Mode |
|---|---|---|
| RAR5 | none, crack it | `13000` |
| RAR3 / RAR4 | known-plaintext attack speeds it up a lot | `12500` + `rar2john` |
| 7z | none, crack it | `11600` |
| ZIP, ZipCrypto (legacy) | **bkrack**: ~12 known bytes recover the keys, no password at all | `17200` / `17210` if you still want the password |
| ZIP, AES-256 | none, crack it | `13600` |

The ZIP/ZipCrypto case is the only genuine "bypass" in this table, which is exactly why old
ZIPs should never be considered protected.

---

## How the extractor works

RAR5 stores everything in a chain of blocks: `crc32 | header_size (vint) | header`. The file
header carries an *extra area* of typed records, and record type `1` is the encryption record:

```
version    vint
flags      vint
kdf_count  1 byte        -> iterations = (1 << kdf_count) + 32
salt       16 bytes
iv         16 bytes
check      12 bytes      -> first 8 bytes used as the password check
```

hashcat wants exactly this, formatted as:

```
$rar5$16$<salt hex>$<kdf_count>$<iv hex>$8$<check[0:8] hex>
```

`rar5_hash.py` walks the chain, skips data areas by their declared size, deduplicates entries
that share a salt, and emits one hash per unique KDF context. Verification then recomputes:

```python
dk  = pbkdf2_hmac("sha256", password.encode(), salt, (1 << log2) + 32, 32)
w   = unpack("<8I", dk)
chk = pack("<2I", w[0] ^ w[2] ^ w[4] ^ w[6], w[1] ^ w[3] ^ w[5] ^ w[7])
```

which is byte-identical to what WinRAR compares and to what hashcat's `m13000` kernel checks.

## Repo layout

```
rar5_hash.py          extractor, verifier, CPU cracker - stdlib only
winrar_crack.ps1      hash -> hashcat -> verify -> extract pipeline
examples/sample.rar   tiny encrypted archive, password 123
examples/sample.hash  its hashcat hash
examples/rar5.hash    case-study test vector
```

## License

MIT. Do whatever you want with it.
