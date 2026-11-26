"""Test suite: run with `python -m unittest discover -s tests -v`."""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from winrar import attacks, crypto, forensics, formats, rar5, zipcrypto  # noqa: E402

SAMPLE = os.path.join(ROOT, "examples", "sample.rar")
KNOWN_HASH = ("$rar5$16$2bd89e9e8f747efe77ccb1a889301979$15$"
              "9e8e540ef5c2ed9fe917e38f97142e3f$8$25d9168251b05acf")


class TestParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = rar5.Archive.open(SAMPLE)

    def test_entries(self):
        names = [e.name for e in self.archive if not e.is_dir]
        self.assertEqual(sorted(names), ["hello.txt", "note.txt"])

    def test_all_encrypted(self):
        self.assertEqual(len(self.archive.encrypted_entries), 2)
        self.assertFalse(self.archive.headers_encrypted)

    def test_kdf_parameters(self):
        entry = self.archive.smallest_target()
        self.assertEqual(entry.log2, 15)
        self.assertEqual(entry.iterations, 32800)
        self.assertEqual(len(entry.salt), 16)
        self.assertEqual(len(entry.iv), 16)
        self.assertEqual(len(entry.check), 12)

    def test_hashcat_line(self):
        self.assertEqual(self.archive.hashes(), [KNOWN_HASH])

    def test_single_target(self):
        self.assertEqual(len(self.archive.unique_targets()), 1)

    def test_foreign_format(self):
        with self.assertRaises(rar5.ArchiveError):
            rar5.Archive.open(os.path.join(ROOT, "README.md"))


class TestCrypto(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entry = rar5.Archive.open(SAMPLE).smallest_target()

    def test_correct_password(self):
        self.assertTrue(crypto.verify(self.entry, "123"))

    def test_wrong_password(self):
        self.assertFalse(crypto.verify(self.entry, "124"))
        self.assertFalse(crypto.verify(self.entry, ""))

    def test_check_length(self):
        self.assertEqual(len(crypto.pswcheck("x", b"\x00" * 16, 15)), 8)

    def test_benchmark_positive(self):
        self.assertGreater(crypto.benchmark(self.entry, rounds=2), 0)


class TestAttacks(unittest.TestCase):
    def test_mask_keyspace(self):
        self.assertEqual(attacks.mask_keyspace("?d?d?d"), 1000)
        self.assertEqual(attacks.mask_keyspace("ab?d"), 10)  # literals are single-char sets
        self.assertEqual(attacks.mask_keyspace("?1?1", ["xyz"]), 9)

    def test_mask_iteration(self):
        values = list(attacks.mask_iter("?d?d", None))
        self.assertEqual(len(values), 100)
        self.assertEqual(values[0], "00")
        self.assertEqual(values[-1], "99")

    def test_bad_mask(self):
        with self.assertRaises(ValueError):
            attacks.mask_keyspace("?z")
        with self.assertRaises(ValueError):
            attacks.mask_keyspace("?5")

    def test_escaped_question_mark(self):
        self.assertEqual(list(attacks.mask_iter("??")), ["?"])

    def test_mutations_cover_case_and_leet(self):
        produced = set(attacks.mutate(["Arena"], level=1))
        self.assertIn("Arena", produced)
        self.assertIn("arena", produced)
        self.assertIn("ARENA", produced)
        self.assertIn("4r3n4", produced)

    def test_mutations_add_suffixes(self):
        produced = list(attacks.mutate(["x"], level=2))
        self.assertIn("x123", produced)
        self.assertIn("x2026", produced)

    def test_targeted_uses_archive_name(self):
        produced = list(attacks.targeted(os.path.join("tmp", "Arena_2024.rar")))
        self.assertTrue(any("Arena" in candidate for candidate in produced))
        self.assertIn("Arena", produced)

    def test_top_passwords_loaded(self):
        values = list(attacks.top_passwords())
        self.assertGreater(len(values), 100)
        self.assertIn("123", values)


class TestEngine(unittest.TestCase):
    def test_cpu_finds_password(self):
        from winrar import engine

        entry = rar5.Archive.open(SAMPLE).smallest_target()
        cracker = engine.CpuEngine(entry, threads=2)
        result = cracker.crack(["nope", "still-nope", "123"], total=3, quiet=True)
        self.assertEqual(result.password, "123")

    def test_cpu_misses(self):
        from winrar import engine

        entry = rar5.Archive.open(SAMPLE).smallest_target()
        cracker = engine.CpuEngine(entry, threads=2)
        result = cracker.crack(["nope"], total=1, quiet=True)
        self.assertIsNone(result.password)


ZIP = os.path.join(ROOT, "examples", "sample_zipcrypto.zip")
ZIP_AES = os.path.join(ROOT, "examples", "sample_aes.zip")
SEVENZIP = os.path.join(ROOT, "examples", "sample_plain.7z")


class TestZipCrypto(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = formats.open_archive(ZIP)

    def test_entries(self):
        self.assertEqual(len(self.archive), 2)
        self.assertTrue(all(e.kind == "zipcrypto" for e in self.archive.encrypted_entries))

    def test_password_check(self):
        entry = self.archive.zipcrypto_target()
        self.assertTrue(zipcrypto.verify_entry(ZIP, entry, "123"))
        self.assertFalse(zipcrypto.verify_entry(ZIP, entry, "124"))

    def test_no_hashcat_format(self):
        self.assertEqual(self.archive.hashes(), [])
        self.assertIsNone(formats.mode_for(self.archive))

    def test_engine_finds_password(self):
        entry = self.archive.zipcrypto_target()
        cracker = zipcrypto.ZipCryptoEngine(entry.header12, entry.check_byte, threads=2,
                                            entry=entry, path=ZIP)
        result = cracker.crack(["nope", "123"], total=2, quiet=True)
        self.assertEqual(result.password, "123")


class TestZipAes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = formats.open_archive(ZIP_AES)

    def test_aes_detected(self):
        self.assertEqual(self.archive.declared_crypto(), "WinZip AES-256")
        self.assertEqual(self.archive.aes_target().aes_mode, 3)

    def test_hash_format(self):
        lines = self.archive.hashes()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("$zip2$*0*3*0*"))
        self.assertTrue(lines[0].endswith("*$/zip2$"))

    def test_mode(self):
        self.assertEqual(formats.mode_for(self.archive), "13600")


class TestSevenZip(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = formats.open_archive(SEVENZIP)

    def test_entries(self):
        names = [e.name for e in self.archive if not e.is_dir]
        self.assertEqual(sorted(names), ["hello.txt", "note.txt"])

    def test_encryption_detected(self):
        self.assertEqual(len(self.archive.encrypted_entries), 2)
        target = self.archive.hash_target()
        self.assertEqual(target["data_type"], 2)
        self.assertEqual(target["cycles"], 19)

    def test_hash_line(self):
        line = self.archive.hashes()[0]
        self.assertTrue(line.startswith("$7z$2$19$0$$16$"))
        self.assertEqual(formats.mode_for(self.archive), "11600")


class TestFormats(unittest.TestCase):
    def test_sniff(self):
        self.assertEqual(formats.sniff(SAMPLE), "RAR5")
        self.assertEqual(formats.sniff(ZIP), "ZIP")
        self.assertEqual(formats.sniff(SEVENZIP), "7Z")

    def test_targets(self):
        cases = {SAMPLE: "rar5", ZIP: "zipcrypto", ZIP_AES: "zipaes", SEVENZIP: "7zip"}
        for path, kind in cases.items():
            target = formats.pick_target(formats.open_archive(path))
            self.assertIsNotNone(target, path)
            self.assertEqual(target.kind, kind, path)

    def test_cpu_support(self):
        self.assertTrue(formats.pick_target(formats.open_archive(SAMPLE)).supports_cpu())
        self.assertFalse(formats.pick_target(formats.open_archive(SEVENZIP)).supports_cpu())


class TestForensics(unittest.TestCase):
    def test_analyze(self):
        report = forensics.analyze(SAMPLE)
        self.assertEqual(report.format, "RAR5")
        self.assertEqual(report.files, 2)
        self.assertEqual(len(report.byte_fingerprint), 64)
        self.assertEqual(len(report.payload_fingerprint), 64)

    def test_same_payload_detected(self):
        reports = [forensics.analyze(ZIP_AES), forensics.analyze(SEVENZIP)]
        groups = forensics.compare(reports)
        self.assertEqual(len(groups["repacks"]), 1)
        self.assertEqual(groups["identical"], [])


if __name__ == "__main__":
    unittest.main()
