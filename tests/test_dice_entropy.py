import hashlib
import os
import tempfile
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dice_entropy as de


class DiceEntropyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.words = de.load_wordlist()

    def test_official_zero_entropy_vector(self):
        mnemonic = de.entropy_to_mnemonic(bytes(16), self.words)
        self.assertEqual(mnemonic, "abandon " * 11 + "about")

    def test_official_all_ones_vector(self):
        mnemonic = de.entropy_to_mnemonic(bytes.fromhex("ff" * 16), self.words)
        self.assertEqual(mnemonic, "zoo " * 11 + "wrong")

    def test_roll_counts(self):
        self.assertEqual([de.roll_count(n) for n in (128, 160, 192, 224, 256)],
                         [52, 64, 77, 90, 102])

    def test_roll_validation(self):
        self.assertEqual(de.parse_rolls("1 2 3", 3), "123")
        with self.assertRaises(ValueError):
            de.parse_rolls("120", 3)

    def test_deterministic_conversion(self):
        rolls = "1" * de.roll_count(128)
        self.assertEqual(de.dice_to_entropy(rolls, 128), bytes(16))

    def test_wordlist_hash(self):
        raw = Path(de.__file__).with_name("english.txt").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), de.WORDLIST_SHA256)

    def test_secure_report_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret.txt"
            de.secure_write_report(path, "secret\n")
            self.assertEqual(path.read_text(), "secret\n")
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                de.secure_write_report(path, "replacement\n")


if __name__ == "__main__":
    unittest.main()

