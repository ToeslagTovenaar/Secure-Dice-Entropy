#!/usr/bin/env python3
"""Offline physical-dice to BIP-39 mnemonic generator (Python stdlib only)."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import math
import os
import secrets
import sys
from pathlib import Path

ENTROPY_BY_WORDS = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"


def load_wordlist() -> list[str]:
    path = Path(__file__).with_name("english.txt")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != WORDLIST_SHA256:
        raise RuntimeError("english.txt failed its SHA-256 integrity check")
    words = raw.decode("ascii").splitlines()
    if len(words) != 2048 or words != sorted(words) or len(set(words)) != 2048:
        raise RuntimeError("english.txt is not a valid BIP-39 English wordlist")
    return words


def roll_count(entropy_bits: int) -> int:
    # Use the shortest batch whose unbiased rejection probability is below 1%.
    count = math.ceil(entropy_bits / math.log2(6))
    target = 1 << entropy_bits
    while (6**count % target) / 6**count >= 0.01:
        count += 1
    return count


def parse_rolls(text: str, expected: int) -> str:
    rolls = "".join(text.split())
    if len(rolls) != expected:
        raise ValueError(f"expected exactly {expected} rolls, received {len(rolls)}")
    bad = sorted(set(rolls) - set("123456"))
    if bad:
        raise ValueError("rolls may contain only digits 1 through 6")
    return rolls


def dice_to_entropy(rolls: str, entropy_bits: int) -> bytes | None:
    """Return uniform entropy, or None when this batch falls in rejection range."""
    value = 0
    for roll in rolls:
        value = value * 6 + (ord(roll) - ord("1"))
    outcomes = 6 ** len(rolls)
    target = 1 << entropy_bits
    acceptance_limit = (outcomes // target) * target
    if value >= acceptance_limit:
        return None
    return (value % target).to_bytes(entropy_bits // 8, "big")


def entropy_to_mnemonic(entropy: bytes, words: list[str]) -> str:
    ent = len(entropy) * 8
    if ent not in ENTROPY_BY_WORDS.values():
        raise ValueError("BIP-39 entropy must be 128, 160, 192, 224, or 256 bits")
    checksum_len = ent // 32
    entropy_bits = f"{int.from_bytes(entropy, 'big'):0{ent}b}"
    digest_bits = f"{hashlib.sha256(entropy).digest()[0]:08b}"
    bits = entropy_bits + digest_bits[:checksum_len]
    return " ".join(words[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11))


def read_rolls(expected: int, visible: bool) -> str:
    prompt = f"Enter exactly {expected} rolls (1-6; spaces/newlines not accepted here): "
    return input(prompt) if visible else getpass.getpass(prompt)


def ask_choice(prompt: str, choices: dict[str, object]):
    while True:
        print(prompt)
        for key, value in choices.items():
            label = value[0] if isinstance(value, tuple) else value
            print(f"  {key}) {label}")
        answer = input("> ").strip().lower()
        if answer in choices:
            value = choices[answer]
            return value[1] if isinstance(value, tuple) else value
        print("Please enter one of: " + ", ".join(choices))


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    while True:
        answer = input(prompt + suffix).strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("Please answer yes or no.")


def secure_write_report(path: Path, content: str) -> None:
    """Create a new owner-only report; never overwrite an existing secret file."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            fd = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if fd != -1:
            os.close(fd)


def build_secret_report(mnemonic: str, source: str, entropy: bytes,
                        addresses: dict[str, list[str]], passphrase_used: bool) -> str:
    lines = [
        "DICE ENTROPY SECRET RECOVERY REPORT",
        "===================================",
        "WARNING: THIS FILE CAN CONTROL ALL FUNDS. ANYONE WHO READS IT CAN STEAL THEM.",
        "Keep it permanently offline. Do not upload, email, photograph, print, or sync it.",
        "",
        f"Entropy source: {source}",
        f"Entropy size: {len(entropy) * 8} bits",
        f"Entropy fingerprint (SHA-256): {hashlib.sha256(entropy).hexdigest()}",
        f"BIP-39 passphrase used for listed addresses: {'YES - stored separately, not in this file' if passphrase_used else 'NO (empty passphrase)'}",
        "",
        "BIP-39 MNEMONIC:",
    ]
    lines.extend(f"{i:2}. {word}" for i, word in enumerate(mnemonic.split(), 1))
    if addresses:
        lines.extend(["", "PUBLIC RECEIVE ADDRESSES:"])
        for network, items in addresses.items():
            lines.extend(["", network])
            lines.extend(f"  {i}: {address}" for i, address in enumerate(items))
    lines.extend([
        "", "RECOVERY AND SECURITY NOTES:",
        "- Verify recovery and every first address on the intended trusted hardware wallet.",
        "- Make a small round-trip transaction before depositing significant funds.",
        "- Derivation paths are printed in the network headings above.",
        "- The dice rolls and raw entropy are intentionally not stored; the mnemonic is sufficient.",
        "- If a BIP-39 passphrase was used, losing it permanently loses access.",
        "- Store redundant physical backups in separate, access-controlled locations.",
        "- Delete this TXT securely or let Tails discard it at shutdown after making backups.",
        "", "This report contains no private-key dump; the mnemonic derives the private keys.",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline guided BIP-39 seed generator.")
    parser.add_argument("--mode", choices=("dice", "system"), help="entropy source")
    parser.add_argument("--words", type=int, choices=ENTROPY_BY_WORDS)
    parser.add_argument(
        "--visible-input", action="store_true",
        help="show rolls while typing (less private; useful for accessibility/debugging)",
    )
    parser.add_argument(
        "--addresses", type=int, metavar="N",
        help="derive the first N public addresses for BTC, EVM, and Solana (1-20)",
    )
    parser.add_argument(
        "--use-passphrase", action="store_true",
        help="prompt twice for an optional BIP-39 passphrase used for address derivation",
    )
    parser.add_argument(
        "--export", nargs="?", const="DICEENTROPY_SECRET.txt", metavar="FILE",
        help="write an owner-only secret report; refuses to overwrite existing files",
    )
    parser.add_argument("--self-test", action="store_true", help="run tests and exit")
    args = parser.parse_args()

    if args.self_test:
        import unittest
        suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent / "tests"))
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1

    interactive = args.mode is None
    print("\nDice Entropy — offline BIP-39 generator")
    print("Keep networking disabled. This program never needs network access.\n")
    mode = args.mode or ask_choice("Choose the entropy source:", {
        "1": ("Physical six-sided dice (independently auditable)", "dice"),
        "2": ("Tails/Linux cryptographic system randomness", "system"),
    })
    word_count = args.words or (ask_choice("Choose mnemonic length:", {
        "1": ("24 words / 256 bits (recommended)", 24),
        "2": ("12 words / 128 bits", 12),
        "3": ("15 words / 160 bits", 15),
        "4": ("18 words / 192 bits", 18),
        "5": ("21 words / 224 bits", 21),
    }) if interactive else 24)
    address_count = args.addresses
    if interactive and address_count is None:
        address_count = 3 if ask_yes_no("Generate the first 3 public addresses for each network?", True) else 0
    address_count = address_count or 0
    if not 0 <= address_count <= 20:
        parser.error("--addresses must be between 1 and 20")

    words = load_wordlist()
    entropy_bits = ENTROPY_BY_WORDS[word_count]
    if mode == "system":
        print(f"\nRequesting {entropy_bits} bits from Python secrets/SystemRandom...")
        entropy = secrets.token_bytes(entropy_bits // 8)
        source_description = "Tails/Linux OS CSPRNG via Python secrets.token_bytes"
    else:
        needed = roll_count(entropy_bits)
        print(f"\nBIP-39 words: {word_count} | entropy: {entropy_bits} bits | dice rolls: {needed}")
        print("Use a fair physical d6. Record every result in order. Input is hidden by default.")
        print("All accepted base-6 outcomes map equally to the 2^N possible entropy values.\n")
        while True:
            try:
                rolls = parse_rolls(read_rolls(needed, args.visible_input), needed)
            except (EOFError, KeyboardInterrupt):
                print("\nCancelled; no mnemonic generated.", file=sys.stderr)
                return 130
            except ValueError as exc:
                print(f"Input error: {exc}. Try again.", file=sys.stderr)
                continue
            entropy = dice_to_entropy(rolls, entropy_bits)
            if entropy is None:
                print("This batch is in the unbiased rejection range. Reroll a completely fresh batch.")
                continue
            break
        source_description = f"{needed} physical d6 rolls with exact rejection sampling"

    mnemonic = entropy_to_mnemonic(entropy, words)
    print("\nYOUR BIP-39 MNEMONIC (write it down by hand):\n")
    for index, word in enumerate(mnemonic.split(), 1):
        print(f"{index:2}. {word}")
    derived_addresses = {}
    use_passphrase = args.use_passphrase
    if interactive and address_count and not use_passphrase:
        use_passphrase = ask_yes_no("Use a BIP-39 passphrase for these addresses?", False)
    passphrase = ""
    if address_count:
        if use_passphrase:
            first = getpass.getpass("\nBIP-39 passphrase (hidden): ")
            second = getpass.getpass("Repeat passphrase (hidden): ")
            if first != second:
                print("Passphrases did not match; no addresses generated.", file=sys.stderr)
                return 2
            passphrase = first
        from address_derivation import derive_public_addresses
        derived_addresses = derive_public_addresses(mnemonic, passphrase, address_count)
        print("\nPUBLIC RECEIVE ADDRESSES (private keys are never displayed):")
        for network, addresses in derived_addresses.items():
            print(f"\n{network}")
            for index, address in enumerate(addresses):
                print(f"  {index}: {address}")
    export_path = Path(args.export).expanduser() if args.export else None
    if interactive and export_path is None:
        print("\nSECURITY WARNING: a TXT copy is an unencrypted bearer secret.")
        print("Saving it to Persistent Storage or another drive leaves a recoverable copy.")
        if ask_yes_no("Create an owner-only secret TXT report anyway?", False):
            name = input("Filename [DICEENTROPY_SECRET.txt]: ").strip() or "DICEENTROPY_SECRET.txt"
            export_path = Path(name).expanduser()
    if export_path:
        report = build_secret_report(mnemonic, source_description, entropy,
                                     derived_addresses, bool(use_passphrase))
        try:
            secure_write_report(export_path, report)
        except FileExistsError:
            print(f"Refusing to overwrite existing file: {export_path}", file=sys.stderr)
            return 3
        print(f"\nSECRET REPORT CREATED: {export_path.resolve()}")
        print("Permissions requested: owner read/write only (0600). Protect or delete it.")
    print("\nVerify your backup, then shut down Tails fully. Treat every saved copy as the wallet.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

