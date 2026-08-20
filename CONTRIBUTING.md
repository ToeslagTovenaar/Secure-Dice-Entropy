# Contributing

Keep the runtime dependency-free and offline. Do not add telemetry, update checks,
network calls, clipboard access, or logging of mnemonics, entropy, dice rolls,
passphrases, or private keys.

Before submitting a change:

1. Read `THREAT_MODEL.md` and preserve its security properties.
2. Add independent published vectors for cryptographic or derivation changes.
3. Run `python3 dice_entropy.py --self-test` on Linux and another supported platform.
4. Inspect the release ZIP and run its tests after extraction.
5. Use only disposable public test vectors in commits, issues, and screenshots.

Changes to entropy conversion, BIP-39 encoding, key derivation, file creation, or
dependency policy require focused security review. Statistical “quality tests” must
never silently reject valid user entropy.
