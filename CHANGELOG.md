# Changelog

## v1.2.2 — 2026-08-20

- Restored byte-exact canonical BIP-39 wordlist publication.
- Added `.gitattributes` so Windows and Linux check out identical hashed files.
- Refreshed the internal source checksum manifest.
- Changed Tails commands to `sh run-on-tails.sh` so ZIP executable bits are irrelevant.
- Verified the full test matrix on Ubuntu and Windows with Python 3.11 and 3.13.

## v1.2.1 — 2026-08-20

- Added a guided interactive workflow.
- Added physical-dice and operating-system CSPRNG entropy modes.
- Changed 24-word dice generation to 102 rolls for approximately 0.058% batch rejection.
- Added optional owner-only, non-overwriting secret TXT reports with prominent warnings.
- Added Bitcoin BIP-84, EVM, and Solana public-address derivation.
- Added published-vector tests, security policy, threat model, and contributor guidance.

This release is experimental and has not undergone a professional independent audit.
