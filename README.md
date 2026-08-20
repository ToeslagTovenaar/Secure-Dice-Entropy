# Dice Entropy — offline BIP-39 generator

Dice Entropy creates English BIP-39 mnemonics from either a **physical fair six-sided
die** or the operating system's cryptographic random generator. It uses only Python's
standard library, works offline, and asks guided questions when launched.

## Important limits

- No seed phrase is literally “the most secure in the world.” A correct 24-word phrase
  has 256 entropy bits, but storage, device compromise, cameras, people, and backups
  remain risks.
- BIP-39 and the displayed derivation path must be supported by the intended wallet.
- Tails reduces exposure; it cannot prove that firmware and hardware are trustworthy.
- Never enter a real mnemonic into a website, chat, cloud note, phone, or online system.

## Recommended Tails procedure

1. Download the release ZIP and checksum on an online computer and verify the ZIP hash.
2. Put it on a clean USB drive. Boot a separately verified, current Tails USB.
3. Unplug Ethernet and keep Wi-Fi disconnected.
4. Extract the ZIP in Tails' temporary storage and open Terminal there.
5. Run `sha256sum -c SHA256SUMS.txt`.
6. Run `python3 dice_entropy.py --self-test`.
7. Run `sh run-on-tails.sh` and answer the guided questions.
8. For dice mode, record every roll in order. If mathematically rejected, roll a whole
   fresh batch. Do not discard outcomes merely because they look unusual.
9. Verify the mnemonic backup twice and compare addresses on the intended hardware
   wallet. Make a small round-trip transaction before depositing significant funds.
10. Destroy the temporary roll sheet safely and shut Tails down fully.

Advanced example:

```bash
sh run-on-tails.sh --mode dice --words 24 --addresses 3
```

Roll counts: 12 words = 52, 15 = 64, 18 = 77, 21 = 90, 24 = 102. These
counts keep unbiased whole-batch rejection below 1%. Extra rolls reduce rejection but
cannot increase BIP-39 beyond its maximum 256 entropy bits.

## Why the dice conversion is unbiased

Six is not a power of two, so direct modulo conversion is biased. This tool interprets
`n` rolls as a uniform integer `x` in `[0, 6^n)`. Let `T = 2^ENT` and
`L = floor(6^n / T) * T`. Values `x >= L` are rejected; every accepted output is
`x mod T`. The accepted range contains exactly the same number of representatives for
every value in `[0, T)`, so the conversion itself adds zero bias.

This guarantee assumes each die face has probability 1/6 and rolls are independent.
Software cannot establish that from 102 samples. Use a sound, freely tumbling die and
cup on a hard surface. Rejection sampling removes conversion bias; it cannot repair a
loaded die, deterministic rolling technique, or compromised observation process.

## System-randomness mode

Choose the system option in the wizard or run:

```bash
sh run-on-tails.sh --mode system --words 24 --addresses 3
```

This calls Python `secrets.token_bytes(32)`, which obtains bytes from the operating
system's cryptographic randomness source. On Linux, Python uses kernel randomness
interfaces and waits during early boot until the pool is initialized. This is suitable
on an authentic, updated Tails system and trusted hardware. Dice mode provides an
entropy source independent of the computer; system mode is faster.

## Public addresses

`--addresses N` derives public receive addresses without displaying private keys:

- Bitcoin native SegWit: `m/84'/0'/0'/0/i`
- Ethereum and BNB Smart Chain: `m/44'/60'/0'/0/i`
- Solana: `m/44'/501'/i'/0'`

Ethereum and BNB Smart Chain intentionally use the same EVM address. Wallet conventions
can differ, so verify the first address on the actual recovery wallet before funding.
`--use-passphrase` prompts twice for a BIP-39 passphrase without echoing it.

## Secret TXT report

The wizard can optionally write an owner-only secret TXT, or use:

```bash
sh run-on-tails.sh --mode dice --words 24 --addresses 3 --export recovery.txt
```

The report is created new with requested Unix mode `0600`, refuses symlinks where
supported, flushes data, and refuses to overwrite an existing file. It contains the
mnemonic, source, entropy fingerprint, passphrase-use status, public addresses, paths,
and recovery warnings. It intentionally excludes dice rolls, raw entropy, private-key
dumps, and the BIP-39 passphrase.

Permissions do not encrypt a file and deletion on flash storage is not reliably secure.
Prefer handwritten or metal backups. A saved TXT is an unencrypted bearer secret: keep
it offline and understand whether its destination is temporary Tails memory, encrypted
Persistent Storage, or an external drive.

## What the program validates

It validates the roll count, face range, exact unbiased conversion, BIP-39 checksum,
bundled wordlist hash, address algorithms, and known standard vectors. It does not claim
to certify physical randomness. Statistical rejection of unusual-looking but valid
sequences would itself bias the result.

## Audit and publishing

- `dice_entropy.py`: guided generator, entropy conversion, and secure report output.
- `address_derivation.py`: minimal address derivation; compare outputs with hardware.
- `english.txt`: canonical 2,048-word BIP-39 English list, pinned by SHA-256.
- `tests/`: published BIP-39, BIP-84, Keccak/EVM, SLIP-10, and Solana vectors.
- `THREAT_MODEL.md`, `SECURITY.md`, and `CONTRIBUTING.md`: release expectations.

GitHub visibility is not a security audit. Tagged releases should publish checksums, be
built from a clean checkout, and be independently reproduced. Never post a real secret
in an issue, pull request, screenshot, test, or log.

## BIP-39 passphrases

Every passphrase creates a valid wallet; a typo opens a different empty wallet. Loss
means permanent loss of access. The passphrase is used only to derive displayed
addresses and is never written to the TXT report. Back it up separately.
