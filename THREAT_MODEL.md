# Threat model

## Intended protections

- Generate standard BIP-39 mnemonics without network access.
- Remove base-6 conversion bias when fair independent physical dice are used.
- Offer the operating system CSPRNG without using Python's simulation PRNG.
- Avoid printing private keys or saving passphrases and dice sequences.
- Refuse overwriting or following symlinks for optional secret-report creation where
  the operating system supports `O_NOFOLLOW`.
- Detect accidental modification of the bundled BIP-39 wordlist and packaged files.

## Assumptions

- The Tails image, Python interpreter, firmware, CPU, RAM, keyboard, display, and dice
  are trustworthy enough for the chosen mode.
- Physical dice are fair and rolls independent; rejection sampling cannot create this.
- The user prevents observation by people, cameras, microphones, remote consoles, and
  compromised peripherals.
- The receiving wallet supports the displayed derivation path and BIP-39 passphrase.

## Out of scope

- Compromised firmware, malicious hardware, side channels, coercion, and physical theft.
- Certifying a die's fairness from a short roll sequence.
- Encrypting, securely deleting, printing, transmitting, or cloud-backing-up secrets.
- Transaction creation/signing and balance/network queries.
- Guaranteeing wallet discovery across every vendor's alternative derivation paths.

Biased entropy can reduce brute-force resistance. Incorrect derivation can make funds
appear missing. Disclosure of a mnemonic plus its optional passphrase permits theft.
Loss of either required recovery component can permanently destroy access.

