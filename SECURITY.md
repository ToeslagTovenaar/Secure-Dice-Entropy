# Security policy

This project creates cryptocurrency recovery secrets. Treat every defect report as
potentially high impact.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could bias entropy, reveal secrets,
derive incorrect addresses, overwrite files, or enable code execution. Contact the
maintainer privately using the security-reporting channel configured in the GitHub
repository. Maintainers must add a real private contact before publishing.

Never include a mnemonic, passphrase, private key, dice sequence, secret report, funded
address relationship, or other real recovery material. Reproduce with published BIP
test vectors or a clearly disposable mnemonic.

Only the newest tagged release is intended to receive fixes. Release artifacts must
include a SHA-256 checksum and pass `python3 dice_entropy.py --self-test` after
extraction. This software has not undergone a professional independent audit.
