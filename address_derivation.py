"""Minimal, dependency-free public-address derivation for offline verification.

Implements only the primitives needed for BIP84 Bitcoin, EVM, and Solana addresses.
Private key material is returned nowhere by the public API.
"""

import hashlib
import hmac
import unicodedata

HARDENED = 0x80000000
SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def mnemonic_seed(mnemonic: str, passphrase: str = "") -> bytes:
    password = unicodedata.normalize("NFKD", mnemonic).encode()
    salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode()
    return hashlib.pbkdf2_hmac("sha512", password, salt, 2048, 64)


def _inv(value: int, modulus: int) -> int:
    return pow(value, modulus - 2, modulus)


def _secp_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return None
    slope = ((3 * x1 * x1) * _inv(2 * y1, SECP_P) if a == b else
             (y2 - y1) * _inv(x2 - x1, SECP_P)) % SECP_P
    x3 = (slope * slope - x1 - x2) % SECP_P
    return x3, (slope * (x1 - x3) - y1) % SECP_P


def _secp_mul(scalar: int):
    result = None
    addend = SECP_G
    while scalar:
        if scalar & 1:
            result = _secp_add(result, addend)
        addend = _secp_add(addend, addend)
        scalar >>= 1
    return result


def _secp_pub(private: int, compressed: bool = True) -> bytes:
    x, y = _secp_mul(private)
    if compressed:
        return bytes([2 | (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _bip32_master(seed: bytes):
    while True:
        digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        key = int.from_bytes(digest[:32], "big")
        if 0 < key < SECP_N:
            return key, digest[32:]
        seed = digest


def _bip32_child(node, index: int):
    key, chain = node
    while True:
        data = (b"\x00" + key.to_bytes(32, "big") if index & HARDENED
                else _secp_pub(key)) + index.to_bytes(4, "big")
        digest = hmac.new(chain, data, hashlib.sha512).digest()
        left = int.from_bytes(digest[:32], "big")
        child = (left + key) % SECP_N
        if left < SECP_N and child != 0:
            return child, digest[32:]
        index += 1


def _bip32_path(seed: bytes, path: list[int]):
    node = _bip32_master(seed)
    for index in path:
        node = _bip32_child(node, index)
    return node


def _hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _bech32_polymod(values):
    result = 1
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    for value in values:
        top = result >> 25
        result = ((result & 0x1FFFFFF) << 5) ^ value
        for i, generator in enumerate(generators):
            if (top >> i) & 1:
                result ^= generator
    return result


def _convertbits(data: bytes, from_bits=8, to_bits=5):
    acc = bits = 0
    output = []
    for value in data:
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            output.append((acc >> bits) & ((1 << to_bits) - 1))
    if bits:
        output.append((acc << (to_bits - bits)) & ((1 << to_bits) - 1))
    return output


def _segwit_address(program: bytes) -> str:
    hrp = "bc"
    data = [0] + _convertbits(program)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    polymod = _bech32_polymod(expanded + data + [0] * 6) ^ 1
    checksum = [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32[v] for v in data + checksum)


def bitcoin_addresses(seed: bytes, count: int) -> list[str]:
    base = [84 | HARDENED, 0 | HARDENED, 0 | HARDENED, 0]
    return [_segwit_address(_hash160(_secp_pub(_bip32_path(seed, base + [i])[0])))
            for i in range(count)]


# Keccak-f[1600], using original Keccak padding required by Ethereum (not SHA3-256).
_KECCAK_RC = (0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
              0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
              0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
              0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
              0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
              0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
              0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
              0x8000000000008080, 0x0000000080000001, 0x8000000080008008)
_KECCAK_R = ((0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61),
             (28, 55, 25, 21, 56), (27, 20, 39, 8, 14))


def _rol64(x, n):
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF if n else x


def _keccak_f(a):
    for rc in _KECCAK_RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol64(a[x + 5 * y], _KECCAK_R[x][y])
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        a[0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\x00" * ((rate - len(padded) % rate) % rate))
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _keccak_f(state)
    return b"".join(x.to_bytes(8, "little") for x in state)[:32]


def _evm_checksum(raw: bytes) -> str:
    lower = raw.hex()
    digest = keccak256(lower.encode()).hex()
    return "0x" + "".join(c.upper() if c in "abcdef" and int(digest[i], 16) >= 8 else c
                           for i, c in enumerate(lower))


def evm_addresses(seed: bytes, count: int) -> list[str]:
    base = [44 | HARDENED, 60 | HARDENED, 0 | HARDENED, 0]
    result = []
    for i in range(count):
        key = _bip32_path(seed, base + [i])[0]
        result.append(_evm_checksum(keccak256(_secp_pub(key, compressed=False)[1:])[-20:]))
    return result


ED_P = 2**255 - 19
ED_D = (-121665 * _inv(121666, ED_P)) % ED_P
ED_B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)


def _ed_add(a, b):
    x1, y1 = a
    x2, y2 = b
    factor = ED_D * x1 * x2 * y1 * y2
    return ((x1 * y2 + y1 * x2) * _inv(1 + factor, ED_P) % ED_P,
            (y1 * y2 + x1 * x2) * _inv(1 - factor, ED_P) % ED_P)


def _ed_pub(seed32: bytes) -> bytes:
    digest = hashlib.sha512(seed32).digest()
    scalar_bytes = bytearray(digest[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    result = (0, 1)
    addend = ED_B
    while scalar:
        if scalar & 1:
            result = _ed_add(result, addend)
        addend = _ed_add(addend, addend)
        scalar >>= 1
    x, y = result
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def _slip10_ed25519(seed: bytes, path: list[int]) -> bytes:
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    key, chain = digest[:32], digest[32:]
    for index in path:
        index |= HARDENED
        digest = hmac.new(chain, b"\x00" + key + index.to_bytes(4, "big"), hashlib.sha512).digest()
        key, chain = digest[:32], digest[32:]
    return key


def _base58(data: bytes) -> str:
    value = int.from_bytes(data, "big")
    output = ""
    while value:
        value, remainder = divmod(value, 58)
        output = B58[remainder] + output
    return B58[0] * (len(data) - len(data.lstrip(b"\0"))) + output


def solana_addresses(seed: bytes, count: int) -> list[str]:
    # Common wallet path: m/44'/501'/account'/0'. Ed25519 permits hardened children only.
    return [_base58(_ed_pub(_slip10_ed25519(seed, [44, 501, i, 0]))) for i in range(count)]


def derive_public_addresses(mnemonic: str, passphrase: str, count: int):
    if not 1 <= count <= 20:
        raise ValueError("address count must be between 1 and 20")
    seed = mnemonic_seed(mnemonic, passphrase)
    return {
        "Bitcoin (BIP84 native SegWit, m/84'/0'/0'/0/i)": bitcoin_addresses(seed, count),
        "Ethereum + BNB Smart Chain (EVM, m/44'/60'/0'/0/i)": evm_addresses(seed, count),
        "Solana (m/44'/501'/i'/0')": solana_addresses(seed, count),
    }
