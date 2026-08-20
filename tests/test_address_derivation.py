import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import address_derivation as ad

MNEMONIC = "abandon " * 11 + "about"


class AddressTests(unittest.TestCase):
    def test_bip39_seed_vector(self):
        self.assertEqual(ad.mnemonic_seed(MNEMONIC, "TREZOR").hex(),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
            "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")

    def test_bip84_official_first_address(self):
        seed = ad.mnemonic_seed(MNEMONIC)
        self.assertEqual(ad.bitcoin_addresses(seed, 2), [
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
        ])

    def test_keccak_empty_vector(self):
        self.assertEqual(ad.keccak256(b"").hex(),
                         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

    def test_evm_known_address(self):
        seed = ad.mnemonic_seed(MNEMONIC)
        self.assertEqual(ad.evm_addresses(seed, 1),
                         ["0x9858EfFD232B4033E47d90003D41EC34EcaEda94"])

    def test_slip10_ed25519_vector(self):
        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        key = ad._slip10_ed25519(seed, [])
        self.assertEqual(key.hex(), "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")
        self.assertEqual(ad._ed_pub(key).hex(), "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed")

    def test_solana_cli_compatible_vector(self):
        # Published solana-keygen BIP44Change vector for twelve "abandon" words.
        seed = ad.mnemonic_seed(" ".join(["abandon"] * 12))
        self.assertEqual(ad.solana_addresses(seed, 1),
                         ["9jSYUQBwV3N2Hg7CocFgQGiCNo8zGSTDymktpHGu9aLe"])


if __name__ == "__main__":
    unittest.main()
