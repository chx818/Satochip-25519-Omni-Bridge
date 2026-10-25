"""Host-side checks for Authentikey binding on the Curve25519 APDU responses."""
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pysatochip.CardDataParser import CardDataParser
from pysatochip.ecc import ECPubkey
from pysatochip_25519 import SatochipCard, SatochipException


class FakeConnector:
    def __init__(self, parser, authentikey):
        self.parser = parser
        self._authentikey = authentikey

    def card_bip32_get_authentikey(self):
        return self._authentikey


class AuthentikeyResponseTest(unittest.TestCase):
    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        public_bytes = self.private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        self.authentikey = ECPubkey(public_bytes)
        parser = CardDataParser()
        parser.authentikey = self.authentikey
        self.card = SatochipCard()
        self.card.connector = FakeConnector(parser, self.authentikey)
        self.card.authentikey = self.authentikey
        self.card._ensure_connected = lambda: None
        self.signed_data = bytes(range(66))
        signature = self.private_key.sign(self.signed_data, ec.ECDSA(hashes.SHA256()))
        self.response = self.signed_data + len(signature).to_bytes(2, "big") + signature

    def test_valid_envelope_is_accepted(self):
        self.card._verify_authentikey_signed_response(self.response, len(self.signed_data))

    def test_signed_data_tampering_is_rejected(self):
        changed = bytearray(self.response)
        changed[40] ^= 1
        with self.assertRaises(SatochipException):
            self.card._verify_authentikey_signed_response(changed, len(self.signed_data))

    def test_signature_tampering_is_rejected(self):
        changed = bytearray(self.response)
        changed[-1] ^= 1
        with self.assertRaises(SatochipException):
            self.card._verify_authentikey_signed_response(changed, len(self.signed_data))

    def test_empty_truncated_or_trailing_signature_is_rejected(self):
        malformed = (
            self.signed_data + b"\x00\x00",
            self.signed_data + b"\x00\x05\x30",
            self.response + b"\x00",
        )
        for response in malformed:
            with self.subTest(response=response):
                with self.assertRaises(SatochipException):
                    self.card._verify_authentikey_signed_response(response, len(self.signed_data))


if __name__ == "__main__":
    unittest.main()
