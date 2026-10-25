"""Offline regression tests for bridge security boundaries."""
import struct
import types
import unittest
from unittest import mock
from cryptography.hazmat.primitives.asymmetric import ed25519

from ledger_ed25519_omni_translator import (
    LedgerHIDFramer, LedgerOmni25519Translator, SW_OK, SW_WRONG_DATA,
    SW_WRONG_LENGTH, SW_CONDITIONS_NOT_SATISFIED, SW_SECURITY_STATUS,
)
import pysatochip_25519 as card_client
from pysatochip_25519 import parse_bip32_path, validate_path, SatochipCard
import test_deep_audit


def path_bytes(path):
    return bytes([len(path)]) + b"".join(struct.pack(">I", x) for x in path)


SOLANA = [0x8000002C, 0x800001F5, 0x80000000, 0x80000000]
TON = [0x8000002C, 0x8000025F, 0x80000000]


class GoodCard:
    def __init__(self):
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes_raw()
        self.staged = None

    def slip10_get_extended_key(self, path):
        self.staged = list(path)
        return self.pub

    def sign_ed25519_message(self, message):
        return self.key.sign(message)


class BadSignatureCard(GoodCard):
    def sign_ed25519_message(self, message):
        return b"\x00" * 64


class BoundaryTests(unittest.TestCase):
    def apdu(self, cla, ins, p1, p2, data=b""):
        self.assertLessEqual(len(data), 255)
        return bytes((cla, ins, p1, p2, len(data))) + data

    def test_reconnect_closes_previous_pcsc_session_before_replacement(self):
        class FakeConnection:
            def __init__(self, name):
                self.name = name
                self.connected_with = None
                self.disconnected = False

            def connect(self, protocol=None):
                self.connected_with = protocol

            def disconnect(self):
                self.disconnected = True

        class FakeReader:
            def __init__(self, connection):
                self.connection = connection

            def __str__(self):
                return "Virtual Smart Card Architecture Virtual PCD 0"

            def createConnection(self):
                return self.connection

        class FakeConnector:
            def __init__(self, _card_type):
                self.cardmonitor = None

            def card_select(self):
                return b"", 0x90, 0x00

            def card_get_status(self):
                return {}, 0x90, 0x00, {
                    "setup_done": True,
                    "is_seeded": True,
                    "needs2FA": False,
                }

            def card_initiate_secure_channel(self):
                return None

            def card_verify_PIN(self, _pin):
                return b"", 0x90, 0x00

        old_connection = FakeConnection("old")
        new_connection = FakeConnection("new")
        card = SatochipCard(pin="test-pin")
        card.connection = old_connection
        card.connector = object()
        card.pin_verified = True
        card.setup_done = True
        card.is_seeded = True
        card.needs_2fa = True
        card.authentikey = b"stale"

        with mock.patch.object(card_client, "readers", return_value=[FakeReader(new_connection)]), \
             mock.patch.object(card_client, "CardConnector", FakeConnector), \
             mock.patch.object(card_client, "CardConnection", types.SimpleNamespace(T1_protocol=1)):
            card.connect()

        self.assertTrue(old_connection.disconnected)
        self.assertIs(card.connection, new_connection)
        self.assertEqual(new_connection.connected_with, 1)
        self.assertTrue(card.pin_verified)
        self.assertFalse(card.needs_2fa)
        self.assertIsNone(card.authentikey)
    def test_text_path_parser_rejects_malformed_and_non_hardened_inputs(self):
        self.assertEqual(
            parse_bip32_path("m/44'/501'/0'/0'"),
            [0x8000002C, 0x800001F5, 0x80000000, 0x80000000],
        )
        for bad in (
            "m", "44'/501'", "m/", "m//44'", "m/44'/501'/0/",
            "m/44'/+501'", "m/44'/501' garbage", " m/44'", "m/44' ",
            "m/2147483648'", "m/44'/501'/0'/0'/1'/2'/3'/4'/5'/6'/7'",
        ):
            with self.subTest(path=bad):
                with self.assertRaises(ValueError):
                    parse_bip32_path(bad)
        for bad in ([True], [0x80000000, False], [0x7FFFFFFF], [0x100000000]):
            with self.subTest(path=bad):
                with self.assertRaises(ValueError):
                    validate_path(bad)

    def test_destructive_deep_audit_mode_is_rejected_before_card_access(self):
        with mock.patch.object(test_deep_audit, "run_live_test") as run_live:
            with self.assertRaises(SystemExit):
                test_deep_audit.main(["--reset-test-seed"])
            run_live.assert_not_called()

    def test_hardened_and_exact_path_validation(self):
        tr = LedgerOmni25519Translator(GoodCard(), allow_blind_sign=True)
        bad = path_bytes([0x8000002C, 0x800001F5, 0x80000000, 0x00000000])
        self.assertEqual(tr.handle_apdu(self.apdu(0xE0, 0x05, 0, 0, bad)), SW_WRONG_DATA)
        trailing = path_bytes(SOLANA) + b"garbage"
        self.assertEqual(tr.handle_apdu(self.apdu(0xE0, 0x05, 0, 0, trailing)), SW_WRONG_DATA)
        other_chain = path_bytes(TON)
        self.assertEqual(tr.handle_apdu(self.apdu(0xE0, 0x05, 0, 0, other_chain)), SW_WRONG_DATA)

    def test_short_case_two_apdu_is_not_treated_as_lc(self):
        tr = LedgerOmni25519Translator(GoodCard(), allow_blind_sign=True)
        self.assertEqual(tr.handle_apdu(bytes((0xE0, 0x05, 0, 0, 0))), SW_WRONG_DATA)

    def test_continuation_requires_matching_chain_and_p1(self):
        tr = LedgerOmni25519Translator(GoodCard(), allow_blind_sign=True)
        first = path_bytes(SOLANA) + b"hello"
        self.assertEqual(tr.handle_apdu(self.apdu(0xE0, 0x06, 0, 0x02, bytes([1]) + first)), SW_OK)
        # TON's shared CLA/INS cannot consume a Solana signing stream.
        self.assertEqual(tr.handle_apdu(self.apdu(0xE0, 0x03, 0, 0x01, b"x")), SW_CONDITIONS_NOT_SATISFIED)
        self.assertIsNone(tr.signing_path)

    def test_unknown_p2_and_orphan_continuation_clear_state(self):
        tr = LedgerOmni25519Translator(GoodCard(), allow_blind_sign=True)
        self.assertEqual(tr.handle_apdu(self.apdu(0xE0, 0x06, 0, 0x80, b"x")), SW_WRONG_DATA)
        self.assertEqual(tr.handle_apdu(self.apdu(0xE0, 0x06, 0, 0x01, b"x")), SW_CONDITIONS_NOT_SATISFIED)
        self.assertIsNone(tr.signing_path)

    def test_blind_signing_is_fail_closed(self):
        tr = LedgerOmni25519Translator(GoodCard())
        payload = bytes([1]) + path_bytes(SOLANA) + b"message"
        self.assertEqual(tr.handle_apdu(self.apdu(0xE0, 0x06, 0, 0, payload)), SW_SECURITY_STATUS)
        self.assertIsNone(tr.signing_path)

    def test_signature_is_verified_before_release(self):
        tr = LedgerOmni25519Translator(BadSignatureCard(), allow_blind_sign=True)
        payload = bytes([1]) + path_bytes(SOLANA) + b"message"
        self.assertEqual(tr.handle_apdu(self.apdu(0xE0, 0x06, 0, 0, payload)), SW_CONDITIONS_NOT_SATISFIED)

    def test_stream_length_limit(self):
        tr = LedgerOmni25519Translator(GoodCard(), allow_blind_sign=True)
        payload = bytes([1]) + path_bytes(SOLANA) + b"x" * 149
        # The Solana path is part of the APDU, while the signed message is 149 bytes.
        self.assertTrue(tr.handle_apdu(self.apdu(0xE0, 0x06, 0, 0x02, payload)) == SW_OK)
        self.assertEqual(tr.handle_apdu(self.apdu(0xE0, 0x06, 0, 0x01, b"y")), SW_WRONG_LENGTH)

    def test_framer_rejects_bad_packets_and_bounds_length(self):
        f = LedgerHIDFramer()
        valid = f.frame_response(b"abcd")[0]
        self.assertEqual(f.feed_packet(valid), b"abcd")
        self.assertIsNone(f.feed_packet(b"\x00" * 64))
        oversized = bytearray(valid)
        oversized[5:7] = (261).to_bytes(2, "big")
        self.assertIsNone(f.feed_packet(bytes(oversized)))
        self.assertEqual(len(f.frame_response(b"x" * 260)), 5)


if __name__ == "__main__":
    unittest.main()


