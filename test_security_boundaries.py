"""Offline regression tests for bridge security boundaries."""
import struct
import types
import unittest
import io
from contextlib import redirect_stdout
from unittest import mock
from cryptography.hazmat.primitives.asymmetric import ed25519

from ledger_ed25519_omni_translator import (
    LedgerHIDFramer, LedgerOmni25519Translator, SW_OK, SW_WRONG_DATA,
    SW_WRONG_LENGTH, SW_CONDITIONS_NOT_SATISFIED, SW_SECURITY_STATUS,
)
from ledger_solana_translator import (
    LedgerSolanaTranslator, SW_WRONG_DATA as LEGACY_SW_WRONG_DATA,
    SW_CONDITIONS_NOT_SATISFIED as LEGACY_SW_CONDITIONS_NOT_SATISFIED,
)
import pysatochip_25519 as card_client
from pysatochip_25519 import parse_bip32_path, validate_path, SatochipCard, SatochipException
import satochip_cli_25519
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


class LegacyBadSignatureCard(GoodCard):
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
        self.assertTrue(card.connector.card_present)
        card.disconnect()
        self.assertTrue(new_connection.disconnected)

    def test_client_rejects_invalid_reader_and_seed_parameters(self):
        with self.assertRaises(ValueError):
            SatochipCard(reader_name=123)
        for seed in (b"", b"short", b"x" * 65, 32):
            with self.subTest(seed=repr(seed)):
                with self.assertRaises(ValueError):
                    SatochipCard(seed=seed)

    def test_client_pairwise_verifies_staged_signatures(self):
        key = ed25519.Ed25519PrivateKey.generate()
        pubkey = key.public_key().public_bytes_raw()
        card = SatochipCard()
        card.connection = object()
        card.connector = types.SimpleNamespace(needs_2FA=False)
        card.staged_public_key = pubkey
        card._ensure_connected = lambda: None
        card._transmit = lambda _ins, _p1, _p2, message: key.sign(message)
        message = b"client-side pairwise verification"
        self.assertEqual(card.sign_ed25519_message(message), key.sign(message))

        bad = SatochipCard()
        bad.connection = object()
        bad.connector = types.SimpleNamespace(needs_2FA=False)
        bad.staged_public_key = pubkey
        bad._ensure_connected = lambda: None
        bad._transmit = lambda _ins, _p1, _p2, _message: b"\x00" * 64
        with self.assertRaises(SatochipException):
            bad.sign_ed25519_message(message)
        self.assertIsNone(bad.connection)
        self.assertIsNone(bad.staged_public_key)

    def test_unbound_signing_and_x25519_are_rejected_without_card_io(self):
        card = SatochipCard()
        card.connection = object()
        card.connector = types.SimpleNamespace(needs_2FA=False)
        card._ensure_connected = lambda: None
        card._transmit = mock.Mock(side_effect=AssertionError("APDU must not be sent"))
        with self.assertRaises(SatochipException):
            card.sign_ed25519_message(b"message")
        with self.assertRaises(SatochipException):
            card.x25519_key_agreement(b"x" * 32)
        card._transmit.assert_not_called()

    def test_transport_error_clears_staged_session(self):
        card = SatochipCard()
        card.connection = object()
        card.connector = types.SimpleNamespace(needs_2FA=False)
        card.staged_public_key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        card._ensure_connected = lambda: None
        card._transmit = mock.Mock(side_effect=OSError("reader transport lost"))
        with self.assertRaises(OSError):
            card.sign_ed25519_message(b"message")
        self.assertIsNone(card.connection)
        self.assertIsNone(card.staged_public_key)

    def test_x25519_failure_clears_staged_session(self):
        card = SatochipCard()
        card.connection = object()
        card.connector = types.SimpleNamespace(needs_2FA=False)
        card.staged_public_key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        card._ensure_connected = lambda: None
        card._transmit = mock.Mock(
            side_effect=SatochipException("X25519 rejected", 0x9C4F)
        )
        with self.assertRaises(SatochipException):
            card.x25519_key_agreement(b"x" * 32)
        self.assertIsNone(card.connection)
        self.assertIsNone(card.staged_public_key)

    def test_cli_reports_pin_zero_counters_and_cleans_up(self):
        raw_status = bytes([0, 16, 1, 0, 7, 6, 2, 1]) + bytes(11)
        fake = types.SimpleNamespace(
            pin="1234",
            reader_name="test reader",
            connector=types.SimpleNamespace(
                pin="1234", pin_nbr=0,
                card_get_status=lambda: (raw_status, 0x90, 0x00, {}),
            ),
            connect=lambda: None,
            disconnect=lambda: None,
        )
        output = io.StringIO()
        with mock.patch.object(satochip_cli_25519, "SatochipCard", return_value=fake), \
             redirect_stdout(output):
            result = satochip_cli_25519.main(["--status", "--pin", "1234"])
        self.assertEqual(result, 0)
        self.assertIn("PIN0 Tries Left:  7", output.getvalue())
        self.assertIn("PUK0 Tries Left:  6", output.getvalue())
        self.assertIsNone(fake.connector.pin)
        self.assertIsNone(fake.connector.pin_nbr)
        self.assertIsNone(fake.pin)

    def test_cli_status_failure_returns_nonzero_and_cleans_up(self):
        fake = types.SimpleNamespace(
            pin="1234",
            reader_name="test reader",
            connector=types.SimpleNamespace(
                pin="1234", pin_nbr=0,
                card_get_status=lambda: (b"", 0x9C, 0x06, {}),
            ),
            connect=lambda: None,
            disconnect=mock.Mock(),
        )
        with mock.patch.object(satochip_cli_25519, "SatochipCard", return_value=fake), \
             redirect_stdout(io.StringIO()):
            result = satochip_cli_25519.main(["--status", "--pin", "1234"])
        self.assertEqual(result, 1)
        fake.disconnect.assert_called_once()
        self.assertIsNone(fake.connector.pin)
        self.assertIsNone(fake.pin)

    def test_client_aborts_session_when_public_key_recovery_fails(self):
        card = SatochipCard()
        card.connection = object()
        card.connector = object()
        card._ensure_connected = lambda: None
        card._transmit = lambda _ins, _p1, _p2, _payload: b"\x00" * 10
        with self.assertRaises(SatochipException):
            card.slip10_get_extended_key(SOLANA)
        self.assertIsNone(card.connection)
        self.assertIsNone(card.connector)
        self.assertIsNone(card.staged_public_key)
    def test_text_path_parser_rejects_malformed_and_non_hardened_inputs(self):
        self.assertEqual(
            parse_bip32_path("m/44'/501'/0'/0'"),
            [0x8000002C, 0x800001F5, 0x80000000, 0x80000000],
        )
        for bad in (
            "44'/501'", "m/", "m//44'", "m/44'/501'/0/",
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

    def test_legacy_solana_translator_enforces_coin_type(self):
        tr = LedgerSolanaTranslator(GoodCard(), allow_blind_sign=True)
        ton_path = path_bytes(TON)
        response = tr.handle_apdu(self.apdu(0xE0, 0x05, 0, 0, ton_path))
        self.assertEqual(response, LEGACY_SW_WRONG_DATA)

    def test_legacy_solana_translator_verifies_signature_before_release(self):
        tr = LedgerSolanaTranslator(LegacyBadSignatureCard(), allow_blind_sign=True)
        payload = bytes([1]) + path_bytes(SOLANA) + b"message"
        response = tr.handle_apdu(self.apdu(0xE0, 0x06, 0, 0, payload))
        self.assertEqual(response, LEGACY_SW_CONDITIONS_NOT_SATISFIED)
        self.assertIsNone(tr.signing_path)
        self.assertIsNone(tr.signing_pubkey)

    def test_legacy_solana_translator_clears_partial_stream_on_intervening_command(self):
        tr = LedgerSolanaTranslator(GoodCard(), allow_blind_sign=True)
        first = bytes([1]) + path_bytes(SOLANA) + b"part"
        self.assertEqual(tr.handle_apdu(self.apdu(0xE0, 0x06, 0, 0x02, first)), SW_OK)
        self.assertIsNotNone(tr.signing_path)
        self.assertEqual(
            tr.handle_apdu(self.apdu(0xB0, 0x01, 0, 0, b""))[-2:],
            SW_OK,
        )
        self.assertIsNone(tr.signing_path)
        self.assertIsNone(tr.signing_pubkey)
        self.assertEqual(
            tr.handle_apdu(self.apdu(0xE0, 0x06, 0, 0x01, b"tail")),
            LEGACY_SW_CONDITIONS_NOT_SATISFIED,
        )

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


