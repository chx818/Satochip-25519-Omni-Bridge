"""Narrow Ledger-Solana APDU translator for the Satochip bridge.

This implements only the APDU subset listed here; it is not a general Ledger
protocol emulator. Ledger HID reports are exactly 64 bytes.
"""
import struct
from cryptography.hazmat.primitives.asymmetric import ed25519
from typing import List, Optional

from pysatochip_25519 import SatochipCard, SatochipException, validate_path

LEDGER_CHANNEL_ID = 0x0101
LEDGER_TAG_APDU = 0x05
MAX_LEDGER_APDU = 260
MAX_SIGN_MESSAGE = 149  # Card secure-channel plaintext limit minus APDU header.

CLA_LEDGER_SYSTEM = 0xB0
INS_GET_APP_AND_VERSION = 0x01
CLA_LEDGER_SOLANA = 0xE0
INS_SOLANA_GET_PUBKEY = 0x05
INS_SOLANA_SIGN_MESSAGE = 0x06

APP_NAME = b"Solana"
APP_VERSION = b"1.4.1"
SW_OK = b"\x90\x00"
SW_WRONG_LENGTH = b"\x67\x00"
SW_WRONG_DATA = b"\x6a\x80"
SW_CLA_NOT_SUPPORTED = b"\x6e\x00"
SW_INS_NOT_SUPPORTED = b"\x6d\x00"
SW_CONDITIONS_NOT_SATISFIED = b"\x69\x85"
SW_SECURITY_STATUS = b"\x69\x82"
P1_NON_CONFIRM = 0x00
P1_CONFIRM = 0x01
P2_EXTEND = 0x01
P2_MORE = 0x02


class LedgerHIDFramer:
    """Strict 64-byte Ledger HID packet assembler/framer."""
    def __init__(self, channel_id: int = LEDGER_CHANNEL_ID):
        self.channel_id = channel_id
        self.reset()

    def reset(self):
        self.rx_buffer = bytearray()
        self.expected_length = 0
        self.expected_seq = 0

    def feed_packet(self, packet: bytes) -> Optional[bytes]:
        if len(packet) != 64:
            self.reset()
            return None
        channel, tag, seq = struct.unpack(">HBH", packet[:5])
        if channel != self.channel_id or tag != LEDGER_TAG_APDU:
            self.reset()
            return None
        if seq == 0:
            self.reset()
            length = struct.unpack(">H", packet[5:7])[0]
            if not 4 <= length <= MAX_LEDGER_APDU:
                return None
            self.expected_length = length
            self.rx_buffer.extend(packet[7:])
            self.expected_seq = 1
        else:
            if self.expected_length == 0 or seq != self.expected_seq:
                self.reset()
                return None
            self.rx_buffer.extend(packet[5:])
            self.expected_seq += 1
            if self.expected_seq > 0xFFFF:
                self.reset()
                return None
        if len(self.rx_buffer) >= self.expected_length:
            result = bytes(self.rx_buffer[:self.expected_length])
            self.reset()
            return result
        return None

    def frame_response(self, apdu_response: bytes) -> List[bytes]:
        apdu_response = bytes(apdu_response)
        if not 1 <= len(apdu_response) <= 0xFFFF:
            raise ValueError("Ledger HID response length must be in 1..65535 bytes")
        packets = []
        first = struct.pack(">HBHH", self.channel_id, LEDGER_TAG_APDU, 0, len(apdu_response))
        packets.append((first + apdu_response[:57]).ljust(64, b"\x00"))
        offset = 57
        seq = 1
        while offset < len(apdu_response):
            header = struct.pack(">HBH", self.channel_id, LEDGER_TAG_APDU, seq)
            packets.append((header + apdu_response[offset:offset + 59]).ljust(64, b"\x00"))
            offset += 59
            seq += 1
        return packets


class LedgerSolanaTranslator:
    """Strict translator for GET_PUBKEY and bounded SIGN_MESSAGE only."""
    def __init__(self, satochip_card: SatochipCard, allow_blind_sign: bool = False):
        self.card = satochip_card
        self.allow_blind_sign = allow_blind_sign
        self.cached_path: List[int] = []
        self.incoming_tx_buffer = bytearray()
        self.signing_path: Optional[List[int]] = None
        self.signing_p1: Optional[int] = None
        self.signing_pubkey: Optional[bytes] = None

    @staticmethod
    def _parse_apdu(apdu: bytes):
        if len(apdu) < 4:
            raise ValueError("truncated APDU header")
        if len(apdu) == 4:
            return apdu[0], apdu[1], apdu[2], apdu[3], b""
        if len(apdu) == 5:
            # Case-2 short APDU: fifth byte is Le (zero means 256).
            return apdu[0], apdu[1], apdu[2], apdu[3], b""
        lc = apdu[4]
        if lc == 0 or len(apdu) != 5 + lc:
            raise ValueError("unsupported extended APDU or inconsistent Lc")
        return apdu[0], apdu[1], apdu[2], apdu[3], apdu[5:]

    @staticmethod
    def _parse_ledger_path(data: bytes) -> List[int]:
        if not data:
            raise ValueError("missing path depth")
        depth = data[0]
        if not 1 <= depth <= 10 or len(data) != 1 + depth * 4:
            raise ValueError("invalid path encoding")
        path = [struct.unpack_from(">I", data, 1 + 4 * i)[0] for i in range(depth)]
        validate_path(path)
        return path

    @staticmethod
    def _validate_solana_path(path: List[int]) -> None:
        # This translator is Solana-specific. Hardened-only validation alone
        # would still allow an Ethereum/TON/etc. path to be signed through the
        # Solana command namespace and silently derive the wrong account.
        if len(path) < 2 or (path[0] & 0x7FFFFFFF) != 44:
            raise ValueError("path is not a BIP44 path")
        if (path[1] & 0x7FFFFFFF) != 501:
            raise ValueError("path is not a Solana path")

    @staticmethod
    def _error(sw: bytes) -> bytes:
        return sw

    def handle_apdu(self, apdu: bytes) -> bytes:
        try:
            cla, ins, p1, p2, data = self._parse_apdu(bytes(apdu))
        except ValueError:
            self._clear_signing_state()
            return SW_WRONG_LENGTH

        if cla == CLA_LEDGER_SYSTEM and ins == INS_GET_APP_AND_VERSION:
            self._clear_signing_state()
            if p1 != 0 or p2 != 0 or data:
                return SW_WRONG_DATA
            body = bytes([1, len(APP_NAME)]) + APP_NAME + bytes([len(APP_VERSION)]) + APP_VERSION + b"\x00"
            return body + SW_OK
        if cla != CLA_LEDGER_SOLANA:
            self._clear_signing_state()
            return SW_CLA_NOT_SUPPORTED

        if ins == INS_SOLANA_GET_PUBKEY:
            self._clear_signing_state()
            if p1 not in (P1_NON_CONFIRM, P1_CONFIRM) or p2 != 0:
                return SW_WRONG_DATA
            try:
                path = self._parse_ledger_path(data)
                self._validate_solana_path(path)
                pubkey = self.card.slip10_get_extended_key(path)
                if len(pubkey) != 32:
                    return SW_CONDITIONS_NOT_SATISFIED
                self.cached_path = path
                # Ledger Solana returns the raw 32-byte Ed25519 public key, without a length TLV.
                return pubkey + SW_OK
            except ValueError:
                return SW_WRONG_DATA
            except SatochipException:
                return SW_CONDITIONS_NOT_SATISFIED
            except Exception:
                return SW_CONDITIONS_NOT_SATISFIED

        if ins == INS_SOLANA_SIGN_MESSAGE:
            if p1 not in (P1_NON_CONFIRM, P1_CONFIRM) or p2 & ~(P2_EXTEND | P2_MORE):
                self._clear_signing_state()
                return SW_WRONG_DATA
            is_extension = bool(p2 & P2_EXTEND)
            more_follows = bool(p2 & P2_MORE)
            try:
                if not is_extension:
                    # A new first APDU replaces any stale partial command. Solana's payload
                    # starts with num_paths=1, then a path encoding [depth | uint32 indices].
                    self._clear_signing_state()
                    if len(data) < 2 or data[0] != 1:
                        return SW_WRONG_DATA
                    path_size = 1 + data[1] * 4
                    path_end = 1 + path_size
                    if path_end > len(data):
                        return SW_WRONG_DATA
                    path = self._parse_ledger_path(data[1:path_end])
                    self._validate_solana_path(path)
                    signing_pubkey = bytes(self.card.slip10_get_extended_key(path))
                    if len(signing_pubkey) != 32:
                        raise ValueError("card returned an invalid Ed25519 public key")
                    self.signing_path = path
                    self.signing_p1 = p1
                    self.signing_pubkey = signing_pubkey
                    self.incoming_tx_buffer.extend(data[path_end:])
                else:
                    if self.signing_path is None or self.signing_p1 != p1:
                        self._clear_signing_state()
                        return SW_CONDITIONS_NOT_SATISFIED
                    self.incoming_tx_buffer.extend(data)

                if len(self.incoming_tx_buffer) > MAX_SIGN_MESSAGE:
                    self._clear_signing_state()
                    return SW_WRONG_LENGTH
                if more_follows:
                    return SW_OK
                if not self.incoming_tx_buffer:
                    self._clear_signing_state()
                    return SW_WRONG_LENGTH
                # This bridge has no trusted display/user-confirmation channel. Never pretend
                # that Ledger's P1_CONFIRM was honored; blind signing is explicit opt-in only.
                if not self.allow_blind_sign:
                    self._clear_signing_state()
                    return SW_SECURITY_STATUS
                message = bytes(self.incoming_tx_buffer)
                signature = self.card.sign_ed25519_message(message)
                signing_pubkey = self.signing_pubkey
                if len(signature) != 64 or signing_pubkey is None or len(signing_pubkey) != 32:
                    self._clear_signing_state()
                    return SW_CONDITIONS_NOT_SATISFIED
                try:
                    ed25519.Ed25519PublicKey.from_public_bytes(signing_pubkey).verify(signature, message)
                except Exception:
                    self._clear_signing_state()
                    return SW_CONDITIONS_NOT_SATISFIED
                self._clear_signing_state()
                return signature + SW_OK
            except ValueError:
                self._clear_signing_state()
                return SW_WRONG_DATA
            except SatochipException:
                self._clear_signing_state()
                return SW_CONDITIONS_NOT_SATISFIED
            except Exception:
                self._clear_signing_state()
                return SW_CONDITIONS_NOT_SATISFIED

        self._clear_signing_state()
        return SW_INS_NOT_SUPPORTED

    def _clear_signing_state(self):
        for i in range(len(self.incoming_tx_buffer)):
            self.incoming_tx_buffer[i] = 0
        self.incoming_tx_buffer.clear()
        self.signing_path = None
        self.signing_p1 = None
        self.signing_pubkey = None
        self.cached_path = []
