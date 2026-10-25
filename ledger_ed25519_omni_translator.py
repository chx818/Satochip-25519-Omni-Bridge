"""ledger_ed25519_omni_translator.py
Universal Ledger APDU Translator for all Ed25519 / SLIP-0010 blockchains:
- Solana (SOL)        [BIP44 501', CLA 0xE0, INS 0x05 / 0x06]
- TON (The Open Net)  [BIP44 607', CLA 0xE0, INS 0x02 / 0x03]
- Sui (SUI)           [BIP44 784', CLA 0x00 / 0xE0, INS 0x02 / 0x03]
- Aptos (APT)         [BIP44 637', CLA 0x5B, INS 0x02 / 0x03]
- Polkadot (DOT/KSM)  [BIP44 354', CLA 0xF9, INS 0x01 / 0x02]
- Near (NEAR)         [BIP44 397', CLA 0x24, INS 0x04 / 0x05]

Translates incoming WebHID Ledger frames from browser wallets (Phantom, Solflare,
Tonkeeper, Sui Wallet, Petra, Pontem, SubWallet, Polkadot.js, etc.) into
native Satochip APDUs over PC/SC using NXP J3R452 hardware acceleration.
"""

import struct
from cryptography.hazmat.primitives.asymmetric import ed25519
from typing import List, Optional, Tuple, Dict, Any
from pysatochip_25519 import SatochipCard, SatochipException, validate_path

# Standard Ledger HID framing constants
LEDGER_CHANNEL_ID = 0x0101
LEDGER_TAG_APDU = 0x05
MAX_LEDGER_APDU = 260
MAX_SIGN_MESSAGE = 149  # Satochip SecureChannel frame limit

# Standard ISO/Ledger Status Words
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

# Universal BOLOS System Commands
CLA_LEDGER_SYSTEM = 0xB0
INS_GET_APP_AND_VERSION = 0x01

# Recognized Ledger Ed25519 Chain Profiles
CHAIN_PROFILES: Dict[str, Dict[str, Any]] = {
    "solana": {
        "name": b"Solana",
        "version": b"1.4.1",
        "coin_type": 501,
        "cla": 0xE0,
        "ins_pubkey": 0x05,
        "ins_sign": 0x06,
        "ins_sign_offchain": 0x07,
    },
    "ton": {
        "name": b"Ton",
        "version": b"1.0.3",
        "coin_type": 607,
        "cla": 0xE0,
        "ins_get_version": 0x01,
        "ins_pubkey": 0x02,
        "ins_sign": 0x03,
    },
    "sui": {
        "name": b"Sui",
        "version": b"0.4.1",
        "coin_type": 784,
        "cla": 0x00,
        "cla_alt": 0xE0,
        "ins_get_version": 0x01,
        "ins_pubkey": 0x02,
        "ins_sign": 0x03,
    },
    "aptos": {
        "name": b"Aptos",
        "version": b"0.5.2",
        "coin_type": 637,
        "cla": 0x5B,
        "ins_get_version": 0x01,
        "ins_pubkey": 0x02,
        "ins_sign": 0x03,
    },
    "polkadot": {
        "name": b"Polkadot",
        "version": b"100.0.1",
        "coin_type": 354,
        "cla": 0xF9,
        "ins_get_version": 0x00,
        "ins_pubkey": 0x01,
        "ins_sign": 0x02,
    },
    "near": {
        "name": b"NEAR",
        "version": b"1.2.1",
        "coin_type": 397,
        "cla": 0x24,
        "ins_get_version": 0x02,
        "ins_pubkey": 0x04,
        "ins_sign": 0x05,
    },
}


class LedgerHIDFramer:
    """Strict 64-byte Ledger HID packet assembler / framer."""
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


class LedgerOmni25519Translator:
    """Universal translator auto-routing across Solana, TON, Sui, Aptos, Polkadot, and Near."""
    def __init__(self, satochip_card: SatochipCard, default_chain: str = "solana", allow_blind_sign: bool = False):
        self.card = satochip_card
        self.allow_blind_sign = allow_blind_sign
        self.active_chain = default_chain if default_chain in CHAIN_PROFILES else "solana"
        self.cached_path: List[int] = []
        self.incoming_tx_buffer = bytearray()
        self.signing_path: Optional[List[int]] = None
        self.signing_p1: Optional[int] = None
        self.signing_chain: Optional[str] = None
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
    def _parse_ledger_path_prefix(data: bytes, offset: int = 0) -> Tuple[List[int], int]:
        if offset < 0 or len(data) <= offset:
            raise ValueError("missing path depth")
        depth = data[offset]
        path_end = offset + 1 + depth * 4
        if not 1 <= depth <= 10 or path_end > len(data):
            raise ValueError("invalid path encoding")
        path = [struct.unpack_from(">I", data, offset + 1 + 4 * i)[0] for i in range(depth)]
        validate_path(path)
        return path, path_end

    @classmethod
    def _parse_ledger_path(cls, data: bytes) -> List[int]:
        path, path_end = cls._parse_ledger_path_prefix(data)
        if path_end != len(data):
            raise ValueError("unexpected bytes after derivation path")
        return path

    def _detect_chain_from_path(self, path: List[int]) -> Optional[str]:
        """Detect chain profile by inspecting BIP44 coin_type index."""
        if len(path) >= 2 and (path[0] & 0x7FFFFFFF) == 44:
            coin = path[1] & 0x7FFFFFFF
            for chain_id, profile in CHAIN_PROFILES.items():
                if profile["coin_type"] == coin:
                    return chain_id
        return None

    def _validate_path_for_chain(self, path: List[int], chain: str) -> None:
        detected = self._detect_chain_from_path(path)
        if detected != chain:
            raise ValueError(f"derivation path does not belong to {chain}")

    def _switch_chain(self, chain: str) -> None:
        if chain not in CHAIN_PROFILES:
            raise ValueError(f"unsupported chain: {chain}")
        if self.active_chain != chain:
            self._clear_signing_state()
            self.cached_path = []
            self.active_chain = chain

    def _handle_chain(self, chain: str, ins: int, p1: int, p2: int, data: bytes) -> bytes:
        if chain == "solana":
            return self._handle_solana(ins, p1, p2, data)
        if chain == "ton":
            return self._handle_ton(ins, p1, p2, data)
        if chain == "sui":
            return self._handle_sui(ins, p1, p2, data)
        if chain == "aptos":
            return self._handle_aptos(ins, p1, p2, data)
        if chain == "polkadot":
            return self._handle_polkadot(ins, p1, p2, data)
        if chain == "near":
            return self._handle_near(ins, p1, p2, data)
        return SW_CLA_NOT_SUPPORTED

    def _chain_for_e0_command(self, ins: int, data: bytes) -> Optional[str]:
        if ins in (0x05, 0x06, 0x07):
            return "solana"
        if ins in (0x02, 0x03):
            try:
                path, _ = self._parse_ledger_path_prefix(data)
            except ValueError:
                return self.active_chain if self.active_chain in ("ton", "sui") else None
            return self._detect_chain_from_path(path)
        if ins == 0x01 and self.active_chain in ("ton", "sui"):
            return self.active_chain
        return None

    def _continuation_chain(self, cla: int, ins: int) -> Optional[str]:
        if cla == 0xE0:
            if ins in (0x06, 0x07):
                return "solana"
            if ins == 0x03 and self.signing_chain in ("ton", "sui"):
                return self.signing_chain
            return None
        for chain_id, profile in CHAIN_PROFILES.items():
            if cla == profile["cla"]:
                sign_ins = profile["ins_sign"]
                if ins == sign_ins:
                    return chain_id
        return None

    def _clear_signing_state(self):
        # Clear all transient path/key metadata as well as the message bytes.
        # ``cached_path`` is not used as an authorization primitive, but leaving
        # it populated after an error or chain switch is an avoidable stale-state
        # hazard for callers/diagnostics and can cause cross-chain confusion.
        for i in range(len(self.incoming_tx_buffer)):
            self.incoming_tx_buffer[i] = 0
        self.incoming_tx_buffer.clear()
        self.signing_path = None
        self.signing_p1 = None
        self.signing_chain = None
        self.signing_pubkey = None
        self.cached_path = []

    def handle_apdu(self, apdu: bytes) -> bytes:
        try:
            cla, ins, p1, p2, data = self._parse_apdu(bytes(apdu))
        except ValueError:
            self._clear_signing_state()
            return SW_WRONG_LENGTH

        # -------------------------------------------------------------
        # 1. BOLOS System: GET_APP_AND_VERSION (0xB0 0x01)
        # -------------------------------------------------------------
        if cla == CLA_LEDGER_SYSTEM and ins == INS_GET_APP_AND_VERSION:
            self._clear_signing_state()
            if p1 != 0 or p2 != 0 or data:
                return SW_WRONG_DATA
            profile = CHAIN_PROFILES.get(self.active_chain, CHAIN_PROFILES["solana"])
            app_name = profile["name"]
            app_ver = profile["version"]
            body = bytes([1, len(app_name)]) + app_name + bytes([len(app_ver)]) + app_ver + b"\x00"
            return body + SW_OK

        # -------------------------------------------------------------
        # 2. Chain-Specific CLA Auto-Detection
        # -------------------------------------------------------------
        # Continuations are bound to the chain and P1 of their first packet.
        # Never route them through the mutable active_chain selected by a later
        # request, otherwise a cross-chain request can consume staged data.
        if p2 & P2_EXTEND:
            chain = self._continuation_chain(cla, ins)
            if self.signing_chain is None or chain != self.signing_chain:
                self._clear_signing_state()
                return SW_CONDITIONS_NOT_SATISFIED
            return self._handle_chain(chain, ins, p1, p2, data)

        if self.signing_path is not None:
            self._clear_signing_state()

        # Polkadot (CLA 0xF9)
        if cla == CHAIN_PROFILES["polkadot"]["cla"]:
            self._switch_chain("polkadot")
            return self._handle_polkadot(ins, p1, p2, data)

        # Aptos (CLA 0x5B)
        if cla == CHAIN_PROFILES["aptos"]["cla"]:
            self._switch_chain("aptos")
            return self._handle_aptos(ins, p1, p2, data)

        # Near (CLA 0x24)
        if cla == CHAIN_PROFILES["near"]["cla"]:
            self._switch_chain("near")
            return self._handle_near(ins, p1, p2, data)

        # Sui (CLA 0x00 or 0xE0 with Sui INS)
        if cla == 0x00:
            self._switch_chain("sui")
            return self._handle_sui(ins, p1, p2, data)

        # -------------------------------------------------------------
        # 3. CLA 0xE0 Shared Dispatch (Solana, TON, Sui)
        # -------------------------------------------------------------
        if cla == 0xE0:
            chain = self._chain_for_e0_command(ins, data)
            if chain is None:
                self._clear_signing_state()
                return SW_INS_NOT_SUPPORTED
            self._switch_chain(chain)
            return self._handle_chain(chain, ins, p1, p2, data)

        self._clear_signing_state()
        return SW_CLA_NOT_SUPPORTED

    # -----------------------------------------------------------------
    # Chain Sub-Handlers
    # -----------------------------------------------------------------

    def _handle_solana(self, ins: int, p1: int, p2: int, data: bytes) -> bytes:
        """Solana: INS 0x05 (Get Pubkey), INS 0x06 / 0x07 (Sign)"""
        if ins == 0x05:
            self._clear_signing_state()
            if p1 not in (P1_NON_CONFIRM, P1_CONFIRM) or p2 != 0:
                return SW_WRONG_DATA
            try:
                path = self._parse_ledger_path(data)
                self._validate_path_for_chain(path, "solana")
                pubkey = self.card.slip10_get_extended_key(path)
                self.cached_path = path
                return pubkey + SW_OK
            except ValueError:
                return SW_WRONG_DATA
            except SatochipException:
                return SW_CONDITIONS_NOT_SATISFIED
            except Exception:
                return SW_CONDITIONS_NOT_SATISFIED

        if ins in (0x06, 0x07):
            return self._execute_streamed_ed25519_sign(p1, p2, data, chain='solana', is_solana=True)

        return SW_INS_NOT_SUPPORTED

    def _handle_ton(self, ins: int, p1: int, p2: int, data: bytes) -> bytes:
        """TON: INS 0x01 (Version), INS 0x02 (Get Pubkey), INS 0x03 (Sign)"""
        if ins == 0x01:
            self._clear_signing_state()
            if p1 != 0 or p2 != 0 or data:
                return SW_WRONG_DATA
            # Return TON App Version 1.0.3
            return bytes([1, 0, 3]) + SW_OK

        if ins == 0x02:
            self._clear_signing_state()
            if p1 not in (P1_NON_CONFIRM, P1_CONFIRM) or p2 != 0:
                return SW_WRONG_DATA
            try:
                path = self._parse_ledger_path(data)
                self._validate_path_for_chain(path, "ton")
                pubkey = self.card.slip10_get_extended_key(path)
                self.cached_path = path
                return pubkey + SW_OK
            except ValueError:
                return SW_WRONG_DATA
            except SatochipException:
                return SW_CONDITIONS_NOT_SATISFIED
            except Exception:
                return SW_CONDITIONS_NOT_SATISFIED

        if ins == 0x03:
            return self._execute_streamed_ed25519_sign(p1, p2, data, chain='ton', is_solana=False)

        return SW_INS_NOT_SUPPORTED

    def _handle_sui(self, ins: int, p1: int, p2: int, data: bytes) -> bytes:
        """Sui: INS 0x01 (Version), INS 0x02 (Get Pubkey), INS 0x03 (Sign)"""
        if ins == 0x01:
            self._clear_signing_state()
            if p1 != 0 or p2 != 0 or data:
                return SW_WRONG_DATA
            # Return Sui App Version 0.4.1
            return bytes([0, 4, 1]) + SW_OK

        if ins == 0x02:
            self._clear_signing_state()
            if p1 not in (P1_NON_CONFIRM, P1_CONFIRM) or p2 != 0:
                return SW_WRONG_DATA
            try:
                path = self._parse_ledger_path(data)
                self._validate_path_for_chain(path, "sui")
                pubkey = self.card.slip10_get_extended_key(path)
                self.cached_path = path
                return pubkey + SW_OK
            except ValueError:
                return SW_WRONG_DATA
            except SatochipException:
                return SW_CONDITIONS_NOT_SATISFIED
            except Exception:
                return SW_CONDITIONS_NOT_SATISFIED

        if ins == 0x03:
            return self._execute_streamed_ed25519_sign(p1, p2, data, chain='sui', is_solana=False)

        return SW_INS_NOT_SUPPORTED

    def _handle_aptos(self, ins: int, p1: int, p2: int, data: bytes) -> bytes:
        """Aptos: INS 0x01 (Version), INS 0x02 (Get Pubkey), INS 0x03 (Sign)"""
        if ins == 0x01:
            self._clear_signing_state()
            if p1 != 0 or p2 != 0 or data:
                return SW_WRONG_DATA
            return bytes([0, 5, 2]) + SW_OK

        if ins == 0x02:
            self._clear_signing_state()
            if p1 not in (P1_NON_CONFIRM, P1_CONFIRM) or p2 != 0:
                return SW_WRONG_DATA
            try:
                path = self._parse_ledger_path(data)
                self._validate_path_for_chain(path, "aptos")
                pubkey = self.card.slip10_get_extended_key(path)
                self.cached_path = path
                return pubkey + SW_OK
            except ValueError:
                return SW_WRONG_DATA
            except SatochipException:
                return SW_CONDITIONS_NOT_SATISFIED
            except Exception:
                return SW_CONDITIONS_NOT_SATISFIED

        if ins == 0x03:
            return self._execute_streamed_ed25519_sign(p1, p2, data, chain='aptos', is_solana=False)

        return SW_INS_NOT_SUPPORTED

    def _handle_polkadot(self, ins: int, p1: int, p2: int, data: bytes) -> bytes:
        """Polkadot: INS 0x00 (Version), INS 0x01 (Get Pubkey), INS 0x02 (Sign)"""
        if ins == 0x00:
            self._clear_signing_state()
            if p1 != 0 or p2 != 0 or data:
                return SW_WRONG_DATA
            # Return [test_mode=0, major=100, minor=0, patch=1]
            return bytes([0, 100, 0, 1]) + SW_OK

        if ins == 0x01:
            self._clear_signing_state()
            if p1 not in (P1_NON_CONFIRM, P1_CONFIRM) or p2 != 0:
                return SW_WRONG_DATA
            try:
                path = self._parse_ledger_path(data)
                self._validate_path_for_chain(path, "polkadot")
                pubkey = self.card.slip10_get_extended_key(path)
                self.cached_path = path
                return pubkey + SW_OK
            except ValueError:
                return SW_WRONG_DATA
            except SatochipException:
                return SW_CONDITIONS_NOT_SATISFIED
            except Exception:
                return SW_CONDITIONS_NOT_SATISFIED

        if ins == 0x02:
            return self._execute_streamed_ed25519_sign(p1, p2, data, chain='polkadot', is_solana=False)

        return SW_INS_NOT_SUPPORTED

    def _handle_near(self, ins: int, p1: int, p2: int, data: bytes) -> bytes:
        """NEAR: INS 0x02 (Version), INS 0x04 (Get Pubkey), INS 0x05 (Sign)"""
        if ins == 0x02:
            self._clear_signing_state()
            if p1 != 0 or p2 != 0 or data:
                return SW_WRONG_DATA
            return bytes([1, 2, 1]) + SW_OK

        if ins == 0x04:
            self._clear_signing_state()
            if p1 not in (P1_NON_CONFIRM, P1_CONFIRM) or p2 != 0:
                return SW_WRONG_DATA
            try:
                path = self._parse_ledger_path(data)
                self._validate_path_for_chain(path, "near")
                pubkey = self.card.slip10_get_extended_key(path)
                self.cached_path = path
                return pubkey + SW_OK
            except ValueError:
                return SW_WRONG_DATA
            except SatochipException:
                return SW_CONDITIONS_NOT_SATISFIED
            except Exception:
                return SW_CONDITIONS_NOT_SATISFIED

        if ins == 0x05:
            return self._execute_streamed_ed25519_sign(p1, p2, data, chain='near', is_solana=False)

        return SW_INS_NOT_SUPPORTED

    # -----------------------------------------------------------------
    # Unified Ed25519 Stream Reassembly & Signing Engine
    # -----------------------------------------------------------------

    def _execute_streamed_ed25519_sign(self, p1: int, p2: int, data: bytes,
                                       chain: str, is_solana: bool = False) -> bytes:
        """Unified stream reassembler & signer across all Ed25519 ledger apps."""
        if p1 not in (P1_NON_CONFIRM, P1_CONFIRM) or p2 & ~(P2_EXTEND | P2_MORE):
            self._clear_signing_state()
            return SW_WRONG_DATA

        is_extension = bool(p2 & P2_EXTEND)
        more_follows = bool(p2 & P2_MORE)

        try:
            if not is_extension:
                self._clear_signing_state()
                if not data:
                    return SW_WRONG_DATA

                # Solana prefixes path with num_paths=1 (1 byte)
                if is_solana:
                    if len(data) < 2 or data[0] != 1:
                        return SW_WRONG_DATA
                    path_size = 1 + data[1] * 4
                    path_end = 1 + path_size
                    if path_end > len(data):
                        return SW_WRONG_DATA
                    path = self._parse_ledger_path(data[1:path_end])
                    payload_bytes = data[path_end:]
                else:
                    # Generic Ed25519 format: [depth(1B) | path(4*depth) | tx_bytes...]
                    path, path_end = self._parse_ledger_path_prefix(data)
                    payload_bytes = data[path_end:]

                self._validate_path_for_chain(path, chain)

                # Stage key in J3R452 card and bind the stream to the returned
                # Ed25519 public key.  The final signature is verified against
                # this key before it is released to the host wallet.
                signing_pubkey = bytes(self.card.slip10_get_extended_key(path))
                if len(signing_pubkey) != 32:
                    raise ValueError("card returned an invalid Ed25519 public key")
                self.signing_path = path
                self.signing_pubkey = signing_pubkey
                self.signing_p1 = p1
                self.signing_chain = chain
                self.incoming_tx_buffer.extend(payload_bytes)
            else:
                if (self.signing_path is None or self.signing_chain != chain or
                        self.signing_p1 != p1):
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

            if not self.allow_blind_sign:
                self._clear_signing_state()
                return SW_SECURITY_STATUS

            message = bytes(self.incoming_tx_buffer)
            # Execute on-card hardware RFC 8032 Ed25519 signature
            signature = bytes(self.card.sign_ed25519_message(message))
            signing_pubkey = self.signing_pubkey
            if len(signature) != 64 or signing_pubkey is None or len(signing_pubkey) != 32:
                self._clear_signing_state()
                return SW_CONDITIONS_NOT_SATISFIED
            try:
                ed25519.Ed25519PublicKey.from_public_bytes(signing_pubkey).verify(signature, message)
            except Exception:
                # Never forward a signature that does not verify against the
                # key staged for this exact path and chain.
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
