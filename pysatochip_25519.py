"""Host client for the Satochip-J3R452-Curve25519 applet.

PC/SC dependencies are optional at import time so protocol and cryptographic
vector tests can run without a reader or pyscard installation.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import struct
from typing import List, Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

try:
    from smartcard.System import readers
    from smartcard.CardConnection import CardConnection
    from pysatochip.CardConnector import CardConnector
except ImportError:  # Offline use / tests; connect() reports the missing dependency.
    readers = None
    CardConnection = None
    CardConnector = None

CLA_SATOCHIP = 0xB0
INS_SLIP10_GET_EXTENDED_KEY = 0x6B
INS_SIGN_ED25519_MESSAGE = 0x70
INS_X25519_KEY_AGREEMENT = 0x68

SW_OK = 0x9000
SW_SLIP10_NON_HARDENED = 0x9C4D
SW_ED25519_UNINITIALIZED = 0x9C4E
SW_X25519_FAILURE = 0x9C4F
MAX_PATH_DEPTH = 10
MAX_SIGN_MESSAGE = 149  # SecureChannel.unwrap documents a 154-byte plaintext APDU limit.
MIN_SLIP10_SEED_LENGTH = 16
MAX_SLIP10_SEED_LENGTH = 64
ED25519_PUBLIC_PROOF_TAG = b"Satochip Ed25519 public key v1"
HMAC_FLAG_2FA = b"\x80\x00"
HMAC_PAD_ED25519 = b"\xce" * 32
HMAC_PAD_X25519 = b"\xcf" * 32
FIELD_P = (1 << 255) - 19


def parse_bip32_path(path_str: str) -> List[int]:
    """Parse a canonical, hardened SLIP-0010 path.

    Ed25519 SLIP-0010 has no public/non-hardened derivation. The textual parser
    requires an exact ``m`` root and rejects malformed/empty components.
    """
    if not isinstance(path_str, str) or (
        path_str != "m" and not path_str.startswith("m/")
    ):
        raise ValueError("path must start with the exact root prefix 'm'")
    if path_str != path_str.strip():
        raise ValueError("path must not contain outer whitespace")
    if path_str == "m":
        validate_path([])
        return []
    elements = path_str[2:].split('/')
    if not elements or any(not elem for elem in elements):
        raise ValueError("path contains an empty component")
    path = []
    for elem in elements:
        if not re.fullmatch(r"[0-9]+(?:['hH])", elem):
            raise ValueError(f"invalid hardened path component: {elem!r}")
        value = int(elem[:-1], 10)
        if value < 0 or value >= 0x80000000:
            raise ValueError(f"Path component out of range: {value}")
        path.append(value | 0x80000000)
    validate_path(path)
    return path


def validate_path(path: List[int]) -> None:
    if not 0 <= len(path) <= MAX_PATH_DEPTH:
        raise ValueError(f"Path depth must be 0..{MAX_PATH_DEPTH}")
    for index in path:
        if (isinstance(index, bool) or not isinstance(index, int)
                or not 0x80000000 <= index <= 0xFFFFFFFF):
            raise ValueError(f"SLIP-0010 Ed25519 requires a uint32 hardened index: {index!r}")


def slip10_path_bytes(path: List[int]) -> bytes:
    validate_path(path)
    return b''.join(struct.pack('>I', index) for index in path)


def ed25519_candidates_from_x25519(public_u: bytes) -> tuple[bytes, bytes]:
    """Recover the two compressed Edwards encodings corresponding to Montgomery u."""
    if len(public_u) != 32:
        raise ValueError("X25519 public key must be exactly 32 bytes")
    u = int.from_bytes(public_u, 'little')
    if u >= FIELD_P:
        raise ValueError("Non-canonical Montgomery u-coordinate")
    denominator = (u + 1) % FIELD_P
    if denominator == 0:
        raise ValueError("Montgomery u-coordinate has no Edwards conversion")
    y = ((u - 1) * pow(denominator, FIELD_P - 2, FIELD_P)) % FIELD_P
    encoded = bytearray(y.to_bytes(32, 'little'))
    candidate0 = bytes(encoded)
    encoded[31] |= 0x80
    return candidate0, bytes(encoded)


def _public_bytes(key) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def recover_ed25519_public_key(public_u: bytes, proof_message: bytes, proof_signature: bytes) -> bytes:
    if len(proof_signature) != 64:
        raise ValueError("Ed25519 proof signature must be 64 bytes")
    matches = []
    for candidate in ed25519_candidates_from_x25519(public_u):
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(candidate).verify(proof_signature, proof_message)
            matches.append(candidate)
        except Exception:
            pass
    if len(matches) != 1:
        raise ValueError("Could not uniquely verify the Ed25519 public-key proof")
    return matches[0]


class CardServiceWrapper:
    """Minimal CardConnector-compatible service wrapper."""
    def __init__(self, connection):
        self.connection = connection


class SatochipException(Exception):
    def __init__(self, message: str, sw: int = 0):
        super().__init__(f"{message} (SW={sw:04X})" if sw else message)
        self.sw = sw


class SatochipCard:
    """Satochip host client. It never silently creates or resets card state."""
    def __init__(self, reader_name: Optional[str] = None, pin: Optional[str] = None, seed: Optional[bytes] = None):
        if reader_name is not None and not isinstance(reader_name, str):
            raise ValueError("reader_name must be a string")
        if seed is not None:
            try:
                seed = memoryview(seed).tobytes()
            except Exception as exc:
                raise ValueError("seed must be bytes-like") from exc
            if not MIN_SLIP10_SEED_LENGTH <= len(seed) <= MAX_SLIP10_SEED_LENGTH:
                raise ValueError(
                    f"SLIP-0010 seed must be {MIN_SLIP10_SEED_LENGTH}.."
                    f"{MAX_SLIP10_SEED_LENGTH} bytes"
                )
        self.reader_name = reader_name
        self.pin = pin
        self.seed = seed
        self.connection = None
        self.connector: Optional[CardConnector] = None
        self.pin_verified = False
        self.needs_2fa = False
        self.is_seeded = False
        self.setup_done = False
        self.authentikey = None
        self.staged_public_key: Optional[bytes] = None

    def connect(self):
        """Connect to an already initialized card and establish a fresh secure channel.

        This method deliberately never imports/replaces a seed and never guesses a PIN
        or reader when doing so could select the wrong card.
        """
        if self.pin is None or not isinstance(self.pin, str) or not self.pin:
            raise SatochipException("A non-empty card PIN must be supplied explicitly")
        if readers is None or CardConnector is None:
            raise SatochipException("PC/SC and pysatochip dependencies are required for card access")
        available = readers()
        if not available:
            raise SatochipException("No PC/SC smartcard readers found")
        target = None
        names = [(reader, str(reader)) for reader in available]
        if self.reader_name:
            query = self.reader_name.casefold()
            exact = [reader for reader, name in names if name.casefold() == query]
            matches = exact or [reader for reader, name in names if query in name.casefold()]
            if len(matches) != 1:
                if not matches:
                    raise SatochipException(f"Requested reader not found: {self.reader_name}")
                raise SatochipException(
                    f"Reader selection is ambiguous for {self.reader_name!r}; use the full reader name"
                )
            target = matches[0]
        else:
            # Prefer the VPCD reader when it is uniquely identifiable.  This avoids
            # accidentally selecting a physical UICC/phone reader on test systems.
            virtual = [reader for reader, name in names
                       if "virtual smart card architecture virtual pcd" in name.casefold()
                       or "virtual pcd" in name.casefold()]
            if len(virtual) == 1:
                target = virtual[0]
            elif len(available) == 1:
                target = available[0]
            else:
                raise SatochipException(
                    "Multiple readers found; specify --reader using the exact reader name"
                )
        self.reader_name = str(target)

        # `connect()` is also the reconnect entry point used by the lazy
        # transmit path. Close any previous PC/SC session before replacing its
        # connector, otherwise a repeated connect can leak a reader handle and
        # leave the old connector's session-derived state alive. Do this only
        # after all selection/argument checks above have succeeded so a failed
        # reconnect attempt does not unnecessarily destroy a working session.
        if self.connection is not None or self.connector is not None:
            self.disconnect()

        try:
            self.connection = target.createConnection()
            protocol = CardConnection.T1_protocol if CardConnection is not None else None
            self.connection.connect(protocol) if protocol is not None else self.connection.connect()
            cc = CardConnector(None)
            if getattr(cc, 'cardmonitor', None):
                try:
                    cc.cardmonitor.deleteObserver(cc.cardobserver)
                except Exception:
                    pass
            cc.cardservice = CardServiceWrapper(self.connection)
            # CardConnector normally sets this while acquiring a CardRequest.
            # We deliberately use a caller-selected PC/SC connection instead,
            # so synchronize the flag before card_select/card_transmit.
            cc.card_present = True
            self.connector = cc
            self.authentikey = None

            _, sw1, sw2 = cc.card_select()
            if (sw1 << 8 | sw2) != SW_OK:
                raise SatochipException("Satochip applet selection failed", (sw1 << 8) | sw2)
            status, sw1, sw2, details = cc.card_get_status()
            sw = (sw1 << 8) | sw2
            if sw != SW_OK:
                raise SatochipException("Could not read card status", sw)
            self.setup_done = bool(details.get('setup_done'))
            self.is_seeded = bool(details.get('is_seeded'))
            self.needs_2fa = bool(details.get('needs2FA'))
            if not self.setup_done:
                raise SatochipException("Card is not set up; refusing implicit setup")

            cc.needs_secure_channel = True
            cc.card_initiate_secure_channel()
            result = cc.card_verify_PIN(self.pin)
            if not isinstance(result, tuple) or len(result) < 3:
                raise SatochipException("PIN verification did not return a status")
            _, sw1, sw2 = result[:3]
            if (sw1 << 8 | sw2) != SW_OK:
                raise SatochipException("PIN verification failed", (sw1 << 8) | sw2)
            self.pin_verified = True

            if self.seed is not None and not self.is_seeded:
                # Never import a seed as a side effect of connect().  A caller that
                # supplied a seed may use it for post-derivation verification only.
                raise SatochipException(
                    "Card has no seed; refusing implicit seed import during connect()"
                )
        except Exception:
            self.disconnect()
            raise

    def disconnect(self):
        """Close the current PC/SC session and erase all session-derived state.

        ``setup_done``/``is_seeded``/``needs_2fa`` describe the previous card
        session, not a durable host-side capability.  Keeping them after a
        removal/reconnect could make callers skip safety checks or misapply a
        2FA policy to a different card, so every disconnect returns the object
        to a neutral state.
        """
        connector = self.connector
        if connector is not None:
            # CardConnector caches the PIN after card_verify_PIN(). Clear that
            # host-side copy before dropping the connector object.
            try:
                connector.pin = None
                connector.pin_nbr = None
                connector.sc = None
                connector.card_present = False
            except Exception:
                pass
        if self.connection is not None:
            try:
                self.connection.disconnect()
            except Exception:
                pass
        self.connection = None
        self.connector = None
        self.pin_verified = False
        self.needs_2fa = False
        self.is_seeded = False
        self.setup_done = False
        self.authentikey = None
        self.staged_public_key = None

    def _ensure_connected(self):
        if self.connector is None or self.connection is None:
            self.connect()

    def _transmit(self, ins: int, p1: int, p2: int, payload: bytes) -> bytes:
        payload = bytes(payload)
        if not 0 <= len(payload) <= 255:
            raise ValueError("Satochip short APDU payload must be 0..255 bytes")
        if not all(0 <= value <= 0xFF for value in (ins, p1, p2)):
            raise ValueError("APDU instruction and parameters must be one-byte values")
        self._ensure_connected()
        apdu = [CLA_SATOCHIP, ins, p1, p2, len(payload), *payload]
        response, sw1, sw2 = self.connector.card_transmit(apdu)
        sw = (sw1 << 8) | sw2
        if sw != SW_OK:
            raise SatochipException(f"Satochip command 0x{ins:02X} failed", sw)
        return bytes(response)

    def _twofa_payload(self, value: bytes, pad: bytes, twofa_response: Optional[bytes]) -> bytes:
        if len(value) != 32 or len(pad) != 32:
            raise ValueError("2FA operation value and pad must each be 32 bytes")
        needs_2fa = bool(self.needs_2fa or getattr(self.connector, 'needs_2FA', False))
        if not needs_2fa:
            if twofa_response is not None:
                raise ValueError("A 2FA response was supplied but the card does not require 2FA")
            return value
        if twofa_response is None or len(twofa_response) != 20:
            raise SatochipException("This operation requires a 20-byte 2FA approval")
        return value + HMAC_FLAG_2FA + bytes(twofa_response)

    def derive_slip10_pubkey(self, path_indices: List[int]) -> bytes:
        """Host reference derivation; requires the seed explicitly supplied by caller."""
        if self.seed is None:
            raise SatochipException("A seed is required for host-side reference derivation")
        validate_path(path_indices)
        digest = hmac.new(b"ed25519 seed", self.seed, hashlib.sha512).digest()
        key, chain = digest[:32], digest[32:]
        for index in path_indices:
            digest = hmac.new(chain, b"\x00" + key + struct.pack('>I', index), hashlib.sha512).digest()
            key, chain = digest[:32], digest[32:]
        return _public_bytes(ed25519.Ed25519PrivateKey.from_private_bytes(key).public_key())

    def _sign_ed25519_message_unbound(
        self, message: bytes, twofa_response: Optional[bytes] = None
    ) -> bytes:
        """Sign only the internal P2=02 public-key proof.

        P2=02 intentionally stages a private key before its Edwards public key
        has been recovered.  Keep that exception private to the derivation
        flow; callers must use the pairwise-bound public method below.
        """
        return self._sign_ed25519_message(message, twofa_response, require_staged=False)

    def sign_ed25519_message(self, message: bytes, twofa_response: Optional[bytes] = None) -> bytes:
        """Sign a message only after the staged Ed25519 key is pairwise bound."""
        if self.staged_public_key is None:
            raise SatochipException(
                "No pairwise-verified Ed25519 key is staged",
                SW_ED25519_UNINITIALIZED,
            )
        return self._sign_ed25519_message(message, twofa_response, require_staged=True)

    def _sign_ed25519_message(
        self,
        message: bytes,
        twofa_response: Optional[bytes],
        require_staged: bool,
    ) -> bytes:
        try:
            message = memoryview(message).tobytes()
        except TypeError as exc:
            raise ValueError("Message must be bytes-like") from exc
        if not 1 <= len(message) <= MAX_SIGN_MESSAGE:
            raise ValueError(f"Message must be 1..{MAX_SIGN_MESSAGE} bytes")
        self._ensure_connected()
        command_started = False
        try:
            payload = message
            needs_2fa = bool(self.needs_2fa or getattr(self.connector, 'needs_2FA', False))
            if needs_2fa:
                if len(message) > MAX_SIGN_MESSAGE - 22:
                    raise ValueError("2FA-protected signing allows at most 127 message bytes")
                digest = hashlib.sha256(message).digest()
                payload += self._twofa_payload(digest, HMAC_PAD_ED25519, twofa_response)[32:]
            elif twofa_response is not None:
                raise ValueError("A 2FA response was supplied but the card does not require 2FA")
            command_started = True
            response = self._transmit(INS_SIGN_ED25519_MESSAGE, 0xFF, 0x00, payload)
            if len(response) != 64:
                raise SatochipException(f"Unexpected Ed25519 signature length: {len(response)}")
            if require_staged:
                if self.staged_public_key is None or len(self.staged_public_key) != 32:
                    raise SatochipException("Pairwise public key state is malformed")
                try:
                    ed25519.Ed25519PublicKey.from_public_bytes(self.staged_public_key).verify(
                        response, message
                    )
                except Exception as verify_error:
                    raise SatochipException(
                        "Card returned an Ed25519 signature that fails pairwise verification"
                    ) from verify_error
            return response
        except Exception as exc:
            if command_started:
                # Do not leave a staged private key usable after a card/native
                # fault, transport error, or invalid signature response.
                self.disconnect()
            if isinstance(exc, SatochipException):
                raise
            raise

    def _verify_authentikey_signed_response(self, response: bytes, signed_length: int) -> None:
        """Verify [signed_data | sig_len | DER ECDSA signature] from the applet.

        The original Satochip client treats the Authentikey signature as the binding between a
        response and the selected card. The Curve25519 extension must preserve that invariant;
        parsing only the public value would allow an untrusted transport/card shim to substitute
        derived data without detection.
        """
        response = bytes(response)
        if (isinstance(signed_length, bool) or not isinstance(signed_length, int)
                or signed_length < 0 or len(response) < signed_length + 2):
            raise SatochipException("Malformed Authentikey-signed response")
        sig_length = int.from_bytes(response[signed_length:signed_length + 2], "big")
        sig_start = signed_length + 2
        sig_end = sig_start + sig_length
        if sig_length == 0 or sig_end != len(response):
            raise SatochipException("Malformed Authentikey signature envelope")
        self._ensure_connected()
        if self.authentikey is None:
            self.authentikey = self.connector.card_bip32_get_authentikey()
        if self.authentikey is None:
            raise SatochipException("Card Authentikey is unavailable")
        try:
            self.connector.parser.verify_signature(
                response[:signed_length], response[sig_start:sig_end], self.authentikey
            )
        except Exception as exc:
            raise SatochipException("Invalid Authentikey signature on card response") from exc

    def slip10_get_extended_key(self, path: Union[str, List[int]],
                                twofa_response: Optional[bytes] = None) -> bytes:
        """Derive/stage an Ed25519 key and recover its public key with on-card proof."""
        path_list = parse_bip32_path(path) if isinstance(path, str) else list(path)
        path_bytes = slip10_path_bytes(path_list)
        self._ensure_connected()
        operation_started = False
        try:
            # P2=02 returns the Montgomery u-coordinate derived from the same SLIP-0010 child.
            # The applet clears its pairwise public key for this intermediate
            # operation; mirror that state before the proof signature below.
            self.staged_public_key = None
            operation_started = True
            response = self._transmit(INS_SLIP10_GET_EXTENDED_KEY, len(path_list), 0x02, path_bytes)
            if len(response) < 66 or response[32:34] != b"\x00\x20":
                raise SatochipException("Malformed X25519 public-key response")
            self._verify_authentikey_signed_response(response, 66)
            public_u = response[34:66]
            proof_message = ED25519_PUBLIC_PROOF_TAG + path_bytes + public_u
            proof_signature = self._sign_ed25519_message_unbound(proof_message, twofa_response)
            pubkey = recover_ed25519_public_key(public_u, proof_message, proof_signature)

            if self.seed is not None:
                expected = self.derive_slip10_pubkey(path_list)
                if not hmac.compare_digest(pubkey, expected):
                    raise SatochipException("Card-derived Ed25519 key does not match the supplied seed")

            # Re-stage with the recovered Ed key so every later signature receives pairwise verify.
            path_and_pubkey = path_bytes + pubkey
            operation_started = True
            response = self._transmit(INS_SLIP10_GET_EXTENDED_KEY, len(path_list), 0x01, path_and_pubkey)
            if len(response) < 66 or response[32:34] != b"\x00\x20" or response[34:66] != pubkey:
                raise SatochipException("Malformed Ed25519 key-staging response")
            self._verify_authentikey_signed_response(response, 66)
            self.staged_public_key = bytes(pubkey)
            return pubkey
        except Exception:
            # P2=02 stages a private key before the host has authenticated the
            # Ed25519 public key. A failed proof, seed check, or P2=01 restage
            # must terminate the PC/SC session so the applet's deselect cleanup
            # removes that unbound key before any later signing call.
            if operation_started:
                self.disconnect()
            raise

    def x25519_key_agreement(self, remote_public_key: bytes,
                             twofa_response: Optional[bytes] = None) -> bytes:
        """Use the currently staged SLIP-0010 key for X25519 key agreement."""
        if self.staged_public_key is None:
            raise SatochipException(
                "No pairwise-verified Ed25519 key is staged",
                SW_ED25519_UNINITIALIZED,
            )
        if len(self.staged_public_key) != 32:
            raise SatochipException("Pairwise public key state is malformed")
        try:
            remote_public_key = memoryview(remote_public_key).tobytes()
        except TypeError as exc:
            raise ValueError("Remote X25519 public key must be bytes-like") from exc
        if len(remote_public_key) != 32:
            raise ValueError("Remote X25519 public key must be exactly 32 bytes")
        self._ensure_connected()
        command_started = False
        try:
            payload = remote_public_key
            if self.needs_2fa or getattr(self.connector, 'needs_2FA', False):
                payload = self._twofa_payload(remote_public_key, HMAC_PAD_X25519, twofa_response)
            elif twofa_response is not None:
                raise ValueError("A 2FA response was supplied but the card does not require 2FA")
            command_started = True
            result = self._transmit(INS_X25519_KEY_AGREEMENT, 0xFF, 0x00, payload)
            if len(result) != 32 or not any(result):
                raise SatochipException("Invalid X25519 shared-secret response", SW_X25519_FAILURE)
            return result
        except Exception:
            if command_started:
                self.disconnect()
            raise
