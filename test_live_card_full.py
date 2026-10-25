"""Non-destructive VPCD integration test for the modified Satochip applet.

The test only performs SELECT/status, SecureChannel + PIN verification,
SLIP-0010 derivation/staging, signatures, X25519 agreement, and a read-only
secp256k1 derivation.  It never calls setup, seed import/reset, lock, factory
reset, terminate, or any permanent policy operation.

PIN is read from SATOCHIP_TEST_PIN or a hidden prompt.  Reader selection is
SATOCHIP_TEST_READER or the client's strict VPCD/unique-reader selection.
"""
import getpass
import os
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pysatochip_25519 import SatochipCard, SatochipException

FIELD_P = (1 << 255) - 19


def _montgomery_u_from_ed25519(public_key: bytes) -> bytes:
    if len(public_key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    y = int.from_bytes(public_key, "little") & ((1 << 255) - 1)
    denominator = (1 - y) % FIELD_P
    if denominator == 0:
        raise ValueError("Ed25519 point cannot be converted to Montgomery u")
    u = ((1 + y) * pow(denominator, FIELD_P - 2, FIELD_P)) % FIELD_P
    return u.to_bytes(32, "little")

SOLANA_PATH = "m/44'/501'/0'/0'"


def _required_pin() -> str:
    value = os.environ.get("SATOCHIP_TEST_PIN")
    if value is not None:
        if not value:
            raise RuntimeError("SATOCHIP_TEST_PIN is set but empty")
        return value
    return getpass.getpass("Satochip test-card PIN (hidden): ")


def run_live_test() -> bool:
    print("=" * 68)
    print("  Non-destructive Satochip-J3R452 Curve25519 VPCD test")
    print("=" * 68)
    card = SatochipCard(
        reader_name=os.environ.get("SATOCHIP_TEST_READER"),
        pin=_required_pin(),
    )
    try:
        print("[1] SELECT + status + SecureChannel + PIN...")
        card.connect()
        print("    PASS: initialized card session established")

        print(f"[2] Derive/stage {SOLANA_PATH} with Authentikey verification...")
        sol_pubkey = card.slip10_get_extended_key(SOLANA_PATH)
        print(f"    PASS: Ed25519 public key {sol_pubkey.hex()}")

        message = b"Satochip-J3R452 non-destructive VPCD audit"
        print("[3] Sign and verify with RFC 8032 Ed25519...")
        signature = card.sign_ed25519_message(message)
        ed25519.Ed25519PublicKey.from_public_bytes(sol_pubkey).verify(signature, message)
        print("    PASS: 64-byte signature verifies")

        print("[4] X25519 agreement against an independently generated peer...")
        peer_private = x25519.X25519PrivateKey.generate()
        peer_public = peer_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        card_secret = card.x25519_key_agreement(peer_public)
        card_u = _montgomery_u_from_ed25519(sol_pubkey)
        expected_secret = peer_private.exchange(x25519.X25519PublicKey.from_public_bytes(card_u))
        if card_secret != expected_secret:
            raise RuntimeError("card X25519 result does not match RFC 7748 host computation")
        print("    PASS: shared secret matches independent RFC 7748 computation")
        try:
            card.x25519_key_agreement(b"\x00" * 32)
        except SatochipException:
            print("    PASS: all-zero low-order peer is rejected")
        else:
            raise RuntimeError("card accepted an all-zero X25519 peer key")

        print("[5] Read-only secp256k1 BIP32 compatibility...")
        eth_pub, _ = card.connector.card_bip32_get_extendedkey("m/44'/60'/0'/0/0")
        encoded = eth_pub.get_public_key_bytes(compressed=True)
        if len(encoded) != 33:
            raise RuntimeError("unexpected compressed secp256k1 public-key length")
        print(f"    PASS: compressed public key {encoded.hex()}")
        print("\nALL NON-DESTRUCTIVE VPCD CHECKS PASSED")
        return True
    finally:
        card.disconnect()


if __name__ == "__main__":
    try:
        ok = run_live_test()
    except Exception as exc:
        print(f"LIVE TEST FAILED: {exc}", file=sys.stderr)
        ok = False
    raise SystemExit(0 if ok else 1)
