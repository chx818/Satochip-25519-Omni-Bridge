"""test_bridge_pipeline.py
Unit tests for the Ledger WebHID framer and Solana APDU translator pipeline.
Uses an offline MockSatochipCard matching RFC 8032 and SLIP-0010 vectors.
"""
import struct
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from ledger_solana_translator import LedgerHIDFramer, LedgerSolanaTranslator

ED25519_SEED = b"ed25519 seed"

def slip10_derive_child(parent_key: bytes, parent_chaincode: bytes, index: int):
    data = b"\x00" + parent_key + struct.pack(">I", index)
    I = hmac.new(parent_chaincode, data, hashlib.sha512).digest()
    return I[:32], I[32:]

def slip10_derive_path(seed: bytes, path: list):
    I = hmac.new(ED25519_SEED, seed, hashlib.sha512).digest()
    k, c = I[:32], I[32:]
    for idx in path:
        k, c = slip10_derive_child(k, c, idx)
    return k, c


class MockSatochipCard:
    """Mock Satochip Card simulating on-card Curve25519 hardware operations."""
    def __init__(self):
        self.seed = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        )
        self.cached_priv_key = None
        self.cached_pub_key = None

    def slip10_get_extended_key(self, path: list) -> bytes:
        k, _ = slip10_derive_path(self.seed, path)
        self.cached_priv_key = k
        ed_priv = ed25519.Ed25519PrivateKey.from_private_bytes(k)
        self.cached_pub_key = ed_priv.public_key().public_bytes_raw()
        return self.cached_pub_key

    def sign_ed25519_message(self, message: bytes) -> bytes:
        if not self.cached_priv_key:
            raise RuntimeError("Key not initialized")
        ed_priv = ed25519.Ed25519PrivateKey.from_private_bytes(self.cached_priv_key)
        return ed_priv.sign(message)


def test_pipeline():
    print("=== Testing Ledger <-> Satochip Translation Pipeline ===")
    mock_card = MockSatochipCard()
    framer = LedgerHIDFramer()
    translator = LedgerSolanaTranslator(mock_card, allow_blind_sign=True)

    # 1. Test GET_APP_AND_VERSION (0xB0 0x01)
    req_apdu = bytes([0xB0, 0x01, 0x00, 0x00, 0x00])
    packets = framer.frame_response(req_apdu)
    assert len(packets) == 1
    assert len(packets[0]) == 64

    # Deframe as if host sent it to emulator
    received_apdu = framer.feed_packet(packets[0])
    assert received_apdu == req_apdu

    # Translate
    resp_apdu = translator.handle_apdu(received_apdu)
    print(f"1. GET_APP_AND_VERSION -> Response: {resp_apdu.hex()}")
    assert b"Solana" in resp_apdu
    assert resp_apdu.endswith(b"\x90\x00")
    print("   [PASS] Wallet successfully detects Ledger 'Solana' app is open!")

    # 2. Test GET_PUBKEY (0xE0 0x05) for m/44'/501'/0'/0'
    path_bytes = bytes([
        4, # depth = 4
        0x80, 0x00, 0x00, 44,
        0x80, 0x00, 0x01, 245, # 501
        0x80, 0x00, 0x00, 0,
        0x80, 0x00, 0x00, 0
    ])
    req_pubkey_apdu = bytes([0xE0, 0x05, 0x00, 0x00, len(path_bytes)]) + path_bytes
    resp_pubkey = translator.handle_apdu(req_pubkey_apdu)
    print(f"2. GET_PUBKEY -> Response: {resp_pubkey.hex()}")
    assert resp_pubkey.endswith(b"\x90\x00")
    pubkey = resp_pubkey[:-2]
    assert len(pubkey) == 32
    print(f"   [PASS] Derived Solana Public Key: {pubkey.hex()}")

    # 3. Test SIGN_MESSAGE (0xE0 0x06)
    test_tx = b"Solana serialized transaction dummy payload: transfer 1.5 SOL to Bob"
    sign_payload = bytes([1]) + path_bytes + test_tx
    req_sign_apdu = bytes([0xE0, 0x06, 0x00, 0x00, len(sign_payload)]) + sign_payload

    # Frame into Ledger WebHID chunks
    sign_packets = framer.frame_response(req_sign_apdu)
    print(f"   Framed into {len(sign_packets)} HID packets (64 bytes each)")

    # Feed chunks to framer
    reassembled_apdu = None
    for pkt in sign_packets:
        res = framer.feed_packet(pkt)
        if res is not None:
            reassembled_apdu = res

    assert reassembled_apdu == req_sign_apdu
    resp_sign = translator.handle_apdu(reassembled_apdu)
    print(f"3. SIGN_MESSAGE -> Response: {resp_sign.hex()}")
    assert resp_sign.endswith(b"\x90\x00")
    sig = resp_sign[:-2]
    assert len(sig) == 64
    print(f"   [PASS] 64-byte Ed25519 signature generated: {sig.hex()[:32]}...{sig.hex()[-32:]}")

    # Verify signature locally with cryptography
    ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(pubkey)
    ed_pub.verify(sig, test_tx)
    print("   [PASS] Signature mathematically verified!")
    print("=== All Pipeline Unit Tests Passed Successfully! ===\n")

if __name__ == '__main__':
    test_pipeline()
