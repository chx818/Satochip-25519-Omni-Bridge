"""test_omni_pipeline.py
Unit tests verifying Universal Ledger Ed25519 Omni-Translator across all 6 chains:
- Solana (SOL)
- TON (The Open Network)
- Sui (SUI)
- Aptos (APT)
- Polkadot (DOT)
- Near (NEAR)
"""

import struct
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from ledger_ed25519_omni_translator import (
    LedgerHIDFramer,
    LedgerOmni25519Translator,
    SW_OK
)

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
    """Mock Satochip Card simulating on-card Curve25519 operations."""
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

def encode_path_apdu(path: list) -> bytes:
    buf = bytearray([len(path)])
    for idx in path:
        buf.extend(struct.pack(">I", idx))
    return bytes(buf)

def run_test():
    print("=" * 70)
    print(" TESTING UNIVERSAL LEDGER ED25519 OMNI-TRANSLATOR (6 CHAINS)")
    print("=" * 70)

    mock_card = MockSatochipCard()
    framer = LedgerHIDFramer()
    translator = LedgerOmni25519Translator(mock_card, default_chain="solana", allow_blind_sign=True)

    # -------------------------------------------------------------
    # 1. Solana (m/44'/501'/0'/0')
    # -------------------------------------------------------------
    print("\n[1] Testing Solana (Phantom / Solflare)")
    sol_path = [0x8000002C, 0x800001F5, 0x80000000, 0x80000000]
    sol_path_bytes = encode_path_apdu(sol_path)

    # 1.1 App handshake
    resp = translator.handle_apdu(bytes([0xB0, 0x01, 0x00, 0x00, 0x00]))
    assert b"Solana" in resp and resp.endswith(SW_OK)
    print("  [OK] App Name -> 'Solana' (v1.4.1)")

    # 1.2 Get Pubkey (CLA 0xE0, INS 0x05)
    resp = translator.handle_apdu(bytes([0xE0, 0x05, 0x00, 0x00, len(sol_path_bytes)]) + sol_path_bytes)
    assert resp.endswith(SW_OK)
    sol_pub = resp[:-2]
    assert len(sol_pub) == 32
    print(f"  [OK] Solana Pubkey: {sol_pub.hex()[:16]}...")

    # 1.3 Sign TX (CLA 0xE0, INS 0x06)
    sol_tx = b"Transfer 2.5 SOL from Alice to Bob on Solana Mainnet"
    sol_payload = bytes([1]) + sol_path_bytes + sol_tx
    resp = translator.handle_apdu(bytes([0xE0, 0x06, 0x00, 0x00, len(sol_payload)]) + sol_payload)
    assert resp.endswith(SW_OK)
    sol_sig = resp[:-2]
    assert len(sol_sig) == 64
    ed25519.Ed25519PublicKey.from_public_bytes(sol_pub).verify(sol_sig, sol_tx)
    print(f"  [OK] Solana Ed25519 Signature Verified 100%!")

    # -------------------------------------------------------------
    # 2. TON (m/44'/607'/0')
    # -------------------------------------------------------------
    print("\n[2] Testing TON (Tonkeeper / MyTonWallet)")
    ton_path = [0x8000002C, 0x8000025F, 0x80000000]
    ton_path_bytes = encode_path_apdu(ton_path)

    # 2.1 Get Pubkey (CLA 0xE0, INS 0x02)
    resp = translator.handle_apdu(bytes([0xE0, 0x02, 0x00, 0x00, len(ton_path_bytes)]) + ton_path_bytes)
    assert resp.endswith(SW_OK)
    ton_pub = resp[:-2]
    assert len(ton_pub) == 32
    print(f"  [OK] TON Pubkey: {ton_pub.hex()[:16]}...")

    # 2.2 Sign TX (CLA 0xE0, INS 0x03)
    ton_tx = b"TON Transfer message: 50 TON to EQCGScrZe... via Tonkeeper"
    ton_payload = ton_path_bytes + ton_tx
    resp = translator.handle_apdu(bytes([0xE0, 0x03, 0x00, 0x00, len(ton_payload)]) + ton_payload)
    assert resp.endswith(SW_OK)
    ton_sig = resp[:-2]
    assert len(ton_sig) == 64
    ed25519.Ed25519PublicKey.from_public_bytes(ton_pub).verify(ton_sig, ton_tx)
    print(f"  [OK] TON Ed25519 Signature Verified 100%!")

    # 2.3 Handshake after auto-switch
    resp = translator.handle_apdu(bytes([0xB0, 0x01, 0x00, 0x00, 0x00]))
    assert b"Ton" in resp and resp.endswith(SW_OK)
    print("  [OK] Auto-switched App Name -> 'Ton' (v1.0.3)")

    # -------------------------------------------------------------
    # 3. Sui (m/44'/784'/0'/0'/0')
    # -------------------------------------------------------------
    print("\n[3] Testing Sui (Sui Wallet / Suiet)")
    sui_path = [0x8000002C, 0x80000310, 0x80000000, 0x80000000, 0x80000000]
    sui_path_bytes = encode_path_apdu(sui_path)

    # 3.1 Get Version (CLA 0x00, INS 0x01)
    resp = translator.handle_apdu(bytes([0x00, 0x01, 0x00, 0x00, 0x00]))
    assert resp.endswith(SW_OK) and resp[:-2] == bytes([0, 4, 1])
    print("  [OK] Sui Version -> 0.4.1")

    # 3.2 Get Pubkey (CLA 0x00, INS 0x02)
    resp = translator.handle_apdu(bytes([0x00, 0x02, 0x00, 0x00, len(sui_path_bytes)]) + sui_path_bytes)
    assert resp.endswith(SW_OK)
    sui_pub = resp[:-2]
    assert len(sui_pub) == 32
    print(f"  [OK] Sui Pubkey: {sui_pub.hex()[:16]}...")

    # 3.3 Sign TX (CLA 0x00, INS 0x03)
    sui_tx = b"Sui BCS TransactionData bytes (Transfer 10 SUI)"
    sui_payload = sui_path_bytes + sui_tx
    resp = translator.handle_apdu(bytes([0x00, 0x03, 0x00, 0x00, len(sui_payload)]) + sui_payload)
    assert resp.endswith(SW_OK)
    sui_sig = resp[:-2]
    assert len(sui_sig) == 64
    ed25519.Ed25519PublicKey.from_public_bytes(sui_pub).verify(sui_sig, sui_tx)
    print(f"  [OK] Sui Ed25519 Signature Verified 100%!")

    # -------------------------------------------------------------
    # 4. Aptos (m/44'/637'/0'/0'/0')
    # -------------------------------------------------------------
    print("\n[4] Testing Aptos (Petra / Pontem)")
    apt_path = [0x8000002C, 0x8000027D, 0x80000000, 0x80000000, 0x80000000]
    apt_path_bytes = encode_path_apdu(apt_path)

    # 4.1 Get Version (CLA 0x5B, INS 0x01)
    resp = translator.handle_apdu(bytes([0x5B, 0x01, 0x00, 0x00, 0x00]))
    assert resp.endswith(SW_OK) and resp[:-2] == bytes([0, 5, 2])
    print("  [OK] Aptos Version -> 0.5.2")

    # 4.2 Get Pubkey (CLA 0x5B, INS 0x02)
    resp = translator.handle_apdu(bytes([0x5B, 0x02, 0x00, 0x00, len(apt_path_bytes)]) + apt_path_bytes)
    assert resp.endswith(SW_OK)
    apt_pub = resp[:-2]
    assert len(apt_pub) == 32
    print(f"  [OK] Aptos Pubkey: {apt_pub.hex()[:16]}...")

    # 4.3 Sign TX (CLA 0x5B, INS 0x03)
    apt_tx = b"Aptos BCS RawTransaction payload: transfer 5 APT"
    apt_payload = apt_path_bytes + apt_tx
    resp = translator.handle_apdu(bytes([0x5B, 0x03, 0x00, 0x00, len(apt_payload)]) + apt_payload)
    assert resp.endswith(SW_OK)
    apt_sig = resp[:-2]
    assert len(apt_sig) == 64
    ed25519.Ed25519PublicKey.from_public_bytes(apt_pub).verify(apt_sig, apt_tx)
    print(f"  [OK] Aptos Ed25519 Signature Verified 100%!")

    # -------------------------------------------------------------
    # 5. Polkadot (m/44'/354'/0'/0'/0')
    # -------------------------------------------------------------
    print("\n[5] Testing Polkadot (Polkadot.js / SubWallet)")
    dot_path = [0x8000002C, 0x80000162, 0x80000000, 0x80000000, 0x80000000]
    dot_path_bytes = encode_path_apdu(dot_path)

    # 5.1 Get Version (CLA 0xF9, INS 0x00)
    resp = translator.handle_apdu(bytes([0xF9, 0x00, 0x00, 0x00, 0x00]))
    assert resp.endswith(SW_OK) and resp[:-2] == bytes([0, 100, 0, 1])
    print("  [OK] Polkadot Version -> 100.0.1")

    # 5.2 Get Pubkey (CLA 0xF9, INS 0x01)
    resp = translator.handle_apdu(bytes([0xF9, 0x01, 0x00, 0x00, len(dot_path_bytes)]) + dot_path_bytes)
    assert resp.endswith(SW_OK)
    dot_pub = resp[:-2]
    assert len(dot_pub) == 32
    print(f"  [OK] Polkadot Pubkey: {dot_pub.hex()[:16]}...")

    # 5.3 Sign TX (CLA 0xF9, INS 0x02)
    dot_tx = b"Polkadot Extrinsic payload: balances.transferKeepAlive(10 DOT)"
    dot_payload = dot_path_bytes + dot_tx
    resp = translator.handle_apdu(bytes([0xF9, 0x02, 0x00, 0x00, len(dot_payload)]) + dot_payload)
    assert resp.endswith(SW_OK)
    dot_sig = resp[:-2]
    assert len(dot_sig) == 64
    ed25519.Ed25519PublicKey.from_public_bytes(dot_pub).verify(dot_sig, dot_tx)
    print(f"  [OK] Polkadot Ed25519 Signature Verified 100%!")

    # -------------------------------------------------------------
    # 6. Near (m/44'/397'/0')
    # -------------------------------------------------------------
    print("\n[6] Testing Near Protocol (Near Wallet / Meteor)")
    near_path = [0x8000002C, 0x8000018D, 0x80000000]
    near_path_bytes = encode_path_apdu(near_path)

    # 6.1 Get Version (CLA 0x24, INS 0x02)
    resp = translator.handle_apdu(bytes([0x24, 0x02, 0x00, 0x00, 0x00]))
    assert resp.endswith(SW_OK) and resp[:-2] == bytes([1, 2, 1])
    print("  [OK] Near Version -> 1.2.1")

    # 6.2 Get Pubkey (CLA 0x24, INS 0x04)
    resp = translator.handle_apdu(bytes([0x24, 0x04, 0x00, 0x00, len(near_path_bytes)]) + near_path_bytes)
    assert resp.endswith(SW_OK)
    near_pub = resp[:-2]
    assert len(near_pub) == 32
    print(f"  [OK] Near Pubkey: {near_pub.hex()[:16]}...")

    # 6.3 Sign TX (CLA 0x24, INS 0x05)
    near_tx = b"Near Borsh Transaction: transfer 20 NEAR to alice.near"
    near_payload = near_path_bytes + near_tx
    resp = translator.handle_apdu(bytes([0x24, 0x05, 0x00, 0x00, len(near_payload)]) + near_payload)
    assert resp.endswith(SW_OK)
    near_sig = resp[:-2]
    assert len(near_sig) == 64
    ed25519.Ed25519PublicKey.from_public_bytes(near_pub).verify(near_sig, near_tx)
    print(f"  [OK] Near Ed25519 Signature Verified 100%!")

    # -------------------------------------------------------------
    # 7. Multi-Frame WebHID Reassembly Test (Streaming)
    # -------------------------------------------------------------
    print("\n[7] Testing 64-byte WebHID Stream Framing (Transport Layer)")
    raw_apdu = bytes([0xE0, 0x05, 0x00, 0x00, len(sol_path_bytes)]) + sol_path_bytes
    packets = framer.frame_response(raw_apdu)
    assert len(packets) >= 1
    assert all(len(p) == 64 for p in packets)

    reassembled = None
    for p in packets:
        res = framer.feed_packet(p)
        if res is not None:
            reassembled = res

    assert reassembled == raw_apdu
    print(f"  [OK] Successfully framed & reassembled {len(raw_apdu)} bytes across {len(packets)} HID frames!")

    print("\n" + "=" * 70)
    print(" ALL 6 ED25519 CHAIN TESTS PASSED 100% (MATHEMATICAL VERIFICATION OK)")
    print("=" * 70)

if __name__ == '__main__':
    run_test()
