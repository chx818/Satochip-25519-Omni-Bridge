"""satochip_cli_25519.py
Card management CLI for Satochip-J3R452-Curve25519.
Allows querying card status, PIN management, and deriving addresses across
Solana, Bitcoin, Ethereum, TON, and Sui.
"""
import sys
import argparse
import getpass
import hashlib
from typing import Optional
from pysatochip_25519 import SatochipCard, SatochipException, parse_bip32_path

# Standard Base58 alphabet
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(data: bytes) -> str:
    origlen = len(data)
    data = data.lstrip(b'\x00')
    newlen = len(data)
    acc = int.from_bytes(data, byteorder='big')
    result = []
    while acc > 0:
        acc, mod = divmod(acc, 58)
        result.append(B58_ALPHABET[mod])
    return (B58_ALPHABET[0] * (origlen - newlen)) + ''.join(reversed(result))


def main():
    parser = argparse.ArgumentParser(description="Satochip-J3R452 Multi-Chain Card Management CLI")
    parser.add_argument("--reader", "-r", type=str, default=None, help="Exact reader name (substring accepted only when unique)")
    parser.add_argument("--status", "-s", action="store_true", help="Query and display card status")
    parser.add_argument("--pin", "-p", type=str, default=None, help="Card PIN for authentication")
    parser.add_argument("--derive-solana", action="store_true", help="Derive Solana address (m/44'/501'/0'/0')")
    parser.add_argument("--derive-all", action="store_true", help="Derive addresses for SOL, TON, Sui")
    parser.add_argument("--test-sign", action="store_true", help="Perform on-card Ed25519 test signature")
    args = parser.parse_args()

    print("==================================================================")
    print(" Satochip-25519-J3R452 Multi-Chain Hardware Management CLI")
    print("==================================================================")

    pin = args.pin if args.pin is not None else getpass.getpass("Card PIN: ")
    if not pin:
        print("[!] A non-empty PIN is required; no card command was sent.")
        return 2
    card = SatochipCard(reader_name=args.reader, pin=pin)
    try:
        card.connect()
    except Exception as e:
        print(f"[!] PC/SC Connection error: {e}")
        print("    Please ensure your smartcard reader is connected and the card is inserted.")
        return 1

    try:
        raw_resp, sw1, sw2, d = card.connector.card_get_status()
        print(f"[+] Connected to reader: {card.reader_name}")
        print(f"[+] Satochip Applet Selected & SecureChannel Established!")
        if len(raw_resp) >= 4:
            print(f"    Protocol Version: v{raw_resp[0]}.{raw_resp[1]}")
            print(f"    Applet Version:   v{raw_resp[2]}.{raw_resp[3]}")
        if len(raw_resp) >= 8:
            print(f"    PIN Tries Left:   {raw_resp[6]}")
            print(f"    PUK Tries Left:   {raw_resp[7]}")
        if len(raw_resp) >= 19:
            # The status byte is applet-specific; do not infer hardware
            # acceleration from an undocumented fixed offset.
            print(f"    Curve25519 feature byte: 0x{raw_resp[18]:02x} (informational; not a certification claim)")
        print("------------------------------------------------------------------")

        if args.derive_solana or args.derive_all:
            sol_path = "m/44'/501'/0'/0'"
            print(f"[*] Deriving Solana Extended Key ({sol_path})...")
            try:
                sol_pubkey = card.slip10_get_extended_key(sol_path)
                sol_addr = b58encode(sol_pubkey)
                print(f"    Public Key (Hex): {sol_pubkey.hex()}")
                print(f"    Solana Address:   {sol_addr}")
            except Exception as e:
                print(f"    [!] Error deriving Solana key: {e}")

        if args.derive_all:
            # TON Path: m/44'/607'/0'
            ton_path = "m/44'/607'/0'"
            print(f"[*] Deriving TON Extended Key ({ton_path})...")
            try:
                ton_pubkey = card.slip10_get_extended_key(ton_path)
                print(f"    Public Key (Hex): {ton_pubkey.hex()}")
            except Exception as e:
                print(f"    [!] Error deriving TON key: {e}")

            # Sui Path: m/44'/784'/0'/0'/0'
            sui_path = "m/44'/784'/0'/0'/0'"
            print(f"[*] Deriving Sui Extended Key ({sui_path})...")
            try:
                sui_pubkey = card.slip10_get_extended_key(sui_path)
                # Sui address: blake2b-256 of (flag_byte 0x00 + pubkey), truncated to 32 bytes
                sui_flag_pub = b"\x00" + sui_pubkey
                sui_addr = hashlib.blake2b(sui_flag_pub, digest_size=32).hexdigest()
                print(f"    Public Key (Hex): {sui_pubkey.hex()}")
                print(f"    Sui ID / Hash:    0x{sui_addr}")
            except Exception as e:
                print(f"    [!] Error deriving Sui key: {e}")

        if args.test_sign:
            print("[*] Running On-Card Ed25519 Signature Test...")
            test_msg = b"Satochip-J3R452 Hardware Ed25519 signature test"
            try:
                # Stage key on card first (Solana standard path)
                card.slip10_get_extended_key("m/44'/501'/0'/0'")
                sig = card.sign_ed25519_message(test_msg)
                print(f"[+] Signature successfully generated by the initialized card!")
                print(f"    Signature (64 bytes): {sig.hex()}")
            except Exception as e:
                print(f"[!] Signature failed: {e}")

    finally:
        card.disconnect()

    print("==================================================================")
    return 0

if __name__ == '__main__':
    sys.exit(main())
