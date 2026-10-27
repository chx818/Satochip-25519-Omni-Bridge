# Satochip-25519-Omni-Bridge

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![WebHID](https://img.shields.io/badge/WebHID-Ledger%20Nano%20S-green.svg)](https://developer.mozilla.org/en-US/docs/Web/API/WebHID_API)
[![Windows USB/IP](https://img.shields.io/badge/Windows-usbip--win2-blueviolet.svg)](https://github.com/vadimgrn/usbip-win2)
[![License](https://img.shields.io/badge/License-LGPL--3.0-orange.svg)](https://www.gnu.org/licenses/lgpl-3.0.html)

> **Driverless Windows WebHID Virtual Ledger Nano S Bridge & Multi-Chain Driver for Satochip-25519 Smart Cards.**  
>
> 🌐 **Language**: [English (Current)](README.md) | [中文 (Chinese)](README.zh-CN.md)  
> 💳 **On-Card Firmware**: [Satochip-25519-Applet](https://github.com/chx818/Satochip-25519-Applet)  
> 📄 **Protocol Specification**: [Protocol Specification Whitepaper](https://github.com/chx818/Satochip-25519-Applet/blob/master/SPECIFICATION-Curve25519.en.md)  

---

> [!TIP]
> **Support this Project / Purchase Pre-Flushed Hardware Cards**:  
> If you are based in China or have access to payment methods supported on Chinese e-commerce platforms, consider purchasing our affordable, ready-to-use, all-in-one smart card to support development! Built on **NXP J3R452**, it integrates **FIDO2 + PIV + OpenPGP + OTP + Satochip + Seedkeeper**, priced at only **¥119 (~$18 USD)**.  
> 🛒 **Order Link**: [Taobao (item.taobao.com)](https://item.taobao.com/item.htm?ft=t&id=1087207954892)

---

## Overview

**`Satochip-25519-Omni-Bridge`** is an experimental, local-loopback compatibility suite. It emulates a standard **Ledger Nano S** (`VID: 0x2C97, PID: 0x0001`, UsagePage: `0xFFA0`) at the Windows kernel level via USB/IP, transparently converting WebHID requests from major Web3 wallets into native APDU commands for smart cards running [**`Satochip-25519-Applet`**](https://github.com/chx818/Satochip-25519-Applet).

Supported Ed25519 / SLIP-0010 blockchains:
* **Solana (SOL)**: BIP44 `501'` (Phantom, Solflare, OKX)
* **TON (The Open Network)**: BIP44 `607'` (Tonkeeper, MyTonWallet)
* **Sui (SUI)**: BIP44 `784'` (Sui Wallet, Suiet)
* **Aptos (APT)**: BIP44 `637'` (Petra, Pontem)
* **Polkadot (DOT / KSM)**: BIP44 `354'` (Polkadot.js, SubWallet)
* **Near Protocol (NEAR)**: BIP44 `397'` (Near Wallet, Meteor)

> [!NOTE]
> **Project & Compatibility Notice**: This is an experimental, community-maintained software compatibility bridge for Satochip smart cards, not a physical Ledger device. Like the original Satochip project, key derivation uses software HMAC-SHA512. Wallets communicate with the bridge via standard WebHID interfaces. Blind signing is disabled by default (`--allow-blind-sign` required to enable).

---

## Architecture & Topology

```
Browser Web3 Wallet (Phantom / Tonkeeper / Sui / Polkadot.js)
                             │
                             ▼ (WebHID: VID 0x2C97, UsagePage 0xFFA0)
            [ Windows hidusb.sys in-box Driver ]
                             │
            [ usbip-win2 Virtual Host Controller ]
                             │ (TCP: 127.0.0.1:3240, Loopback only)
                             ▼
            [ virtual_ledger_usbip_daemon.py ]
              ├── HID 64-byte Packet Reassembly
              └── Loopback Socket Isolation
                             │
                             ▼
            [ ledger_ed25519_omni_translator.py ]
              ├── Multi-Chain Routing Engine (SOL/TON/SUI/APT/DOT/NEAR)
              ├── Hardened Path Validation & Stream Isolation
              └── Verify-Before-Release Signature Guard
                             │
                             ▼ (PC/SC WinSCard + SecureChannel)
            [ pysatochip_25519.py ]
              ├── Authentikey ECDSA Signature Verification
              └── Montgomery-to-Edwards Birational Inversion
                             │
                             ▼ (ISO 7816-4)
            [ NXP J3R452 Card (Satochip-25519-Applet) ]
```

---

## Key Features & Design Principles

1. **Local Loopback Isolation**: The daemon binds strictly to `127.0.0.1`. Remote and non-loopback network connections are rejected at initialization to ensure all APDU and USB/IP communication remains on the local machine.
2. **Explicit Blind Signing Control**: Because virtual bridges lack a dedicated hardware display screen, blind signing is disabled by default. When disabled, unverified signing requests return `SW_SECURITY_STATUS` (`0x6982`).
3. **Client-Side Pairwise Verification**: Before any Ed25519 signature is released to WebHID clients, both the translator and the underlying `pysatochip_25519` driver verify the 64-byte signature mathematically against the staged Edwards public key via RFC 8032.
4. **Fail-Safe Session Teardown**: If a card error, transport fault, or invalid low-order X25519 peer key occurs, the PC/SC session is immediately terminated. This forces the card OS to deselect the applet, wiping transient RAM private keys and preventing stale staged keys from lingering.
5. **Standard USB HID State Machine**: Implements complete USB device and HID control transfer handling (`SET_ADDRESS`, `SET_CONFIGURATION`, `GET_STATUS`, `GET_CONFIGURATION`, `GET_INTERFACE`, `SET_INTERFACE`, `SET_IDLE`, `SET_PROTOCOL`, and a dedicated `DESCRIPTOR_HID` 0x21). This ensures reliable, driverless plug-and-play enumeration on Windows via `hidusb.sys`.
6. **Authentikey Public Key Verification**: Public keys and chaincodes exported via `0x6B` are cryptographically certified by the card's internal Authentikey ECDSA signature, verified by the host driver to confirm card identity.
7. **Multi-Packet Stream Consistency**: Multi-packet APDU streams (`P2_EXTEND`) are strictly bound to the initial chain profile, derivation path, and P1 parameter. Any intervening command, out-of-order chunk, or cross-chain request resets the signing buffer.
8. **Credential & Buffer Hygiene**: Sensitive transaction payloads, card PINs, and session references are scrubbed from memory immediately upon signature completion, error abort, or daemon shutdown.

---

## Installation & Setup

### 1. Install Python Dependencies

```powershell
# Clone the repository
git clone https://github.com/chx818/Satochip-25519-Omni-Bridge.git
cd Satochip-25519-Omni-Bridge

# Install requirements and package
pip install -r requirements.txt
pip install -e .
```

### 2. Install `usbip-win2` Kernel Driver (One-Time Setup)

The virtual USB controller requires `usbip-win2` (WHQL digitally signed):

```powershell
# Using Windows Package Manager:
winget install -e --id vadimgrn.usbip-win2
```
Or download the installer from [vadimgrn/usbip-win2 Releases](https://github.com/vadimgrn/usbip-win2/releases).

---

## Usage Guide

### Inspect Card Status & Derive Addresses

```powershell
# Query card status and Curve25519 engine readiness:
python satochip_cli_25519.py --status

# One-click address derivation for Solana, TON, and Sui:
python satochip_cli_25519.py --derive-all
```
*(PIN is prompted securely via a hidden password prompt)*

### Start Virtual Ledger Bridge

Run the batch launcher:

```cmd
start_virtual_ledger.bat
```

1. Enter your card PIN in the dedicated daemon prompt (cached only in host session memory).
2. The launcher automatically probes `127.0.0.1:3240` until the card SecureChannel is established, then executes `usbip attach`.
3. Open Windows **Device Manager** $\to$ **Human Interface Devices** to confirm `Ledger Nano S` is mounted!
4. Launch a supported wallet and select its Ledger/WebHID integration. This bridge has no trusted display, so transaction approval is not visually verified by the card; blind signing remains disabled unless you explicitly opt in with `--allow-blind-sign`.

To stop the bridge and detach virtual devices:

```cmd
stop_virtual_ledger.bat
```

---

## Test Suite & Verification

The repository includes comprehensive offline protocol tests and non-destructive smart card integration checks:

```powershell
# Run protocol boundary, USB/IP framing, and Authentikey verification tests (36 unit tests):
python -m unittest -v test_security_boundaries.py test_usbip_protocol.py test_authentikey_response.py

# Run universal 6-chain translation & RFC 8032 math verification:
python test_omni_pipeline.py

# Run non-destructive live smart card integration test (requires card in reader):
# Set your PIN via environment variable or enter it at the hidden prompt:
$env:SATOCHIP_TEST_PIN="1234"
python test_live_card_full.py
```

---

## Project Structure

| File | Purpose |
| :--- | :--- |
| [`ledger_ed25519_omni_translator.py`](ledger_ed25519_omni_translator.py) | Universal 6-chain Ledger APDU router & stream state machine |
| [`pysatochip_25519.py`](pysatochip_25519.py) | Low-level PC/SC driver, Authentikey verification & X25519 inversion |
| [`virtual_ledger_usbip_daemon.py`](virtual_ledger_usbip_daemon.py) | Loopback-only USB/IP daemon & HID 64-byte packet framer |
| [`satochip_cli_25519.py`](satochip_cli_25519.py) | Multi-chain hardware card management CLI |
| [`start_virtual_ledger.bat`](start_virtual_ledger.bat) | Safe launcher with port polling and USB attachment |
| [`stop_virtual_ledger.bat`](stop_virtual_ledger.bat) | Script to detach virtual device and stop services |
| [`test_security_boundaries.py`](test_security_boundaries.py) | Regression tests for path validation, blind signing & buffer bounds |
| [`test_usbip_protocol.py`](test_usbip_protocol.py) | USB descriptor, IPv4 loopback & URB handling unit tests |
| [`test_omni_pipeline.py`](test_omni_pipeline.py) | Full 6-chain offline emulation with mathematical verification |
| [`test_live_card_full.py`](test_live_card_full.py) | Non-destructive live smart card integration test |

---

## License

This software is released under the **GNU Lesser General Public License v3.0 (LGPL-3.0)**.  
See [`LICENSE`](https://www.gnu.org/licenses/lgpl-3.0.html) for details.
