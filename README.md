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
> **Compatibility Notice**: This is a local compatibility bridge, not a physical Ledger device and not officially certified by Ledger SAS. Wallets interact through standard WebHID interfaces. Users must test and verify behavior against specific wallet versions, browser updates, and network environments.

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

## Security Model & Protective Boundaries

1. **Strict IPv4 Loopback Binding**: The daemon binds strictly to `127.0.0.1`. IPv6 and non-loopback addresses are rejected at initialization to prevent LAN exposure.
2. **Fail-Closed Blind Signing**: Because virtual bridges lack a dedicated trusted display screen, `--allow-blind-sign` is disabled by default. When disabled, unverified signing requests are rejected with `SW_SECURITY_STATUS` (`0x6982`).
3. **Verify-Before-Release Guard**: The bridge mathematically verifies on-card Ed25519 signatures locally against the staged public key before releasing them to WebHID.
4. **Continuation Stream Isolation**: Multi-packet signing streams (`P2_EXTEND`) are bound to the specific chain, derivation path, and P1 parameter of the initial packet. Any out-of-order or cross-chain packets immediately abort the session and zero out the buffer.
5. **Authentikey Identity Binding**: Every derived public key and chaincode exported by the card is cryptographically certified by an on-card Authentikey signature, validated by `pysatochip_25519.py` to defeat man-in-the-middle tampering.
6. **Zero Memory Residue**: Sensitive transaction payload buffers are explicitly zeroed out in memory immediately after signing or upon any error condition.

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
4. Launch Chrome, open **Phantom**, **Tonkeeper**, or **Sui Wallet**, select **"Connect Hardware Wallet $\to$ Ledger"**, and approve transactions natively.

To stop the bridge and detach virtual devices:

```cmd
stop_virtual_ledger.bat
```

---

## Test Suite & Verification

The repository contains an exhaustive offline and live hardware test suite:

```powershell
# Run security boundaries, USB/IP framing, and Authentikey anti-tamper unit tests:
python -m unittest -v test_security_boundaries.py test_usbip_protocol.py test_authentikey_response.py

# Run universal 6-chain translation & RFC 8032 math verification:
python test_omni_pipeline.py

# Run legacy single-chain pipeline verification:
python test_bridge_pipeline.py

# Run non-destructive live card integration test (requires card in reader):
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
