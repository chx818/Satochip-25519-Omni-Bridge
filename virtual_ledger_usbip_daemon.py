"""virtual_ledger_usbip_daemon.py
Virtual USB Ledger Nano S Daemon using USB/IP protocol on Windows.
Simulates a genuine Ledger device (VID: 0x2C97, PID: 0x0001) over USB/IP.
Bridges incoming WebHID reports directly to Satochip-J3R452 via PC/SC.
"""
import sys
import argparse
import getpass
import ipaddress
import socket
import struct
import threading
import queue
from typing import Optional
from ledger_ed25519_omni_translator import LedgerHIDFramer, LedgerOmni25519Translator
from pysatochip_25519 import SatochipCard

# USB Standard Constants
USB_DT_DEVICE = 0x01
USB_DT_CONFIG = 0x02
USB_DT_STRING = 0x03
USB_DT_INTERFACE = 0x04
USB_DT_ENDPOINT = 0x05
USB_DT_HID = 0x21
USB_DT_REPORT = 0x22

# USB/IP Command Codes
USBIP_CMD_SUBMIT = 0x0001
USBIP_CMD_UNLINK = 0x0002
USBIP_RET_SUBMIT = 0x0003
USBIP_RET_UNLINK = 0x0004

OP_REQ_DEVLIST = 0x8005
OP_REP_DEVLIST = 0x0005
OP_REQ_IMPORT = 0x8003
OP_REP_IMPORT = 0x0003

# Descriptors for Ledger Nano S
DESCRIPTOR_DEVICE = struct.pack(
    "<BBHBBBBHHHBBBB",
    18,                 # bLength
    USB_DT_DEVICE,      # bDescriptorType
    0x0200,             # bcdUSB (USB 2.0)
    0x00,               # bDeviceClass
    0x00,               # bDeviceSubClass
    0x00,               # bDeviceProtocol
    64,                 # bMaxPacketSize0
    0x2C97,             # idVendor (Ledger SAS)
    0x0001,             # idProduct (Ledger Nano S)
    0x0100,             # bcdDevice (1.00)
    1,                  # iManufacturer
    2,                  # iProduct
    3,                  # iSerialNumber
    1                   # bNumConfigurations
)

DESCRIPTOR_REPORT = bytes([
    0x06, 0xa0, 0xff, # Usage Page (Vendor Defined 0xFFA0)
    0x09, 0x01,       # Usage (0x01)
    0xa1, 0x01,       # Collection (Application)
    0x09, 0x02,       #   Usage (0x02) - Input Report
    0x15, 0x00,       #   Logical Min (0)
    0x26, 0xff, 0x00, #   Logical Max (255)
    0x75, 0x08,       #   Report Size (8 bits)
    0x95, 0x40,       #   Report Count (64 bytes)
    0x81, 0x02,       #   Input (Data, Var, Abs)
    0x09, 0x03,       #   Usage (0x03) - Output Report
    0x15, 0x00,       #   Logical Min (0)
    0x26, 0xff, 0x00, #   Logical Max (255)
    0x75, 0x08,       #   Report Size (8 bits)
    0x95, 0x40,       #   Report Count (64 bytes)
    0x91, 0x02,       #   Output (Data, Var, Abs)
    0xc0              # End Collection
])

# Configuration + Interface + HID + Endpoints (Total length: 41 bytes)
DESCRIPTOR_CONFIG = (
    struct.pack("<BBHBBBBB", 9, USB_DT_CONFIG, 41, 1, 1, 0, 0x80, 50) +   # Config
    struct.pack("<BBBBBBBBB", 9, USB_DT_INTERFACE, 0, 0, 2, 3, 0, 0, 0) + # Interface (Class 3 HID)
    struct.pack("<BBHBBBH", 9, USB_DT_HID, 0x0111, 0, 1, USB_DT_REPORT, len(DESCRIPTOR_REPORT)) + # HID
    struct.pack("<BBBBHB", 7, USB_DT_ENDPOINT, 0x81, 0x03, 64, 1) +        # EP 0x81 (Interrupt IN)
    struct.pack("<BBBBHB", 7, USB_DT_ENDPOINT, 0x02, 0x03, 64, 1)          # EP 0x02 (Interrupt OUT)
)
# The HID descriptor is embedded immediately after the device and interface
# descriptors in the configuration descriptor. Keep a named copy because
# Windows HID enumeration commonly requests it separately (GET_DESCRIPTOR,
# type 0x21), rather than reading it only as part of the full configuration.
DESCRIPTOR_HID = DESCRIPTOR_CONFIG[18:27]

STRINGS = {
    0: struct.pack("<BBH", 4, USB_DT_STRING, 0x0409), # English
    1: b"\x0e\x03" + "Ledger".encode("utf-16le"),
    2: b"\x0e\x03" + "Nano S".encode("utf-16le"),
    3: b"\x0a\x03" + "0001".encode("utf-16le"),
}


class VirtualLedgerUSBIPServer:
    def __init__(self, port: int = 3240, host: str = "127.0.0.1", card_pin: Optional[str] = None,
                 reader_name: Optional[str] = None, seed: Optional[bytes] = None,
                 allow_blind_sign: bool = False, default_chain: str = "solana"):
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("USB/IP port must be an integer in 1..65535")
        if not isinstance(host, str) or not host:
            raise ValueError("USB/IP listener host must be a non-empty string")
        self.port = port
        self.host = host
        try:
            # The implementation deliberately binds AF_INET below.  Reject
            # explicit IPv6 loopback instead of accepting it and failing later
            # with a misleading bind/address-family error.  Also require every
            # IPv4 resolution result to remain loopback-only (no DNS rebinding
            # or accidental LAN exposure).
            addresses = {
                item[4][0]
                for item in socket.getaddrinfo(
                    host, None, family=socket.AF_INET, type=socket.SOCK_STREAM
                )
            }
        except OSError as exc:
            raise ValueError(f"could not resolve USB/IP listener address: {exc}") from exc
        if not addresses or any(not ipaddress.ip_address(address).is_loopback
                                for address in addresses):
            raise ValueError('USB/IP listener must bind only to an IPv4 loopback address')
        if card_pin is None or not str(card_pin):
            raise ValueError("card_pin must be supplied explicitly")
        self.card_pin = str(card_pin)
        self.reader_name = reader_name
        self.seed = seed
        self.running = False
        self.card = None
        self.translator = None
        self.framer = LedgerHIDFramer()
        self.in_reports_queue = queue.Queue(maxsize=32)
        self.import_lock = threading.Lock()
        self.allow_blind_sign = allow_blind_sign
        self.default_chain = default_chain
        # Minimal USB device state needed by standard enumeration requests.
        # These values are per imported USB session and are reset whenever the
        # client attaches/detaches, just like a physical device would be.
        self.device_address = 0
        self.configuration = 0
        self.interface_alt_setting = 0
        self.hid_protocol = 1  # report protocol; the interface has no boot protocol

    def init_card(self):
        print("[+] Connecting to Satochip Card on reader:", self.reader_name)
        self.card = SatochipCard(reader_name=self.reader_name, pin=self.card_pin, seed=self.seed)
        # Fail closed. A virtual device without the real card must never claim Ledger support.
        self.card.connect()
        print("[+] Connected to card, PIN verified, and SecureChannel established!")
        self.translator = LedgerOmni25519Translator(self.card, default_chain=self.default_chain, allow_blind_sign=self.allow_blind_sign)
        print(f"[+] Universal Ed25519 Omni-Bridge ready! (Default App: {self.default_chain.capitalize()})")
        print("    Auto-routes: Solana, TON, Sui, Aptos, Polkadot, Near")
        if not self.allow_blind_sign:
            print("[!] Blind signing is disabled: this bridge has no trusted display/confirmation UI.")

    def start(self):
        self.init_card()
        self.running = True
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, self.port))
                sock.listen(5)
                print(f"[*] Virtual Ledger USB/IP server listening on {self.host}:{self.port}")
                print("    Use usbip attach -r 127.0.0.1 -b 1-1 for a local Windows attachment.")
                while self.running:
                    try:
                        conn, addr = sock.accept()
                        threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
                    except Exception as e:
                        if self.running:
                            print(f"[!] Server accept error: {e}")
                        break
        finally:
            self.running = False
            if self.card is not None:
                self.card.disconnect()
                self.card.pin = None
            # Do not retain the daemon's PIN or optional host-side seed after
            # the listener has stopped. The virtual device is not reusable
            # after shutdown and must be recreated with explicit credentials.
            self.card_pin = None
            self.seed = None
            self.translator = None
            self.card = None

    @staticmethod
    def recv_exact(conn: socket.socket, length: int) -> Optional[bytes]:
        if length < 0 or length > 65536:
            return None
        chunks = bytearray()
        while len(chunks) < length:
            part = conn.recv(length - len(chunks))
            if not part:
                return None
            chunks.extend(part)
        return bytes(chunks)

    def handle_client(self, conn: socket.socket, addr):
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            while self.running:
                header = self.recv_exact(conn, 4)
                if header is None:
                    break
                version, opcode = struct.unpack(">HH", header)

                if opcode == OP_REQ_DEVLIST:
                    status_bytes = self.recv_exact(conn, 4)
                    if status_bytes is None:
                        break
                    status = struct.unpack(">I", status_bytes)[0]
                    if version != 0x0111 or status != 0:
                        self.send_devlist(conn, success=False)
                    else:
                        self.send_devlist(conn, success=True)
                elif opcode == OP_REQ_IMPORT:
                    status_bytes = self.recv_exact(conn, 4)
                    busid_raw = self.recv_exact(conn, 32)
                    if status_bytes is None or busid_raw is None:
                        break
                    status = struct.unpack(">I", status_bytes)[0]
                    busid = busid_raw.rstrip(b"\x00")
                    if version != 0x0111 or status != 0 or busid != b"1-1":
                        self.send_import(conn, success=False)
                        break
                    if not self.import_lock.acquire(blocking=False):
                        self.send_import(conn, success=False)
                        break
                    self.send_import(conn, success=True)
                    self._reset_usb_session()
                    try:
                        self.handle_urbs(conn)
                    finally:
                        self._reset_usb_session()
                        self.import_lock.release()
                    break
        except Exception as e:
            pass
        finally:
            conn.close()

    @staticmethod
    def _usb_device_descriptor() -> bytes:
        path = b"/sys/devices/virtual/usb/1-1".ljust(256, b"\x00")
        busid = b"1-1".ljust(32, b"\x00")
        return struct.pack(
            ">256s32sIIIHHHBBBBBB",
            path, busid,
            1, 1, 3,                         # busnum, devnum, speed
            0x2C97, 0x0001, 0x0100,          # vendor, product, bcdDevice
            0x00, 0x00, 0x00,                # device class/subclass/protocol
            1, 1, 1                          # configuration value/count, interfaces
        )

    def send_devlist(self, conn: socket.socket, success: bool = True):
        # OP_REP_DEVLIST: version(2), opcode(2), status(4), nExportedDevice(4)
        rep = struct.pack(">HHII", 0x0111, OP_REP_DEVLIST, 0 if success else 1,
                          1 if success else 0)
        if not success:
            conn.sendall(rep)
            return
        # One usbip_usb_device followed by one usbip_usb_interface.
        intf_info = struct.pack(">BBBB", 0x03, 0x00, 0x00, 0x00)  # HID
        conn.sendall(rep + self._usb_device_descriptor() + intf_info)

    def send_import(self, conn: socket.socket, success: bool):
        # OP_REP_IMPORT
        rep = struct.pack(">HHI", 0x0111, OP_REP_IMPORT, 0 if success else 1)
        if not success:
            conn.sendall(rep)
            return
        path = b"/sys/devices/virtual/usb/1-1".ljust(256, b"\x00")
        busid_bytes = b"1-1".ljust(32, b"\x00")
        # OP_REP_IMPORT returns exactly one usbip_usb_device (312 bytes),
        # without the interface records used by OP_REP_DEVLIST.
        conn.sendall(rep + self._usb_device_descriptor())

    def handle_urbs(self, conn: socket.socket):
        """Handle USB Request Blocks (URB) from Windows USB/IP driver."""
        while self.running:
            basic = self.recv_exact(conn, 20)
            if basic is None:
                break
            command, seqnum, devid, direction, ep = struct.unpack(">IIIII", basic)

            if command == USBIP_CMD_SUBMIT:
                submit_body = self.recv_exact(conn, 28)
                if submit_body is None:
                    break
                transfer_flags, transfer_buffer_length, start_frame, number_of_packets, interval, setup = \
                    struct.unpack(">IIiii8s", submit_body)
                # Direction: 0 = OUT, 1 = IN.  The imported device is bus 1,
                # device 1, and this implementation has no isochronous URBs.
                out_data = b""
                if (devid != 0x00010001 or ep > 0xFF or direction not in (0, 1)
                        or transfer_buffer_length > 4096
                        or number_of_packets not in (-1, 0)):
                    break
                if direction == 0 and transfer_buffer_length > 0:
                    out_data = self.recv_exact(conn, transfer_buffer_length)
                    if out_data is None:
                        break

                status = 0
                resp_data = b""
                actual_length = 0
                ep_number = ep & 0x7F
                if ep_number == 0:
                    # Control transfers use the bmRequestType direction bit too.
                    request_is_in = bool(setup[0] & 0x80)
                    if request_is_in != bool(direction):
                        status = -22  # -EINVAL
                    elif direction == 1:
                        resp_data = self.handle_control_transfer(setup, transfer_buffer_length)
                        actual_length = len(resp_data)
                    else:
                        # For a control OUT URB, the payload length must agree
                        # with wLength.  Reject mismatches instead of silently
                        # accepting bytes that the setup packet did not request.
                        if transfer_buffer_length != struct.unpack_from("<H", setup, 6)[0]:
                            status = -22  # -EINVAL
                        else:
                            # Standard SET_* requests have no response payload.
                            # The setup request has already been consumed above.
                            self.handle_control_transfer(setup, transfer_buffer_length)
                            actual_length = len(out_data)

                elif ep_number == 2 and direction == 0:
                    # Interrupt OUT - one complete 64-byte Ledger HID report.
                    if transfer_buffer_length != 64 or len(out_data) != 64:
                        status = -22
                    else:
                        self.process_incoming_report(out_data)
                        actual_length = len(out_data)

                elif ep_number == 1 and direction == 1:
                    # Interrupt IN - the advertised Ledger HID report is one
                    # complete 64-byte report. Never truncate it into a short
                    # HID frame or accept a buffer too small to carry it.
                    if transfer_buffer_length != 64:
                        status = -22
                    else:
                        resp_data = self.get_outgoing_report(64)
                        actual_length = len(resp_data)

                else:
                    status = -32  # -EPIPE / unsupported endpoint

                # USB/IP ret_submit has a 20-byte common header followed by
                # five signed 32-bit fields and an 8-byte setup echo.
                ret_hdr = struct.pack(
                    ">IIIIIiiiii8s",
                    USBIP_RET_SUBMIT, seqnum, devid, direction, ep,
                    status, actual_length, start_frame, number_of_packets, 0,
                    setup
                )
                conn.sendall(ret_hdr + (resp_data if direction == 1 else b""))

            elif command == USBIP_CMD_UNLINK:
                unlink_data = self.recv_exact(conn, 28)
                if unlink_data is None:
                    break
                # There are no asynchronous URBs in this bridge.  Consume the
                # request, then acknowledge it while preserving the common-header
                # identity fields expected by usbip clients.
                ret_hdr = struct.pack(
                    ">IIIIIi24s", USBIP_RET_UNLINK, seqnum, devid, direction, ep,
                    0, b"\x00" * 24
                )
                conn.sendall(ret_hdr)
            else:
                break

    def handle_control_transfer(self, setup: bytes, req_len: int) -> bytes:
        if len(setup) != 8 or req_len < 0 or req_len > 4096:
            return b""
        bmRequestType, bRequest, wValue, wIndex, wLength = struct.unpack("<BBHHH", setup)
        limit = min(req_len, wLength)
        request_type = bmRequestType & 0x60
        recipient = bmRequestType & 0x1F
        request_is_in = bool(bmRequestType & 0x80)

        if request_type == 0x00:
            # Standard device/interface requests used during HID enumeration.
            if not request_is_in:
                if bRequest == 0x05:  # SET_ADDRESS
                    if (recipient != 0 or wIndex != 0 or wLength != 0
                            or wValue > 127):
                        return b""
                    self.device_address = wValue
                    return b""
                if bRequest == 0x09:  # SET_CONFIGURATION
                    if (recipient != 0 or wIndex != 0 or wLength != 0
                            or wValue not in (0, 1)):
                        return b""
                    self.configuration = wValue
                    if wValue == 0:
                        self.interface_alt_setting = 0
                    return b""
                if bRequest == 0x0B:  # SET_INTERFACE
                    if (recipient != 1 or wIndex != 0 or wValue != 0
                            or wLength != 0 or self.configuration != 1):
                        return b""
                    self.interface_alt_setting = 0
                    return b""
                return b""

            if bRequest == 0x00:  # GET_STATUS
                if (wValue != 0 or wLength != 2
                        or recipient not in (0, 1, 2)):
                    return b""
                # Device, interface, and the two interrupt endpoints have no
                # feature bits set (no remote wakeup, halt, or self power).
                return b"\x00\x00"[:limit]
            if bRequest == 0x08:  # GET_CONFIGURATION
                if recipient != 0 or wValue != 0 or wIndex != 0 or wLength != 1:
                    return b""
                return bytes((self.configuration,))[:limit]
            if bRequest == 0x0A:  # GET_INTERFACE
                if (recipient != 1 or wValue != 0 or wIndex != 0
                        or wLength != 1 or self.configuration != 1):
                    return b""
                return bytes((self.interface_alt_setting,))[:limit]

            if bRequest != 0x06:  # GET_DESCRIPTOR
                return b""

            desc_type = (wValue >> 8) & 0xFF
            desc_index = wValue & 0xFF
            if desc_type == USB_DT_DEVICE:
                if recipient != 0 or wIndex != 0:
                    return b""
                value = DESCRIPTOR_DEVICE
            elif desc_type == USB_DT_CONFIG:
                if recipient != 0 or wIndex != 0:
                    return b""
                value = DESCRIPTOR_CONFIG
            elif desc_type == USB_DT_STRING:
                if recipient != 0 or desc_index not in STRINGS:
                    return b""
                # A host may request the language-specific string table with
                # either wIndex=0 or the advertised English LANGID.
                if wIndex not in (0, 0x0409):
                    return b""
                value = STRINGS[desc_index]
            elif desc_type == USB_DT_HID:
                if recipient != 1 or desc_index != 0 or wIndex != 0:
                    return b""
                value = DESCRIPTOR_HID
            elif desc_type == USB_DT_REPORT:
                if recipient != 1 or desc_index != 0 or wIndex != 0:
                    return b""
                value = DESCRIPTOR_REPORT
            else:
                return b""
            return value[:limit]

        # HID class requests that do not carry a response payload.
        if request_type == 0x20 and not request_is_in and bRequest in (0x0A, 0x0B):
            if recipient != 1 or wIndex != 0 or wLength != 0:
                return b""
            if bRequest == 0x0A:  # SET_IDLE: high byte is duration, low is ID
                if (wValue & 0xFF) != 0:
                    return b""
            else:  # SET_PROTOCOL: 0=boot, 1=report; this interface is report-only
                if wValue not in (0, 1):
                    return b""
                self.hid_protocol = wValue
            return b""
        if request_type == 0x20 and request_is_in and bRequest in (0x01, 0x02):
            # GET_REPORT/GET_IDLE are not needed by Ledger clients. Do not
            # fabricate report contents or expose state for an unimplemented
            # class request; return an empty data stage instead.
            return b""
        return b""

    def process_incoming_report(self, report_bytes: bytes):
        apdu = self.framer.feed_packet(report_bytes)
        if apdu:
            # Never log command/response payloads: Solana messages and signatures are sensitive.
            try:
                resp_apdu = self.translator.handle_apdu(apdu)
            except Exception:
                resp_apdu = b"\x6f\x00"
            pkts = self.framer.frame_response(resp_apdu)
            for packet in pkts:
                try:
                    self.in_reports_queue.put_nowait(packet)
                except queue.Full:
                    self._reset_usb_session()
                    return

    def get_outgoing_report(self, max_len: int) -> bytes:
        # A Ledger HID report is exactly 64 bytes. Returning a truncated
        # report would make the USB/IP transport emit a malformed HID frame;
        # reject undersized IN buffers at the URB boundary instead.
        if max_len != 64:
            return b""
        try:
            pkt = self.in_reports_queue.get(timeout=0.1)
            if len(pkt) != 64:
                self._reset_usb_session()
                return b""
            return pkt
        except queue.Empty:
            return b""

    def _reset_usb_session(self):
        self.framer.reset()
        while True:
            try:
                self.in_reports_queue.get_nowait()
            except queue.Empty:
                break
        if self.translator is not None:
            self.translator._clear_signing_state()
            self.translator.cached_path = []
        self.device_address = 0
        self.configuration = 0
        self.interface_alt_setting = 0
        self.hid_protocol = 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Universal Satochip-to-Ledger Ed25519 Omni-Bridge "
                    "(SOL/TON/SUI/APT/DOT/NEAR)"
    )
    parser.add_argument("--pin", default=None,
                        help="Card PIN (avoid this option when possible; prompted securely if omitted)")
    parser.add_argument("--reader", default=None, help="Exact/substring PC/SC reader selection")
    parser.add_argument("--host", default="127.0.0.1", help="Listen address; loopback only")
    parser.add_argument("--port", type=int, default=3240)
    parser.add_argument("--app", default="solana",
                        choices=["solana", "ton", "sui", "aptos", "polkadot", "near"],
                        help="Default initial Ledger app identity (auto-routes across all chains)")
    parser.add_argument("--allow-blind-sign", action="store_true",
                        help="DANGEROUS: permit remote blind signing without a trusted device display")
    args = parser.parse_args(argv)
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(
                args.host, None, family=socket.AF_INET, type=socket.SOCK_STREAM
            )
        }
    except OSError as exc:
        parser.error(f"cannot resolve --host as IPv4: {exc}")
    if not addresses or any(
        not ipaddress.ip_address(address).is_loopback
        for address in addresses
    ):
        parser.error("--host must resolve only to an IPv4 loopback address")
    pin = args.pin if args.pin is not None else getpass.getpass("Card PIN: ")
    if not isinstance(pin, str) or not pin:
        parser.error("card PIN must be non-empty")
    if args.allow_blind_sign:
        print("WARNING: blind signing enabled; verify transactions on a trusted independent display.")
    server = VirtualLedgerUSBIPServer(
        port=args.port,
        host=args.host,
        card_pin=pin,
        reader_name=args.reader,
        default_chain=args.app,
        allow_blind_sign=args.allow_blind_sign,
    )
    server.start()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())


