"""Offline USB/IP protocol regression tests."""
import socket
import struct
import threading
import unittest
from unittest import mock

import virtual_ledger_usbip_daemon as daemon

from virtual_ledger_usbip_daemon import (
    VirtualLedgerUSBIPServer, USBIP_CMD_SUBMIT, USBIP_RET_SUBMIT,
    USB_DT_DEVICE, DESCRIPTOR_DEVICE, STRINGS,
)


class CaptureSocket:
    def __init__(self):
        self.data = bytearray()
    def sendall(self, data):
        self.data.extend(data)


class USBIPTests(unittest.TestCase):
    def make_server(self):
        return VirtualLedgerUSBIPServer(card_pin="test-pin")

    def test_usb_device_descriptor_and_import_lengths(self):
        server = self.make_server()
        self.assertEqual(len(server._usb_device_descriptor()), 312)
        cap = CaptureSocket()
        server.send_import(cap, success=True)
        self.assertEqual(len(cap.data), 8 + 312)
        self.assertEqual(struct.unpack(">HHI", cap.data[:8]), (0x0111, 0x0003, 0))
        cap = CaptureSocket()
        server.send_devlist(cap, success=True)
        self.assertEqual(len(cap.data), 12 + 312 + 4)

    def test_control_descriptor_honors_wlength(self):
        server = self.make_server()
        setup = struct.pack("<BBHHH", 0x80, 0x06, USB_DT_DEVICE << 8, 0, 8)
        self.assertEqual(server.handle_control_transfer(setup, 64), DESCRIPTOR_DEVICE[:8])

    def test_hid_string_descriptor_and_in_report_boundaries(self):
        server = self.make_server()
        for index, value in STRINGS.items():
            self.assertEqual(value[0], len(value))
            setup = struct.pack("<BBHHH", 0x80, 0x06, (3 << 8) | index, 0, 255)
            self.assertEqual(server.handle_control_transfer(setup, 255), value)
        self.assertEqual(server.get_outgoing_report(0), b"")
        self.assertEqual(server.get_outgoing_report(63), b"")
        self.assertEqual(server.get_outgoing_report(65), b"")
        server.in_reports_queue.put(b"A" * 64)
        self.assertEqual(server.get_outgoing_report(64), b"A" * 64)

    def test_ipv6_loopback_is_rejected_by_ipv4_only_listener(self):
        with self.assertRaises(ValueError):
            VirtualLedgerUSBIPServer(host="::1", card_pin="test-pin")

    def test_packaging_entrypoint_constructs_and_starts_server(self):
        with mock.patch.object(daemon, "VirtualLedgerUSBIPServer") as constructor:
            self.assertEqual(daemon.main(["--pin", "test-pin"]), 0)
            constructor.assert_called_once()
            constructor.return_value.start.assert_called_once_with()

    def test_packaging_entrypoint_rejects_empty_prompted_pin(self):
        with mock.patch.object(daemon.getpass, "getpass", return_value=""):
            with self.assertRaises(SystemExit):
                daemon.main([])

    def test_submit_response_uses_signed_number_of_packets(self):
        server = self.make_server()
        server.running = True
        left, right = socket.socketpair()
        thread = threading.Thread(target=server.handle_urbs, args=(left,), daemon=True)
        thread.start()
        setup = struct.pack("<BBHHH", 0x80, 0x06, USB_DT_DEVICE << 8, 0, 18)
        request = struct.pack(">IIIII", USBIP_CMD_SUBMIT, 9, 0x00010001, 1, 0)
        request += struct.pack(">IIiii8s", 0, 18, 0, -1, 0, setup)
        right.sendall(request)
        response = b""
        while len(response) < 48 + 18:
            block = right.recv(4096)
            if not block:
                break
            response += block
        server.running = False
        right.close()
        thread.join(timeout=1)
        left.close()
        self.assertEqual(len(response), 66)
        fields = struct.unpack(">IIIIIiiiii8s", response[:48])
        self.assertEqual(fields[0], 0x0003)
        self.assertEqual(fields[1], 9)
        self.assertEqual(fields[5], 0)
        self.assertEqual(fields[6], 18)
        self.assertEqual(fields[8], -1)
        self.assertEqual(response[48:66], DESCRIPTOR_DEVICE)
        self.assertEqual(response[40:48], setup)


if __name__ == "__main__":
    unittest.main()






