"""Fixtures test the verifier; they are not guest execution evidence."""
import importlib
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))


class NativeNetEvidence(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT / 'tools/verify_native_net.py').is_file(), 'native pair verifier missing')
        self.tool = importlib.import_module('verify_native_net')
        self.pages = []
        self.serial = []
        for node in (1, 2):
            words = [0] * 512
            words[:10] = [0x4359584e45543133, 1, 1, node, 3-node, 65535, 65535, 64, 16, 0]
            self.pages.append(struct.pack('<512Q', *words))
            boot = ''.join(f'SMP_CPU_ON a={cpu} b={cpu} c=0\n' for cpu in (1, 2, 3))
            self.serial.append((boot + 'SMP_BOOT_OK a=4 b=15 c=0\n' +
                                f'NET_PAIR_START node={node} peer={3-node} EL1_ETHERNET_ONLY\n' +
                                f'NET_PAIR_READY node={node} peer={3-node} received=65535\n').encode())

    def test_two_distinct_completed_guests_only_certify_ethernet(self):
        result = self.tool.validate(self.serial, self.pages, [4, 4])
        self.assertEqual(result['nodes'], 2)
        self.assertTrue(result['native_ethernet_verified'])
        self.assertFalse(result['native_cluster_verified'])
        self.assertFalse(result['tls_verified'])

    def test_one_guest_duplicated_cannot_certify_pair(self):
        with self.assertRaisesRegex(ValueError, 'distinct'):
            self.tool.validate([self.serial[0]] * 2, [self.pages[0]] * 2, [4, 4])

    def test_marker_without_received_frames_rejected(self):
        words = list(struct.unpack('<512Q', self.pages[0]))
        words[5] = 32767
        self.pages[0] = struct.pack('<512Q', *words)
        with self.assertRaisesRegex(ValueError, 'receive'):
            self.tool.validate(self.serial, self.pages, [4, 4])

    def test_unacknowledged_peer_rejected(self):
        words = list(struct.unpack('<512Q', self.pages[1]))
        words[6] = 0
        self.pages[1] = struct.pack('<512Q', *words)
        with self.assertRaisesRegex(ValueError, 'acknowledgment'):
            self.tool.validate(self.serial, self.pages, [4, 4])

    def test_missing_secondary_cpus_rejected(self):
        with self.assertRaisesRegex(ValueError, 'four'):
            self.tool.validate(self.serial, self.pages, [4, 1])

    def test_four_created_cpus_are_not_four_booted_cpus(self):
        self.serial[0] = self.serial[0].replace(b'SMP_CPU_ON a=3 b=3 c=0\n', b'')
        with self.assertRaisesRegex(ValueError, 'secondary'):
            self.tool.validate(self.serial, self.pages, [4, 4])

    def test_malformed_page_and_untrusted_serial_rejected(self):
        with self.assertRaises(ValueError):
            self.tool.validate(self.serial, [self.pages[0][:-1], self.pages[1]], [4, 4])
        with self.assertRaisesRegex(ValueError, 'serial'):
            self.tool.validate([b'NET_PAIR_READY\n', self.serial[1]], self.pages, [4, 4])


class CaptureEvidence(unittest.TestCase):
    def setUp(self):
        self.tool = importlib.import_module('verify_native_net')

    def capture(self, nodes=(1, 2)):
        data = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65536, 1))
        for node in nodes:
            for ordinal in range(64):
                # Independent wire fixture, not read from the guest implementation.
                packet = bytearray.fromhex(f'02000000000{3-node}02000000000{node}88b5')
                packet += b'CYXNET13' + bytes([1, node, 3-node, ordinal % 16])
                packet += struct.pack('<HQ', 65535, ordinal)
                packet += bytes(node ^ (ordinal % 16) ^ (ordinal if (at - 36) % 8 == 0 else 0) ^ at
                                for at in range(36, 64))
                data += struct.pack('<IIII', 0, ordinal, 64, 64) + packet
        return bytes(data)

    def test_actual_wire_coverage_requires_both_directions(self):
        result = self.tool.validate_capture(self.capture())
        self.assertEqual(result['frames_by_source'], [64, 64])
        with self.assertRaisesRegex(ValueError, 'directions'):
            self.tool.validate_capture(self.capture((1,)))

    def test_truncated_or_corrupt_wire_cannot_support_guest_claim(self):
        data = self.capture()
        for malformed in (data[:-1], data[:100], data[:24], data[:10]):
            with self.assertRaises(ValueError):
                self.tool.validate_capture(malformed)
        corrupted = bytearray(data)
        corrupted[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'payload'):
            self.tool.validate_capture(corrupted)

    def test_repeated_packet_cannot_replace_missing_sequences(self):
        data = self.capture()
        only_zero = data[:24] + (data[24:104] * 64) + (data[24+64*80:104+64*80] * 64)
        with self.assertRaisesRegex(ValueError, 'sequence'):
            self.tool.validate_capture(only_zero)

    def test_partial_acknowledgments_do_not_form_a_full_peer_receipt(self):
        data = bytearray(self.capture())
        for offset in range(40, len(data), 80):
            packet = bytearray(data[offset:offset + 64])
            packet[26:28] = (1 << packet[25]).to_bytes(2, 'little')
            for at in range(36, 64):
                packet[at] = packet[23] ^ packet[25] ^ packet[26] ^ packet[27] ^ packet[28 + (at - 36) % 8] ^ at
            data[offset:offset + 64] = packet
        with self.assertRaisesRegex(ValueError, 'acknowledgment'):
            self.tool.validate_capture(data)


if __name__ == '__main__':
    unittest.main()
