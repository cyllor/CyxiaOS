"""Startup sampling exercises the actual optional-diagnostic call site."""
import unittest

from verify_domains import refresh_snapshot
import test_verify_domains as fixtures


class DiscoverySampling(unittest.TestCase):
    def test_all_zero_optional_bank_does_not_require_unpublished_boot_epoch(self):
        bundle = {key: bytes(len(raw)) for key, raw in
                  fixtures.EvidenceParserTests().snapshot().items()}
        bundle['DISCOVERY_EVIDENCE'] = bytes(512)
        guest = {}
        refresh_snapshot(guest, bundle)
        self.assertEqual(guest['discovery_evidence'], [0] * 64)
        self.assertFalse(guest['discovery']['present'])
        self.assertEqual(guest['progress_diagnostic_status']['discovery'], 'not_published')

    def test_nonzero_bad_header_and_truncation_are_still_rejected(self):
        for raw in (bytes(511), b'\x02' + bytes(511)):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                bundle = fixtures.EvidenceParserTests().snapshot()
                bundle['DISCOVERY_EVIDENCE'] = raw
                refresh_snapshot({}, bundle)


if __name__ == '__main__':
    unittest.main()
