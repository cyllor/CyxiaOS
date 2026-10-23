"""Evidence parser rejects truncated, duplicate or gap-concealing snapshots."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'tools'))
from verify_ai_system import REQUIRED, parse_snapshot


class AiSystemEvidenceTests(unittest.TestCase):
    def sample(self):
        return (b'AI_SYSTEM schema=1 full_contract=false\r\n' +
                b''.join(f'AI_DOMAIN name={name} committed=3\r\n'.encode() for name in sorted(REQUIRED)) +
                b'AI_GAPS global_learning=absent\r\nAI_SYSTEM_END\r\n')

    def test_complete_snapshot_preserves_domains_and_values(self):
        rows = parse_snapshot(self.sample())
        self.assertEqual(rows.keys(), REQUIRED)
        self.assertEqual(rows['process']['committed'], 3)

    def test_truncation_missing_domain_duplicates_and_concealed_gaps_fail(self):
        sample = self.sample()
        for damaged in (
            sample.replace(b'AI_SYSTEM_END\r\n', b''),
            sample.replace(b'AI_DOMAIN name=process committed=3\r\n', b''),
            sample.replace(b'AI_SYSTEM_END', b'AI_DOMAIN name=process committed=4\r\nAI_SYSTEM_END'),
            sample.replace(b'full_contract=false', b'full_contract=true'),
            sample.replace(b'AI_GAPS ', b'HIDDEN '),
        ):
            with self.subTest(damaged=damaged[-80:]):
                with self.assertRaises(AssertionError):
                    parse_snapshot(damaged)
