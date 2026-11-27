"""Host parser regressions only; the real heap-pool scenario runs in QEMU."""
import re
import unittest

from os_heap_pool import snapshot


class Console:
    def __init__(self, ledger):
        self.data = (b'ANON_POOL capacity=65536 free=32 used=65504 peak=65504 virtual_pages=16384\n'
                     + ledger + b'\nAI_DOMAIN name=anonymous grant_units=65504 release_units=0\nAI_SYSTEM_END\n')

    def command(self, command):
        if command != 'ai system':
            raise AssertionError(command)
        return 0

    def until(self, pattern, start):
        match = re.search(pattern, self.data[start:])
        if match is None:
            raise ValueError('missing receipt')
        return match


class LedgerReceipt(unittest.TestCase):
    def test_quarantine_is_retained_in_conservation(self):
        row = snapshot(Console(b'ANON_POOL_LEDGER free=20 reserved=0 allocated=65500 quarantined=16 permanent=0 conservation=OK'))
        self.assertEqual(row['ledger']['quarantined'], 16)

    def test_missing_or_divergent_ledger_rejected(self):
        for ledger in (
            b'',
            b'ANON_POOL_LEDGER free=32 reserved=0 allocated=65504 quarantined=0 permanent=0 conservation=DIVERGENCE',
            b'ANON_POOL_LEDGER free=31 reserved=0 allocated=65504 quarantined=0 permanent=0 conservation=OK',
            b'ANON_POOL_LEDGER free=33 reserved=0 allocated=65503 quarantined=0 permanent=0 conservation=OK',
            b'ANON_POOL_LEDGER free=32 reserved=0 allocated=65504 quarantined=0 permanent=1 conservation=OK',
        ):
            with self.subTest(ledger=ledger), self.assertRaises(ValueError):
                snapshot(Console(ledger))


if __name__ == '__main__':
    unittest.main()
