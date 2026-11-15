"""Validate installed resource receipts independently of a native VM."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
import install_xkb_data as installer
import os_smoke
import x86_64 as pc


class XkbReceiptTests(unittest.TestCase):
    def test_missing_changed_duplicate_and_foreign_assets_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            assets = []
            for path in [target for _, target in installer.ASSETS] + [installer.RULE_TARGET]:
                target = prefix / 'rootfs' / path.lstrip('/')
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(path.encode())
                assets.append(dict(path=path, bytes=target.stat().st_size, sha256=pc.sha(target)))
            receipt = dict(status='PASS', generation=dict(repeat_identical=True), assets=assets,
                           source=dict(sha256=installer.load_package()['expected_sha256']),
                           manifest=dict(sha256=pc.sha(installer.MANIFEST)))
            report = prefix / 'xkb-assets.json'
            report.write_text(json.dumps(receipt))
            self.assertEqual(len(os_smoke.xkb_data_inputs(prefix)['assets']), 30)
            selected = prefix / 'rootfs' / installer.RULE_TARGET.lstrip('/')
            original = selected.read_bytes()
            selected.write_bytes(b'x' * len(original))
            with self.assertRaises(ValueError): os_smoke.xkb_data_inputs(prefix)
            selected.unlink()
            with self.assertRaises(ValueError): os_smoke.xkb_data_inputs(prefix)
            selected.write_bytes(original)
            for mutation in ('duplicate', 'foreign', 'source', 'nonrepeatable'):
                bad = json.loads(json.dumps(receipt))
                if mutation == 'duplicate': bad['assets'].append(bad['assets'][0])
                elif mutation == 'foreign': bad['assets'][0]['path'] = '/elsewhere'
                elif mutation == 'source': bad['source']['sha256'] = '0' * 64
                else: bad['generation']['repeat_identical'] = False
                report.write_text(json.dumps(bad))
                with self.assertRaises(ValueError): os_smoke.xkb_data_inputs(prefix)


if __name__ == '__main__':
    unittest.main()
