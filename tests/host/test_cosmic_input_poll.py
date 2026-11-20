"""Run the actual kernel input poll with real software buffering.

Only hardware event availability, transport failure and UART output are faked.
The production poll body and driver InputBuffer are compiled unchanged.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
from test_governance_billing_priority import function


class CosmicInputPoll(unittest.TestCase):
    def test_actual_poll_drains_bounded_fair_batches_and_preserves_loss_recovery(self):
        source = (ROOT / 'kernel/src/desktop/graphics.rs').read_text()
        body = function(source, 'pub fn poll()')
        template = (ROOT / 'tests/host/cosmic_input_poll.rs').read_text()
        key = hashlib.sha256((body + template).encode() +
                             (ROOT / 'crates/driver-virtio/src/lib.rs').read_bytes() +
                             (ROOT / 'crates/driver-virtio/src/input_buffer.rs').read_bytes()).hexdigest()
        with native_lease(DEFAULT_NATIVE_LOCK), tempfile.TemporaryDirectory(prefix='cyx-input-poll-') as tmp:
            idle_native_host()
            tmp = Path(tmp)
            (tmp / 'harness.rs').write_text(template.replace('// PRODUCTION_POLL', body))
            (tmp / 'Cargo.toml').write_text(
                '[package]\nname="cosmic-input-poll-regression"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="harness.rs"\n[workspace]\n[dependencies]\n'
                'cyxia-driver-virtio={path=' + json.dumps(str(ROOT / 'crates/driver-virtio')) + '}\n')
            env = dict(os.environ, CARGO_NET_OFFLINE='true', CARGO_INCREMENTAL='0',
                       CARGO_TARGET_DIR=str(ROOT / 'target/host-cosmic-input-poll' / key))
            result = subprocess.run([shutil.which('cargo'), 'test', '--offline', '--manifest-path',
                                     str(tmp / 'Cargo.toml'), '--', '--nocapture', '--test-threads=1'],
                                    cwd=tmp, env=env, capture_output=True, text=True, timeout=90)
            print(result.stdout, end='')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
