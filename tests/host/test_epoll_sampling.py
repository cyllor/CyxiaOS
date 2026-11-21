"""Run the production readiness callback with real POSIX pools and epolls."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from native_session import DEFAULT_NATIVE_LOCK, idle_native_host, native_lease
from test_governance_billing_priority import function


class EpollSampling(unittest.TestCase):
    def test_readiness_query_does_not_publish_unrelated_events(self):
        user = ROOT / 'kernel/src/desktop/user'
        fixture = Path(__file__).with_name('epoll_sampling_harness.rs').read_text()
        for marker, module, original in [
            ('UNIX_OPERATIONS', 'unix', ['pub(super) fn with<', 'pub(super) fn handle(']),
            ('PIPE_OPERATIONS', 'pipes', ['pub(super) fn with<']),
            ('PTY_OPERATIONS', 'pty', ['pub(super) fn with<']),
        ]:
            source = (user / (module + '.rs')).read_text()
            symbols = original + [symbol for symbol in ('pub(super) fn poll(', 'fn ready_bits(')
                                  if symbol in source]
            fixture = fixture.replace('// ' + marker, '\n'.join(function(source, name) for name in symbols))
        event = (user / 'event.rs').read_text()
        fixture = fixture.replace('// SOURCE_READINESS', function(event, 'fn source_readiness('))
        with native_lease(DEFAULT_NATIVE_LOCK), tempfile.TemporaryDirectory(prefix='cyx-epoll-sampling-') as tmp:
            idle_native_host()
            directory = Path(tmp)
            (directory / 'fixture.rs').write_text('#![allow(dead_code)]\n' + fixture)
            manifest = directory / 'Cargo.toml'
            manifest.write_text(
                '[package]\nname="epoll-sampling-regression"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="fixture.rs"\n[workspace]\n[dependencies]\n'
                'cyxia-posix={path=' + json.dumps(str(ROOT / 'crates/posix')) + ',features=["cosmic-applets-v1"]}\n')
            environment = dict(os.environ, CARGO_INCREMENTAL='0', RUST_MIN_STACK='16777216',
                               CARGO_TARGET_DIR=str(ROOT / 'target/host-epoll-sampling'))
            result = subprocess.run(['cargo', 'test', '--offline', '--manifest-path', str(manifest),
                                     '--', '--test-threads=1'], capture_output=True, text=True,
                                    cwd=directory, env=environment, timeout=90)
            print(result.stdout, end='')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
