"""Run the CPU0 checkpoint service against a sector-backed host device."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class CheckpointReuse(unittest.TestCase):
    def test_checkpoint_service(self):
        crates = ['contracts', 'kernel-core', 'ai-fs', 'ai-runtime', 'posix', 'shell']
        dependencies = [f'cyxia-{name}={{path={json.dumps(str(ROOT / "crates" / name))}}}'
                        for name in crates]
        driver = json.dumps(str(ROOT / 'crates/driver-virtio'))
        dependencies.append(f'driver={{package="cyxia-driver-virtio",path={driver}}}')
        with tempfile.TemporaryDirectory(prefix='cyx-checkpoint-') as tmp:
            directory = Path(tmp)
            (directory / 'Cargo.toml').write_text(
                '[package]\nname="checkpoint-reuse"\nversion="0.1.0"\nedition="2024"\n'
                '[features]\nported=[]\n[lib]\npath="fixture.rs"\n[workspace]\n[dependencies]\n'
                + '\n'.join(dependencies) + '\n')
            (directory / 'fixture.rs').write_text(Path(__file__).with_name('checkpoint_reuse_harness.rs').read_text())
            source = (ROOT / 'kernel/src/desktop/storage.rs').read_text()
            (directory / 'storage.rs').write_text(source + '''
#[cfg(test)]
pub(super) fn reboot() {
    // This fixture serializes its tests like the sole CPU0 foreground owner.
    unsafe { *core::ptr::addr_of_mut!(SERVICE) = Service::new() };
}
''')
            subprocess.run(['cargo', 'test', '--offline', '--features', 'ported', '--lib',
                            '--', '--test-threads=1'], cwd=directory, check=True, timeout=90,
                           env=dict(os.environ, CARGO_INCREMENTAL='0', RUST_MIN_STACK='33554432',
                                    CARGO_TARGET_DIR=str(ROOT / 'target/host-checkpoint-reuse')))


if __name__ == '__main__':
    unittest.main()
