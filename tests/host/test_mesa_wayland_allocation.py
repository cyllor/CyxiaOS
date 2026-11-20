"""Fault injection into actual Mesa functions, with the original callback chain."""
import hashlib
import json
from pathlib import Path
import resource
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PORT = ROOT / 'ports/cosmic/native-mesa-wayland-oom-v1'
PATCH = ROOT / 'ports/cosmic/patches/mesa-26.2.3-wayland-swrast-allocation.patch'
FUNCTIONS = ('swrast_update_buffers', 'dri2_wl_swrast_get_frontbuffer_data',
             'dri2_wl_swrast_get_backbuffer_data', 'dri2_wl_swrast_get_image',
             'dri2_wl_swrast_put_image2', 'dri2_wl_swrast_swap_buffers_with_damage',
             'dri2_wl_swrast_swap_buffers')


def function(source, name):
    begin = source.index('\n' + name + '(')
    begin = source.rfind('\nstatic ', 0, begin) + 1
    brace = source.index('{', begin)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[begin:end]


class MesaWaylandAllocation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        cls.temporary = tempfile.TemporaryDirectory(prefix='cyx-mesa-allocation-')
        cls.addClassCleanup(cls.temporary.cleanup)
        folder = Path(cls.temporary.name)
        original = PORT / 'upstream/platform_wayland.c'
        assert hashlib.sha256(original.read_bytes()).hexdigest() == json.loads(
            (PORT / 'source-policy.json').read_text())['upstream_sha256']
        target = folder / 'src/egl/drivers/dri2/platform_wayland.c'
        target.parent.mkdir(parents=True)
        target.write_bytes(original.read_bytes())
        if PATCH.exists():
            subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(PATCH)],
                           cwd=folder, capture_output=True, check=True)
        source = target.read_text()
        fixture = (Path(__file__).with_name('mesa_wayland_allocation.c')).read_text()
        merged = fixture.replace('/* MESA_FUNCTIONS */', '\n\n'.join(function(source, name) for name in FUNCTIONS))
        unit = folder / 'unit.c'
        unit.write_text(merged)
        cls.binary = folder / 'probe'
        compiled = subprocess.run(['clang', '-std=c11', '-DNDEBUG', '-O1', '-Wall', '-Wextra', '-Werror',
            '-Wno-unused-parameter', '-Wno-unused-function', str(unit), '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=30)
        assert compiled.returncode == 0, compiled.stderr

    def check_mode(self, mode):
        run = subprocess.run([str(self.binary), mode], text=True, capture_output=True, timeout=3)
        self.assertEqual(run.returncode, 0, f'{mode}: status={run.returncode} {run.stdout} {run.stderr}')
        self.assertIn('MESA_WAYLAND_ALLOCATION PASS', run.stdout)

    def test_failed_allocation_rolls_back_backbuffer_publication(self): self.check_mode('rollback')
    def test_repeated_denial_remains_failure(self): self.check_mode('retry')
    def test_late_loader_callback_after_failed_allocation_is_safe(self): self.check_mode('late_callback')
    def test_damage_swap_propagates_failure_without_submission(self): self.check_mode('swap_damage')
    def test_ordinary_swap_propagates_failure_without_submission(self): self.check_mode('swap')
    def test_real_copy_and_submission_recover_after_denial(self): self.check_mode('recover')
    def test_healthy_copy_and_submission_are_preserved(self): self.check_mode('healthy')


if __name__ == '__main__':
    unittest.main()
