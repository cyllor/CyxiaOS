import unittest
from tools.doctor import assess
class DoctorTests(unittest.TestCase):
    def facts(self):
        return dict(rust='rustc 1.95.0', cargo='cargo 1.95.0', qemu='QEMU emulator version 10.2.2', targets=['aarch64-unknown-none-softfloat'], llvm=True, rust_path='/absolute/rustc')
    def test_missing_target(self):
        f=self.facts(); f['targets']=['aarch64-apple-darwin']
        r=assess(f); self.assertFalse(r['baremetal_target']['ready']); self.assertFalse(r['ready'])
    def test_rust_outside_path(self):
        self.assertTrue(assess(self.facts())['ready'])
    def test_version_mismatch(self):
        f=self.facts(); f['qemu']='QEMU emulator version 9.2.0'
        self.assertFalse(assess(f)['ready'])
