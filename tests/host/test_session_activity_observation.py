"""Replay the actual phase-9 broker arm and real Authority with fresh clocks."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import env


class SessionActivityObservation(unittest.TestCase):
    def test_actual_admission_records_kernel_clock_and_does_not_renew_expired_authority(self):
        source = (ROOT / 'kernel/src/unified_task.rs').read_text()
        arm = source[source.index('    if phase == 9 {'):source.index('    if phase == 0 ||')]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest = '[package]\nname="v15-activity-observation"\nversion="0.1.0"\nedition="2024"\n'
            manifest += '[dependencies]\ncyxia-kernel-core={path=' + json.dumps(
                str(ROOT / 'crates/kernel-core')) + '}\n[lib]\npath="harness.rs"\n'
            (directory / 'Cargo.toml').write_text(manifest)
            harness = '''
use core::sync::atomic::{AtomicU64,Ordering};
use cyxia_kernel_core::control_plane::task_admission::Authority;
static mut AUTHORITY: Authority = Authority::new();
static BOOT: AtomicU64 = AtomicU64::new(1);
#[path=DIAGNOSTIC_PATH]
mod activity_diagnostic;
fn request(phase:u64,token:u64,offset:u64,now:u64,connected:bool,epoch:u64)->(u64,usize,u64) {
    activity_diagnostic::broker_timing([now-3,now-2,now-1]);
ACTUAL_ARM
    unreachable!()
}
#[test]
fn actual_fresh_admission_and_transport_boundaries() {
    assert_eq!(request(9,1,7,100,true,7),(0,0,0));
    assert_eq!(request(9,3,7,1599,true,7),(0,0,0));
    let accepted=activity_diagnostic::snapshot();
    let row=&accepted[8+2*24..8+3*24];
    assert_eq!(row[7],1599,"EL1 clock must be the actual broker argument");
    assert_eq!(row[8..12],[7,1,100,1]);
    assert_eq!(row[12..18],[0,0,7,1,1599,1]);
    assert_eq!(request(9,3,7,3099,true,7),(3,0,0));
    let expired=activity_diagnostic::snapshot();
    let first=&expired[8+24..8+2*24];
    assert_eq!(first[7],3099);
    assert_eq!(first[8..12],[7,1,1599,1]);
    assert_eq!(first[12..18],[3,3,7,0,1599,2],"expired authority must close, not renew");
    assert_eq!(request(9,3,7,3200,false,7),(3,0,0));
    let disconnected=activity_diagnostic::snapshot();
    assert_eq!(&disconnected[8+24..8+2*24],first,"first failure must not be overwritten");
    let latest=&disconnected[8+2*24..8+3*24];
    assert_eq!(latest[6],0);
    assert_eq!(latest[12..18],[3,1,7,0,1599,2],"transport guard is distinct from expiry");
    assert_eq!(request(9,1,8,4000,true,7),(3,0,0),"wrong epoch must never register");
    assert_eq!(unsafe{(&*core::ptr::addr_of!(AUTHORITY)).session_observation()},[7,0,1599,2]);
    let words=activity_diagnostic::snapshot();
    assert_eq!(words[..8],[0x4359585341435431,2,104,24,5,3,2,1]);
    for row in words[8..].chunks_exact(24) {
        assert!(row[0]>0 && row[0]%2==0);
        assert_eq!(&row[18..21],&[row[7]-3,row[7]-2,row[7]-1]);
        assert!(row[21..].iter().all(|w|*w==0));
    }
}
'''.replace('DIAGNOSTIC_PATH', json.dumps(str(ROOT / 'kernel/src/session_activity_diagnostic.rs')))
            harness = harness.replace('ACTUAL_ARM', arm)
            (directory / 'harness.rs').write_text(harness)
            result = subprocess.run([str(Path(env()['PATH'].split(':')[0]) / 'cargo'), 'test',
                '--offline', '--manifest-path', str(directory / 'Cargo.toml'), '--target-dir',
                str(ROOT / 'target/host-v15-activity-observation'), '--', '--test-threads=1'],
                cwd=ROOT, env=env(), capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
