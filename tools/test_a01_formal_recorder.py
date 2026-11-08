"""Drive the actual first-return recorder with expected-probe then normal returns.

Only architectural MRS outputs and clocks are controlled. The selector, write
ordering, first-publication latch and register/context field copies are the
actual production function, not a reimplementation of its behavior.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

from doctor import ROOT, RUST_BIN, env


def function(source, name):
    start = source.index(name)
    body = source.index('{', start)
    depth = 1
    end = body + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


class ActualFirstReturnRecorder(unittest.TestCase):
    def test_expected_permission_probe_cannot_seal_or_block_normal_el0_return(self):
        source = (ROOT / 'kernel/src/boot_recovery/formal.rs').read_text()
        recorder = function(source, 'pub(crate) fn el0_return(')
        start = recorder.index('    unsafe {\n        core::arch::asm!')
        end = recorder.index('\n    }', start) + len('\n    }')
        # Replace only the MRS observation seam; never replace the selector or
        # its one-time latch. The real three outputs are assigned explicitly.
        recorder = recorder[:start] + '\n    el = 4; actual_root = root; tcr = 0x80;\n' + recorder[end:]
        program = r'''
use core::sync::atomic::{AtomicU64,Ordering};
mod cpu {pub fn slot()->usize{2}}
mod timer {pub fn ticks()->u64{100}}
mod user {#[derive(Default)] pub struct Context {pub kind:u64,pub status:u64,pub esr:u64,pub pc:u64}}
struct Formal([AtomicU64;256]);
static A01_FORMAL_EVIDENCE:Formal=Formal([const{AtomicU64::new(0)};256]);
// REAL_GET_PUT
// REAL_RECORDER
fn main(){
 let scenario=std::env::args().nth(1).unwrap(); let row=32+2*24+12;
 let probe=user::Context{kind:8,esr:(0x24<<26)|15,pc:0x1006c,..Default::default()};
 el0_return(&probe,0x42000000,1);
 assert_eq!(get(row),0,"expected permission probe sealed the ordinary return row");
 let normal=user::Context{kind:if scenario=="svc"{8}else{9},esr:if scenario=="svc"{0x15<<26}else{0},pc:0x10080,..Default::default()};
 el0_return(&normal,0x42000000,1);
 assert_eq!(get(row),2,"normal return never sealed");
 assert_eq!(get(row+3),normal.esr,"probe ESR survived later normal return");
 assert_eq!(get(row+4),normal.kind);assert_eq!(get(row+5),normal.pc);
 assert_eq!(get(row+6),0x42000000);assert_eq!(get(row+7),0x42000000);
 let later=user::Context{pc:0x20000,..normal};el0_return(&later,0x43000000,1);
 assert_eq!(get(row+5),0x10080,"first normal fact was overwritten");
 println!("HOST_ONLY actual-recorder probe-{} PASS native_acceptance_status=NOT_RUN",scenario);
}
'''
        program = program.replace('// REAL_GET_PUT', '\n'.join(function(source, name)
            for name in ('fn put(', 'fn get('))).replace('// REAL_RECORDER', recorder)
        with tempfile.TemporaryDirectory(prefix='cyxia-a01-formal-recorder-') as tmp:
            root = Path(tmp)
            path, binary = root / 'recorder.rs', root / 'recorder'
            path.write_text(program)
            compiled = subprocess.run([str(RUST_BIN / 'rustc'), '--edition=2024',
                '-C', 'opt-level=1', str(path), '-o', str(binary)],
                env=env(), capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            for scenario in ('svc', 'preempt'):
                result = subprocess.run([str(binary), scenario], capture_output=True,
                                        text=True, timeout=5)
                with self.subTest(scenario=scenario):
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('actual-recorder probe-' + scenario + ' PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
