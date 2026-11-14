"""Real capture function and real repr(C) Context; host-only, never native proof."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from doctor import ROOT,RUST_BIN,env
from test_a01_formal_recorder import function


class ActualRecorder(unittest.TestCase):
    def test_capture_copies_every_word_and_does_not_reconstruct_expected_patterns(self):
        source=(ROOT/'kernel/src/diagnostics/register_evidence.rs').read_text()
        context=(ROOT/'crates/arch-aarch64/src/user.rs').read_text()
        structure=function(context,'pub struct Context {')
        body='\n'.join(function(source,n) for n in ('fn put(','fn get(','fn capture('))
        program=r'''
use core::sync::atomic::{AtomicU64,Ordering};
mod user {#[repr(C,align(16))] // STRUCTURE
}
struct Capture([AtomicU64;5632]);
static REGISTER_V15_EVIDENCE:Capture=Capture([const{AtomicU64::new(0)};5632]);
const EVENT:usize=112;
// BODY
fn main(){
 let mut raw=[0u64;104];for (i,x) in raw.iter_mut().enumerate(){*x=i as u64*0x101+7;}
 assert_eq!(core::mem::size_of::<user::Context>(),832);
 // No architectural event is fabricated here: this only tests copying arbitrary raw values.
 let ctx=unsafe{core::ptr::read_unaligned(raw.as_ptr().cast::<user::Context>())};
 capture(&ctx,64,0,7,100,110,1,0,1);
 assert_eq!((0..8).map(|i|get(96+i)).collect::<Vec<_>>(),vec![7,100,110,1,0,1,6,1]);
 for i in 0..104{assert_eq!(get(104+i),raw[i],"field {i}");}
 raw[37]^=0x100;raw[102]^=1;raw[103]^=2;
 let changed=unsafe{core::ptr::read_unaligned(raw.as_ptr().cast::<user::Context>())};
 capture(&changed,64,4,9,200,210,2,0,0);
 for i in 0..104{assert_eq!(get(64+32+4*112+8+i),raw[i],"changed field {i}");}
 println!("HOST_ONLY real-register-recorder PASS native_acceptance_status=NOT_RUN");
}
'''.replace('// STRUCTURE',structure).replace('// BODY',body)
        with tempfile.TemporaryDirectory(prefix='cyx-register-recorder-') as tmp:
            src,binary=Path(tmp)/'test.rs',Path(tmp)/'test'
            src.write_text(program)
            compiled=subprocess.run([str(RUST_BIN/'rustc'),'--edition=2024',str(src),'-o',str(binary)],
                                    env=env(),capture_output=True,text=True,timeout=30)
            self.assertEqual(compiled.returncode,0,compiled.stderr)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)


if __name__=='__main__':unittest.main()
