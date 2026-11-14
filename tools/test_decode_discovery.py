import pathlib
import shutil
import struct
import subprocess
import tempfile
import unittest
from decode_discovery import decode

class DiscoveryDecoderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=pathlib.Path(__file__).resolve().parents[1]
        cargo=shutil.which('cargo') or str(pathlib.Path.home()/'.cargo/bin/cargo')
        target=root/'target'
        import os
        target=pathlib.Path(os.environ.get('CARGO_TARGET_DIR',target))
        subprocess.run([cargo,'build','--locked','--offline','-p','cyxia-cluster-transport'],cwd=root,check=True,capture_output=True)
        library=max((target/'debug/deps').glob('libcyxia_cluster_transport-*.rlib'),key=lambda p:p.stat().st_mtime_ns)
        source='mod actual {\n'+(root/'kernel/src/runtime/cluster/unified_discovery.rs').read_text()+'''
pub fn run() {
 use cyxia_cluster_transport::{discovery::{Discovery,Message},tcp::DiscoverySnapshot};
 let mut state=Discovery::new([1;32],[2;32],[10,42,0,1],24,40001,0).unwrap();
 state.announce(1,[7;16]).unwrap();
 state.receive([10,42,0,2],&Message {node:[2;32],port:8443,nonce:[9;16]}.encode().unwrap(),2).unwrap();
 let attempt=state.begin_auth(3).unwrap();
 let s=DiscoverySnapshot {counters:state.counters,candidates:1,attempts:1,selected:Some(attempt),
  selected_ms:3,candidate_ms:2,sent:1,sent_ms:1,sent_nonce:[7;16],next_ms:2000,
  local_node:[1;32],peer_node:[2;32],local_ip:[10,42,0,1],local_port:40001};
 publish(1,1,5,Some(State::Established),s);
 use std::io::Write;
 for w in &DISCOVERY_EVIDENCE.words {std::io::stdout().write_all(&w.load(Ordering::Acquire).to_le_bytes()).unwrap();}
}
}
fn main(){actual::run()}
'''
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory);(path/'probe.rs').write_text(source)
            rustc=shutil.which('rustc') or str(pathlib.Path.home()/'.cargo/bin/rustc')
            compiled=subprocess.run([rustc,'--edition=2024','-C','panic=abort',str(path/'probe.rs'),'--extern',f'cyxia_cluster_transport={library}',
                            '-L',f'dependency={target}/debug/deps','-o',str(path/'probe')],capture_output=True)
            if compiled.returncode:raise AssertionError(compiled.stderr.decode())
            cls.raw=subprocess.check_output([str(path/'probe')])
    def test_actual_kernel_publisher_decodes_only_public_candidate_state(self):
        result=decode(self.raw,boot=1)
        self.assertEqual(result['selected']['ipv4'],'10.42.0.2')
        self.assertEqual(result['selected']['nonce'],(bytes([9])*16).hex())
        self.assertEqual(result['sent'],1)
        self.assertFalse(result['native_acceptance_verified'])
        self.assertFalse(result['complete_history'])
    def test_unpublished_interrupted_malformed_and_cross_boot_rejected(self):
        self.assertFalse(decode(bytes(512))['present'])
        for index,value in [(0,1),(1,0),(2,2),(3,2),(7,2),(11,9),(12,5),(13,5),(17,0),(18,0),(38,9),(63,1)]:
            words=list(struct.unpack('<64Q',self.raw));words[index]=value
            with self.subTest(index=index),self.assertRaises(ValueError):decode(struct.pack('<64Q',*words),boot=1)
if __name__=='__main__':unittest.main()
