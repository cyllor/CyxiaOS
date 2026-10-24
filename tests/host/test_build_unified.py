from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
import build_unified as build


class UnifiedBuilder(unittest.TestCase):
    def test_code_manifest_retains_build_and_crypto_but_excludes_mutable_evidence(self):
        entries={'Cargo.lock':'a','kernel/build.rs':'b','kernel/src/unified.rs':'c','user/prototype-cluster/vendor/ring/build.rs':'d','user/prototype-cluster/vendor/ring/pregenerated/a.S':'e','user/prototype-cluster/tools/build.sh':'f','user/prototype-cluster/vendor/ring/crypto/limbs/limbs.inl':'f1','user/prototype-cluster/vendor/ring/crypto/fipsmodule/ec/ecp_nistz384.inl':'f2','user/custom/model.weights':'f3','.cargo/config.toml':'f4','rust-toolchain.toml':'f5','docs/evidence.md':'g','tools/verify_unified.py':'h','tests/host/test_v13_disk.py':'i','crates/prototype/tests/foo.rs':'j'}
        with patch.object(build,'manifest',return_value=entries):result=build.code_source_map()
        self.assertEqual(set(result),set(list(entries)[:11]))
    def test_included_crypto_inline_mutation_changes_code_binding(self):
        name='user/prototype-cluster/vendor/ring/crypto/limbs/limbs.inl'
        with patch.object(build,'manifest',return_value={name:'before'}):before=build.code_source_map()
        with patch.object(build,'manifest',return_value={name:'after'}):after=build.code_source_map()
        self.assertNotEqual(before,after)
    def test_identity_metadata_checks_actual_public_pin_without_private_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);public=bytes(range(32));peer=bytes(range(32,64))
            for name,data in {'own.pub':public,'local.pin':hashlib.sha256(public).digest(),'peer.pub':peer,'peer.pin':hashlib.sha256(peer).digest(),'cert.der':b'public certificate','key.der':b'PRIVATE-KEY-MUST-NOT-LEAK'}.items():(p/name).write_bytes(data)
            result=build.identity_metadata(p)
            self.assertEqual(result['node_id'],hashlib.sha256(public).hexdigest())
            self.assertNotIn('PRIVATE-KEY',json.dumps(result));self.assertNotIn('key.der',json.dumps(result))
            (p/'peer.pin').write_bytes(bytes(32))
            with self.assertRaises(ValueError):build.identity_metadata(p)
    def test_json_messages_select_exact_kernel_artifact_and_actual_task_directory(self):
        messages=[{'reason':'build-script-executed','package_id':'path+file:///repo/kernel#cyxia-kernel@0.1.0','out_dir':'/build/out'}, {'reason':'compiler-artifact','target':{'name':'unrelated'},'executable':'/bad'}, {'reason':'compiler-artifact','target':{'name':'cyxia-kernel'},'executable':'/build/cyxia-kernel'}]
        self.assertEqual(build.parse_cargo_build_messages('\n'.join(map(json.dumps,messages))), (Path('/build/cyxia-kernel'),Path('/build/out')))
        with self.assertRaises(ValueError):build.parse_cargo_build_messages('{}')


if __name__=='__main__':unittest.main()
