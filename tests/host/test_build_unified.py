from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
import build_unified as build


class UnifiedBuilder(unittest.TestCase):
    def source_tree(self, entries):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        subprocess.run(['git', 'init', '--quiet', str(root)], check=True)
        sources = {'Cargo.lock': 'lock', 'kernel/src/smp.rs': 'smp',
                   'crates/arch-aarch64/src/user.rs': 'user', **entries}
        for name, content in sources.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        return root

    def test_code_manifest_retains_build_and_crypto_but_excludes_mutable_evidence(self):
        entries={'Cargo.lock':'a','kernel/build.rs':'b','kernel/src/unified.rs':'c','user/prototype-cluster/vendor/ring/build.rs':'d','user/prototype-cluster/vendor/ring/pregenerated/a.S':'e','user/prototype-cluster/tools/build.sh':'f','user/prototype-cluster/vendor/ring/crypto/limbs/limbs.inl':'f1','user/prototype-cluster/vendor/ring/crypto/fipsmodule/ec/ecp_nistz384.inl':'f2','user/custom/model.weights':'f3','.cargo/config.toml':'f4','rust-toolchain.toml':'f5','docs/evidence.md':'g','tools/verify_unified.py':'h','tests/host/test_v13_disk.py':'i','crates/prototype/tests/foo.rs':'j'}
        root = self.source_tree(entries)
        result = build.code_source_map(root)
        self.assertEqual(set(result), set(list(entries)[:11]) |
                         {'kernel/src/smp.rs', 'crates/arch-aarch64/src/user.rs'})
        for name, digest in result.items():
            self.assertEqual(digest, hashlib.sha256((root / name).read_bytes()).hexdigest())

    def test_included_crypto_inline_mutation_changes_code_binding(self):
        name='user/prototype-cluster/vendor/ring/crypto/limbs/limbs.inl'
        root = self.source_tree({name: 'before'})
        before = build.code_source_map(root)
        (root / name).write_text('after')
        after = build.code_source_map(root)
        self.assertNotEqual(before,after)
        self.assertNotEqual(before[name], after[name])

    def test_missing_excluded_fixture_does_not_hide_missing_compiled_source(self):
        fixture = 'crates/prototype/tests/fixture.bin'
        compiled = 'user/custom/model.weights'
        root = self.source_tree({fixture: 'test fixture', compiled: 'model'})
        subprocess.run(['git', 'add', '.'], cwd=root, check=True)
        (root / fixture).unlink()
        self.assertIn(compiled, build.code_source_map(root))
        (root / compiled).unlink()
        with self.assertRaisesRegex(ValueError, 'missing, linked, or external'):
            build.code_source_map(root)

    def test_compiled_source_symlink_is_rejected(self):
        root = self.source_tree({})
        link = root / 'user/model.weights'
        link.parent.mkdir()
        link.symlink_to(root / 'Cargo.lock')
        with self.assertRaisesRegex(ValueError, 'missing, linked, or external'):
            build.code_source_map(root)
    def test_identity_metadata_checks_actual_public_pin_without_private_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);public=bytes(range(32));peer=bytes(range(32,64))
            billing_seed=bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
            billing_public=bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
            peer_billing_public=bytes.fromhex('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c')
            for name,data in {'own.pub':public,'local.pin':hashlib.sha256(public).digest(),'peer.pub':peer,'peer.pin':hashlib.sha256(peer).digest(),'cert.der':b'public certificate','key.der':b'PRIVATE-KEY-MUST-NOT-LEAK','billing.seed':billing_seed,'billing.pub':billing_public,'peer.billing.pub':peer_billing_public}.items():(p/name).write_bytes(data)
            result=build.identity_metadata(p)
            self.assertEqual(result['node_id'],hashlib.sha256(public).hexdigest())
            self.assertNotIn('PRIVATE-KEY',json.dumps(result));self.assertNotIn('key.der',json.dumps(result))
            (p/'peer.pin').write_bytes(bytes(32))
            with self.assertRaises(ValueError):build.identity_metadata(p)
    def test_embedded_role_audit_requires_the_exact_nonempty_image(self):
        build.audit_embedded_role(b'kernel-prefix' + b'governance-image' + b'-suffix',
                                  b'governance-image', 'governance')
        with self.assertRaisesRegex(ValueError, 'exact embedded governance'):
            build.audit_embedded_role(b'kernel-without-role', b'governance-image',
                                      'governance')
        with self.assertRaisesRegex(ValueError, 'exact embedded governance'):
            build.audit_embedded_role(b'kernel', b'', 'governance')

    def test_json_messages_select_exact_kernel_artifact_and_actual_task_directory(self):
        messages=[{'reason':'build-script-executed','package_id':'path+file:///repo/kernel#cyxia-kernel@0.1.0','out_dir':'/build/out'}, {'reason':'compiler-artifact','target':{'name':'unrelated'},'executable':'/bad'}, {'reason':'compiler-artifact','target':{'name':'cyxia-kernel'},'executable':'/build/cyxia-kernel'}]
        self.assertEqual(build.parse_cargo_build_messages('\n'.join(map(json.dumps,messages))), (Path('/build/cyxia-kernel'),Path('/build/out')))
        with self.assertRaises(ValueError):build.parse_cargo_build_messages('{}')


if __name__=='__main__':unittest.main()
