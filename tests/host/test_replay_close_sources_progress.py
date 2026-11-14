"""Actual paid progress/owner chain and Core capture closure; no native verdict."""
from pathlib import Path
import json
import re
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from doctor import RUST_BIN,env
from test_governance_billing_priority import function
from test_baseline_progress import program as paid_program


def program():
    owner=(ROOT/'kernel/src/runtime/learning/learning_replay/owner.rs').read_text()
    facade=(ROOT/'kernel/src/runtime/learning/learning_replay.rs').read_text()
    code=paid_program().split('#[test]',1)[0]
    previous=function(code,'mod learning_replay {')
    fixture=(ROOT/'tests/host/replay_close_sources_harness.rs').read_text()
    signatures={
        'OWNER_DROP':'impl Drop for Guard','OWNER_LOCK':'fn lock()',
        'OWNER_WITH':'fn with<T>','OWNER_HINT':'fn publish_drain_hint(',
        'OWNER_DRAIN':'pub(super) fn drain_pending(', 'OWNER_STEP':'pub fn service_step()',
        'OWNER_SERVICE':'pub(super) fn service_pending(',
    }
    for marker,signature in signatures.items():
        fixture=fixture.replace('// ACTUAL_'+marker,function(owner,signature))
    for flag in ['DRAIN_PENDING','SERVICE_PENDING']:
        fixture=fixture.replace('// ACTUAL_'+flag,re.search(r'^static '+flag+r':.*;$',owner,re.M)[0])
    for marker,signature in [('FACADE_PENDING','pub fn baseline_activation_pending('),
                             ('FACADE_DRAIN','pub fn owned_drain_pending('),
                             ('FACADE_ADMISSION','pub fn admission_progress_pending(')]:
        fixture=fixture.replace('// ACTUAL_'+marker,function(facade,signature))
    body=function(owner,'fn service(')
    for marker,signature in [('CLOSE','Phase::CloseSources =>'),('SEAL','Phase::Seal =>')]:
        fixture=fixture.replace('// ACTUAL_'+marker,function(body,signature))
    assert '// ACTUAL_' not in fixture
    return code.replace(previous,fixture)


class CloseSourcesProgress(unittest.TestCase):
    def test_already_entered_cleanup_keeps_paid_progress_until_seal(self):
        code=program()
        with tempfile.TemporaryDirectory() as temporary:
            d=Path(temporary);source=d/'close.rs'
            (d/'Cargo.toml').write_text(
                '[package]\nname="replay-close-sources"\nversion="0.1.0"\nedition="2024"\n'
                '[lib]\npath="close.rs"\n[dependencies]\ncyxia-prototype={path='
                +json.dumps(str(ROOT/'crates/prototype'))+'}\nsha2="=0.10.9"\n[workspace]\n')
            command=[str(RUST_BIN/'cargo'),'test','--offline','--manifest-path',str(d/'Cargo.toml'),
                     '--target-dir',str(ROOT/'target/host-baseline-progress'),'--','--test-threads=1']
            def run(text,case=None):
                source.write_text(text)
                return subprocess.run(command+(['--exact',case] if case else []),cwd=ROOT,
                    env=env(),capture_output=True,text=True,timeout=120)
            result=run(code)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('10 passed',result.stdout)
            # Reproduce the lost service reason while preserving all credit/clock/closure rules.
            phases='Phase::Drain | Phase::CloseSources | Phase::Seal'
            self.assertEqual(code.count(phases),1)
            negative=run(code.replace(phases,'Phase::Drain'),'already_owned_source_gets_real_paid_progress')
            self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
            self.assertIn('real paid helper lost already-owned CloseSources progress',negative.stdout+negative.stderr)
            # A service reason must not acquire the separate queued-admission authority.
            pending='let pending = crate::learning_replay::admission_progress_pending();'
            self.assertEqual(code.count(pending),1)
            negative=run(code.replace(pending,'let pending = crate::learning_replay::baseline_activation_pending();'),
                         'close_and_seal_do_not_grant_ordinary_admission')
            self.assertNotEqual(negative.returncode,0,negative.stdout+negative.stderr)
            self.assertIn('CloseSources/Seal service hint granted extra ordinary admission',negative.stdout+negative.stderr)


if __name__=='__main__':unittest.main()
