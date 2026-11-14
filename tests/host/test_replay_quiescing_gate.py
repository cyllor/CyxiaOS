"""Execute the production Quiescing arm with controlled original gate inputs."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


class ReplayQuiescingGate(unittest.TestCase):
    def test_actual_gate_blocks_preserve_identity_and_short_circuit(self):
        root = (ROOT / 'kernel/src/runtime/control/domain_control/replay.rs').read_text()
        arm = function(function(root, 'pub fn poll(token:'), 'Phase::Quiescing =>')
        predicate = function((ROOT / 'kernel/src/runtime/control/domain_control.rs').read_text(),
                             'fn execution_blocks_replacement(')
        template = (ROOT / 'tests/host/replay_quiescing_harness.rs').read_text()
        code = template.replace('// ACTUAL_ARM', arm).replace('// ACTUAL_PREDICATE', predicate)
        code = code.replace('// BANK_MODULE', '#[path=' + json.dumps(str(ROOT / 'kernel/src/runtime/control/domain_control/replay/quiescing_diagnostic.rs')) + '] mod quiescing_diagnostic;')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source, binary = directory / 'gate.rs', directory / 'gate'
            source.write_text(code)
            built = subprocess.run([str(RUST_BIN/'rustc'), '--edition=2024', '--test',
                                    str(source), '-o', str(binary)], env=env(),
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run([str(binary), '--test-threads=1'], capture_output=True,
                                    text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('3 passed', result.stdout)
            # Removing the real publication hook must reproduce the original
            # missing-observation failure, rather than passing via test setup.
            self.assertGreater(arm.count('gate.publish();'), 0)
            source.write_text(code.replace('gate.publish();', ''))
            negative_build = subprocess.run([str(RUST_BIN/'rustc'), '--edition=2024', '--test',
                                            str(source), '-o', str(binary)], env=env(),
                                           capture_output=True, text=True, timeout=30)
            self.assertEqual(negative_build.returncode, 0, negative_build.stdout + negative_build.stderr)
            negative = subprocess.run([str(binary), '--test-threads=1'], capture_output=True,
                                      text=True, timeout=5)
            self.assertNotEqual(negative.returncode, 0, negative.stdout + negative.stderr)
            self.assertIn('actual desired gate was not retained', negative.stdout + negative.stderr)

    def test_actual_rotation_needs_64_paid_replay_pieces_for_512_slots(self):
        root = (ROOT / 'kernel/src/runtime/control/domain_control/replay.rs').read_text()
        execution = (ROOT / 'kernel/src/runtime/tasks/domain_tasks/execution.rs').read_text()
        arm = function(function(root, 'pub fn poll(token:'), 'Phase::Quiescing =>')
        service = function(execution, 'pub fn service(_now:')
        dispatch = function(service, 'if external == Ok(9)')
        # Only adapt the external callee to the actual extracted root poll;
        # dispatch condition and bounded root arm stay verbatim production.
        dispatch = dispatch.replace('crate::learning_replay::service_step()', 'poll(s, r, at)')
        import re
        rotation = re.search(r'let phase = s.service_phase;\s+s.service_phase = \(phase \+ 1\) % 11;', service)
        self.assertIsNotNone(rotation)
        predicate = function((ROOT / 'kernel/src/runtime/control/domain_control.rs').read_text(),
                             'fn execution_blocks_replacement(')
        code = (ROOT / 'tests/host/replay_quiescing_harness.rs').read_text()
        code = code.replace('// ACTUAL_ARM', arm).replace('// ACTUAL_PREDICATE', predicate)
        code = code.replace('// BANK_MODULE', '#[path=' + json.dumps(str(ROOT / 'kernel/src/runtime/control/domain_control/replay/quiescing_diagnostic.rs')) + '] mod quiescing_diagnostic;')
        code = code.replace('[Option<Desired>;16]', '[Option<Desired>;512]').replace('desired:[None;16]', 'desired:[None;512]')
        code = code.replace('struct State{job:', 'struct State{service_phase:usize,job:').replace('(State{job:', '(State{service_phase:0,job:')
        code += '\nfn real_rotation(s:&mut State,r:&mut Root,at:u64){' + rotation[0] + 'let external=Ok::<usize,Error>(phase);' + dispatch + '}\n'
        code += r'''#[test]fn paid_rotation_full_scan(){
            let(mut s,mut r)=setup();
            for turn in 1..=702 {real_rotation(&mut s,&mut r,turn*100_000_000);assert_eq!(r.phase,Phase::Quiescing);}
            assert_eq!(r.cursor,504);real_rotation(&mut s,&mut r,70_300_000_000);
            assert_eq!(r.phase,Phase::Scanning);assert_eq!(quiescing_diagnostic::snapshot()[4],64);
            println!("actual rotation: 703 paid service turns, 64 polls, no blockers, 70.3s at 100ms/caller");
        }'''
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary); source=directory/'rotation.rs'; binary=directory/'rotation'
            source.write_text(code)
            built=subprocess.run([str(RUST_BIN/'rustc'),'--edition=2024','--test',str(source),'-o',str(binary)],env=env(),capture_output=True,text=True,timeout=30)
            self.assertEqual(built.returncode,0,built.stdout+built.stderr)
            result=subprocess.run([str(binary),'--exact','paid_rotation_full_scan','--nocapture'],capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('703 paid service turns, 64 polls, no blockers',result.stdout)


if __name__ == '__main__': unittest.main()
