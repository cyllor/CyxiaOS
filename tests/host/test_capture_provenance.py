"""Actual collector diagnostics, with compile-valid negative controls."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from decode_capture_provenance import decode
from test_governance_billing_priority import function
import struct


class CaptureProvenance(unittest.TestCase):
    def test_decoder_rejects_foreign_or_concurrent_banks_and_reports_partial_scope(self):
        self.assertEqual(decode(bytes(1024)), {'present': False, 'attribution_complete': False})
        words = [0] * 128
        words[:14] = [0x4359535243450001, 1, 2, 7, 11, 5, 2, 1, 1, 0, 1, 1, 3, 2]
        words[16:40] = [99, 8, 13, 2, 2, 0, 1, 37, 100, 137, 100, 137,
                        0x10a, 0, 0, 0, 0, 0, 0, 0, 0, 100, 137, 1]
        packed = lambda: struct.pack('<128Q', *words)
        result = decode(packed(), (7, 11, 5))
        self.assertFalse(result['attribution_complete'])
        self.assertEqual(result['bucket_overflow_calls'], 1)
        self.assertEqual(result['sources'][0]['original_owner'], [99, 8])
        self.assertEqual(result['sources'][0]['resolved_source'], [13, 2])
        self.assertIsNone(result['sources'][0]['task_identity'])
        words[14] = 2
        words[112:128] = [13, 2, 13, 2, 2 | (3 << 16), 100, 137, 0x10a,
                          1, 2, 77, 8, 9, 4097, 6, 2]
        sample = decode(packed(), (7, 11, 5))['overflow_sample']
        self.assertTrue(sample['frozen_at_capacity'])
        self.assertEqual(sample['core'], 3)
        self.assertEqual(sample['task_identity']['caller'], [77, 8])
        words[14] = 0
        with self.assertRaisesRegex(ValueError, 'run identity mismatch'):
            decode(packed(), (7, 11, 6))
        words[2] = 3
        with self.assertRaisesRegex(ValueError, 'concurrent'):
            decode(packed())
        words[2] = 4
        words[10] = 0
        with self.assertRaisesRegex(ValueError, 'overflow accounting'):
            decode(packed())

    def test_actual_collector_counterexamples_compile_and_fail_behaviorally(self):
        original = (ROOT / 'kernel/src/learning_evidence/provenance.rs').read_text()
        bridge = (ROOT / 'kernel/src/learning_evidence.rs').read_text()
        harness = (ROOT / 'crates/prototype/tests/native_capture_provenance.rs').read_text()
        execution = (ROOT / 'kernel/src/domain_tasks/execution.rs').read_text()
        # Exercise the actual TaskGuard-owned cleanup wrapper and identity copy.
        # Physical cleanup and replay membership are controlled boundaries; the
        # true collector, source lookup, clocks and interval store remain real.
        start = harness.index('            bridge::measure_task(')
        end = harness.index('            assert_eq!(', start)
        harness = harness[:start] + '            assert_eq!(task_boundary::cleanup_example(), Ok(()));\n' + harness[end:]
        harness += '''
mod task_boundary {
    use cyxia_prototype::domains::{Error,ObjectKey};
    struct Task {parent:ObjectKey,spawn_id:u64,key:ObjectKey,recipe:u16}
    struct State {tasks:[Task;1]}
    mod replay {
        use super::*;
        pub fn work_source(parent:ObjectKey,id:u64,recipe:u16)->Option<ObjectKey> {
            (parent==ObjectKey{id:70,generation:8} && id==9 && recipe==2)
                .then_some(ObjectKey{id:13,generation:1})
        }
    }
    fn cleanup_inner(_: &mut State,_:usize)->Result<(),Error> {
        crate::domain_platform::at(crate::OBS+200_000_037); Ok(())
    }
    pub fn cleanup_example()->Result<(),Error> {
        let mut state=State{tasks:[Task{parent:ObjectKey{id:70,generation:8},spawn_id:9,
            key:ObjectKey{id:4097,generation:6},recipe:2}]};
        cleanup(&mut state,0)
    }
'''+function(execution,'fn capture_task_identity(')+'\n'+function(execution,'fn cleanup(')+'\n}\n'
        harness = harness.replace('crate::learning_evidence::', 'crate::bridge::')
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            bank = folder / 'provenance.rs'
            evidence = folder / 'learning_evidence.rs'
            bridge = bridge.replace('"learning_evidence/', '"' + str(ROOT / 'kernel/src/learning_evidence') + '/')
            bridge = bridge.replace(str(ROOT / 'kernel/src/learning_evidence/provenance.rs'), str(bank))
            evidence.write_text(bridge)
            harness = harness.replace('"../../../kernel/src/domain_tasks/cancellation.rs"',
                                      json.dumps(str(ROOT / 'kernel/src/domain_tasks/cancellation.rs')))
            harness = harness.replace('"../../../kernel/src/learning_evidence.rs"', json.dumps(str(evidence)))
            (folder / 'test.rs').write_text(harness)
            (folder / 'Cargo.toml').write_text(
                '[package]\nname="capture-provenance-counterexamples"\nversion="0.1.0"\nedition="2024"\n'
                '[[test]]\nname="provenance"\npath="test.rs"\n[dependencies]\ncyxia-prototype={path='
                + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline', '--manifest-path',
                       str(folder / 'Cargo.toml'), '--target-dir',
                       str(ROOT / 'target/host-capture-provenance'), '--', '--nocapture']
            def run(source):
                bank.write_text(source)
                return subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                                      text=True, timeout=120)
            result = run(original)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            mutations = [
                (original.replace('let b = &TRACE_SOURCE_EVIDENCE;', 'return;\n    let b = &TRACE_SOURCE_EVIDENCE;'),
                 'source provenance lost the original full RunKey'),
                (original.replace('e.owner.id,', 'e.source.id,'),
                 'original child and resolved source must stay distinct'),
                (original.replace('let b = &TRACE_SOURCE_EVIDENCE;',
                                  'let _ = crate::domain_platform::now_ns();\n    let b = &TRACE_SOURCE_EVIDENCE;'),
                 'diagnostics added a clock read'),
                (original.replace('i.caller.generation,', '0,'),
                 'left == right'),
            ]
            for source, failure in mutations:
                self.assertNotEqual(source, original)
                result = run(source)
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, output)
                self.assertIn('Finished `test`', output, 'negative control must compile: ' + output)
                self.assertIn(failure, output)
            wrong_caller = harness.replace('caller: task.parent,', 'caller: task.key,')
            self.assertNotEqual(wrong_caller, harness)
            (folder / 'test.rs').write_text(wrong_caller)
            result = run(original)
            output = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0, output)
            self.assertIn('Finished `test`', output)
            self.assertIn('TaskGuard caller/request/child identity was not copied', output)
            (folder / 'test.rs').write_text(harness)
            result = run(original)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
