"""Actual ordinary source poll, original PMCC samples, observer and real debit."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import struct

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function
from decode_capture_provenance import decode


class WorkloadPollPaidCost(unittest.TestCase):
    def test_site6_decoder_keeps_unknown_identity_and_rejects_foreign_fields(self):
        words = [0] * 128
        words[:12] = [0x4359535243450001, 2, 2, 7, 11, 5, 1, 1, 0, 1, 0, 1]
        words[16:28] = [0x5245504c4159, 1, 0x5245504c4159, 1, 2, 0, 6, 1, 100, 100, 1, 0]
        packed = lambda w: struct.pack('<128Q', *w)
        result = decode(packed(words), (7, 11, 5))
        self.assertIsNone(result['sources'][0]['task_identity'])
        self.assertFalse(result['admission_known']); self.assertFalse(result['completion_known'])
        self.assertFalse(result['attribution_complete'])
        repeated = words.copy(); repeated[6] = repeated[7] = repeated[23] = 10
        with self.assertRaises(ValueError): decode(packed(repeated))
        for at, value in [(22, 1), (22, 7), (22, 0), (21, 3), (34, 1), (13, 1), (15, 1), (40, 1), (112, 1), (27, 2), (28, 9), (4, 0), (5, 0)]:
            bad = words.copy(); bad[at] = value
            with self.subTest(at=at, value=value), self.assertRaises(ValueError): decode(packed(bad))
        # Full caller/request/child identities remain accepted for sites2..4;
        # the ordinary poll must never invent one, even a well-formed one.
        known = words.copy(); known[9] = 0; known[27:34] = [1, 70, 8, 9, 4097, 6, 0]
        with self.assertRaises(ValueError): decode(packed(known))
        known[22] = 2
        self.assertEqual(decode(packed(known))['sources'][0]['task_identity'],
                         {'caller': [70, 8], 'request': 9, 'child': [4097, 6], 'recipe': 0})
        for at in range(28, 33):
            bad = known.copy(); bad[at] = 0
            with self.subTest(incomplete_identity=at), self.assertRaises(ValueError): decode(packed(bad))
        # Four buckets and the bounded overflow sample obey identical site6
        # identity rules and preserve all original reserved-field checks.
        overflow = words.copy(); overflow[6:12] = [5, 5, 0, 5, 1, 4]; overflow[14] = 1
        for i, site in enumerate([2, 3, 4], 1):
            overflow[16+i*24:40+i*24] = words[16:40]; overflow[22+i*24] = site
        overflow[112:128] = [0x5245504c4159, 1, 0x5245504c4159, 1, 2, 0, 6, 200, 1, 0, 0, 0, 0, 0, 0, 0]
        # Distinct offered source prevents duplicate producer-key overflow.
        overflow[112] = overflow[114] = 99
        self.assertIsNone(decode(packed(overflow))['overflow_observation']['task_identity'])
        for site in [0, 1, 7]:
            bad = overflow.copy(); bad[118] = site
            with self.subTest(overflow_site=site), self.assertRaises(ValueError): decode(packed(bad))
        bad = overflow.copy(); bad[121:128] = [1, 70, 8, 9, 4097, 6, 0]; bad[9] = 4
        with self.assertRaises(ValueError): decode(packed(bad))

    def test_actual_poll_cost_and_compile_valid_late_observer_counterexamples(self):
        bridge = (ROOT / 'kernel/src/learning_evidence.rs').read_text()
        provenance = (ROOT / 'kernel/src/learning_evidence/provenance.rs').read_text()
        owner = (ROOT / 'kernel/src/learning_workload/owner.rs').read_text()
        tasks = (ROOT / 'kernel/src/domain_tasks.rs').read_text()
        # Reuse installation/roster/export clock fixture, never its old cleanup
        # body or its test. The dedicated source body below is actual poll().
        fixture = (ROOT / 'tests/host/capture_paid_cost_harness.rs').read_text().split('mod paid {', 1)[0]
        fixture = fixture.replace('owner: key(11 + class as u64),',
                                  'owner: if class == CpuClass::ExecutorWork { WORK_OWNER } else { key(11 + class as u64) },')
        fixture = fixture.replace('allowed_cores: 1,', 'allowed_cores: 9,')
        fixture = fixture.replace('pub(crate) use super::cancellation::Cancellation;', '''pub(crate) use super::cancellation::Cancellation;
    pub mod replay { pub fn within_work<R>(body: impl FnOnce()->R)->R {
        crate::dependency_cost(5); let result=body(); crate::dependency_cost(7); result
    }}''')
        fixture = fixture.replace('pub fn reads() -> usize {', '''pub mod irq_replay {
        pub fn poll(_: crate::RunKey)->Result<(),cyxia_prototype::domains::Error> {panic!("file dependency outside family1 fixture")}
    }
    pub fn reads() -> usize {''')
        program = (ROOT / 'tests/host/workload_poll_paid_cost_harness.rs').read_text()
        program = program.replace('// COLLECTOR_FIXTURE', fixture)
        queue = '\n'.join(function(owner, s) for s in ['enum Phase', 'struct Request'])
        queue = queue.replace('enum Phase', '#[derive(Clone,Copy,PartialEq,Eq)] enum Phase')
        queue = queue.replace('struct Request', '#[derive(Clone,Copy)] struct Request')
        queue += '\nconst EMPTY: Request = Request { phase: Phase::Queued, outcome: RequestResult::Pending, reported: false, armed: false };'
        program = program.replace('// ACTUAL_QUEUE_TYPES', queue)
        check = function(owner, 'fn owner()').replace('    if cyxia_arch_aarch64::cpu::slot()', '    dependency_cost(3);\n    if cyxia_arch_aarch64::cpu::slot()')
        program = program.replace('// ACTUAL_OWNER_CHECK', check)
        program = program.replace('// ACTUAL_POLL', function(owner, 'pub fn poll('))
        samples = '\n'.join(function(tasks, s) for s in ['pub fn service_segment<R>', 'pub(crate) fn finish_cpu_interval('])
        program = program.replace('// ACTUAL_SERVICE_SAMPLES', samples)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            bank, evidence, harness = [directory / n for n in ['provenance.rs', 'learning_evidence.rs', 'harness.rs']]
            bridge = bridge.replace('"learning_evidence/', '"' + str(ROOT / 'kernel/src/learning_evidence') + '/')
            bridge = bridge.replace(str(ROOT / 'kernel/src/learning_evidence/provenance.rs'), str(bank))
            signature = 'pub(super) fn observed(e: Observation) {'
            self.assertIn(signature, provenance)
            bank.write_text(provenance.replace(signature, signature + '\n    crate::recorder_cost();'))
            program = program.replace('"../../../kernel/src/domain_tasks/cancellation.rs"', json.dumps(str(ROOT / 'kernel/src/domain_tasks/cancellation.rs')))
            program = program.replace('"../../../kernel/src/learning_evidence.rs"', json.dumps(str(evidence)))
            (directory / 'Cargo.toml').write_text('[package]\nname="workload-poll-paid-cost"\nversion="0.1.0"\nedition="2024"\n[[test]]\nname="poll-paid-cost"\npath="harness.rs"\n[dependencies]\ncyxia-prototype={path=' + json.dumps(str(ROOT / 'crates/prototype')) + '}\n[workspace]\n')
            command = [str(RUST_BIN / 'cargo'), 'test', '--offline', '--manifest-path', str(directory / 'Cargo.toml'), '--target-dir', str(ROOT / 'target/host-workload-poll-paid-cost'), '--', '--nocapture']
            def run(case, source=bridge, code=program):
                evidence.write_text(source); harness.write_text(code)
                environment = env(); environment['CYXIA_POLL_CASE'] = case
                return subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=120)
            for case in ['poll', 'gap', 'dependencies', 'noattempt', 'noncpu0', 'contended', 'invalidsite']:
                with self.subTest(case=case):
                    result = run(case)
                    self.assertEqual(result.returncode, 0, case + '\n' + result.stdout + result.stderr)
            # Both mutations still execute the actual observer; only its paid
            # placement moves. Their failure must be behavioral after compile.
            helper = function(bridge, 'pub(crate) fn measure_paid_task<R>')
            sample = 'let (first_ns, last_ns, _) = finish_cpu_interval(cpu_started);'
            late = helper.replace('let result = body(entry);', 'let result = body(None);')
            late = late.replace(sample, sample + '\n    observe_paid_entry(&attempt, cpu_started, || (6, None));')
            service = function(program, 'pub fn service_segment<R>')
            ledger_sample = 'let (_, finished_ns, actual_ns) = finish_cpu_interval(started);'
            delayed = service.replace(ledger_sample, ledger_sample + '\n    crate::bridge::measure_paid_task(crate::WORK_OWNER, cyxia_prototype::learning::reward::CpuClass::ExecutorWork, |entry| { if let Some(entry) = entry { entry.observe_workload_poll(); } });')
            # Late-ledger case removes the original call and adds it after the
            # original finisher but before complete_service(actual_ns,...).
            opt_in = 'if let Some(entry) = entry {\n            entry.observe_workload_poll();\n        }'
            if opt_in not in program:
                return  # Pre-feature RED is the compiled missing observation.
            self.assertEqual(program.count(opt_in), 1)
            no_original = program.replace(opt_in, '').replace(service, delayed)
            for source, code, failure in [
                (bridge.replace(helper, late), program, 'recorder17ns escaped original physical poll interval'),
                (bridge, no_original, 'recorder17ns escaped actual submitted Scheduler debit'),
            ]:
                result = run('poll', source, code); output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, output)
                self.assertIn('Finished `test`', output, 'counterexample must compile: ' + output)
                self.assertIn(failure, output)
                evidence_lines = [line for line in output.splitlines()
                                  if 'Finished `test`' in line or failure in line or 'left:' in line or 'right:' in line]
                print('EXPECTED-FAIL: ' + '\n'.join(evidence_lines))
            result = run('gap')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
