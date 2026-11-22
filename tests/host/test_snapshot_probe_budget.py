"""The opt-in native diagnostic binds a failure to its submitted CPU0 bill."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_a01_formal_recorder import function


class SnapshotProbeBudget(unittest.TestCase):
    def test_deferred_settlement_keeps_the_first_submitted_stage(self):
        runtime = (ROOT / 'kernel/src/runtime/cluster/unified.rs').read_text()
        execution = (ROOT / 'kernel/src/runtime/tasks/domain_tasks/execution.rs').read_text()
        start = execution.index('static SNAPSHOT_PROBE_EVIDENCE:')
        bank = execution[start:execution.index('\n];', start) + 3]
        source = r'''
use std::sync::atomic::{AtomicU64, Ordering};
mod cpu { pub fn slot() -> usize { 0 } }
mod unified {
    use super::*;
    use std::cell::UnsafeCell;
    struct ServiceStage(UnsafeCell<u64>);
    unsafe impl Sync for ServiceStage {}
    static UNIFIED_SERVICE_STAGE: ServiceStage = ServiceStage(UnsafeCell::new(0));
    struct Evidence { words: [AtomicU64; 512] }
    static UNIFIED_EVIDENCE: Evidence = Evidence {
        words: [const { AtomicU64::new(0) }; 512],
    };
    // STAGE_FUNCTIONS
}
mod execution {
    use super::*;
    // BANK
    // RECORD_FUNCTION
    pub fn check() {
        assert_eq!(std::mem::size_of_val(&SNAPSHOT_PROBE_EVIDENCE), 128);
        assert_eq!(SNAPSHOT_PROBE_EVIDENCE[1].load(Ordering::Acquire), 2);
        // The actor identity/outcome words are independent of failure capture.
        SNAPSHOT_PROBE_EVIDENCE[4].store(4096, Ordering::Release);
        SNAPSHOT_PROBE_EVIDENCE[5].store(7, Ordering::Release);
        unified::service_stage(200);
        unified::capture_service_completion_stage();
        // Another caller may update the current stage while the task gate
        // defers authoritative settlement of the already submitted bill.
        unified::service_stage(61);
        snapshot_probe_service_overrun(19, 2_600_000, 2_500_000);
        let first = [200, 19, 2_600_000, 2_500_000];
        for (i, expected) in first.into_iter().enumerate() {
            assert_eq!(SNAPSHOT_PROBE_EVIDENCE[12 + i].load(Ordering::Acquire), expected);
        }
        unified::service_stage(75);
        unified::capture_service_completion_stage();
        snapshot_probe_service_overrun(20, 3_000_000, 2_500_000);
        for (i, expected) in first.into_iter().enumerate() {
            assert_eq!(SNAPSHOT_PROBE_EVIDENCE[12 + i].load(Ordering::Acquire), expected);
        }
        assert_eq!(SNAPSHOT_PROBE_EVIDENCE[4].load(Ordering::Acquire), 4096);
        assert_eq!(SNAPSHOT_PROBE_EVIDENCE[5].load(Ordering::Acquire), 7);
        assert_eq!(SNAPSHOT_PROBE_EVIDENCE[6].load(Ordering::Acquire), 0);
    }
}
fn main() { execution::check(); println!("DEFERRED_BUDGET_STAGE PASS"); }
'''
        source = source.replace('// STAGE_FUNCTIONS', '\n'.join(function(runtime, name) for name in [
            'pub(crate) fn service_stage(', 'pub(crate) fn current_service_stage(',
            'pub(crate) fn capture_service_completion_stage(',
            'pub(crate) fn completed_service_stage(',
        ]))
        source = source.replace('// BANK', bank)
        source = source.replace('// RECORD_FUNCTION', function(
            execution, 'pub(super) fn snapshot_probe_service_overrun('))
        with tempfile.TemporaryDirectory(prefix='snapshot-probe-budget-') as temporary:
            path = Path(temporary) / 'harness.rs'
            binary = Path(temporary) / 'harness'
            path.write_text(source)
            result = subprocess.run([
                str(RUST_BIN / 'rustc'), '--edition=2024', str(path), '-o', str(binary),
            ], env=env(), capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('DEFERRED_BUDGET_STAGE PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
