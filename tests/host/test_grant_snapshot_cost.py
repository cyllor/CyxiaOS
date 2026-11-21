"""Observe record traversal in the production snapshot body, not CPU timing.

The record container is an explicit observation seam. Actual ledger transitions
and independent record rescans are checked by kernel-core's own tests.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env
from test_governance_billing_priority import function


class GrantSnapshotCost(unittest.TestCase):
    def test_status_snapshot_does_not_traverse_grant_records(self):
        source = (ROOT / 'crates/kernel-core/src/grants.rs').read_text()
        snapshot = function(source, '    pub fn snapshot(')
        harness = r'''
#![allow(dead_code)]
use std::sync::atomic::{AtomicUsize, Ordering};

static READS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy)]
struct ResourceGrant {
    remaining: u32,
    in_use: u32,
}

struct Records(Vec<Option<ResourceGrant>>);
impl Records {
    fn iter(&self) -> std::slice::Iter<'_, Option<ResourceGrant>> {
        READS.fetch_add(self.0.len(), Ordering::SeqCst);
        self.0.iter()
    }
}

#[derive(Debug, PartialEq, Eq)]
struct LedgerSnapshot {
    capacity: u32,
    free: u32,
    reserved_unredeemed: u32,
    in_use: u32,
}

struct Ledger {
    capacity: u32,
    grants: Records,
    reserved_unredeemed: u32,
    in_use: u32,
}

impl Ledger {
    // SNAPSHOT
}

fn main() {
    let expected = LedgerSnapshot { capacity: 4096, free: 4070, reserved_unredeemed: 12, in_use: 14 };
    for size in [128, 1024] {
        let mut records = vec![None; size];
        records[0] = Some(ResourceGrant { remaining: 7, in_use: 3 });
        records[size - 1] = Some(ResourceGrant { remaining: 5, in_use: 11 });
        let ledger = Ledger {
            capacity: 4096, grants: Records(records), reserved_unredeemed: 12, in_use: 14,
        };
        READS.store(0, Ordering::SeqCst);
        for _ in 0..10 {
            assert_eq!(ledger.snapshot(), expected);
        }
        assert_eq!(READS.load(Ordering::SeqCst), 0, "status snapshot traversed grant records");
    }
}
'''
        with tempfile.TemporaryDirectory(prefix='cyxia-grant-snapshot-') as temporary:
            root = Path(temporary)
            code = root / 'snapshot.rs'
            binary = root / 'snapshot'
            code.write_text(harness.replace('    // SNAPSHOT', snapshot))
            built = subprocess.run([str(RUST_BIN / 'rustc'), '--edition=2024', str(code), '-o', str(binary)],
                                   env=env(), capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)


if __name__ == '__main__':
    unittest.main()
