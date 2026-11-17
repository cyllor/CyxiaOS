"""Execute actual code-permission wrappers and executable cleanup on host fixtures.

The production transaction helper, make_writable, publish_code and clear are read
from this checkout at test time. PTE/TLB operations and the owner ledger are
explicit test doubles; these tests do not execute an OS, replace real AP fences,
or prove the historical guest panic's cause. The host catches clear's fatal panic
only to verify that zeroing and release were not reached. The production kernel
terminates at that boundary; its already-taken lease Option is not misreported.

Run with the repository Rust toolchain on PATH. CYXIA_NATIVE_LOCK may select the
same explicit native lease used by another build coordinator; the default follows
the existing notification-launch host test's shared lease.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from doctor import env
from native_session import idle_native_host, native_lease
from test_governance_billing_priority import function

LOCK = Path(os.environ.get("CYXIA_NATIVE_LOCK", str(
    ROOT / "artifacts/v017-cosmic-completion-20261116/native-session.lock"))).expanduser().resolve()


def production_program():
    arch = (ROOT / "kernel/src/desktop/process_arch.rs").read_text()
    executable = (ROOT / "kernel/src/desktop/memory/exec_memory.rs").read_text()
    space = (ROOT / "crates/arch-x86_64/src/space.rs").read_text()
    pieces = {
        "@WRAPPERS@": "\n".join(function(arch, signature) for signature in (
            "pub fn make_writable(", "pub fn publish_code(")),
        "@CLEAR@": function(executable, "pub fn clear(&mut self)"),
        "@ERROR@": function(space, "pub enum Error {"),
        "@PAGE_BYTES@": re.search(r"pub const PAGE_BYTES: u64 = [^;]+;", space).group(),
        "@HELPER@": json.dumps(str(ROOT / "crates/arch-x86_64/src/code_permissions.rs"),
                              ensure_ascii=False),
    }
    program = HARNESS
    for marker, value in pieces.items():
        if program.count(marker) != 1:
            raise ValueError("Ambiguous production insertion: " + marker)
        program = program.replace(marker, value)
    return program, pieces


HARNESS = r'''
// Generated host-only integration harness. No fake hardware result is guest evidence.
#![allow(dead_code)] // Dependency/owner stubs deliberately expose the production shape.
use std::{cell::{Cell, RefCell}, rc::Rc};
pub const HIGH: u64 = 0; // The fixture's owned buffer is ordinary host memory.
#[derive(Debug, PartialEq, Eq)]
pub enum Errno { Fault, Io }
mod space {
    @PAGE_BYTES@
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    @ERROR@
}
#[path = @HELPER@]
mod code_permissions;
use code_permissions::{Backend, Pages, Phase};
use space::Error;

struct Hardware {
    base: u64, phase: [Phase; 3], pte: [bool; 3], local: [bool; 3], peer: [bool; 3],
    calls: usize, fail: Option<usize>,
}
impl Hardware {
    fn index(&self, p: u64) -> usize { ((p - self.base) / 4096) as usize }
    fn op(&mut self) -> Result<(), Error> {
        self.calls += 1;
        if self.fail == Some(self.calls) { Err(Error::Timeout) } else { Ok(()) }
    }
    fn zero_eligible(&self) -> bool {
        self.phase == [Phase::StableWritable; 3] && self.local == [true; 3] && self.peer == [true; 3]
    }
}
impl Backend for Hardware {
    fn phase(&self, p: u64) -> Phase { self.phase[self.index(p)] }
    fn record(&mut self, p: u64, phase: Phase) { let i = self.index(p); self.phase[i] = phase; }
    fn aliases(&self, _: u64) -> (u64, u64) { (0, 0) } // All old roots retired in this fixture.
    fn set_writable(&mut self, p: u64, writable: bool) -> Result<(), Error> {
        self.op()?;
        let i = self.index(p); self.pte[i] = writable;
        Ok(())
    }
    fn synchronize(&mut self) -> Result<(), Error> {
        self.local = self.pte; // BSP flush occurs even when remote ACK then fails.
        self.op()?;
        self.peer = self.pte;
        Ok(())
    }
}
thread_local! { static HARDWARE: RefCell<Option<Hardware>> = const { RefCell::new(None) }; }
fn with_hw<T>(f: impl FnOnce(&mut Hardware) -> T) -> T {
    HARDWARE.with(|h| f(h.borrow_mut().as_mut().unwrap()))
}
mod machine {
    pub mod runtime {
        use crate::*;
        pub fn is_user_code_writable(p: u64) -> bool {
            with_hw(|h| h.phase(p) == Phase::StableWritable)
        }
        pub unsafe fn seal_user_code(p: u64, length: usize) -> Result<(), Error> {
            with_hw(|h| code_permissions::seal(Pages::new(p, length, h.base + 12288)?, h))
        }
        pub unsafe fn unseal_user_code(p: u64, length: usize) -> Result<(), Error> {
            with_hw(|h| code_permissions::unseal(Pages::new(p, length, h.base + 12288)?, h))
        }
    }
}
#[unsafe(no_mangle)]
extern "C" fn x86_runtime_code_sealed(p: u64) -> bool {
    with_hw(|h| h.phase(p) == Phase::StableSealed)
}
mod process_arch {
    use crate::Errno;
    @WRAPPERS@
}
struct PageCount(u32);
struct ReleaseReceipt(u32, u32, PageCount);
impl ReleaseReceipt {
    unsafe fn after_revoke(id: u32, owner: u32, pages: PageCount) -> Self { Self(id, owner, pages) }
}
struct Ledger { charged: Rc<Cell<bool>>, releases: Rc<Cell<usize>> }
impl Ledger {
    fn release_completed(&mut self, receipt: ReleaseReceipt) -> Result<(), ()> {
        assert_eq!((receipt.0, receipt.1, receipt.2.0), (20, 10, 3));
        assert!(self.charged.replace(false));
        self.releases.set(self.releases.get() + 1);
        Ok(())
    }
}
struct Table { cleared: bool }
impl Table { fn clear(&mut self) { self.cleared = true; } }
enum Domain { Elf }
mod ai {
    pub struct Counter;
    impl Counter { pub fn release(&mut self, _: u64) {} }
    pub fn record(_: super::Domain, f: impl FnOnce(&mut Counter)) { f(&mut Counter); }
}
mod executable {
    use crate::{Ledger, Table, PageCount, ReleaseReceipt, Domain, ai};
    pub struct Image {
        pub lease: Option<(u32, u32)>, pub base: u64, pub pages: u32,
        pub tables: [Table; 1], pub stack_table: Table, pub ledger: Ledger,
        pub slots: [u16; 3], pub permissions: [u8; 3], pub model: u64,
    }
    impl Image { @CLEAR@ }
}
#[repr(align(4096))]
struct Buffer([u8; 12288]);
fn fixture(phase: Phase) -> (Box<Buffer>, executable::Image, Rc<Cell<bool>>, Rc<Cell<usize>>) {
    let mut buffer = Box::new(Buffer([0xa5; 12288]));
    let base = buffer.0.as_mut_ptr() as u64;
    let writable = phase == Phase::StableWritable;
    HARDWARE.with(|h| *h.borrow_mut() = Some(Hardware { base, phase: [phase; 3],
        pte: [writable; 3], local: [writable; 3], peer: [writable; 3], calls: 0, fail: None }));
    let charged = Rc::new(Cell::new(true)); let releases = Rc::new(Cell::new(0));
    let image = executable::Image { lease: Some((10, 20)), base, pages: 3,
        tables: [Table { cleared: false }], stack_table: Table { cleared: false },
        ledger: Ledger { charged: charged.clone(), releases: releases.clone() },
        slots: [1, 2, 3], permissions: [5; 3], model: 8197 };
    (buffer, image, charged, releases)
}

#[test]
fn actual_clear_repairs_failed_seal_before_zero_and_exactly_one_release() {
    let (buffer, mut image, charged, releases) = fixture(Phase::StableWritable);
    with_hw(|h| h.fail = Some(4)); // Three actual helper PTE updates, then ACK failure.
    assert_eq!(process_arch::publish_code(image.base, 12288), Err(Errno::Io));
    assert!(!with_hw(|h| h.zero_eligible()));
    assert!(!x86_runtime_code_sealed(image.base));
    with_hw(|h| h.fail = None);
    image.clear(); // Actual unchanged production clear, with actual candidate wrapper.
    assert!(with_hw(|h| h.zero_eligible()));
    assert!(buffer.0.iter().all(|b| *b == 0));
    assert!(!charged.get()); assert_eq!(releases.get(), 1);
    assert!(image.lease.is_none()); assert_eq!(image.pages, 0);
    image.clear(); assert_eq!(releases.get(), 1);
}

#[test]
fn actual_clear_failure_keeps_backing_charged_without_zero_or_release() {
    let (buffer, mut image, charged, releases) = fixture(Phase::StableWritable);
    with_hw(|h| h.fail = Some(4));
    assert_eq!(process_arch::publish_code(image.base, 12288), Err(Errno::Io));
    with_hw(|h| h.fail = Some(h.calls + 1)); // The first real recovery fence fails too.
    let fatal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| image.clear()));
    assert!(fatal.is_err()); // Production panic terminates the kernel, it does not unwind/retry.
    assert!(charged.get()); assert_eq!(releases.get(), 0);
    assert!(buffer.0.iter().all(|b| *b == 0xa5));
    assert!(!image.tables[0].cleared && !image.stack_table.cleared);
    assert!(image.lease.is_none()); // Preserve truthful existing lease.take semantics.
    assert_eq!(image.pages, 3);
    assert!(!x86_runtime_code_sealed(image.base));
    assert!(!machine::runtime::is_user_code_writable(image.base));
}

#[test]
fn actual_publish_cache_requires_every_page_stable_sealed() {
    let (_buffer, image, _, _) = fixture(Phase::StableWritable);
    with_hw(|h| { h.phase[0] = Phase::StableSealed; h.pte[0] = false; h.peer[0] = false; h.local[0] = false; });
    process_arch::publish_code(image.base, 12288).unwrap();
    assert_eq!(with_hw(|h| h.calls), 4);
    assert_eq!(with_hw(|h| h.phase), [Phase::StableSealed; 3]);
    assert_eq!(with_hw(|h| h.peer), [false; 3]);
}

#[test]
fn actual_unseal_final_fence_failure_cannot_be_cached_as_rx_or_writable() {
    let (_buffer, image, charged, _) = fixture(Phase::StableSealed);
    with_hw(|h| h.fail = Some(3)); // Per-page recovery: flush, PTE RW, failed final flush.
    assert_eq!(process_arch::make_writable(image.base, 12288), Err(Errno::Io));
    assert_eq!(with_hw(|h| h.pte[0]), true);
    assert!(!x86_runtime_code_sealed(image.base));
    assert!(!machine::runtime::is_user_code_writable(image.base));
    assert!(charged.get());
    with_hw(|h| h.fail = None);
    process_arch::publish_code(image.base, 12288).unwrap();
    assert_eq!(with_hw(|h| h.phase), [Phase::StableSealed; 3]);
    assert_eq!(with_hw(|h| h.pte), [false; 3]);
    assert_eq!(with_hw(|h| h.peer), [false; 3]);
}
'''


class CodePermissionTransactions(unittest.TestCase):
    def test_actual_wrappers_and_fatal_cleanup_boundaries(self):
        program, _ = production_program()
        environment = env()
        compiler = shutil.which("rustc", path=environment["PATH"])
        self.assertIsNotNone(compiler, "Repository Rust toolchain is required on PATH")
        LOCK.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="cyxia-code-permissions-") as temporary, native_lease(LOCK):
            idle_native_host()
            source = Path(temporary) / "transactions.rs"
            binary = Path(temporary) / "transactions-tests"
            source.write_text(program)
            compiled = subprocess.run(
                [compiler, "--edition=2024", "--test", "-Dwarnings", str(source), "-o", str(binary)],
                cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            # The helper's nine embedded tests belong to the crate's own suite;
            # this reusable test runs only the four actual-method integration cases.
            ran = subprocess.run([str(binary), "actual_", "--test-threads=1"],
                                 cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30)
            output = ran.stdout + ran.stderr
            self.assertEqual(ran.returncode, 0, output)
            self.assertIn("4 passed; 0 failed", output)


if __name__ == "__main__":
    unittest.main()
