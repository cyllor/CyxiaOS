//! Cumulative CPU0-foreground receipts, independent of reusable process slots.
use core::fmt::Write;
use cyxia_ai_runtime::accounting::{Attempt, Counters, Outcome};
use cyxia_posix::Errno;

#[derive(Clone, Copy)]
#[repr(usize)]
#[allow(dead_code)] // Stable output schema also exposes zero counts for unbuilt ported domains.
pub(crate) enum Domain {
    CpuProcess,
    CpuThread,
    CpuQuantum,
    Process,
    Thread,
    Anonymous,
    Elf,
    SpawnReceipt,
    Unix,
    Pipe,
    Pty,
    AncillaryMessages,
    AncillaryReferences,
    SharedPages,
    SharedObjects,
    SharedMappings,
}
const NAMES: [&str; 16] = [
    "cpu_process",
    "cpu_thread",
    "cpu_quantum",
    "process",
    "thread",
    "anonymous",
    "elf",
    "spawn_receipt",
    "unix",
    "pipe",
    "pty",
    "ancillary_messages",
    "ancillary_references",
    "shared_pages",
    "shared_objects",
    "shared_mappings",
];
static mut COUNTERS: [Counters; 16] = [Counters::ZERO; 16];
const _: () = assert!(core::mem::size_of::<[Counters; 16]>() <= 4096);

// Only CPU0 foreground calls these functions. IRQ handlers never read/write the
// object. The closure cannot retain a reference; no policy or callback runs here.
pub(crate) fn record(domain: Domain, update: impl FnOnce(&mut Counters)) {
    unsafe {
        update(&mut (*core::ptr::addr_of_mut!(COUNTERS))[domain as usize]);
    }
}
pub(crate) fn admission<T>(domain: Domain, attempt: Attempt, result: &Result<T, Errno>) {
    let (outcome, errno) = match result {
        Ok(_) => (Outcome::Committed, 0),
        Err(error) => {
            let outcome = if attempt.evaluated && !attempt.approved {
                Outcome::Denied
            } else if attempt.proposed {
                Outcome::Failed
            } else {
                match error {
                    Errno::Nomem | Errno::Again | Errno::Busy => Outcome::Capacity,
                    Errno::Inval
                    | Errno::Nosys
                    | Errno::Perm
                    | Errno::Access
                    | Errno::Fault
                    | Errno::Noent
                    | Errno::Badf => Outcome::Invalid,
                    _ => Outcome::Failed,
                }
            };
            (outcome, *error as u64)
        }
    };
    record(domain, |c| c.admission(attempt, outcome, errno));
}
pub(super) fn status(out: &mut impl Write) {
    // A bounded foreground copy is coherent on the current single-core target.
    let snapshot = unsafe { *core::ptr::addr_of!(COUNTERS) };
    for (name, c) in NAMES.into_iter().zip(snapshot) {
        writeln!(out, "AI_DOMAIN name={name} requests={} proposals={} approved={} denied={} capacity={} invalid={} failed={} committed={} granted={} released={} grant_units={} release_units={} ai={} guard={} cancelled={} enters={} returns={} elapsed_ms={} last_model={} last_errno={}\r", c.requests, c.proposals, c.approved, c.denied, c.capacity, c.invalid, c.failed, c.committed, c.granted, c.released, c.grant_units, c.release_units, c.ai, c.guard, c.cancelled, c.enters, c.returns, c.elapsed_ms, c.last_model, c.last_errno).unwrap();
    }
    writeln!(
        out,
        "AI_SCOPE name=native_ipc policy=operator_test_mechanism online_learning=false\r"
    )
    .unwrap();
}
