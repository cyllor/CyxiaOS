// Diagnostic only. One writer per control CPU; no live Rust readers. The
// external decoder consumes a stopped snapshot and the release validity word.
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicU64, Ordering},
};
use cyxia_prototype::{
    domains::Error,
    policy::{self, PlanReceipt, PublicationTime},
};

const SCHEMA: u64 = 0x4359505542430001;
// Row ABI (all u64, little endian): 0 schema, 1 flags (stop/conflict/
// overflow/chronology = 1/2/4/8), 2 CPU, 3..10 identity, 11 carried debit,
// 12..13 start wall/CPU, 14 decode CPU, 15 Registry read count, 16..17 native
// precommit, 18..19 Registry return, 20 return kind (none/Err/refused/version),
// 21 version, 22 receipt error+1, 23..24 release, 25..26 original final sample,
// 27 cumulative CPU, 28 final cap error+1, 29..30 result version/error+1,
// 31..32 Registry/local stop, 33..42 original Registry wall/CPU samples,
// 43..45 returned PlanId, 46 precommit-present, 47..62 reserved, 63 validity.
// The five Registry samples are first validation, after prepare, after
// revalidation, after model authorization, and after retaining the receipt.
#[repr(C, align(64))]
struct Row {
    words: UnsafeCell<[u64; 63]>,
    published: AtomicU64,
}
unsafe impl Sync for Row {}
impl Row {
    const fn new() -> Self {
        Self {
            words: UnsafeCell::new([0; 63]),
            published: AtomicU64::new(0),
        }
    }
    fn get(&self, i: usize) -> u64 {
        unsafe { self.words.get().cast::<u64>().add(i).read_volatile() }
    }
    fn put(&self, i: usize, value: u64) {
        unsafe { self.words.get().cast::<u64>().add(i).write_volatile(value) }
    }
    fn flag(&self, flag: u64) {
        self.put(1, self.get(1) | flag);
    }
    fn sample(&self, i: usize, at: PublicationTime) {
        if at.cpu.cpu as u64 != self.get(2) {
            self.flag(2);
        }
        self.put(i, at.wall_ns);
        self.put(i + 1, at.cpu.ns);
    }
}
#[repr(C, align(64))]
struct Bank([Row; 2]);
#[used]
#[unsafe(no_mangle)]
static DOMAIN_PUBLICATION_COST: Bank = Bank([const { Row::new() }; 2]);
const _: () = assert!(core::mem::size_of::<Bank>() == 1024);

fn current(job: u64) -> Option<&'static Row> {
    let cpu = cyxia_arch_aarch64::cpu::slot();
    // This native worker profile dispatches only CPUs 1/2. Other CPU IDs are
    // absent diagnostic coverage, never permission failures or array indices.
    if !(1..=2).contains(&cpu) {
        return None;
    }
    let row = &DOMAIN_PUBLICATION_COST.0[cpu - 1];
    if row.get(0) != SCHEMA || row.get(1) & 1 != 0 {
        return None;
    }
    if row.get(5) != job {
        row.flag(2);
        return None;
    }
    Some(row)
}

/// identity: boot, controller, original Job sequence, target id/generation,
/// model generation, domain and kind. A stopped row is never overwritten.
pub fn begin(identity: [u64; 8], debit: policy::CpuTime, at: PublicationTime) {
    let cpu = cyxia_arch_aarch64::cpu::slot();
    if !(1..=2).contains(&cpu) {
        return;
    }
    let row = &DOMAIN_PUBLICATION_COST.0[cpu - 1];
    if row.get(1) & 1 != 0 {
        return;
    }
    row.published.store(0, Ordering::Release);
    for i in 0..63 {
        row.put(i, 0);
    }
    row.put(0, SCHEMA);
    row.put(2, cpu as u64);
    for (i, v) in identity.into_iter().enumerate() {
        row.put(i + 3, v);
    }
    row.put(11, debit.ns);
    row.sample(12, at);
    if debit.cpu != at.cpu.cpu {
        row.flag(2);
    }
}

/// Transparently preserves the Registry's existing five clock reads. No
/// additional Registry/owner query, or manufactured interval, is introduced.
pub struct Clock<'a, C> {
    pub inner: &'a mut C,
    pub job: u64,
}
impl<C: policy::Clock> policy::Clock for Clock<'_, C> {
    fn read(&mut self) -> PublicationTime {
        let at = self.inner.read();
        if let Some(row) = current(self.job) {
            let n = row.get(15);
            if n < 5 {
                row.sample(33 + n as usize * 2, at);
            } else {
                row.flag(4);
            }
            row.put(15, n.saturating_add(1));
        }
        at
    }
}
pub fn precommit(job: u64, at: PublicationTime) {
    if let Some(row) = current(job) {
        if row.get(46) != 0 {
            row.flag(2);
        }
        row.put(46, 1);
        row.sample(16, at);
    }
}
pub fn returned(job: u64, at: PublicationTime, result: Result<&PlanReceipt, Error>) {
    if let Some(row) = current(job) {
        row.sample(18, at);
        match result {
            Ok(receipt) => {
                row.put(20, if receipt.version == 0 { 2 } else { 3 });
                row.put(21, receipt.version);
                if let policy::ExecutionState::Failed(e) = receipt.state() {
                    row.put(22, e as u64 + 1);
                }
                let id = receipt.id;
                for (i, v) in [id.boot_epoch, id.controller_epoch, id.plan_seq]
                    .into_iter()
                    .enumerate()
                {
                    row.put(43 + i, v);
                }
                if [id.boot_epoch, id.controller_epoch, id.plan_seq]
                    != [row.get(3), row.get(4), job]
                {
                    row.flag(2);
                }
            }
            Err(e) => {
                row.put(20, 1);
                row.put(22, e as u64 + 1);
            }
        }
    }
}
pub fn released(job: u64, at: PublicationTime) {
    if let Some(row) = current(job) {
        row.sample(23, at);
    }
}
pub fn finish(
    job: u64,
    at: PublicationTime,
    decoded: u64,
    result: Result<u64, Error>,
    cap: Result<(), Error>,
    registry_stopped: bool,
    local_stop: bool,
) {
    if let Some(row) = current(job) {
        row.sample(25, at);
        row.put(14, decoded);
        let total = at
            .cpu
            .ns
            .checked_sub(row.get(13))
            .and_then(|v| v.checked_add(row.get(11)));
        row.put(27, total.unwrap_or(u64::MAX));
        if total.is_none() {
            row.flag(4);
        }
        row.put(28, cap.err().map_or(0, |e| e as u64 + 1));
        row.put(29, result.unwrap_or(0));
        row.put(30, result.err().map_or(0, |e| e as u64 + 1));
        row.put(31, u64::from(registry_stopped));
        row.put(32, u64::from(local_stop));
        // Check actual chronology, including the precommit sample interleaved
        // between Registry commit and finished reads. Invalid evidence stays
        // explicit; it never changes the protected result or cap.
        let mut last = (row.get(12), row.get(13));
        let n = row.get(15).min(5) as usize;
        for i in 0..n {
            let sample = (row.get(33 + i * 2), row.get(34 + i * 2));
            if sample.0 < last.0 || sample.1 < last.1 {
                row.flag(8);
            }
            last = sample;
        }
        if row.get(46) != 0
            && (n != 5
                || row.get(16) < row.get(39)
                || row.get(17) < row.get(40)
                || row.get(16) > row.get(41)
                || row.get(17) > row.get(42))
        {
            row.flag(8);
        }
        for i in [18, 23, 25] {
            let sample = (row.get(i), row.get(i + 1));
            if sample.0 < last.0 || sample.1 < last.1 {
                row.flag(8);
            }
            last = sample;
        }
        if registry_stopped || local_stop {
            row.flag(1);
        }
        row.published.store(job, Ordering::Release);
    }
}
