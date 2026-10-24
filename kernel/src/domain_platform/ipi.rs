//! SGI0 is a wake notification for a fixed per-CPU mailbox. It never carries a
//! policy or substitutes for task/reference/DMA quiescence acknowledgements.
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_arch_aarch64::cpu;
use cyxia_driver_gicv2::Gic;
use cyxia_prototype::domains::{
    Error,
    platform::{IpiAck, IpiKey, IpiMailboxes, IpiProgress, IpiPublication, IpiResult},
};

const CPUS: usize = 8;
const WAKE_SGI: u8 = 0;
const SELFTEST: bool = include!(concat!(env!("OUT_DIR"), "/domain-selftest.rs"));
static TARGETS: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
static MAILBOXES: IpiMailboxes = IpiMailboxes::new();
static mut PROBE: Option<IpiKey> = None;
static mut PROBE_SEQUENCE: u64 = 0;
static mut PROBE_AT: u64 = 0;

#[repr(C, align(4096))]
pub struct IpiEvidence {
    words: [AtomicU64; 512],
}
#[used]
#[unsafe(no_mangle)]
pub static IPI_EVIDENCE: IpiEvidence = IpiEvidence {
    words: [const { AtomicU64::new(0) }; 512],
};
fn row(cpu: usize) -> usize {
    16 + cpu * 14
}
fn put(index: usize, value: u64) {
    IPI_EVIDENCE.words[index].store(value, Ordering::Release);
}
fn inc(index: usize) {
    IPI_EVIDENCE.words[index].fetch_add(1, Ordering::Relaxed);
}

/// Called on each actual CPU after attaching its own banked GIC interface.
/// Record hardware target bits instead of assuming logical-slot bit positions.
pub fn register_ipi_cpu(gic: &Gic, slot: usize) -> Result<(), Error> {
    if slot >= CPUS || cpu::slot() != slot {
        return Err(Error::Auth);
    }
    let target = u64::from(gic.local_target_mask().map_err(|_| Error::Unsupported)?);
    for (other, value) in TARGETS.iter().enumerate() {
        if other != slot && value.load(Ordering::Acquire) == target {
            return Err(Error::Conflict);
        }
    }
    match TARGETS[slot].compare_exchange(0, target, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {}
        Err(old) if old == target => {}
        Err(_) => return Err(Error::Conflict),
    }
    MAILBOXES.register(
        slot as u16,
        super::CORE_GENERATION.load(Ordering::Acquire).max(1),
    )?;
    gic.enable(u32::from(WAKE_SGI)).map_err(|_| Error::Io)?;
    put(row(slot) + 3, target);
    IPI_EVIDENCE.words[2].fetch_or(1 << slot, Ordering::Release);
    put(1, 1);
    put(0, 0x4359_4950_4900_0001);
    Ok(())
}

/// A topology epoch is a conservative generation for every registered CPU.
/// Updating it leaves all pending requests and sticky old ACKs intact.
pub(super) fn publish_generation(core: u64) -> Result<(), Error> {
    for (slot, target) in TARGETS.iter().enumerate() {
        if target.load(Ordering::Acquire) != 0 {
            MAILBOXES.register(slot as u16, core)?;
        }
    }
    put(3, core);
    Ok(())
}

pub fn request_ipi(key: IpiKey) -> Result<IpiProgress, Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    let target = TARGETS
        .get(usize::from(key.cpu))
        .ok_or(Error::Range)?
        .load(Ordering::Acquire);
    if target == 0 {
        return Err(Error::NotReady);
    }
    if key.cpu_generation != super::CORE_GENERATION.load(Ordering::Acquire) {
        return Err(Error::Stale);
    }
    match MAILBOXES.publish(key)? {
        IpiPublication::Existing(state) => Ok(state),
        IpiPublication::New => {
            let r = row(usize::from(key.cpu));
            put(r, key.request_id);
            put(r + 1, key.cpu_generation);
            put(r + 2, super::now_ns());
            // Never clear an ACK here: a delayed earlier SGI may already
            // have woken the receiver after this mailbox was published.
            crate::smp::gic()
                .send_sgi(WAKE_SGI, target as u8)
                .map_err(|_| Error::Io)?;
            inc(4);
            // A receiver may be publishing its ACK concurrently; acceptance
            // is already certain and must not be reported as an unowned Busy.
            Ok(IpiProgress::Pending)
        }
    }
}

/// Call from the real SGI0 exception branch after GIC EOI. No owner or policy
/// locks are taken here. A duplicate interrupt never repeats mailbox work.
pub fn ipi_enter(slot: usize) -> bool {
    if slot >= CPUS || cpu::slot() != slot {
        return false;
    }
    inc(5);
    let generation = super::CORE_GENERATION.load(Ordering::Acquire);
    let Some(ack) = MAILBOXES.receive(slot as u16, generation, super::now_ns()) else {
        inc(7);
        return false;
    };
    let r = row(slot);
    put(r + 5, ack.key.cpu_generation);
    put(r + 6, ack.observed_generation);
    put(r + 7, ack.completed_ns);
    put(
        r + 8,
        if ack.result == IpiResult::Observed {
            1
        } else {
            2
        },
    );
    put(r + 9, slot as u64);
    IPI_EVIDENCE.words[r + 12].fetch_add(1, Ordering::Relaxed);
    put(r + 4, ack.key.request_id);
    true
}
pub fn ipi_result(key: IpiKey) -> Result<IpiProgress, Error> {
    MAILBOXES.query(key)
}
pub fn consume_ipi(key: IpiKey) -> Result<IpiAck, Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    let ack = MAILBOXES.consume(key)?;
    let r = row(usize::from(key.cpu));
    if IPI_EVIDENCE.words[r + 10].load(Ordering::Acquire) != key.request_id
        || IPI_EVIDENCE.words[r + 11].load(Ordering::Acquire) != key.cpu_generation
    {
        put(r + 11, key.cpu_generation);
        put(r + 10, key.request_id);
        inc(6);
    }
    Ok(ack)
}

/// Optional native probe, using the same hardware and completion path as an
/// ordinary wake. It issues no replacement until the old receipt is consumed.
/// The hard per-CPU ticker is independent of this 100ms observation interval.
pub(super) fn probe_turn(now: u64) {
    if !SELFTEST || cpu::slot() != 0 {
        return;
    }
    if let Some(key) = unsafe { *core::ptr::addr_of!(PROBE) } {
        match ipi_result(key) {
            Ok(IpiProgress::Acknowledged(ack)) => {
                if ack.key != key {
                    put(13, 1);
                    return;
                }
                if ack.result == IpiResult::Observed
                    && ack.observed_generation != key.cpu_generation
                {
                    put(13, 2);
                    return;
                }
                if consume_ipi(key).is_err() {
                    return;
                }
                if ack.result == IpiResult::Observed {
                    inc(9);
                } else {
                    inc(10);
                }
                unsafe {
                    *core::ptr::addr_of_mut!(PROBE) = None;
                }
            }
            Ok(IpiProgress::Pending) | Err(Error::Busy) => return,
            Err(_) => {
                put(13, 3);
                return;
            }
        }
    }
    let generation = super::CORE_GENERATION.load(Ordering::Acquire);
    if generation == 0
        || TARGETS[3].load(Ordering::Acquire) == 0
        || now.saturating_sub(unsafe { *core::ptr::addr_of!(PROBE_AT) }) < 100_000_000
    {
        return;
    }
    let Some(request_id) = unsafe { *core::ptr::addr_of!(PROBE_SEQUENCE) }.checked_add(1) else {
        put(13, 4);
        return;
    };
    let key = IpiKey {
        request_id,
        cpu: 3,
        cpu_generation: generation,
    };
    match request_ipi(key) {
        Ok(_) | Err(Error::Io) => {
            // Even an uncertain MMIO attempt retains the original request.
            unsafe {
                *core::ptr::addr_of_mut!(PROBE) = Some(key);
                *core::ptr::addr_of_mut!(PROBE_SEQUENCE) = request_id;
                *core::ptr::addr_of_mut!(PROBE_AT) = now;
            }
            put(11, request_id);
            put(12, generation);
            inc(8);
        }
        Err(Error::Busy | Error::Again | Error::Stale | Error::NotReady) => {}
        Err(_) => put(13, 5),
    }
}
