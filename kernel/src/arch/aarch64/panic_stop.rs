//! Fixed four-core terminal stop coordination. Enter only after the vector
//! closes admission and installs the trusted local emergency stack.
use core::arch::asm;

#[cfg(all(
    feature = "v020-panic-stop-selftest",
    feature = "v020-production-diagnostic"
))]
compile_error!("panic-stop self-tests use the isolated resident SMP profile");

#[cfg(feature = "v020-production")]
use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "v020-production")]
use cyxia_arch_aarch64::{cpu, timer};
#[cfg(feature = "v020-production")]
use cyxia_driver_gicv2::{CpuTargets, Gic, IrqAck};

#[cfg(feature = "v020-production")]
const CORES: usize = 4;
#[cfg(feature = "v020-production")]
const ALL_CORES: u64 = (1 << CORES) - 1;
#[cfg(feature = "v020-production")]
const STOP_SGI: u8 = 15;
// Exactly one irreversible terminal stop per boot. This generation never
// reopens, wraps, or survives a fresh firmware entry.
#[cfg(feature = "v020-production")]
const GENERATION: u64 = 1;
#[cfg(feature = "v020-production")]
const WAIT_POLLS: u32 = 1 << 20;
#[cfg(feature = "v020-production")]
const NO_IRQ_TOKEN: u64 = 1023; // GICv2 spurious/no active interrupt.
#[cfg(feature = "v020-production")]
const OBSERVED_CLOSURE: u64 = 0x80; // vectors.S terminal entry marker.

#[cfg(feature = "v020-production")]
static TARGETS: CpuTargets = CpuTargets::new();

#[cfg(feature = "v020-production")]
#[repr(C)]
struct StopCpu {
    affinity: AtomicU64,
    target: AtomicU64,
    ack_token: AtomicU64,
    ack_affinity: AtomicU64,
    ack_ticks: AtomicU64,
    irq_token: AtomicU64,
}

#[cfg(feature = "v020-production")]
impl StopCpu {
    const fn empty() -> Self {
        Self {
            affinity: AtomicU64::new(0),
            target: AtomicU64::new(0),
            ack_token: AtomicU64::new(0),
            ack_affinity: AtomicU64::new(0),
            ack_ticks: AtomicU64::new(0),
            irq_token: AtomicU64::new(0),
        }
    }
}

#[cfg(feature = "v020-production")]
#[repr(C, align(4096))]
struct StopRecord {
    magic: AtomicU64,
    ready: AtomicU64,
    owner_token: AtomicU64,
    expected: AtomicU64,
    confirmed: AtomicU64,
    unknown: AtomicU64,
    result: AtomicU64,
    began: AtomicU64,
    ended: AtomicU64,
    frequency: AtomicU64,
    sent_targets: AtomicU64,
    cpus: [StopCpu; CORES],
}

#[cfg(feature = "v020-production")]
#[used]
#[unsafe(no_mangle)]
static CYXIA_STOP_EVIDENCE: StopRecord = StopRecord {
    magic: AtomicU64::new(0),
    ready: AtomicU64::new(0),
    owner_token: AtomicU64::new(0),
    expected: AtomicU64::new(0),
    confirmed: AtomicU64::new(0),
    unknown: AtomicU64::new(0),
    result: AtomicU64::new(0),
    began: AtomicU64::new(0),
    ended: AtomicU64::new(0),
    frequency: AtomicU64::new(0),
    sent_targets: AtomicU64::new(0),
    cpus: [const { StopCpu::empty() }; CORES],
};

#[cfg(feature = "v020-production")]
const _: () = {
    assert!(core::mem::size_of::<StopRecord>() == 4096);
    assert!(core::mem::offset_of!(StopRecord, cpus) == 88);
    assert!(core::mem::size_of::<StopCpu>() == 48);
};

/// A CPU registers its own hardware target and MPIDR after attaching its
/// banked GIC interface. A failed target registration leaves stop unavailable.
#[cfg(feature = "v020-production")]
pub(crate) fn register_cpu(gic: &Gic, slot: usize) {
    let Some(row) = CYXIA_STOP_EVIDENCE.cpus.get(slot) else {
        return;
    };
    if cpu::registered_slot() != Some(slot) {
        return;
    }
    let Ok(target) = gic.local_target_mask() else {
        return;
    };
    if TARGETS.register(slot, target).is_err() || gic.enable(u32::from(STOP_SGI)).is_err() {
        return;
    }
    row.affinity.store(cpu::affinity(), Ordering::Relaxed);
    row.target.store(u64::from(target), Ordering::Release);
}

/// CPU0 calls this only after acquiring the ordinary SMP online word. A
/// not-yet-registered system still closes admission and parks locally.
#[cfg(feature = "v020-production")]
pub(crate) fn publish_ready(online: u64) {
    let stop = &CYXIA_STOP_EVIDENCE;
    if online == ALL_CORES
        && stop
            .cpus
            .iter()
            .all(|row| row.target.load(Ordering::Acquire) != 0)
    {
        stop.magic.store(0x4359_5853_544f_5001, Ordering::Relaxed);
        stop.ready.store(1, Ordering::Release);
    }
}

#[cfg(feature = "v020-production")]
fn elect(candidate: u64) -> u64 {
    let owner = &CYXIA_STOP_EVIDENCE.owner_token;
    // Bounded weak CAS retries. An exclusive-monitor failure with no owner
    // leaves the caller parked and never replaces a published owner.
    for _ in 0..16 {
        match owner.compare_exchange_weak(0, candidate, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return candidate,
            Err(other) if other != 0 => return other,
            Err(_) => core::hint::spin_loop(),
        }
    }
    owner.load(Ordering::Acquire)
}

#[cfg(feature = "v020-production")]
fn await_owner(stop: &StopRecord, began: u64) -> u64 {
    let wait = timer::frequency() / 10;
    for _ in 0..WAIT_POLLS {
        let owner = stop.owner_token.load(Ordering::Acquire);
        if owner != 0 {
            return owner;
        }
        let now = timer::ticks();
        if now < began || now - began >= wait {
            break;
        }
        core::hint::spin_loop();
    }
    0
}

#[cfg(feature = "v020-production")]
fn publish_ack(row: &StopCpu, token: u64, affinity: u64, irq: u64) {
    // The vector has DAIF masked. Stop the local clock source and complete
    // ordered local memory/MMIO before making the terminal ACK observable.
    unsafe {
        cpu::disable_timer();
        asm!("dsb sy", "isb", options(nostack));
    }
    row.ack_affinity.store(affinity, Ordering::Relaxed);
    row.ack_ticks.store(timer::ticks(), Ordering::Relaxed);
    row.irq_token.store(irq, Ordering::Relaxed);
    row.ack_token.store(token, Ordering::Release);
}

#[cfg(feature = "v020-production")]
fn collect(stop: &StopRecord, token: u64, began: u64, until: u64) -> u64 {
    let mut mask = 0;
    for (slot, row) in stop.cpus.iter().enumerate() {
        if row.ack_token.load(Ordering::Acquire) == token
            && row.ack_affinity.load(Ordering::Relaxed) == row.affinity.load(Ordering::Relaxed)
            && (began..=until).contains(&row.ack_ticks.load(Ordering::Relaxed))
        {
            mask |= 1 << slot;
        }
    }
    mask
}

#[cfg(feature = "v020-production")]
fn coordinate(slot: usize, gic: &Gic, stop: &StopRecord, token: u64, began: u64) {
    let frequency = timer::frequency();
    let mut mask = 0;
    for (index, row) in stop.cpus.iter().enumerate() {
        if index != slot {
            mask |= row.target.load(Ordering::Relaxed) as u8;
        }
    }
    stop.expected.store(ALL_CORES, Ordering::Relaxed);
    stop.began.store(began, Ordering::Relaxed);
    stop.frequency.store(frequency, Ordering::Relaxed);
    // No ordinary service is resumed after this request or on timeout.
    if gic.send_sgi(STOP_SGI, mask).is_ok() {
        stop.sent_targets.store(u64::from(mask), Ordering::Relaxed);
    }
    let mut confirmed = 0;
    let wait_ticks = frequency / 10;
    if wait_ticks != 0
        && let Some(until) = began.checked_add(wait_ticks)
    {
        for _ in 0..WAIT_POLLS {
            let ended = timer::ticks();
            if ended < began || ended > until {
                break;
            }
            confirmed = collect(stop, token, began, until);
            if confirmed == ALL_CORES || ended == until {
                break;
            }
            core::hint::spin_loop();
        }
    }
    let ended = timer::ticks();
    if ended < began {
        confirmed = 0;
    }
    stop.ended.store(ended, Ordering::Relaxed);
    stop.confirmed.store(confirmed, Ordering::Relaxed);
    stop.unknown
        .store(ALL_CORES & !confirmed, Ordering::Relaxed);
    stop.result.store(
        if confirmed == ALL_CORES { 1 } else { 2 },
        Ordering::Release,
    );
}

/// SAFETY of entry is established by vectors.S: terminal DAIF mask and a
/// fresh trusted emergency SP. No ordinary locks, recovery, or resource
/// release are permitted from this entry, including after complete CPU ACKs.
#[unsafe(no_mangle)]
extern "C" fn exception_quiescent_stop(kind: u64) -> ! {
    #[cfg(feature = "v020-production")]
    {
        let stop = &CYXIA_STOP_EVIDENCE;
        // At this point an uninitialized or damaged CPU identity provides no
        // quiescence evidence. Never infer an ACK from admission closure.
        if stop.ready.load(Ordering::Acquire) != 1 {
            cyxia_stop_park()
        }
        let Some(slot) = cpu::registered_slot() else {
            cyxia_stop_park()
        };
        let Some(row) = stop.cpus.get(slot) else {
            cyxia_stop_park()
        };
        let affinity = cpu::affinity();
        if affinity != row.affinity.load(Ordering::Relaxed) {
            cyxia_stop_park()
        }
        // SAFETY: acquiring ready above also acquired every registered CPU's
        // GIC object. This is the local banked interface of the actual CPU.
        let Some(gic) = (unsafe { crate::smp::gic_for_terminal_stop(slot) }) else {
            cyxia_stop_park()
        };
        let began = timer::ticks();
        let candidate = (GENERATION << 8) | (slot as u64 + 1);
        let token = if kind & OBSERVED_CLOSURE != 0 {
            await_owner(stop, began)
        } else {
            elect(candidate)
        };
        if token >> 8 != GENERATION || !(1..=CORES as u64).contains(&(token & 0xff)) {
            cyxia_stop_park()
        }
        let irq = if matches!(kind & !OBSERVED_CLOSURE, 5 | 9) {
            // The emergency vector may have taken the stop IPI directly,
            // before ordinary interrupt dispatch had read this IAR.
            let ack = gic.acknowledge();
            gic.end(ack);
            match ack {
                IrqAck::Active { token, .. } => u64::from(token),
                IrqAck::Spurious => NO_IRQ_TOKEN,
            }
        } else {
            NO_IRQ_TOKEN
        };
        publish_ack(row, token, affinity, irq);
        if token == candidate {
            coordinate(slot, gic, stop, token, began);
        }
    }
    #[cfg(not(feature = "v020-production"))]
    let _ = kind;
    cyxia_stop_park()
}

#[inline(never)]
#[unsafe(no_mangle)]
extern "C" fn cyxia_stop_park() -> ! {
    // SAFETY: this path is terminal. Stay masked even if events wake WFE.
    unsafe {
        asm!(
            "msr daifset, #15",
            "2: wfe",
            "b 2b",
            options(nostack, noreturn)
        )
    }
}

#[cfg(feature = "v020-panic-stop-selftest")]
pub(crate) fn exercise() -> ! {
    unsafe extern "C" {
        fn cyxia_request_quiescent_stop() -> !;
    }
    // SAFETY: isolated four-core EL1 test, after normal healthy SMP startup.
    // Uses exactly the same terminal stop sequence as the protected vector.
    unsafe { cyxia_request_quiescent_stop() }
}

#[cfg(feature = "v020-panic-stop-late-selftest")]
pub(crate) fn hold_healthy_peer_until_result(slot: usize) {
    if slot != CORES - 1 {
        return;
    }
    // The healthy last peer explicitly defers its first IRQ enable until
    // the owner has sealed the result, then enters the same GIC path.
    // Never extend an owner's deadline or retain an unbounded test wait.
    let until = timer::ticks().saturating_add(timer::frequency());
    for _ in 0..WAIT_POLLS * 8 {
        if CYXIA_STOP_EVIDENCE.result.load(Ordering::Acquire) != 0 || timer::ticks() >= until {
            return;
        }
        core::hint::spin_loop();
    }
}
