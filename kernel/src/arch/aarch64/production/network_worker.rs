//! Scheduler and ownership handoff for the authorized network service.
use super::net_resident::Resident;
use super::{ONLINE, cpu, now_ns, timer};
use crate::smp::GATES;
use core::{
    mem::MaybeUninit,
    ptr::addr_of_mut,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use cyxia_kernel_core::{
    control_plane::{
        Error, Plane,
        cpu0_v0199::{BUSINESS_MASK, CONTROL_WINDOW_NS as WINDOW_NS},
        dispatch::Token,
    },
    security::process::authorize_business_core,
};
use cyxia_prototype::domains::{
    ObjectKey,
    tasks::{CpuLayout, Dispatch, RunState, Scheduler, ThreadSpec},
};

pub(crate) const CPU: usize = 1;
pub(super) const BUDGET_NS: u64 = 20_000_000;
pub(super) const MAX_SLICE_NS: u64 = 6_000_000;
const EXIT_MARGIN_NS: u64 = 350_000;
const POLL_NS: u64 = 2_000_000;
const CLOSED: u64 = u64::MAX;

static PREPARED: AtomicU64 = AtomicU64::new(0);
static PUBLISHED: AtomicU64 = AtomicU64::new(0);
static IDLE_ARMED: AtomicBool = AtomicBool::new(false);
#[unsafe(link_section = ".bss.sec_n")]
static mut ENGINE: MaybeUninit<Resident> = MaybeUninit::uninit();
#[cfg(not(cyxia_business_package))]
static mut SCHEDULER: Scheduler = Scheduler::new();

pub(super) fn stage(epoch: u64, mut engine: Resident) -> Result<(), Error> {
    if cpu::slot() != 0
        || epoch == 0
        || epoch == CLOSED
        || PUBLISHED.load(Ordering::Acquire) != 0
        || PREPARED.load(Ordering::Acquire) != 0
    {
        engine.stop();
        return Err(Error::Denied);
    }
    // SAFETY: CPU0 is the only initializer. CPU1 may borrow the engine only
    // after this stage is published as a business dispatch generation.
    unsafe { (*addr_of_mut!(ENGINE)).write(engine) };
    PREPARED.store(epoch, Ordering::Release);
    Ok(())
}

pub(super) fn staged(epoch: u64) -> bool {
    epoch != 0 && PREPARED.load(Ordering::Acquire) == epoch
}

#[cfg(cyxia_business_package)]
pub(super) fn running_on(slot: usize, epoch: u64) -> bool {
    slot == CPU && PUBLISHED.load(Ordering::Acquire) == epoch
}

pub(super) fn thread(epoch: u64) -> ObjectKey {
    ObjectKey {
        id: 0x200,
        generation: epoch,
    }
}

pub(super) fn admit(scheduler: &mut Scheduler, placement: CpuLayout) -> Result<(), Error> {
    let epoch = placement.generation;
    if cpu::slot() != 0 || !staged(epoch) {
        return Err(Error::Denied);
    }
    authorize_business_core(
        CPU as u16,
        epoch,
        placement.business_mask,
        placement.healthy_mask,
        0,
        scheduler.stats().quarantine_mask,
    )
    .map_err(|_| Error::Denied)?;
    // The combined profile uses a separate fairness group for ordinary
    // business work and the network service.
    let group = ObjectKey {
        id: if cfg!(cyxia_business_package) {
            0x101
        } else {
            0x100
        },
        generation: epoch,
    };
    scheduler.register_group(group).map_err(|_| Error::Denied)?;
    scheduler
        .admit(
            ThreadSpec {
                key: thread(epoch),
                group,
                cpu: CPU as u16,
                allowed_mask: 1 << CPU,
                minimum_ns: 0,
                budget_ns: BUDGET_NS,
            },
            placement,
            now_ns(),
        )
        .map_err(|_| Error::Denied)
}

pub(super) fn publish(epoch: u64) {
    if staged(epoch) {
        PUBLISHED.store(epoch, Ordering::Release);
    } else {
        close();
    }
}

pub(super) fn close() {
    PUBLISHED.store(CLOSED, Ordering::Release);
}

fn placement(epoch: u64) -> CpuLayout {
    CpuLayout {
        business_mask: BUSINESS_MASK,
        healthy_mask: ONLINE.load(Ordering::Acquire),
        generation: epoch,
    }
}

#[cfg(not(cyxia_business_package))]
pub(super) fn open(epoch: u64) -> Result<(), Error> {
    if !staged(epoch) {
        close();
        return Ok(());
    }
    // SAFETY: the scheduler is private to CPU0 before publication and private
    // to CPU1 after it. Neither typed borrow crosses the handoff.
    admit(unsafe { &mut *addr_of_mut!(SCHEDULER) }, placement(epoch))?;
    GATES[CPU].open(Token {
        generation: epoch,
        plane: Plane::Business,
    })?;
    publish(epoch);
    Ok(())
}

pub(super) fn advance(dispatch: Dispatch, started: u64) -> RunState {
    if cpu::slot() != CPU
        || dispatch.cpu != CPU as u16
        || dispatch.thread != thread(dispatch.core_generation)
        || PUBLISHED.load(Ordering::Acquire) != dispatch.core_generation
    {
        return RunState::Exited;
    }
    let now = now_ns();
    let Some(end) = dispatch
        .window
        .checked_add(1)
        .and_then(|w| w.checked_mul(WINDOW_NS))
    else {
        close();
        return RunState::Exited;
    };
    let remaining = dispatch
        .reserved_ns
        .saturating_sub(timer::cpu_elapsed_ns(started))
        .min(end.saturating_sub(now))
        .saturating_sub(EXIT_MARGIN_NS);
    if remaining == 0 {
        return RunState::Runnable;
    }
    // SAFETY: only CPU1 enters here under its exact single live dispatch.
    // A concurrent close clears admission and never borrows the engine.
    let engine = unsafe { (*addr_of_mut!(ENGINE)).assume_init_mut() };
    if engine.step(now + remaining).is_err() {
        close();
        return RunState::Exited;
    }
    RunState::Runnable
}

pub(super) fn retire_owned() {
    assert_eq!(cpu::slot(), CPU);
    if PREPARED.swap(0, Ordering::AcqRel) != 0 {
        // SAFETY: the stopped CPU1 worker is the only owner after staging.
        // No later dispatch may use this engine, and DMA backing stays pinned.
        unsafe { (*addr_of_mut!(ENGINE)).assume_init_mut() }.stop();
    }
}

fn idle(period: u64) {
    let deadline = now_ns().saturating_add(period);
    let deadline =
        ((u128::from(deadline) * u128::from(timer::frequency())).div_ceil(1_000_000_000)) as u64;
    IDLE_ARMED.store(true, Ordering::Relaxed);
    // SAFETY: only the registered CPU1 worker owns its private timer.
    unsafe {
        timer::arm(deadline);
        timer::enable_irqs();
    }
    timer::idle();
    unsafe {
        core::arch::asm!(
            "msr daifset, #2",
            "isb",
            options(nomem, nostack, preserves_flags)
        );
        cpu::disable_timer();
    }
    IDLE_ARMED.store(false, Ordering::Relaxed);
}

pub(crate) fn rearm_idle_timer(slot: usize) {
    if slot == CPU && IDLE_ARMED.load(Ordering::Relaxed) {
        // Rearm even if the first IRQ arrived just before WFI.
        let interval = timer::frequency().div_ceil(500).max(1);
        unsafe { timer::arm(timer::ticks().saturating_add(interval)) };
    }
}

fn with_scheduler<T>(access: impl FnOnce(&mut Scheduler) -> T) -> Option<T> {
    #[cfg(cyxia_business_package)]
    return super::signed_business::try_scheduler(access);
    #[cfg(not(cyxia_business_package))]
    {
        // SAFETY: CPU1 alone repeatedly borrows the published local scheduler.
        Some(access(unsafe { &mut *addr_of_mut!(SCHEDULER) }))
    }
}

#[cfg(not(cyxia_business_package))]
pub(crate) fn worker(slot: usize) -> ! {
    assert!(slot == CPU && cpu::slot() == CPU);
    // SAFETY: this secondary is the only owner of its local PMU.
    unsafe { timer::init_cpu_accounting() };
    loop {
        let epoch = PUBLISHED.load(Ordering::Acquire);
        if epoch == CLOSED {
            break;
        }
        if epoch != 0 {
            run(epoch);
            break;
        }
        idle(WINDOW_NS);
    }
    retire_owned();
    unsafe { timer::enable_irqs() };
    loop {
        timer::idle();
    }
}

#[cfg(cyxia_business_package)]
pub(super) fn after_business_exit() {
    let epoch = PUBLISHED.load(Ordering::Acquire);
    if epoch != 0 && epoch != CLOSED {
        run(epoch);
    }
    retire_owned();
}

fn run(epoch: u64) {
    let token = Token {
        generation: epoch,
        plane: Plane::Business,
    };
    while PUBLISHED.load(Ordering::Acquire) == epoch {
        let Ok(permit) = GATES[CPU].try_enter(token) else {
            idle(POLL_NS);
            continue;
        };
        let start = timer::cpu_ticks();
        let selection = with_scheduler(|scheduler| {
            scheduler.dispatch_with_window_headroom(
                CPU,
                placement(epoch),
                now_ns(),
                MAX_SLICE_NS,
                MAX_SLICE_NS,
            )
        });
        if let Some(Ok(Some(grant))) = selection {
            let state = advance(grant, start);
            let settled = loop {
                if let Some(result) = with_scheduler(|scheduler| {
                    scheduler.complete(grant, timer::cpu_elapsed_ns(start), state, now_ns())
                }) {
                    break result;
                }
                core::hint::spin_loop();
            };
            if settled.is_err() || state == RunState::Exited {
                close();
            }
        } else if matches!(selection, Some(Err(_))) {
            close();
        }
        drop(permit);
        if PUBLISHED.load(Ordering::Acquire) == epoch {
            idle(POLL_NS);
        }
    }
}
