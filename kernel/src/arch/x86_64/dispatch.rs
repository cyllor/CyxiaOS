//! AP execution of owned user jobs. CPU0 retains process/service/allocator policy.
//! Integration must drain the whole user phase before CPU0 accesses user bytes,
//! destroys a process, changes backing, or publishes another set of mappings.
use super::runtime;
use crate::{address_space::ProcessSpace, process_arch};
#[cfg(all(feature = "cosmic-session", not(feature = "abi-trace")))]
use core::sync::atomic::{AtomicBool, Ordering};
use cyxia_arch_x86_64::{cpu, dispatch::Handoff, space::Error as CpuError};
use cyxia_posix::Errno;

pub(crate) struct Job {
    pub context: process_arch::Context,
    pub space: ProcessSpace,
    pub deadline_ns: u64,
    #[cfg(all(feature = "cosmic-session", not(feature = "abi-trace")))]
    pub allow_local_clock: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ticket {
    cpu: usize,
    generation: u64,
}
impl Ticket {
    pub fn cpu(self) -> usize {
        self.cpu
    }
    pub fn generation(self) -> u64 {
        self.generation
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Owner,
    Cpu,
    Deadline,
    Ticket,
    Busy,
    GenerationExhausted,
    Timeout,
    Wake(CpuError),
}
pub(crate) struct Submission {
    pub ticket: Ticket,
    /// Job ownership is published even if IPI delivery times out. In that case
    /// retain the ticket, retry wake/drain, and never recover/reuse its frames.
    pub wake: Result<(), CpuError>,
}
struct ExitRecord {
    exit: Result<process_arch::Exit, Errno>,
    entered: bool,
    entered_ns: u64,
    returned_ns: u64,
    local_syscalls: u64,
}
pub(crate) struct Completion {
    pub ticket: Ticket,
    pub job: Job,
    pub exit: Result<process_arch::Exit, Errno>,
    /// True only when real resume returned a captured user trap/IRQ/syscall.
    pub entered: bool,
    pub entered_ns: u64,
    pub returned_ns: u64,
    pub local_syscalls: u64,
}
pub(crate) struct Drained {
    /// Index = AP logical CPU slot minus one. Every requested job is returned;
    /// unused CPUs are None. Caller verifies all roots stopped before services;
    /// mapping owners revoke affected PTEs before releasing backing.
    pub completions: [Option<Completion>; 3],
}
static SLOTS: [Handoff<Job, ExitRecord>; 3] = [const { Handoff::new() }; 3];
#[cfg(all(feature = "cosmic-session", not(feature = "abi-trace")))]
static CPU0_SERVICE_PENDING: AtomicBool = AtomicBool::new(false);

fn owner() -> Result<(), Error> {
    if runtime::cpu_slot() != 0 {
        return Err(Error::Owner);
    }
    Ok(())
}

/// CPU0 calls this after collecting the previous phase and before publishing
/// any job in the next one. The hint only limits optional in-worker batching.
#[cfg(all(feature = "cosmic-session", not(feature = "abi-trace")))]
pub(crate) fn begin_phase() {
    owner().expect("CPU0 owns parallel user phases");
    CPU0_SERVICE_PENDING.store(false, Ordering::Release);
}

fn slot(cpu: usize) -> Result<&'static Handoff<Job, ExitRecord>, Error> {
    if !(1..4).contains(&cpu) || runtime::online_cpus() & (1 << cpu) == 0 {
        return Err(Error::Cpu);
    }
    Ok(&SLOTS[cpu - 1])
}
fn ticket_error(error: cyxia_arch_x86_64::dispatch::Error) -> Error {
    use cyxia_arch_x86_64::dispatch::Error as HandoffError;
    match error {
        HandoffError::Busy => Error::Busy,
        HandoffError::Stale => Error::Ticket,
        HandoffError::GenerationExhausted => Error::GenerationExhausted,
    }
}

/// All job roots and code permissions must be prepared before publishing the
/// first job in a parallel user phase. A rejection returns ownership unchanged.
pub(crate) fn submit(cpu: usize, job: Job) -> Result<Submission, (Error, Job)> {
    if let Err(error) = owner() {
        return Err((error, job));
    }
    let handoff = match slot(cpu) {
        Ok(slot) => slot,
        Err(error) => return Err((error, job)),
    };
    if job.deadline_ns <= runtime::now_ns() {
        return Err((Error::Deadline, job));
    }
    if job.space.root().is_err() {
        return Err((Error::Ticket, job));
    }
    // CPU0 relinquishes both owned values, not references into a Runner. The
    // static mailbox pins Context for the full hardware resume interval.
    let generation =
        unsafe { handoff.publish(job) }.map_err(|(error, job)| (ticket_error(error), job))?;
    Ok(Submission {
        ticket: Ticket { cpu, generation },
        wake: runtime::wake(cpu),
    })
}
pub(crate) fn request_stop(ticket: Ticket) -> Result<(), Error> {
    owner()?;
    let handoff = slot(ticket.cpu)?;
    if unsafe { handoff.request_stop(ticket.generation) }.map_err(ticket_error)? {
        runtime::wake(ticket.cpu).map_err(Error::Wake)?;
    }
    Ok(())
}
pub(crate) fn try_collect(ticket: Ticket) -> Result<Option<Completion>, Error> {
    owner()?;
    let handoff = slot(ticket.cpu)?;
    let Some((job, record)) =
        (unsafe { handoff.try_collect(ticket.generation) }).map_err(ticket_error)?
    else {
        return Ok(None);
    };
    Ok(Some(Completion {
        ticket,
        job,
        exit: record.exit,
        entered: record.entered,
        entered_ns: record.entered_ns,
        returned_ns: record.returned_ns,
        local_syscalls: record.local_syscalls,
    }))
}

/// Non-consuming readiness check for the IF-clear sleep boundary. Completion
/// ownership still transfers only through try_collect after the worker returns.
pub(crate) fn is_complete(ticket: Ticket) -> Result<bool, Error> {
    owner()?;
    slot(ticket.cpu)?
        .is_done(ticket.generation)
        .map_err(ticket_error)
}

/// Stop and recover the complete batch before foreground service work. On any
/// error every uncollected slot remains owned/pinned; timeout is never a release.
pub(crate) fn drain(tickets: &[Ticket], deadline_ns: u64) -> Result<Drained, Error> {
    owner()?;
    if tickets.len() > 3 {
        return Err(Error::Ticket);
    }
    let mut mask = 0u8;
    for &ticket in tickets {
        let handoff = slot(ticket.cpu)?;
        if mask & (1 << ticket.cpu) != 0 {
            return Err(Error::Ticket);
        }
        mask |= 1 << ticket.cpu;
        handoff.is_done(ticket.generation).map_err(ticket_error)?;
    }
    // Try every peer even if one delivery fails. Real completion below is the
    // authority; a failed wake cannot be treated as a successful stop ACK.
    for &ticket in tickets {
        let _ = request_stop(ticket);
    }
    loop {
        let mut all_done = true;
        for &ticket in tickets {
            all_done &= slot(ticket.cpu)?
                .is_done(ticket.generation)
                .map_err(ticket_error)?;
        }
        if all_done {
            break;
        }
        let now = runtime::now_ns();
        if now >= deadline_ns {
            return Err(Error::Timeout);
        }
        runtime::idle_until(deadline_ns.min(now.saturating_add(1_000_000))).map_err(Error::Wake)?;
    }
    let mut completions = core::array::from_fn(|_| None);
    for &ticket in tickets {
        completions[ticket.cpu - 1] =
            Some(try_collect(ticket)?.expect("single CPU0 owner of completed dispatch"));
    }
    Ok(Drained { completions })
}

/// Register this callback through runtime::release_aps at integration time.
/// APs touch their owned context/root, private syscall output, and local timers.
pub(crate) extern "C" fn worker(cpu_slot: usize) -> ! {
    assert_eq!(runtime::cpu_slot(), cpu_slot);
    let handoff = slot(cpu_slot).expect("online worker AP");
    loop {
        // Check cancellation with IF clear immediately before resume. A WAKE
        // after this check stays pending until user IF=1; it cannot be consumed
        // in a gap before entry and then lost while the user keeps executing.
        cpu::disable_interrupts();
        let ran = unsafe {
            handoff.run(|job, cancel| {
                let started = runtime::now_ns();
                #[cfg(all(feature = "cosmic-session", not(feature = "abi-trace")))]
                let mut local_syscalls = 0;
                #[cfg(not(all(feature = "cosmic-session", not(feature = "abi-trace"))))]
                let local_syscalls = 0;
                let exit = if cancel.is_requested() || job.deadline_ns <= started {
                    Err(Errno::Again)
                } else {
                    match job.space.root() {
                        Ok(root) => loop {
                            let exit = process_arch::enter(&mut job.context, root, job.deadline_ns);
                            // The original absolute deadline and pending wake
                            // bound re-entry. Cap local completions so a polling
                            // job still hands off to CPU0 regularly. Allow the
                            // first clock read even when a peer has returned.
                            #[cfg(all(feature = "cosmic-session", not(feature = "abi-trace")))]
                            if job.allow_local_clock
                                && local_syscalls < 8
                                && matches!(exit, Ok(process_arch::Exit::Syscall))
                                && !cancel.is_requested()
                                && (local_syscalls == 0
                                    || !CPU0_SERVICE_PENDING.load(Ordering::Acquire))
                                && process_arch::complete_ap_clock(
                                    &mut job.context,
                                    root,
                                    job.deadline_ns,
                                )
                            {
                                local_syscalls += 1;
                                continue;
                            }
                            break exit;
                        },
                        Err(error) => Err(error),
                    }
                };
                // Keep the hint set even if CPU0 collects this worker early.
                // Peers still leave their roots through the ordinary return.
                #[cfg(all(feature = "cosmic-session", not(feature = "abi-trace")))]
                if !matches!(exit, Ok(process_arch::Exit::Preempted) | Err(Errno::Again)) {
                    CPU0_SERVICE_PENDING.store(true, Ordering::Release);
                }
                runtime::cancel_timer();
                let entered = exit.is_ok() || local_syscalls != 0;
                ExitRecord {
                    entered,
                    entered_ns: if entered { started } else { 0 },
                    returned_ns: runtime::now_ns(),
                    exit,
                    local_syscalls,
                }
            })
        };
        unsafe { cpu::enable_interrupts() };
        if ran {
            // Completion is already Release-published, so CPU0 polling/drain
            // remains correct if notification delivery fails.
            let _ = runtime::wake(0);
        }
        runtime::idle_while(|| !handoff.is_ready());
    }
}
