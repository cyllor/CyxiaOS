//! CPU-only AP execution. CPU0 retains every process/service/allocator policy.
//! Integration must drain the whole user phase before CPU0 accesses user bytes,
//! destroys a process, changes backing, or publishes another set of mappings.
use super::runtime;
use crate::{address_space::ProcessSpace, process_arch};
use cyxia_arch_x86_64::{cpu, dispatch::Handoff, space::Error as CpuError};
use cyxia_posix::Errno;

pub(crate) struct Job {
    pub context: process_arch::Context,
    pub space: ProcessSpace,
    pub deadline_ns: u64,
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
}
pub(crate) struct Completion {
    pub ticket: Ticket,
    pub job: Job,
    pub exit: Result<process_arch::Exit, Errno>,
    /// True only when real resume returned a captured user trap/IRQ/syscall.
    pub entered: bool,
    pub entered_ns: u64,
    pub returned_ns: u64,
}
pub(crate) struct Drained {
    /// Index = AP logical CPU slot minus one. Every requested job is returned;
    /// unused CPUs are None. Caller retires all roots before service work.
    pub completions: [Option<Completion>; 3],
}
static SLOTS: [Handoff<Job, ExitRecord>; 3] = [const { Handoff::new() }; 3];

fn owner() -> Result<(), Error> {
    if runtime::cpu_slot() != 0 {
        return Err(Error::Owner);
    }
    Ok(())
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
    }))
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
/// APs touch only their mailbox, architectural Context/root, and local timers.
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
                let exit = if cancel.is_requested() || job.deadline_ns <= started {
                    Err(Errno::Again)
                } else {
                    match job.space.root() {
                        Ok(root) => process_arch::enter(&mut job.context, root, job.deadline_ns),
                        Err(error) => Err(error),
                    }
                };
                runtime::cancel_timer();
                ExitRecord {
                    entered: exit.is_ok(),
                    entered_ns: if exit.is_ok() { started } else { 0 },
                    returned_ns: runtime::now_ns(),
                    exit,
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
