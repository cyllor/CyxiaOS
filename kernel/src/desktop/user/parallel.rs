//! Parallel CPU mechanism for the existing process/thread policy. CPU0 prepares
//! each root, transfers owned contexts, drains the complete phase, and only then
//! runs shared syscall/fault/service code. A worker can finish private clock
//! reads within its own grant. Stopped roots retain stable mappings;
//! mapping owners revoke affected PTEs before clearing or releasing backing.
use super::*;
use crate::machine::{dispatch, runtime};
use cyxia_ai_runtime::{UserCandidate, UserDispatch};

#[derive(Clone, Copy)]
struct CpuReceipt {
    entries: u64,
    cancelled: u64,
    preemptions: u64,
    syscalls: u64,
    local_syscalls: u64,
    faults: u64,
    pid: u32,
    tid: u32,
    entered_ns: u64,
    returned_ns: u64,
}
const EMPTY_RECEIPT: CpuReceipt = CpuReceipt {
    entries: 0,
    cancelled: 0,
    preemptions: 0,
    syscalls: 0,
    local_syscalls: 0,
    faults: 0,
    pid: 0,
    tid: 0,
    entered_ns: 0,
    returned_ns: 0,
};
// Every access is by CPU0 outside the drained AP user phase.
static mut RECEIPTS: [CpuReceipt; 3] = [EMPTY_RECEIPT; 3];
pub(super) fn status(out: &mut impl Write) {
    let receipts = unsafe { *core::ptr::addr_of!(RECEIPTS) };
    for (index, receipt) in receipts.into_iter().enumerate() {
        writeln!(out, "USER_AP cpu={} enters={} cancelled={} preemptions={} syscalls={} faults={} last_pid={} last_tid={} entered_ns={} returned_ns={} local_syscalls={} source=HPET_WALL cpu_billing=false\r",
            index + 1, receipt.entries, receipt.cancelled, receipt.preemptions,
            receipt.syscalls, receipt.faults, receipt.pid, receipt.tid,
            receipt.entered_ns, receipt.returned_ns, receipt.local_syscalls).unwrap();
    }
}
fn receipt(index: usize, pid: u32, tid: u32, done: &dispatch::Completion) {
    let record = unsafe { &mut (*core::ptr::addr_of_mut!(RECEIPTS))[index] };
    if !done.entered {
        record.cancelled = record.cancelled.saturating_add(1);
        return;
    }
    record.entries = record.entries.saturating_add(1);
    record.local_syscalls = record.local_syscalls.saturating_add(done.local_syscalls);
    record.pid = pid;
    record.tid = tid;
    record.entered_ns = done.entered_ns;
    record.returned_ns = done.returned_ns;
    match done.exit {
        Ok(Exit::Syscall) => record.syscalls = record.syscalls.saturating_add(1),
        Ok(Exit::Preempted) => record.preemptions = record.preemptions.saturating_add(1),
        Ok(Exit::Fault { .. }) => record.faults = record.faults.saturating_add(1),
        Err(_) => {}
    }
}

struct Slice {
    budget_ms: u64,
    model: u64,
    #[cfg(feature = "ported")]
    thread_decision: Option<(u64, DecisionSource)>,
}
impl Runner {
    fn prepare_job(
        &mut self,
        fs: &mut FileSystem,
        ledger: &mut GrantLedger,
        ipc: &mut LocalIpc,
        competing: usize,
    ) -> Option<(dispatch::Job, Slice)> {
        if self.status.state != UserState::Running
            || !self.thread.active
            || self.thread.waiting.is_some()
        {
            return None;
        }
        if self
            .test_lifetime
            .is_some_and(|limit| now().saturating_sub(self.started) >= limit)
        {
            self.finish(fs, ledger, ipc, UserState::Timeout, 124);
            return None;
        }
        #[cfg(feature = "ported")]
        match self.deliver_signal() {
            Ok(None) => {}
            Ok(Some(code)) => {
                self.status.exit_signal = code.saturating_sub(128);
                self.finish(fs, ledger, ipc, UserState::Exited, code);
                return None;
            }
            Err(_) => {
                self.finish(fs, ledger, ipc, UserState::Fault, 139);
                return None;
            }
        }
        if self.prepare_space().is_err() {
            self.finish(fs, ledger, ipc, UserState::Fault, 139);
            return None;
        }
        let (budget_ms, model) =
            cyxia_ai_runtime::user_cpu_policy(self.thread.cpu_bound, competing.min(8))
                .expect("bounded existing process quantum policy");
        let budget_ms = if cfg!(feature = "cosmic-session") { budget_ms * 8 } else { budget_ms };
        ai::record(AiDomain::CpuQuantum, |c| c.proposal(model));
        Some((
            dispatch::Job {
                context: core::mem::replace(&mut self.thread.context, Context::empty()),
                space: core::mem::replace(
                    &mut self.space,
                    crate::address_space::ProcessSpace::new(),
                ),
                // Set only after all roots have been prepared, before publication.
                deadline_ns: 0,
                #[cfg(all(feature = "cosmic-session", not(feature = "abi-trace")))]
                allow_local_clock: self.linux
                    && !self.thread.retry_syscall
                    && self.thread.retry_descriptor.is_none(),
            },
            Slice {
                budget_ms,
                model,
                #[cfg(feature = "ported")]
                thread_decision: self.threads.shared.dispatch.take(),
            },
        ))
    }
    fn complete_job(
        &mut self,
        slice: Slice,
        exit: Result<Exit, Errno>,
        entered: bool,
        elapsed_ns: u64,
        fs: &mut FileSystem,
        ledger: &mut GrantLedger,
        ipc: &mut LocalIpc,
    ) {
        // Supervisor already stopped ALL roots and restored ALL runner owners.
        if entered {
            self.status.last_slice_ms = slice.budget_ms;
            self.status.cpu_model = slice.model;
            self.status.ai_slices = self.status.ai_slices.saturating_add(1);
            ai::record(AiDomain::CpuQuantum, |c| {
                c.dispatch(DecisionSource::AiDirect);
                c.entered();
                c.returned();
                // This existing receipt is elapsed wall time, never CPU debit.
                c.elapsed(elapsed_ns / 1_000_000);
            });
            #[cfg(feature = "ported")]
            if let Some((model, source)) = slice.thread_decision {
                self.status.thread_rank_model = model;
                match source {
                    DecisionSource::AiDirect => {
                        self.status.thread_ai_selections =
                            self.status.thread_ai_selections.saturating_add(1)
                    }
                    DecisionSource::SafetyGuard => {
                        self.status.thread_guard_selections =
                            self.status.thread_guard_selections.saturating_add(1)
                    }
                    _ => unreachable!(),
                }
                ai::record(AiDomain::CpuThread, |c| c.dispatch(source));
            }
            self.complete_exit(exit, fs, ledger, ipc);
            self.thread.ready_since = now();
        } else {
            ai::record(AiDomain::CpuQuantum, |c| c.cancelled());
            #[cfg(feature = "ported")]
            if slice.thread_decision.is_some() {
                ai::record(AiDomain::CpuThread, |c| c.cancelled());
            }
            // Cancelled/expired before entry is not a user fault and keeps its
            // original context runnable. Real entry errors remain failures.
            if !matches!(exit, Err(Errno::Again)) {
                self.complete_exit(exit, fs, ledger, ipc);
            }
        }
    }
    fn record_selection(&mut self, decision: UserDispatch, entered: bool) {
        if entered {
            self.status.rank_model = decision.model;
            match decision.source {
                DecisionSource::AiDirect => {
                    self.status.ai_selections = self.status.ai_selections.saturating_add(1)
                }
                DecisionSource::SafetyGuard => {
                    self.status.guard_selections = self.status.guard_selections.saturating_add(1)
                }
                _ => unreachable!(),
            }
            ai::record(AiDomain::CpuProcess, |c| c.dispatch(decision.source));
        } else {
            ai::record(AiDomain::CpuProcess, |c| c.cancelled());
        }
    }
}
impl Supervisor {
    fn report_dispatch(&mut self, index: usize, out: &mut impl Write) {
        let runner = &self.runners[index];
        #[cfg(feature = "graphics")]
        if matches!(runner.thread.waiting, Some(Wait::Display)) {
            assert!(self.display_owner.is_none());
            self.display_owner = Some((runner.status.pid, runner.thread.tid));
        }
        if !runner.status.state.active() {
            writeln!(out, "\r\n{PROCESS_LABEL} pid={} {:?} code={} free_pages={} {FAULT_LABEL}={:#x} far={:#x}\r",
                runner.status.pid, runner.status.state, runner.status.code,
                self.ledger.snapshot().free, runner.status.esr, runner.status.far).unwrap();
        }
    }
    pub(super) fn dispatch_parallel(
        &mut self,
        mut candidates: [Option<UserCandidate>; SLOTS],
        shell: &mut cyxia_shell::Shell,
        out: &mut impl Write,
    ) {
        let online = runtime::online_cpus();
        let ready = candidates.iter().flatten().count();
        let competing = shell
            .runtime_mut()
            .tasks()
            .filter(|t| t.state == cyxia_ai_runtime::TaskState::Ready && !t.paused)
            .count()
            + ready.saturating_sub(1);
        if online & 0b1110 == 0 {
            // Single-CPU machines retain the same existing synchronous backend.
            if let Some(choice) = super::process_dispatch_policy(&candidates) {
                ai::record(AiDomain::CpuProcess, |c| c.proposal(choice.model));
                let runner = &mut self.runners[choice.index];
                let entered =
                    runner.tick(shell.fs_mut(), &mut self.ledger, &mut self.ipc, competing);
                runner.record_selection(choice, entered);
                // Age must restart after a granted slice, exactly as the AP and
                // aarch64 paths do. Otherwise the starvation guard freezes on the
                // permanently oldest candidate and CPU0 never rotates.
                runner.thread.ready_since = now();
                self.report_dispatch(choice.index, out);
            }
            return;
        }
        let mut jobs: [Option<dispatch::Job>; 3] = core::array::from_fn(|_| None);
        let mut slices: [Option<Slice>; 3] = core::array::from_fn(|_| None);
        let mut choices = [None; 3];
        for index in 0..3 {
            if online & (1 << (index + 1)) == 0 {
                continue;
            }
            let Some(choice) = super::process_dispatch_policy(&candidates) else {
                break;
            };
            candidates[choice.index] = None; // Distinct process; never sibling threads.
            ai::record(AiDomain::CpuProcess, |c| c.proposal(choice.model));
            if let Some((job, slice)) = self.runners[choice.index].prepare_job(
                shell.fs_mut(),
                &mut self.ledger,
                &mut self.ipc,
                competing,
            ) {
                jobs[index] = Some(job);
                slices[index] = Some(slice);
                choices[index] = Some(choice);
            } else {
                ai::record(AiDomain::CpuProcess, |c| c.cancelled());
                self.report_dispatch(choice.index, out);
            }
        }
        // Publication starts only after every root and signal frame is complete.
        // From here to full retirement CPU0 accesses NO user bytes or services.
        #[cfg(all(feature = "cosmic-session", not(feature = "abi-trace")))]
        if ready != 0 {
            dispatch::begin_phase();
        }
        let mut tickets = [None; 3];
        let mut completions: [Option<dispatch::Completion>; 3] = core::array::from_fn(|_| None);
        let started = now_ns();
        for index in 0..3 {
            let Some(mut job) = jobs[index].take() else {
                continue;
            };
            job.deadline_ns =
                started.saturating_add(slices[index].as_ref().unwrap().budget_ms * 1_000_000);
            match dispatch::submit(index + 1, job) {
                Ok(submission) => {
                    tickets[index] = Some(submission.ticket);
                    // Failed IPI delivery does not return ownership. Drain will
                    // retry the stop/wake and require actual completion.
                    let _ = submission.wake;
                }
                Err((_error, job)) => jobs[index] = Some(job),
            }
        }
        if tickets.iter().any(Option::is_some) {
            // Session workers keep their already granted, timer-bounded quanta:
            // a polling parent's syscall must not repeatedly stop a CPU-bound
            // child and force its complete address-space rebuild. Collect every
            // real completion before any service work. Other profiles retain
            // the original stop-on-first behavior and owned peer drain.
            let drain_deadline = started.saturating_add(1_000_000_000);
            'phase: loop {
                for index in 0..3 {
                    if let Some(ticket) = tickets[index] {
                        if let Some(done) =
                            dispatch::try_collect(ticket).expect("owned dispatch ticket")
                        {
                            completions[index] = Some(done);
                            tickets[index] = None;
                            if !cfg!(feature = "cosmic-session") {
                                break 'phase;
                            }
                        }
                    }
                }
                if tickets.iter().all(Option::is_none) {
                    break;
                }
                let current = now_ns();
                assert!(
                    current < drain_deadline,
                    "AP completion timeout; retain all backing"
                );
                runtime::idle_until_while(
                    drain_deadline.min(current.saturating_add(1_000_000)),
                    || tickets.iter().flatten().all(|&ticket| {
                        !dispatch::is_complete(ticket).expect("owned dispatch ticket")
                    }),
                ).expect("AP completion wait");
            }
            let mut peers = [None; 3];
            let mut count = 0;
            for ticket in tickets.into_iter().flatten() {
                peers[count] = Some(ticket);
                count += 1;
            }
            if count > 0 {
                let raw = core::array::from_fn::<_, 3, _>(|i| {
                    peers[i].unwrap_or_else(|| peers[0].unwrap())
                });
                let drained = dispatch::drain(&raw[..count], drain_deadline)
                    .expect("AP drain failed; retain all backing");
                for (index, done) in drained.completions.into_iter().enumerate() {
                    if done.is_some() {
                        completions[index] = done;
                    }
                }
            }
        }
        // ALL workers have returned to kernel CR3 and left residency. Keep roots
        // owned but stopped. VM owners revoke affected PTEs before freeing any
        // backing; ordinary syscalls need no page-table/alias reconstruction.
        for job in jobs.iter().flatten() {
            job.space.quiescent().expect("unpublished root must be stopped");
        }
        for done in completions.iter().flatten() {
            done.job.space.quiescent().expect("completed root must be stopped");
        }
        let mut outcomes = [None; 3];
        for index in 0..3 {
            let Some(choice) = choices[index] else {
                continue;
            };
            let (job, exit, entered, elapsed) = if let Some(done) = completions[index].take() {
                let runner = &mut self.runners[choice.index];
                receipt(index, runner.status.pid, runner.thread.tid, &done);
                runner.status.syscalls = runner.status.syscalls.saturating_add(done.local_syscalls);
                (
                    done.job,
                    done.exit,
                    done.entered,
                    done.returned_ns.saturating_sub(done.entered_ns),
                )
            } else {
                (
                    jobs[index]
                        .take()
                        .expect("rejected publication retains owner"),
                    Err(Errno::Again),
                    false,
                    0,
                )
            };
            self.runners[choice.index].thread.context = job.context;
            self.runners[choice.index].space = job.space;
            outcomes[index] = Some((exit, entered, elapsed));
        }
        // Restore every runner before a completion can address another process.
        for index in 0..3 {
            let Some(choice) = choices[index] else {
                continue;
            };
            let (exit, entered, elapsed) = outcomes[index].take().unwrap();
            let runner = &mut self.runners[choice.index];
            runner.complete_job(
                slices[index].take().unwrap(),
                exit,
                entered,
                elapsed,
                shell.fs_mut(),
                &mut self.ledger,
                &mut self.ipc,
            );
            runner.record_selection(choice, entered);
            self.report_dispatch(choice.index, out);
        }
    }
}
