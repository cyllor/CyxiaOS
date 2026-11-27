//! CPU1 owns each resident guest entry and the continuation of its SVC.
use super::*;
use crate::ExceptionFrame;
use core::task::Poll;

pub(crate) const CPU: usize = 1;
const DEPART_MARGIN_NS: u64 = 250_000;
const MAX_ENTRIES_PER_TURN: usize = 8;
const DISPATCH_LIMIT: u64 = 1_000_000;
const FATAL_BROKER_CONTEXT: u64 = 0x4e45_5401;
static EXPECTED_ENTRY: AtomicU64 = AtomicU64::new(0);

pub(super) fn publish_entry(root: u64, asid: u8) {
    if cpu::registered_slot() != Some(CPU)
        || root == 0
        || root & 4095 != 0
        || !matches!(asid, 0x40..=0x42)
        || EXPECTED_ENTRY
            .compare_exchange(
                0,
                root | (u64::from(asid) << 48),
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_err()
    {
        fatal(FATAL_BROKER_CONTEXT);
    }
}

pub(super) fn finish_entry(context: &mut user::Context) {
    use cyxia_kernel_core::security::process::{
        SavedEl0Frame, TrapDecision, TrapKind, TrapSource, decide_trap, resume_frame,
    };
    if EXPECTED_ENTRY.load(Ordering::Acquire) != 0 {
        fatal(FATAL_BROKER_CONTEXT);
    }
    if context.kind == 9 {
        return;
    }
    if context.kind != 8 || context.status & 0x1f != 0 {
        fatal(FATAL_BROKER_CONTEXT);
    }
    let ctr: u64;
    // SAFETY: EL1 samples the platform's read-only CTR value.
    unsafe {
        core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack, preserves_flags));
    }
    let decision = decide_trap(
        TrapSource::LowerElAarch64,
        TrapKind::Sync,
        context.esr,
        context.pc,
        ctr,
    );
    match decision {
        TrapDecision::Syscall | TrapDecision::TerminateTask => {}
        TrapDecision::Yield { .. } | TrapDecision::EmulateCtr { .. } => {
            let frame = SavedEl0Frame {
                x: context.regs,
                sp_el0: context.sp,
                elr: context.pc,
                spsr: context.status,
            };
            let resumed =
                resume_frame(frame, decision).unwrap_or_else(|_| fatal(FATAL_BROKER_CONTEXT));
            context.regs = resumed.x;
            context.pc = resumed.elr;
            context.status = resumed.spsr;
            // Account this entry and resume on the next paid turn.
            context.kind = 9;
        }
        TrapDecision::FailStop | TrapDecision::IrqProtocol => fatal(FATAL_BROKER_CONTEXT),
    }
}

pub(crate) fn verify_trap(slot: usize, frame: &ExceptionFrame, kind: u64) -> bool {
    if slot != CPU || !matches!(kind, 8 | 9) || EXPECTED_ENTRY.load(Ordering::Acquire) == 0 {
        return false;
    }
    let captured = user::captured_user_root();
    if frame.spsr & 0x1f != 0
        || captured == 0
        || EXPECTED_ENTRY
            .compare_exchange(captured, 0, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
    {
        fatal(FATAL_BROKER_CONTEXT);
    }
    true
}

pub(crate) struct Verifier {
    layout: Layout,
    context: user::Context,
    dispatched: u64,
    signing: bool,
    scrub_cursor: Option<usize>,
}

pub(crate) enum Progress {
    Pending,
    Retired,
    Rejected,
}

impl Verifier {
    pub(crate) fn load<E>(
        identity: BootIdentity<'static>,
        checkpoint: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<Self, E> {
        let layout = load_image_checkpointed(
            identity.verifier_image(),
            &guest_memory(),
            SHARED_PAGES,
            true,
            checkpoint,
        )?;
        stage_connection(identity, identity.local_pin(), false, 0, 0, 0);
        let context = fresh_context(&layout);
        Ok(Self {
            layout,
            context,
            dispatched: 0,
            signing: false,
            scrub_cursor: None,
        })
    }

    pub(crate) fn begin(&mut self, epoch: u64, source: u32, accepted_ns: u64) {
        // The previously retired SVC still has to return its exact reply
        // to the stopped continuation. Only change connection metadata.
        bind_connection(true, epoch, source, accepted_ns);
        self.dispatched = 0;
    }

    pub(crate) fn run<P: Port>(
        &mut self,
        port: &mut P,
        entropy: &mut EntropyFill<'_>,
        close_poll: ClosePoll<P>,
        signer: &mut signer::Signer<'_>,
        deadline_ns: u64,
    ) -> Result<Progress, GuestStop> {
        let exit_by = deadline_ns.saturating_sub(DEPART_MARGIN_NS);
        let root = phys(guest_memory().root as u64);
        let stop = |code, dispatched| Err(GuestStop { code, dispatched });
        for _ in 0..MAX_ENTRIES_PER_TURN {
            let now = now_ns();
            if now >= exit_by {
                return Ok(Progress::Pending);
            }
            if unsafe { CLOSE_SEEN } || self.dispatched == DISPATCH_LIMIT {
                return stop(902, self.dispatched);
            }
            let window = unsafe { TLS_WINDOW }.ok_or(GuestStop {
                code: 903,
                dispatched: self.dispatched,
            })?;
            let expiry = window.deadline().0;
            if now >= expiry {
                return Err(tls_timeout(window, now, self.dispatched));
            }
            let role_deadline = exit_by.min(expiry);
            if self.signing {
                match signer.poll_certificate_verify(role_deadline) {
                    Poll::Pending => return Ok(Progress::Pending),
                    Poll::Ready(signature) => {
                        self.signing = false;
                        certificate_verify_reply(signature);
                    }
                }
                // Settle the signer's prepaid turn before another role runs.
                return Ok(Progress::Pending);
            }
            step(
                &mut self.context,
                root,
                GUEST_ASID,
                ticks_at_ns(role_deadline),
            );
            if self.context.kind == 9 {
                return Ok(Progress::Pending);
            }
            if self.context.kind != 8 || self.context.esr >> 26 != 0x15 {
                return stop(900, self.dispatched);
            }
            if self.context.esr & 0xffff != 0x43 {
                return stop(901, self.dispatched);
            }
            let now = now_ns();
            if now >= expiry {
                return Err(tls_timeout(window, now, self.dispatched));
            }
            self.dispatched += 1;
            let op = shared_read(OFF_OP);
            if op == OP_TLS_CERTIFICATE_VERIFY {
                let len = shared_read(OFF_LEN);
                let arg = shared_read(OFF_ARG0);
                self.signing = allowed(op, len, arg)
                    && certificate_verify_request().is_some_and(|(epoch, expires, hash)| {
                        signer.begin_certificate_verify(epoch, expires, hash)
                    });
                if !self.signing {
                    certificate_verify_reply(None);
                }
                return Ok(Progress::Pending);
            }
            broker(port, entropy, Some(close_poll), Some(signer));
            if unsafe { CLOSE_SEEN } {
                return stop(902, self.dispatched);
            }
            if retired() {
                // Stop stream I/O before waking the verifier or relistening.
                unsafe { CONNECTED = false };
                return Ok(Progress::Retired);
            }
            if unsafe { RETIREMENT } == Retirement::Rejected {
                return Ok(Progress::Rejected);
            }
            if op == OP_YIELD || now_ns() >= exit_by {
                return Ok(Progress::Pending);
            }
        }
        Ok(Progress::Pending)
    }

    pub(crate) fn authenticated(&self, connection: u64) -> bool {
        unsafe { TLS_AUTHENTICATED_EPOCH == connection }
    }

    pub(crate) fn revoke(&mut self) {
        if self.scrub_cursor.is_some() {
            return;
        }
        let memory = guest_memory();
        // SAFETY: the verifier has returned to its exclusive owner. Pin
        // this backing until every bounded cleanup turn has finished.
        unsafe {
            CONNECTED = false;
            TLS_WINDOW = None;
            ADMISSION_RECEIPT = None;
            TLS_AUTHENTICATED_EPOCH = 0;
            core::ptr::addr_of_mut!(self.context).write_volatile(user::Context::empty());
            core::ptr::addr_of_mut!((*memory.root).0[0]).write_volatile(0);
        }
        tlbi();
        self.scrub_cursor = Some(0);
    }

    /// Overwrite a bounded portion of the isolated writable backing.
    pub(crate) fn scrub_step(&mut self) -> bool {
        const PAGES_PER_TURN: usize = 16;
        let Some(from) = self.scrub_cursor else {
            return true;
        };
        let bss = self.layout.bss_end.saturating_sub(self.layout.bss_first);
        let total = bss + STACK_PAGES + SHARED_PAGES;
        let to = (from + PAGES_PER_TURN).min(total);
        let memory = guest_memory();
        for i in from..to {
            let page = if i < bss {
                unsafe { memory.frames.add(self.layout.bss_first + i) }
            } else if i < bss + STACK_PAGES {
                unsafe { memory.stack.add(i - bss) }
            } else {
                unsafe { memory.shared.add(i - bss - STACK_PAGES) }
            };
            // SAFETY: the verifier root has been revoked and its former
            // writable pages remain pinned and exclusive to this owner.
            unsafe { page.write_volatile(Page::ZERO) };
        }
        self.scrub_cursor = Some(to);
        to == total
    }
}
