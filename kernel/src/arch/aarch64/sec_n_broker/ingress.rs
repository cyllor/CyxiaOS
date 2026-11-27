//! Run frame parsing in a private EL0 address space before giving the native
//! TCP owner a structurally eligible frame. EL1 retains device, transport
//! state, admission and all credential custody.
use super::*;
use cyxia_contracts::net_ingress::{FRAME_VA, RETURN_SVC};
#[cfg(cyxia_resident_net)]
use cyxia_kernel_core::control_plane::cpu0_v0199::CONTROL_WINDOW_NS;
use cyxia_net_transport::device::MTU;

#[cfg(not(cyxia_resident_net))]
const ELF: &[u8] =
    include_bytes!("../../../../../target/aarch64-unknown-none/release/cyxia-echo-ingress");
const ASID: u8 = 0x42;
const FRAMES: usize = 16;
const STACK: usize = 4;
const MAX_TURN_NS: u64 = 2_000_000;
const _: () = {
    assert!(FRAME_VA as u64 == SHARED_VA);
    assert!(MTU < PAGE);
};

#[unsafe(link_section = ".bss.sec_n")]
#[unsafe(export_name = "V020_SEC_N_INGRESS_SPACE")]
static mut SPACE: AddressSpace<FRAMES, STACK> = AddressSpace::ZERO;

pub(crate) struct Parser {
    memory: Memory,
    entry: u64,
    registers: [u64; 4],
    checked: u64,
    accepted: u64,
    #[cfg(cyxia_resident_net)]
    expired: u64,
    #[cfg(cyxia_resident_net)]
    pending: Option<PendingFrame>,
}

#[cfg(cyxia_resident_net)]
struct PendingFrame {
    context: user::Context,
    len: usize,
    cpu_left_ns: u64,
    expires_ns: u64,
}

impl Parser {
    #[cfg(not(cyxia_resident_net))]
    pub(crate) fn load(mac: [u8; 6], local: [u8; 4], peer: [u8; 4], port: u16) -> Self {
        Self::load_image(ELF, mac, local, peer, port)
    }

    pub(crate) fn load_image(
        image: &[u8],
        mac: [u8; 6],
        local: [u8; 4],
        peer: [u8; 4],
        port: u16,
    ) -> Self {
        assert_eq!(cpu::slot(), 0);
        // SAFETY: only the one-shot CPU0 network owner loads this root. No
        // credential owner, DMA queue or secondary retains its backing pages.
        let memory = unsafe { AddressSpace::memory(core::ptr::addr_of_mut!(SPACE)) };
        let layout = load_image(image, &memory, 1, false);
        let mut mac_register = [0; 8];
        mac_register[..6].copy_from_slice(&mac);
        report(
            "V020_SEC_N_PARSER_SPACE",
            u64::from(ASID),
            layout.used_frames as u64,
            1,
        );
        Self {
            memory,
            entry: layout.entry,
            registers: [
                u64::from_le_bytes(mac_register),
                u64::from(u32::from_be_bytes(local)),
                u64::from(u32::from_be_bytes(peer)),
                u64::from(port),
            ],
            checked: 0,
            accepted: 0,
            #[cfg(cyxia_resident_net)]
            expired: 0,
            #[cfg(cyxia_resident_net)]
            pending: None,
        }
    }

    fn context(&self, len: usize) -> user::Context {
        let mut ctx = user::Context::empty();
        ctx.pc = self.entry;
        ctx.sp = STACK_VA + (STACK * PAGE) as u64;
        ctx.regs[0] = len as u64;
        ctx.regs[1..5].copy_from_slice(&self.registers);
        ctx
    }

    fn stage(&self, frame: &[u8]) -> Result<(), device::Error> {
        if frame.len() > MTU {
            return Err(device::Error::Frame);
        }
        // SAFETY: the frame fits the sole mapped input page. It is separate
        // from the DMA buffer and cannot be modified by the parser.
        unsafe {
            self.memory
                .shared
                .cast::<u8>()
                .copy_from_nonoverlapping(frame.as_ptr(), frame.len());
        }
        Ok(())
    }

    fn clear(&self, len: usize) {
        // SAFETY: this parser's EL0 context is stopped and len was staged.
        unsafe { self.memory.shared.cast::<u8>().write_bytes(0, len) };
    }

    #[cfg(not(cyxia_resident_net))]
    pub(crate) fn accepts(&mut self, frame: &[u8]) -> Result<bool, device::Error> {
        let mut ctx = self.context(frame.len());
        let deadline_ns = now_ns().saturating_add(MAX_TURN_NS);
        let root = phys(self.memory.root as u64);
        self.stage(frame)?;
        while now_ns() < deadline_ns {
            step(&mut ctx, root, ASID, ticks_at_ns(deadline_ns));
            if ctx.kind != 9 {
                break;
            }
        }
        self.clear(frame.len());
        if now_ns() >= deadline_ns {
            return Err(device::Error::Device);
        }
        self.verdict(&ctx)
    }

    fn verdict(&mut self, ctx: &user::Context) -> Result<bool, device::Error> {
        if ctx.kind != 8
            || ctx.esr >> 26 != 0x15
            || ctx.esr & 0xffff != u64::from(RETURN_SVC)
            || ctx.regs[0] > 1
        {
            return Err(device::Error::Device);
        }
        self.checked = self.checked.saturating_add(1);
        self.accepted = self.accepted.saturating_add(ctx.regs[0]);
        Ok(ctx.regs[0] == 1)
    }

    #[cfg(cyxia_resident_net)]
    pub(crate) fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    #[cfg(cyxia_resident_net)]
    pub(crate) fn stage_frame(&mut self, frame: &[u8]) -> Result<(), device::Error> {
        if self.has_pending() {
            return Err(device::Error::Device);
        }
        self.stage(frame)?;
        self.pending = Some(PendingFrame {
            context: self.context(frame.len()),
            len: frame.len(),
            cpu_left_ns: MAX_TURN_NS,
            expires_ns: now_ns().saturating_add(CONTROL_WINDOW_NS),
        });
        Ok(())
    }

    /// Resume at most one turn of the same immutable frame and context.
    /// A preemption consumes execution credit while retaining the input.
    #[cfg(cyxia_resident_net)]
    pub(crate) fn poll_frame(
        &mut self,
        frame: &mut [u8; MTU],
        owner_deadline_ns: u64,
    ) -> Result<Option<usize>, device::Error> {
        let Some(pending) = self.pending.as_mut() else {
            return Ok(None);
        };
        let now = now_ns();
        let end = pending.expires_ns.min(owner_deadline_ns);
        if now < end && pending.cpu_left_ns != 0 && matches!(pending.context.kind, 0 | 9) {
            let deadline_ns = end.min(now.saturating_add(pending.cpu_left_ns));
            let started = timer::cpu_ticks();
            step(
                &mut pending.context,
                phys(self.memory.root as u64),
                ASID,
                ticks_at_ns(deadline_ns),
            );
            pending.cpu_left_ns = pending
                .cpu_left_ns
                .saturating_sub(timer::cpu_elapsed_ns(started));
        }
        let now = now_ns();
        let expired = now >= pending.expires_ns || pending.cpu_left_ns == 0;
        if !expired && (now >= owner_deadline_ns || matches!(pending.context.kind, 0 | 9)) {
            return Ok(None);
        }
        let pending = self.pending.take().expect("staged parser frame");
        let verdict = if expired {
            self.checked = self.checked.saturating_add(1);
            self.expired = self.expired.saturating_add(1);
            Ok(false)
        } else {
            self.verdict(&pending.context)
        };
        if matches!(verdict, Ok(true)) {
            // SAFETY: the verified context stopped and could only read this
            // page. Return the exact admitted bytes, then clear the staging.
            unsafe {
                self.memory
                    .shared
                    .cast::<u8>()
                    .copy_to_nonoverlapping(frame.as_mut_ptr(), pending.len);
            }
        }
        self.clear(pending.len);
        verdict.map(|accepted| accepted.then_some(pending.len))
    }

    #[cfg(cyxia_resident_net)]
    pub(crate) fn discard_frame(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.clear(pending.len);
        }
    }

    #[cfg(cyxia_resident_net)]
    pub(crate) fn counts(&self) -> (u64, u64, u64) {
        (self.checked, self.accepted, self.expired)
    }

    #[cfg(not(cyxia_resident_net))]
    pub(crate) fn publish(&self) {
        report(
            "V020_SEC_N_PARSER_FRAMES",
            self.checked,
            self.accepted,
            self.checked - self.accepted,
        );
    }
}
