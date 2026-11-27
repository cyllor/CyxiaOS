//! Run frame parsing in a private EL0 address space before giving the native
//! TCP owner a structurally eligible frame. EL1 retains device, transport
//! state, admission and all credential custody.
use super::*;
use cyxia_contracts::net_ingress::{FRAME_VA, RETURN_SVC};
use cyxia_net_transport::device::MTU;

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
}

impl Parser {
    pub(crate) fn load(mac: [u8; 6], local: [u8; 4], peer: [u8; 4], port: u16) -> Self {
        assert_eq!(cpu::slot(), 0);
        // SAFETY: only the one-shot CPU0 network owner loads this root. No
        // credential owner, DMA queue or secondary retains its backing pages.
        let memory = unsafe { AddressSpace::memory(core::ptr::addr_of_mut!(SPACE)) };
        let layout = load_image(ELF, &memory, 1, false);
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
        }
    }

    pub(crate) fn accepts(&mut self, frame: &[u8]) -> Result<bool, device::Error> {
        if frame.len() > MTU {
            return Err(device::Error::Frame);
        }
        let mut ctx = user::Context::empty();
        ctx.pc = self.entry;
        ctx.sp = STACK_VA + (STACK * PAGE) as u64;
        ctx.regs[0] = frame.len() as u64;
        ctx.regs[1..5].copy_from_slice(&self.registers);
        let deadline_ns = now_ns().saturating_add(MAX_TURN_NS);
        let root = phys(self.memory.root as u64);
        let mailbox = self.memory.shared.cast::<u8>();
        // SAFETY: the frame fits the sole mapped input page. It is separate
        // from the DMA buffer and cannot be modified by the parser.
        unsafe { mailbox.copy_from_nonoverlapping(frame.as_ptr(), frame.len()) };
        while now_ns() < deadline_ns {
            step(&mut ctx, root, ASID, ticks_at_ns(deadline_ns));
            if ctx.kind != 9 {
                break;
            }
        }
        // EL0 has stopped and EL1 still owns the input page.
        unsafe { mailbox.write_bytes(0, frame.len()) };
        if ctx.kind != 8
            || ctx.esr >> 26 != 0x15
            || ctx.esr & 0xffff != u64::from(RETURN_SVC)
            || ctx.regs[0] > 1
            || now_ns() >= deadline_ns
        {
            return Err(device::Error::Device);
        }
        self.checked += 1;
        self.accepted += ctx.regs[0];
        Ok(ctx.regs[0] == 1)
    }

    pub(crate) fn publish(&self) {
        report(
            "V020_SEC_N_PARSER_FRAMES",
            self.checked,
            self.accepted,
            self.checked - self.accepted,
        );
    }
}
