//! Linux x86-64 rt_sigframe, using bounded legacy FXSAVE state (no XSAVE).
//! Layout references: Linux v6.12 arch/x86/include/{asm/sigframe.h,
//! uapi/asm/sigcontext.h,uapi/asm/ucontext.h}; pinned musl 1.2.6 x86_64 signal.h.
use crate::{
    Errno, ImageAbi,
    signal::{AltStack, Info},
};
pub const UCONTEXT_OFFSET: usize = 8;
pub const MCONTEXT_OFFSET: usize = 48;
pub const SIGINFO_OFFSET: usize = 312;
pub const FPSTATE_OFFSET: usize = 456;
pub const FRAME_BYTES: usize = 968;
const MASK_OFFSET: usize = 304;
const UNBLOCKABLE: u64 = (1 << 8) | (1 << 18);
// Actual GPR order provided by the x86 CPU Context, translated to Linux gregset.
const GREGS: [usize; 15] = [7, 6, 5, 4, 3, 2, 1, 0, 8, 9, 10, 13, 11, 14, 12];
/// Informational thread fault registers, captured only from real exceptions.
/// Linux signal_64.c exports these independently of the interrupted GPR bank;
/// sigreturn does not give user bytes authority over the kernel's saved record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FaultState {
    pub trapno: u64,
    pub error: u64,
    pub cr2: u64,
}
impl FaultState {
    pub const EMPTY: Self = Self {
        trapno: 0,
        error: 0,
        cr2: 0,
    };
    pub fn capture(&mut self, vector: u16, error: u64, address: u64) {
        if vector > 255 {
            return;
        } // Synthetic SYSCALL entry is not an exception.
        self.trapno = u64::from(vector);
        self.error = error;
        if vector == 14 {
            self.cr2 = address;
        }
    }
}
/// Linux distinguishes allocated PROT_NONE from an absent mapping even though
/// both use not-present hardware PTEs. The memory owner supplies VMA membership.
pub const fn page_fault_code(error: u64, allocated: bool) -> i32 {
    if error & 1 != 0 || allocated { 2 } else { 1 }
}
/// Linux v6.12 traps.c and fpu/core.c mappings for the captured fault classes.
/// Floating-point si_code comes from saved unmasked status, never a guessed
/// arithmetic subtype. SIMD and x87 use different masks in the real FXSAVE bank.
pub fn fault_signal(vector: u16, error: u64, fxsave: &[u8; 512]) -> (u32, i32) {
    match vector {
        14 => (11, page_fault_code(error, false)),
        6 => (4, 2), // SIGILL / ILL_ILLOPN
        0 => (8, 1), // SIGFPE / FPE_INTDIV
        16 | 19 => {
            let pending = if vector == 16 {
                let control = u16::from_le_bytes(fxsave[..2].try_into().unwrap());
                let status = u16::from_le_bytes(fxsave[2..4].try_into().unwrap());
                u32::from(status & !control)
            } else {
                let mxcsr = u32::from_le_bytes(fxsave[24..28].try_into().unwrap());
                mxcsr & !(mxcsr >> 7)
            };
            let code = if pending & 1 != 0 {
                7
            } else if pending & 4 != 0 {
                3
            } else if pending & 8 != 0 {
                4
            } else if pending & 0x12 != 0 {
                5
            } else if pending & 0x20 != 0 {
                6
            } else {
                0
            };
            (8, code)
        }
        // Existing general-protection/unsupported-fault domain: SI_KERNEL.
        _ => (11, 128),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameState {
    pub registers: [u64; 15],
    pub pc: u64,
    pub sp: u64,
    pub flags: u64,
    pub fault: FaultState,
    pub fxsave: [u8; 512],
}
fn put64(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn get64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn put32(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn user(value: u64) -> bool {
    (4096..0x0000_8000_0000_0000).contains(&value)
}
pub fn frame_address(stack: AltStack, sp: u64, on_stack: bool) -> Result<u64, Errno> {
    let top = if on_stack && stack.size != 0 && !stack.contains(sp) {
        stack.base.checked_add(stack.size).ok_or(Errno::Fault)?
    } else {
        sp
    };
    if !user(top) {
        return Err(Errno::Fault);
    }
    // Preserve the interrupted function's 128-byte SysV red zone. Entry to the
    // handler is a real C call shape: RSP%16==8 and an aligned FXSAVE pointer.
    let limit = top
        .checked_sub(128 + FRAME_BYTES as u64)
        .ok_or(Errno::Fault)?;
    let address = (limit.checked_add(8).ok_or(Errno::Fault)? & !63)
        .checked_sub(8)
        .ok_or(Errno::Fault)?;
    if !user(address)
        || (stack.size != 0 && (on_stack || stack.contains(sp)) && address < stack.base)
    {
        return Err(Errno::Fault);
    }
    Ok(address)
}
#[allow(
    clippy::too_many_arguments,
    reason = "Keep the independently validated Linux signal-frame inputs explicit at the ABI boundary."
)]
pub fn encode_frame(
    out: &mut [u8; FRAME_BYTES],
    address: u64,
    state: &FrameState,
    mask: u64,
    signal: u32,
    info: Info,
    stack: AltStack,
    restorer: u64,
    selectors: [u16; 2],
) -> Result<(), Errno> {
    if !(1..=64).contains(&signal) || address % 64 != 56 || !user(restorer) {
        return Err(Errno::Inval);
    }
    out.fill(0);
    put64(out, 0, restorer);
    put64(out, UCONTEXT_OFFSET, 6); // UC_SIGCONTEXT_SS|UC_STRICT_RESTORE_SS.
    out[24..48].copy_from_slice(&stack.encode(state.sp));
    for (index, &register) in GREGS.iter().enumerate() {
        put64(out, MCONTEXT_OFFSET + index * 8, state.registers[register]);
    }
    put64(out, MCONTEXT_OFFSET + 120, state.sp);
    put64(out, MCONTEXT_OFFSET + 128, state.pc);
    put64(out, MCONTEXT_OFFSET + 136, state.flags);
    out[MCONTEXT_OFFSET + 144..MCONTEXT_OFFSET + 146].copy_from_slice(&selectors[0].to_le_bytes());
    out[MCONTEXT_OFFSET + 150..MCONTEXT_OFFSET + 152].copy_from_slice(&selectors[1].to_le_bytes());
    put64(out, MCONTEXT_OFFSET + 152, state.fault.error);
    put64(out, MCONTEXT_OFFSET + 160, state.fault.trapno);
    put64(out, MCONTEXT_OFFSET + 168, mask & !UNBLOCKABLE);
    put64(out, MCONTEXT_OFFSET + 176, state.fault.cr2);
    put64(
        out,
        MCONTEXT_OFFSET + 184,
        address
            .checked_add(FPSTATE_OFFSET as u64)
            .ok_or(Errno::Fault)?,
    );
    put64(out, MASK_OFFSET, mask & !UNBLOCKABLE);
    put32(out, SIGINFO_OFFSET, signal);
    put32(out, SIGINFO_OFFSET + 8, info.code as u32);
    if signal == 17 && info.code > 0 {
        put32(out, SIGINFO_OFFSET + 16, info.sender_pid);
        put32(out, SIGINFO_OFFSET + 24, info.address as u32);
    } else if info.code <= 0 {
        put32(out, SIGINFO_OFFSET + 16, info.sender_pid);
    } else {
        put64(out, SIGINFO_OFFSET + 16, info.address);
    }
    out[FPSTATE_OFFSET..FPSTATE_OFFSET + 512].copy_from_slice(&state.fxsave);
    out[FPSTATE_OFFSET + 464..].fill(0); // No unsupported extended-state authority.
    Ok(())
}
pub fn decode_frame(
    bytes: &[u8; FRAME_BYTES],
    address: u64,
    selectors: [u16; 2],
) -> Result<(FrameState, u64, AltStack), Errno> {
    let flags = get64(bytes, UCONTEXT_OFFSET);
    if address % 64 != 56
        || flags & !6 != 0
        || get64(bytes, UCONTEXT_OFFSET + 8) != 0
        || get64(bytes, MCONTEXT_OFFSET + 184)
            != address
                .checked_add(FPSTATE_OFFSET as u64)
                .ok_or(Errno::Fault)?
        || bytes[FPSTATE_OFFSET + 464..].iter().any(|b| *b != 0)
        || u16::from_le_bytes(
            bytes[MCONTEXT_OFFSET + 144..MCONTEXT_OFFSET + 146]
                .try_into()
                .unwrap(),
        ) != selectors[0]
        || u16::from_le_bytes(
            bytes[MCONTEXT_OFFSET + 150..MCONTEXT_OFFSET + 152]
                .try_into()
                .unwrap(),
        ) != selectors[1]
    {
        return Err(Errno::Inval);
    }
    let mut registers = [0; 15];
    for (index, &register) in GREGS.iter().enumerate() {
        registers[register] = get64(bytes, MCONTEXT_OFFSET + index * 8);
    }
    let pc = get64(bytes, MCONTEXT_OFFSET + 128);
    let sp = get64(bytes, MCONTEXT_OFFSET + 120);
    let flags = get64(bytes, MCONTEXT_OFFSET + 136);
    if !user(pc) || !user(sp) || flags & ((3 << 12) | (1 << 14) | (1 << 17)) != 0 {
        return Err(Errno::Inval);
    }
    let mut fxsave = [0; 512];
    fxsave.copy_from_slice(&bytes[FPSTATE_OFFSET..FPSTATE_OFFSET + 512]);
    let mxcsr = u32::from_le_bytes(fxsave[24..28].try_into().unwrap());
    if mxcsr & !0xffff != 0 {
        return Err(Errno::Inval);
    } // Hardware mask is enforced by CPU restore.
    let stack = AltStack::decode_for(bytes[24..48].try_into().unwrap(), false, ImageAbi::X86_64)?;
    Ok((
        FrameState {
            registers,
            pc,
            sp,
            flags,
            fault: FaultState {
                trapno: get64(bytes, MCONTEXT_OFFSET + 160),
                error: get64(bytes, MCONTEXT_OFFSET + 152),
                cr2: get64(bytes, MCONTEXT_OFFSET + 176),
            },
            fxsave,
        },
        get64(bytes, MASK_OFFSET) & !UNBLOCKABLE,
        stack,
    ))
}
