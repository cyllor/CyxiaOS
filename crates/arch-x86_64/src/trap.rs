//! Hardware-independent exception frame layout, checked on the host.

/// Registers plus the complete 64-bit-mode hardware return frame.
/// Intel SDM 3A, 7.14.2: unlike legacy-mode interrupts, 64-bit-mode interrupts
/// push SS:RSP unconditionally, including when the interrupted CPL was zero.
#[repr(C)]
#[derive(Default)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl TrapFrame {
    pub fn from_user(&self) -> bool {
        self.cs & 3 == 3
    }

    pub fn user_stack(&self) -> Option<(u64, u64)> {
        self.from_user().then_some((self.rsp, self.ss))
    }
}
