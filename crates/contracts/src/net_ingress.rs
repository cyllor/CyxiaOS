//! Private AArch64 diagnostic frame-parser handoff. EL1 owns the one-page
//! frame mapping. Only the boolean verdict in x0 returns to its caller.
pub const FRAME_VA: usize = 0x0200_0000;
pub const RETURN_SVC: u16 = 0x45;
