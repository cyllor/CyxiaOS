//! Linux user ABI numbers from the pinned musl architecture headers.
//! Call sites name operations; each ISA supplies its own real kernel ABI.
#[cfg(target_arch = "aarch64")]
mod selected {
    pub const MINSIGSTKSZ: u64 = 6144;
    pub const SIGALTSTACK: u64 = 132;
    pub const GETPID: u64 = 172;
    pub const GETTID: u64 = 178;
    pub const TGKILL: u64 = 131;
    pub const RT_SIGACTION: u64 = 134;
    pub const CLOCK_GETTIME: u64 = 113;
    pub const FUTEX: u64 = 98;
    pub const CLOCK_NANOSLEEP: u64 = 115;
}
#[cfg(target_arch = "x86_64")]
mod selected {
    pub const MINSIGSTKSZ: u64 = 2048;
    pub const SIGALTSTACK: u64 = 131;
    pub const GETPID: u64 = 39;
    pub const GETTID: u64 = 186;
    pub const TGKILL: u64 = 234;
    pub const RT_SIGACTION: u64 = 13;
    pub const CLOCK_GETTIME: u64 = 228;
    pub const FUTEX: u64 = 202;
    pub const CLOCK_NANOSLEEP: u64 = 230;
}
pub use selected::*;
