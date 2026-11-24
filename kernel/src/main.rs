#![no_std]
#![no_main]
#[cfg(all(
    feature = "v0199-local-native",
    any(feature = "unified-runtime", feature = "tcp-v13-selftest")
))]
compile_error!(
    "V0.19.9 native single-device profile cannot link historical D16 cluster, peer billing or remote TLS entrypoints; use an explicitly isolated --no-default-features legacy diagnostic build instead"
);
#[cfg(all(feature = "full-os", not(target_arch = "x86_64")))]
compile_error!("full-os is currently an explicit x86 runtime profile");
// CPU selection and profile wiring are the only responsibilities of this root.
#[cfg(target_arch = "aarch64")]
include!("composition/aarch64.rs");
#[cfg(all(target_arch = "x86_64", feature = "os-runtime"))]
include!("composition/x86_64.rs");
#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64/mod.rs"]
mod machine;
#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/mod.rs"]
mod machine;
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("unsupported CyxiaOS architecture");

// Integration ABI consumed by existing native modules and host harnesses.
#[cfg(all(target_arch = "aarch64", not(feature = "smp-selftest")))]
#[allow(unused_imports)]
pub(crate) use machine::hex;
#[cfg(target_arch = "aarch64")]
#[allow(unused_imports)]
pub(crate) use machine::{ExceptionFrame, HIGH, UART, halt, log, try_log};

#[cfg(any(
    target_arch = "x86_64",
    all(
        target_arch = "aarch64",
        feature = "selftest",
        not(feature = "smp-selftest")
    )
))]
#[path = "selftest/memory.rs"]
mod selftest;
