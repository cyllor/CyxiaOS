//! Narrow AArch64 SHA-256 accelerator for immutable protected evidence.
//!
//! Kernel Rust remains soft-float. One handwritten assembly symbol masks
//! interrupts, preserves Q0-Q31 plus FPCR/FPSR, runs Armv8 SHA2 instructions,
//! and restores CPACR_EL1 and DAIF before returning.

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
mod imp {
    use core::arch::asm;

    core::arch::global_asm!(include_str!("sha256.S"), options(raw));

    const INITIAL: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    unsafe extern "C" {
        fn cyxia_sha256_compress_hw(state: *mut u32, blocks: *const u8, count: usize);
    }

    fn available() -> bool {
        let features: u64;
        unsafe {
            asm!(
                "mrs {features}, id_aa64isar0_el1",
                features = out(reg) features,
                options(nomem, nostack, preserves_flags)
            );
        }
        (features >> 12) & 0xf != 0
    }

    /// Return the standard SHA-256 digest when this CPU implements Armv8 SHA2.
    /// Callers retain their existing software digest as the explicit fallback.
    pub fn digest(bytes: &[u8]) -> Option<[u8; 32]> {
        if !available() {
            return None;
        }
        let bit_len = u64::try_from(bytes.len()).ok()?.checked_mul(8)?;
        let full_blocks = bytes.len() / 64;
        let mut state = INITIAL;
        if full_blocks != 0 {
            unsafe {
                cyxia_sha256_compress_hw(state.as_mut_ptr(), bytes.as_ptr(), full_blocks);
            }
        }

        let tail = &bytes[full_blocks * 64..];
        let padding_blocks = if tail.len() <= 55 { 1 } else { 2 };
        let padding_len = padding_blocks * 64;
        let mut padding = [0u8; 128];
        padding[..tail.len()].copy_from_slice(tail);
        padding[tail.len()] = 0x80;
        padding[padding_len - 8..padding_len].copy_from_slice(&bit_len.to_be_bytes());
        unsafe {
            cyxia_sha256_compress_hw(state.as_mut_ptr(), padding.as_ptr(), padding_blocks);
        }

        let mut output = [0u8; 32];
        for (word, chunk) in state.into_iter().zip(output.chunks_exact_mut(4)) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        Some(output)
    }

    pub fn digest_page(page: &[u8; 4096]) -> Option<[u8; 32]> {
        digest(page)
    }

    pub fn selftest() -> bool {
        static ZERO_PAGE: [u8; 4096] = [0; 4096];
        const EXPECTED: [u8; 32] = [
            0xad, 0x7f, 0xac, 0xb2, 0x58, 0x6f, 0xc6, 0xe9, 0x66, 0xc0, 0x04, 0xd7, 0xd1, 0xd1,
            0x6b, 0x02, 0x4f, 0x58, 0x05, 0xff, 0x7c, 0xb4, 0x7c, 0x7a, 0x85, 0xda, 0xbd, 0x8b,
            0x48, 0x89, 0x2c, 0xa7,
        ];
        match digest_page(&ZERO_PAGE) {
            None => true,
            Some(actual) => actual == EXPECTED,
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use imp::{digest, digest_page, selftest};

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub fn digest(_: &[u8]) -> Option<[u8; 32]> {
    None
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub fn digest_page(_: &[u8; 4096]) -> Option<[u8; 32]> {
    None
}

#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
pub const fn selftest() -> bool {
    true
}
