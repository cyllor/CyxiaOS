//! Narrow AArch64 SHA-256 accelerator for immutable protected evidence.
//!
//! Kernel Rust remains soft-float. The handwritten wrapper masks interrupts,
//! enables Advanced SIMD only around the compression routine, preserves the
//! complete Q0-Q31/FPCR/FPSR bank, and restores CPACR_EL1 before returning.

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
mod imp {
    use core::arch::{aarch64::*, asm};

    core::arch::global_asm!(include_str!("sha256.S"));

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
    const K32: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1,
        0x923f_82a4, 0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
        0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786,
        0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
        0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147,
        0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
        0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
        0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
        0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a,
        0x5b9c_ca4f, 0x682e_6ff3, 0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
        0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
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

    /// Return the standard SHA-256 digest when the current CPU implements the
    /// Armv8 SHA2 extension. The input is immutable for the duration of this
    /// bounded transition; callers retain their ordinary software fallback.
    pub fn digest(bytes: &[u8]) -> Option<[u8; 32]> {
        if !available() {
            return None;
        }
        let bit_len = u64::try_from(bytes.len()).ok()?.checked_mul(8)?;
        let full = bytes.len() / 64;
        let mut state = INITIAL;
        if full != 0 {
            unsafe {
                cyxia_sha256_compress_hw(state.as_mut_ptr(), bytes.as_ptr(), full);
            }
        }
        let tail = &bytes[full * 64..];
        let padding_blocks = if tail.len() <= 55 { 1 } else { 2 };
        let padding_len = padding_blocks * 64;
        let mut padding = [0u8; 128];
        padding[..tail.len()].copy_from_slice(tail);
        padding[tail.len()] = 0x80;
        padding[padding_len - 8..padding_len].copy_from_slice(&bit_len.to_be_bytes());
        unsafe {
            cyxia_sha256_compress_hw(
                state.as_mut_ptr(),
                padding.as_ptr(),
                padding_blocks,
            );
        }
        let mut output = [0u8; 32];
        for (word, bytes) in state.into_iter().zip(output.chunks_exact_mut(4)) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        Some(output)
    }

    pub fn digest_page(page: &[u8; 4096]) -> Option<[u8; 32]> {
        digest(page)
    }

    pub fn selftest() -> bool {
        static ZERO_PAGE: [u8; 4096] = [0; 4096];
        const EXPECTED: [u8; 32] = [
            0xad, 0x7f, 0xac, 0xb2, 0x58, 0x6f, 0xc6, 0xe9, 0x66, 0xc0, 0x04, 0xd7,
            0xd1, 0xd1, 0x6b, 0x02, 0x4f, 0x58, 0x05, 0xff, 0x7c, 0xb4, 0x7c, 0x7a,
            0x85, 0xda, 0xbd, 0x8b, 0x48, 0x89, 0x2c, 0xa7,
        ];
        digest_page(&ZERO_PAGE).is_none_or(|digest| digest == EXPECTED)
    }

    /// Called only by `cyxia_sha256_compress_hw` after it has installed the
    /// explicit SIMD save/restore boundary and verified hardware support.
    #[unsafe(no_mangle)]
    #[target_feature(enable = "neon,sha2")]
    pub unsafe extern "C" fn cyxia_sha256_compress_inner(
        state: *mut u32,
        blocks: *const u8,
        count: usize,
    ) {
        let state = unsafe { &mut *state.cast::<[u32; 8]>() };
        let blocks = unsafe { core::slice::from_raw_parts(blocks.cast::<[u8; 64]>(), count) };
        unsafe { compress(state, blocks) };
    }

    #[inline(always)]
    #[target_feature(enable = "neon,sha2")]
    unsafe fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        unsafe {
            let mut abcd = vld1q_u32(state[..4].as_ptr());
            let mut efgh = vld1q_u32(state[4..].as_ptr());
            for block in blocks {
                let abcd_orig = abcd;
                let efgh_orig = efgh;
                let mut s0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block[..16].as_ptr())));
                let mut s1 =
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block[16..32].as_ptr())));
                let mut s2 =
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block[32..48].as_ptr())));
                let mut s3 =
                    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block[48..].as_ptr())));

                let mut tmp = vaddq_u32(s0, vld1q_u32(K32[0..].as_ptr()));
                round4(&mut abcd, &mut efgh, tmp);
                tmp = vaddq_u32(s1, vld1q_u32(K32[4..].as_ptr()));
                round4(&mut abcd, &mut efgh, tmp);
                tmp = vaddq_u32(s2, vld1q_u32(K32[8..].as_ptr()));
                round4(&mut abcd, &mut efgh, tmp);
                tmp = vaddq_u32(s3, vld1q_u32(K32[12..].as_ptr()));
                round4(&mut abcd, &mut efgh, tmp);

                for at in (16..64).step_by(16) {
                    s0 = sha256su1(sha256su0(s0, s1), s2, s3);
                    tmp = vaddq_u32(s0, vld1q_u32(K32[at..].as_ptr()));
                    round4(&mut abcd, &mut efgh, tmp);
                    s1 = sha256su1(sha256su0(s1, s2), s3, s0);
                    tmp = vaddq_u32(s1, vld1q_u32(K32[at + 4..].as_ptr()));
                    round4(&mut abcd, &mut efgh, tmp);
                    s2 = sha256su1(sha256su0(s2, s3), s0, s1);
                    tmp = vaddq_u32(s2, vld1q_u32(K32[at + 8..].as_ptr()));
                    round4(&mut abcd, &mut efgh, tmp);
                    s3 = sha256su1(sha256su0(s3, s0), s1, s2);
                    tmp = vaddq_u32(s3, vld1q_u32(K32[at + 12..].as_ptr()));
                    round4(&mut abcd, &mut efgh, tmp);
                }
                abcd = vaddq_u32(abcd, abcd_orig);
                efgh = vaddq_u32(efgh, efgh_orig);
            }
            vst1q_u32(state[..4].as_mut_ptr(), abcd);
            vst1q_u32(state[4..].as_mut_ptr(), efgh);
        }
    }

    #[inline(always)]
    unsafe fn round4(abcd: &mut uint32x4_t, efgh: &mut uint32x4_t, wk: uint32x4_t) {
        unsafe {
            let previous = *abcd;
            *abcd = sha256h(previous, *efgh, wk);
            *efgh = sha256h2(*efgh, previous, wk);
        }
    }

    #[inline(always)]
    unsafe fn sha256h(
        mut hash_efgh: uint32x4_t,
        hash_abcd: uint32x4_t,
        wk: uint32x4_t,
    ) -> uint32x4_t {
        unsafe {
            asm!(
                "sha256h {hash_efgh:q}, {hash_abcd:q}, {wk:v}.4s",
                hash_efgh = inout(vreg) hash_efgh,
                hash_abcd = in(vreg) hash_abcd,
                wk = in(vreg) wk,
                options(pure, nomem, nostack, preserves_flags)
            );
        }
        hash_efgh
    }

    #[inline(always)]
    unsafe fn sha256h2(
        mut hash_efgh: uint32x4_t,
        hash_abcd: uint32x4_t,
        wk: uint32x4_t,
    ) -> uint32x4_t {
        unsafe {
            asm!(
                "sha256h2 {hash_efgh:q}, {hash_abcd:q}, {wk:v}.4s",
                hash_efgh = inout(vreg) hash_efgh,
                hash_abcd = in(vreg) hash_abcd,
                wk = in(vreg) wk,
                options(pure, nomem, nostack, preserves_flags)
            );
        }
        hash_efgh
    }

    #[inline(always)]
    unsafe fn sha256su0(mut first: uint32x4_t, second: uint32x4_t) -> uint32x4_t {
        unsafe {
            asm!(
                "sha256su0 {first:v}.4s, {second:v}.4s",
                first = inout(vreg) first,
                second = in(vreg) second,
                options(pure, nomem, nostack, preserves_flags)
            );
        }
        first
    }

    #[inline(always)]
    unsafe fn sha256su1(
        mut first: uint32x4_t,
        second: uint32x4_t,
        third: uint32x4_t,
    ) -> uint32x4_t {
        unsafe {
            asm!(
                "sha256su1 {first:v}.4s, {second:v}.4s, {third:v}.4s",
                first = inout(vreg) first,
                second = in(vreg) second,
                third = in(vreg) third,
                options(pure, nomem, nostack, preserves_flags)
            );
        }
        first
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
