//! V0.19.9 system-call ABI v3 register/argument preflight (SEC-S).
//!
//! The input is a *copied* AArch64 EL0 x8 + x0..x5 register image plus the
//! trusted startup-package ABI tag, not an SVC immediate or Linux ABI.
//! Validation here is necessary but not sufficient. The real EL1 trap handler
//! must also authorize the caller/capability, check actual user VA permissions,
//! copy all payloads to bounded kernel memory, and validate subprotocol bytes.
//! In particular 0x50 cannot be trusted based on user-supplied endpoint labels.
use super::{
    Error,
    syscall::{Syscall, decode_syscall},
};

pub const ABI_VERSION: u16 = 3;
pub const MAX_PLAN_BYTES: usize = 6464;
pub const MAX_DECISIONS: usize = 16;
pub const DECISION_RECORD_BYTES: usize = 256;
pub const MAX_APPLY_REPORT_BYTES: usize = 96 + 256;
// EC=SVC64 (0x15), IL=1 (32-bit instruction), ISS immediate=0, RES0.
const AARCH64_SVC: u64 = 0x5600_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedCall {
    pub operation: Syscall,
    pub args: [u64; 6],
}

/// Frozen ABI v3 result for a rejected register preflight. Endpoint-specific
/// errors are decided after authenticating the live holder.
pub const fn preflight_errno(error: Error) -> i64 {
    match error {
        Error::Unauthorized => -1, // E_AUTH
        _ => -2,                   // E_FORMAT
    }
}

// Check only register-level arithmetic. Actual user VA ownership, mapping,
// access permissions and stable copy-in/out remain mandatory in EL1.
fn span(address: u64, length: u64) -> bool {
    address != 0 && address.checked_add(length).is_some()
}
// The ABI declares disjoint input/output intervals. Adjacent buffers are
// legal; even partially overlapping ones are rejected before any user copy.
fn disjoint(a: u64, alen: u64, b: u64, blen: u64) -> bool {
    match (a.checked_add(alen), b.checked_add(blen)) {
        (Some(aend), Some(bend)) => aend <= b || bend <= a,
        _ => false,
    }
}

/// Decode the architectural exception syndrome and register image together.
/// Only the lower-AArch64 synchronous exception adapter may call this with
/// its saved ESR_EL1 and trusted package ABI. This remains preflight, not
/// capability authorization or a completed syscall.
pub fn decode_aarch64_svc_v3(
    verified_package_abi: u16,
    esr: u64,
    regs: &[u64; 31],
) -> Result<ValidatedCall, Error> {
    decode_aarch64_authorized_svc_v3(verified_package_abi, esr, regs, |_, _| true)
}

/// Let the native adapter check the stopped caller's operation and selector
/// before decoding untrusted request arguments. The adapter authenticates the
/// live task before calling and still verifies full endpoint rights and copy
/// spans before any side effect.
pub fn decode_aarch64_authorized_svc_v3(
    verified_package_abi: u16,
    esr: u64,
    regs: &[u64; 31],
    permits: impl FnOnce(Syscall, u64) -> bool,
) -> Result<ValidatedCall, Error> {
    if verified_package_abi != ABI_VERSION || esr != AARCH64_SVC {
        return Err(Error::Invalid);
    }
    let number = regs[8];
    let operation = decode_syscall(number)?;
    if !permits(operation, regs[0]) {
        return Err(Error::Unauthorized);
    }
    validate_arguments(
        number,
        operation,
        [regs[0], regs[1], regs[2], regs[3], regs[4], regs[5]],
    )
}

/// Lifecycle admission for an authenticated bootstrap task with no installed
/// capabilities. Protected calls have a uniform refusal before EL1 examines
/// any arguments. Process or service backends must not use this as a grant.
pub fn decode_aarch64_lifecycle_svc_v3(
    verified_package_abi: u16,
    esr: u64,
    regs: &[u64; 31],
) -> Result<ValidatedCall, Error> {
    decode_aarch64_authorized_svc_v3(verified_package_abi, esr, regs, |operation, _| {
        matches!(
            operation,
            Syscall::Exit | Syscall::Yield | Syscall::Sleep | Syscall::Clock
        )
    })
}

fn vector_shape(input_len: u64, output_cap: u64) -> bool {
    if !(44..=464).contains(&input_len) || !(input_len - 16).is_multiple_of(28) {
        return false;
    }
    let count = (input_len - 16) / 28;
    output_cap >= 16 + 64 * count
}

/// The package's trusted ABI selection must be checked at every native trap.
/// This module intentionally has no auto-migration from the v1 calling
/// convention (SVC immediate + x0..x4 + multiple return registers).
pub fn decode_v3(
    verified_package_abi: u16,
    x8: u64,
    args: [u64; 6],
) -> Result<ValidatedCall, Error> {
    if verified_package_abi != ABI_VERSION {
        return Err(Error::Invalid);
    }
    validate_arguments(x8, decode_syscall(x8)?, args)
}

fn validate_arguments(x8: u64, operation: Syscall, args: [u64; 6]) -> Result<ValidatedCall, Error> {
    let zero_tail = |start: usize| args[start..].iter().all(|v| *v == 0);
    let allowed = match x8 {
        0x01 => zero_tail(1) && args[0] == (args[0] as i32 as i64 as u64),
        0x02 | 0x04 => zero_tail(0),
        0x03 => zero_tail(1),
        0x10 => {
            zero_tail(5)
                && args[0] != 0
                && args[1] != 0
                && args[2] != 0
                && args[3] != 0
                && args[4] != 0
        }
        0x11 => zero_tail(4) && args[0] != 0 && args[1] != 0 && args[2] != 0 && args[3] != 0,
        0x12 => zero_tail(3) && args[0] != 0 && args[1] != 0 && args[2] != 0,
        0x13 => zero_tail(5) && args[0] != 0 && args[1] != 0 && args[3] != 0 && args[4] != 0,
        0x20 => {
            args[1] != 0
                && args[2] & !1 == 0
                && args[1].is_multiple_of(4096)
                && args[4] != 0
                && args[5] != 0
        }
        0x21 => {
            zero_tail(5)
                && args[0] != 0
                && args[1] != 0
                && args[2].is_multiple_of(4096)
                && matches!(args[3], 1 | 2)
                && args[4] != 0
        }
        0x22 => {
            zero_tail(4)
                && args[0] != 0
                && args[1].is_multiple_of(4096)
                && args[2] != 0
                && args[2].is_multiple_of(4096)
                && args[3] != 0
        }
        0x30 => {
            args[0] != 0
                && args[1] != 0
                && args[2] <= 512
                && args[3] != 0
                && args[5] & !1 == 0
                && (args[4] != 0 || args[5] & 1 == 1)
        }
        0x31 => {
            args[0] != 0
                && args[4] & !3 == 0
                && args[5] != 0
                && (if args[4] & 2 != 0 {
                    args[4] == 2 && args[1] == 0 && args[2] == 0 && args[3] == 0
                } else {
                    args[1] != 0 && args[2] >= 552 && (args[3] != 0 || args[4] & 1 != 0)
                })
        }
        0x32 => {
            zero_tail(5)
                && args[0] != 0
                && args[1] != 0
                && args[2] != 0
                && args[3] != 0
                && args[4] != 0
        }
        0x40 => {
            zero_tail(5)
                && args[0] != 0
                && (1..=15).contains(&args[1])
                && args[3] != 0
                && args[4] >= 264
        }
        0x41 => {
            zero_tail(4)
                && args[0] != 0
                && args[1] >= 64
                && args[1] <= MAX_PLAN_BYTES as u64
                && args[2] != 0
                && (1..=MAX_DECISIONS as u64).contains(&args[3])
        }
        0x42 => zero_tail(4) && args[0] != 0 && args[1] == 24 && args[2] != 0 && args[3] >= 64,
        0x43 => {
            zero_tail(3)
                && args[0] != 0
                && args[1] != 0
                && (96..=MAX_APPLY_REPORT_BYTES as u64).contains(&args[2])
        }
        0x50 => args[0] != 0 && args[1] != 0 && args[2] != 0 && args[4] != 0 && args[5] != 0,
        _ => false,
    };
    if !allowed {
        return Err(Error::Invalid);
    }
    // Validate both advertised buffer ranges and exact register-level sizes
    // before the native adapter can reserve quota or copy user data.
    let bounded = match x8 {
        0x10 => {
            (32..=288).contains(&args[2])
                && args[4] >= 48
                && span(args[1], args[2])
                && span(args[3], args[4])
        }
        0x11 => args[3] >= 48 && span(args[2], args[3]),
        0x13 => args[4] >= 48 && span(args[3], args[4]),
        0x20 => args[5] >= 32 && span(args[4], args[5]) && (args[0] == 0 || span(args[0], args[1])),
        0x21 => args[2].checked_add(4096).is_some(),
        0x22 => args[1].checked_add(args[2]).is_some(),
        0x30 => span(args[1], args[2]),
        0x31 => args[4] == 2 || span(args[1], args[2]),
        0x32 => vector_shape(args[1], args[3]) && span(args[0], args[1]) && span(args[2], args[3]),
        0x40 => span(args[3], args[4]),
        0x41 => {
            span(args[0], args[1])
                && args[3]
                    .checked_mul(DECISION_RECORD_BYTES as u64)
                    .is_some_and(|n| span(args[2], n))
        }
        0x42 => span(args[0], args[1]) && span(args[2], args[3]),
        0x43 => span(args[1], args[2]),
        0x50 => span(args[1], args[2]) && span(args[4], args[5]),
        _ => true,
    };
    if !bounded {
        return Err(Error::Invalid);
    }
    let separate = match x8 {
        0x10 => disjoint(args[1], args[2], args[3], args[4]),
        0x32 | 0x42 => disjoint(args[0], args[1], args[2], args[3]),
        0x41 => args[3]
            .checked_mul(DECISION_RECORD_BYTES as u64)
            .is_some_and(|n| disjoint(args[0], args[1], args[2], n)),
        0x50 => disjoint(args[1], args[2], args[4], args[5]),
        _ => true,
    };
    if !separate {
        return Err(Error::Invalid);
    }
    Ok(ValidatedCall { operation, args })
}

/// Canonical private-stack startup placement (V0.19.9 §2.2.1).
/// The caller owns and has mapped this exact private RW stack backing.
/// Fresh stack bytes are scrubbed before copying the bounded argument block.
/// Returned initial x0/x1/SP do not confer capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupRegisters {
    pub sp: u64,
    pub x0: u64,
    pub x1: u64,
}
pub fn stage_spawn_args(
    stack: &mut [u8],
    base: u64,
    args: &[u8],
) -> Result<StartupRegisters, Error> {
    if stack.len() < 4096
        || !stack.len().is_multiple_of(4096)
        || !base.is_multiple_of(4096)
        || args.len() > 256
    {
        return Err(Error::Invalid);
    }
    let end = base
        .checked_add(u64::try_from(stack.len()).map_err(|_| Error::Invalid)?)
        .ok_or(Error::Invalid)?;
    let offset = stack.len().checked_sub(args.len()).ok_or(Error::Invalid)? & !15;
    let sp = base.checked_add(offset as u64).ok_or(Error::Invalid)?;
    if sp & 15 != 0 || sp < base || sp > end {
        return Err(Error::Invalid);
    }
    stack.fill(0);
    if args.is_empty() {
        return Ok(StartupRegisters {
            sp: end,
            x0: 0,
            x1: 0,
        });
    }
    stack[offset..offset + args.len()].copy_from_slice(args);
    Ok(StartupRegisters {
        sp,
        x0: sp,
        x1: args.len() as u64,
    })
}

/// An independently authenticated EL1 role/capability check must run on both
/// sides of any blocking/retry boundary. A caller may not select its role by
/// changing x8, a service ID or any user-visible field.
pub fn requires_protected_capability(operation: Syscall) -> bool {
    matches!(
        operation,
        Syscall::SubmitPlan | Syscall::ReportResult | Syscall::ServiceCall
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn allowed(n: u64, a: [u64; 6]) -> bool {
        decode_v3(3, n, a).is_ok()
    }

    #[test]
    fn spawn_args_are_private_aligned_and_fresh_registers_are_exact() {
        let mut stack = [0xa5u8; 8192];
        let a = stage_spawn_args(&mut stack, 0x10000, &[1; 17]).unwrap();
        assert_eq!(
            a,
            StartupRegisters {
                sp: 0x11fe0,
                x0: 0x11fe0,
                x1: 17
            }
        );
        assert!(stack[..8160].iter().all(|&v| v == 0));
        assert_eq!(&stack[8160..8177], &[1; 17]);
        assert!(stack[8177..].iter().all(|&v| v == 0));
        let a = stage_spawn_args(&mut stack, 0x10000, &[]).unwrap();
        assert_eq!(
            a,
            StartupRegisters {
                sp: 0x12000,
                x0: 0,
                x1: 0
            }
        );
        assert!(stack.iter().all(|&v| v == 0));
        assert!(stage_spawn_args(&mut stack, 0x10001, &[]).is_err());
        assert!(stage_spawn_args(&mut stack, u64::MAX - 4095, &[]).is_err());
        assert!(stage_spawn_args(&mut stack, 0x10000, &[1; 257]).is_err());
    }
    #[test]
    fn frozen_nineteen_calls_have_unique_syscall_numbers() {
        let mut seen = [false; 256];
        let nums = [
            0x01, 0x02, 0x03, 0x04, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x30, 0x31, 0x32,
            0x40, 0x41, 0x42, 0x43, 0x50,
        ];
        assert_eq!(nums.len(), 19);
        for n in nums {
            assert!(!seen[n as usize]);
            seen[n as usize] = true;
            assert!(decode_syscall(n).is_ok());
        }
        assert_eq!(decode_syscall(0x51), Err(Error::Invalid));
    }

    #[test]
    fn native_authority_precedes_argument_preflight_for_every_call() {
        let mut regs = [0; 31];
        regs[0] = 42;
        regs[5] = u64::MAX;
        for number in [
            0x01, 0x02, 0x03, 0x04, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x30, 0x31, 0x32,
            0x40, 0x41, 0x42, 0x43, 0x50,
        ] {
            regs[8] = number;
            assert_eq!(
                decode_aarch64_authorized_svc_v3(
                    ABI_VERSION,
                    AARCH64_SVC,
                    &regs,
                    |operation, first| {
                        assert_eq!(operation, decode_syscall(number).unwrap());
                        assert_eq!(first, 42);
                        false
                    }
                ),
                Err(Error::Unauthorized)
            );
            assert_eq!(
                decode_aarch64_authorized_svc_v3(ABI_VERSION, AARCH64_SVC, &regs, |_, _| true),
                Err(Error::Invalid)
            );
        }

        regs[8] = 0x04;
        assert_eq!(
            decode_aarch64_authorized_svc_v3(1, AARCH64_SVC, &regs, |_, _| panic!()),
            Err(Error::Invalid)
        );
        assert_eq!(
            decode_aarch64_authorized_svc_v3(ABI_VERSION, AARCH64_SVC | 1, &regs, |_, _| panic!()),
            Err(Error::Invalid)
        );
        regs[8] = 0x51;
        assert_eq!(
            decode_aarch64_authorized_svc_v3(ABI_VERSION, AARCH64_SVC, &regs, |_, _| panic!()),
            Err(Error::Invalid)
        );
    }
    #[test]
    fn lifecycle_without_grants_uses_the_same_abi_and_refuses_all_protected_calls() {
        const ESR: u64 = 0x5600_0000;
        let mut regs = [0; 31];
        for (number, operation) in [
            (0x01, Syscall::Exit),
            (0x02, Syscall::Yield),
            (0x03, Syscall::Sleep),
            (0x04, Syscall::Clock),
        ] {
            regs[8] = number;
            let call = decode_aarch64_lifecycle_svc_v3(ABI_VERSION, ESR, &regs).unwrap();
            assert_eq!(call.operation, operation);
            assert_eq!(decode_aarch64_svc_v3(ABI_VERSION, ESR, &regs), Ok(call));
        }
        regs[5] = 1;
        assert_eq!(
            decode_aarch64_lifecycle_svc_v3(ABI_VERSION, ESR, &regs),
            Err(Error::Invalid)
        );
        for number in [
            0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x30, 0x31, 0x32, 0x40, 0x41, 0x42, 0x43,
            0x50,
        ] {
            regs[8] = number;
            assert_eq!(
                decode_aarch64_lifecycle_svc_v3(ABI_VERSION, ESR, &regs),
                Err(Error::Unauthorized)
            );
            assert_eq!(
                decode_aarch64_lifecycle_svc_v3(1, ESR, &regs),
                Err(Error::Invalid)
            );
        }
        assert_eq!(
            decode_aarch64_lifecycle_svc_v3(ABI_VERSION, ESR | 1, &regs),
            Err(Error::Invalid)
        );
        regs[8] = 0x51;
        assert_eq!(
            decode_aarch64_lifecycle_svc_v3(ABI_VERSION, ESR, &regs),
            Err(Error::Invalid)
        );
        assert_eq!(preflight_errno(Error::Unauthorized), -1);
        assert_eq!(preflight_errno(Error::Invalid), -2);
    }

    #[test]
    fn v1_abi_or_svc_immediate_cannot_silently_become_v3() {
        assert_eq!(decode_v3(1, 0x02, [0; 6]), Err(Error::Invalid));
        assert_eq!(decode_v3(0, 0x02, [0; 6]), Err(Error::Invalid));
        assert_eq!(decode_v3(3, 0, [0; 6]), Err(Error::Invalid));
        assert!(allowed(0x02, [0; 6]));
        assert!(!allowed(0x02, [0, 0, 0, 0, 0, 1]));
        assert!(allowed(0x01, [u64::MAX, 0, 0, 0, 0, 0]));
        assert!(!allowed(0x01, [0x0000_0000_ffff_ffff, 0, 0, 0, 0, 0]));
        assert!(allowed(0x04, [0; 6]));
    }
    #[test]
    fn v3_publication_and_decision_capability_arguments_fail_closed() {
        assert!(allowed(0x41, [0x1000, 212, 0x2000, 1, 0, 0]));
        assert!(!allowed(0x41, [0x1000, 212, 0x2000, 0, 0, 0]));
        assert!(!allowed(0x41, [0x1000, 6465, 0x2000, 1, 0, 0]));
        assert!(!allowed(0x41, [0x1000, 212, 0x2000, 1, 1, 0]));
        assert!(!allowed(0x41, [0x1000, 212, 0x2000, 1, 0, 1]));
        assert!(allowed(0x42, [0x1000, 24, 0x2000, 64, 0, 0]));
        assert!(!allowed(0x42, [0x1000, 16, 0x2000, 64, 0, 0]));
        assert!(allowed(0x43, [3, 0x1000, 96, 0, 0, 0]));
        assert!(!allowed(0x43, [3, 0x1000, 95, 0, 0, 0]));
        assert!(!allowed(0x43, [3, 0x1000, 96, 1, 0, 0]));
        assert!(allowed(0x50, [3, 0x1000, 256, 0, 0x2000, 8]));
        assert!(!allowed(0x50, [3, 0x1000, 256, 0, 0x2000, 0]));
        assert!(requires_protected_capability(Syscall::SubmitPlan));
        assert!(requires_protected_capability(Syscall::ServiceCall));
        assert!(!requires_protected_capability(Syscall::Clock));
    }
    #[test]
    fn read_only_and_nonblocking_ipc_state_machine_argument_gate() {
        assert!(allowed(0x31, [3, 0x1000, 552, 100, 0, 1]));
        assert!(allowed(0x31, [3, 0, 0, 0, 2, 1]));
        assert!(!allowed(0x31, [3, 0x1000, 552, 100, 2, 1]));
        assert!(!allowed(0x31, [3, 0, 0, 0, 2, 0]));
        assert!(!allowed(0x31, [3, 0x1000, 551, 100, 0, 1]));
        assert!(!allowed(0x30, [3, 0x1000, 32, 1, 0, 0]));
        assert!(allowed(0x30, [3, 0x1000, 32, 1, 0, 1]));
        assert!(!allowed(0x30, [3, 0x1000, 32, 1, 100, 2]));
        assert!(allowed(0x40, [4, 12, 1, 0x1000, 264, 0]));
        assert!(!allowed(0x40, [4, 16, 1, 0x1000, 264, 0]));
        assert!(allowed(0x32, [0x1000, 44, 0x2000, 512, 100, 0]));
        assert!(!allowed(0x32, [0x1000, 44, 0x2000, 512, 100, 1]));
    }
    #[test]
    fn syscall_spans_and_fixed_reply_capacity_fail_before_dispatch() {
        let top = u64::MAX;
        assert!(allowed(0x10, [1, 0x1000, 32, 0x2000, 48, 0]));
        assert!(!allowed(0x10, [1, 0x1000, 289, 0x2000, 48, 0]));
        assert!(!allowed(0x10, [1, top - 15, 32, 0x2000, 48, 0]));
        assert!(!allowed(0x11, [1, 1, 0x2000, 47, 0, 0]));
        assert!(!allowed(0x13, [1, 1, 100, top - 20, 48, 0]));
        assert!(allowed(0x20, [0, 4096, 0, 1, 0x2000, 32]));
        assert!(!allowed(0x20, [0, 4096, 0, 1, 0x2000, 31]));
        assert!(!allowed(0x20, [top - 4095, 8192, 0, 1, 0x2000, 32]));
        assert!(!allowed(0x21, [1, 1, top - 4095, 1, 1, 0]));
        assert!(!allowed(0x22, [1, top - 4095, 4096, 1, 0, 0]));
        assert!(!allowed(0x30, [1, top - 2, 3, 1, 0, 1]));
        assert!(!allowed(0x31, [1, top - 500, 552, 0, 1, 1]));
        assert!(allowed(0x31, [1, 0, 0, 0, 2, 1]));
        assert!(allowed(0x32, [0x1000, 464, 0x2000, 1040, 100, 0]));
        assert!(!allowed(0x32, [0x1000, 464, 0x2000, 1039, 100, 0]));
        assert!(!allowed(0x32, [0x1000, 45, 0x2000, 1040, 100, 0]));
        assert!(!allowed(0x32, [0x1000, 16, 0x2000, 1040, 100, 0]));
        assert!(!allowed(0x40, [1, 4, 1, top - 100, 264, 0]));
        assert!(!allowed(0x41, [0x1000, 212, top - 255, 1, 0, 0]));
        assert!(!allowed(0x42, [top - 23, 24, 0x2000, 64, 0, 0]));
        assert!(!allowed(0x43, [1, top - 95, 96, 0, 0, 0]));
        assert!(!allowed(0x50, [1, 0x1000, 32, 1, top, 2]));
    }

    #[test]
    fn disjoint_copies_and_actual_svc_syndrome_fail_closed() {
        assert!(allowed(0x10, [1, 0x1000, 32, 0x1020, 48, 0]));
        assert!(!allowed(0x10, [1, 0x1000, 32, 0x101f, 48, 0]));
        assert!(!allowed(0x32, [0x1000, 44, 0x1001, 80, 100, 0]));
        assert!(!allowed(0x42, [0x1000, 24, 0x0fff, 64, 0, 0]));
        assert!(!allowed(0x41, [0x1000, 212, 0x10d3, 1, 0, 0]));
        assert!(!allowed(0x50, [3, 0x1000, 256, 0, 0x10ff, 8]));
        assert!(allowed(0x50, [3, 0x1000, 256, 0, 0x1100, 8]));
        let mut regs = [0; 31];
        regs[8] = 4;
        assert_eq!(
            decode_aarch64_svc_v3(3, 0x5600_0000, &regs)
                .unwrap()
                .operation,
            Syscall::Clock
        );
        for esr in [
            0x5600_0001,
            0x5400_0000,
            0x5400_0004,
            0x5a00_0000,
            0x5601_0000,
        ] {
            assert!(decode_aarch64_svc_v3(3, esr, &regs).is_err());
        }
        assert!(decode_aarch64_svc_v3(1, 0x5600_0000, &regs).is_err());
    }
}
