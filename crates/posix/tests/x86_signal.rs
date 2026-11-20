use cyxia_posix::{
    signal::{AltStack, Info},
    signal_x86_64 as codec,
};

#[test]
fn x86_tokio_style_sigterm_registration_accepts_restart_action() {
    use cyxia_posix::{
        ImageAbi,
        signal::{Action, SA_RESTART, SA_RESTORER, SA_SIGINFO},
    };
    let action = Action {
        handler: 0x0100_0005,
        flags: SA_SIGINFO | SA_RESTART | SA_RESTORER,
        restorer: 0x0100_0007,
        mask: 0,
    };
    let control = Action {
        flags: action.flags & !SA_RESTART,
        ..action
    };
    assert_eq!(
        Action::decode_for(&control.encode(), ImageAbi::X86_64),
        Ok(control)
    );
    assert_eq!(
        Action::decode_for(&action.encode(), ImageAbi::X86_64),
        Ok(action),
        "Tokio SIGTERM action was rejected with EINVAL"
    );
}

#[test]
fn restart_eligibility_preserves_abi_and_timed_wait_boundaries() {
    use cyxia_posix::{ImageAbi, signal::restartable_syscall};
    for number in [0, 1, 19, 20, 42, 43, 44, 45, 46, 47, 61, 73, 288] {
        assert!(
            restartable_syscall(ImageAbi::X86_64, number, [0; 6]),
            "{number}"
        );
    }
    for number in [7, 35, 74, 75, 230, 232, 271, 281, u64::MAX] {
        assert!(
            !restartable_syscall(ImageAbi::X86_64, number, [0; 6]),
            "{number}"
        );
    }
    for operation in [0, 9, 128, 137] {
        let mut args = [0; 6];
        args[1] = operation;
        assert!(restartable_syscall(ImageAbi::X86_64, 202, args));
        args[3] = 0x1000;
        assert!(!restartable_syscall(ImageAbi::X86_64, 202, args));
    }
    for operation in [1, 3, 4, 10, 256] {
        let mut args = [0; 6];
        args[1] = operation;
        assert!(!restartable_syscall(ImageAbi::X86_64, 202, args));
    }
    assert!(!restartable_syscall(ImageAbi::Aarch64, 63, [0; 6]));
    use cyxia_posix::signal::{Action, SA_RESTART, SA_RESTORER};
    let action = Action {
        handler: 0x100004,
        flags: SA_RESTORER | SA_RESTART,
        restorer: 0x100008,
        mask: 0,
    };
    assert!(action.validate_for(ImageAbi::Aarch64).is_err());
    assert!(
        Action {
            flags: action.flags | 0x20,
            ..action
        }
        .validate_for(ImageAbi::X86_64)
        .is_err()
    );
}
#[test]
fn x86_signal_frame_roundtrips_actual_register_order_redzone_and_fxsave() {
    let mut fxsave = [0; 512];
    fxsave[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
    fxsave[160] = 0x87;
    let state = codec::FrameState {
        registers: core::array::from_fn(|i| i as u64 + 100),
        pc: 0x100003,
        sp: 0x300fff0,
        flags: 0x202,
        fault: codec::FaultState {
            trapno: 14,
            error: 7,
            cr2: 0xdead,
        },
        fxsave,
    };
    let address = codec::frame_address(AltStack::DISABLED, state.sp, false).unwrap();
    assert_eq!(address % 16, 8);
    assert_eq!((address + codec::FPSTATE_OFFSET as u64) % 64, 0);
    assert!(address + codec::FRAME_BYTES as u64 <= state.sp - 128);
    let mut bytes = [0; codec::FRAME_BYTES];
    codec::encode_frame(
        &mut bytes,
        address,
        &state,
        0,
        11,
        Info {
            code: 1,
            sender_pid: 1,
            address: 0xdead,
        },
        AltStack::DISABLED,
        0x100001,
        [0x23, 0x1b],
    )
    .unwrap();
    assert_eq!(
        &bytes[codec::MCONTEXT_OFFSET..codec::MCONTEXT_OFFSET + 8],
        &107u64.to_le_bytes()
    );
    for (offset, value) in [(152, 7u64), (160, 14), (176, 0xdead)] {
        assert_eq!(
            &bytes[codec::MCONTEXT_OFFSET + offset..codec::MCONTEXT_OFFSET + offset + 8],
            &value.to_le_bytes()
        );
    }
    let (restored, mask, stack) = codec::decode_frame(&bytes, address, [0x23, 0x1b]).unwrap();
    assert_eq!(restored, state);
    assert_eq!(mask, 0);
    assert_eq!(stack, AltStack::DISABLED);
    bytes[codec::MCONTEXT_OFFSET + 136..codec::MCONTEXT_OFFSET + 144]
        .copy_from_slice(&0x3202u64.to_le_bytes());
    assert!(codec::decode_frame(&bytes, address, [0x23, 0x1b]).is_err());
}

#[test]
fn x86_actions_accept_byte_addresses_and_private_signal_frames_accept_call_stack_alignment() {
    use cyxia_posix::{
        ImageAbi,
        signal::{Action, Actions, SA_RESTORER, Signals},
    };
    let action = Action {
        handler: 0x100001,
        flags: SA_RESTORER,
        restorer: 0x100003,
        mask: 0,
    };
    assert!(action.validate().is_err());
    let mut actions = Actions::new();
    actions
        .set_action_for(10, action, ImageAbi::X86_64)
        .unwrap();
    let mut signals = Signals::new();
    signals.raise(&actions, 10, Info::EMPTY, false).unwrap();
    signals
        .enter_for(&mut actions, 10, 0x3000ff8, 0x200000, ImageAbi::X86_64)
        .unwrap();
    assert_eq!(signals.frame_tls(0x3000ff8).unwrap(), 0x200000);
    signals.leave(0x3000ff8, 0).unwrap();
}

#[test]
fn fault_state_keeps_real_cr2_across_other_exceptions_and_ignores_synthetic_entries() {
    let mut fault = codec::FaultState::default();
    fault.capture(14, 7, 0x0400_1234);
    assert_eq!(
        fault,
        codec::FaultState {
            trapno: 14,
            error: 7,
            cr2: 0x0400_1234
        }
    );
    fault.capture(6, 0, 0x0100_0023);
    assert_eq!(
        fault,
        codec::FaultState {
            trapno: 6,
            error: 0,
            cr2: 0x0400_1234
        }
    );
    fault.capture(256, 0, 0x0100_0042);
    assert_eq!(
        fault,
        codec::FaultState {
            trapno: 6,
            error: 0,
            cr2: 0x0400_1234
        }
    );
}

#[test]
fn linux_fault_codes_distinguish_page_permissions_and_captured_fp_status() {
    let mut fx = [0; 512];
    fx[..2].copy_from_slice(&0x037fu16.to_le_bytes());
    fx[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
    assert_eq!(codec::fault_signal(14, 4, &fx), (11, 1)); // not-present read
    assert_eq!(codec::fault_signal(14, 7, &fx), (11, 2)); // present RO write
    assert_eq!(codec::fault_signal(14, 21, &fx), (11, 2)); // present NX execute
    assert_eq!(codec::page_fault_code(4, true), 2); // allocated PROT_NONE
    assert_eq!(codec::page_fault_code(4, false), 1); // absent VMA
    assert_eq!(codec::fault_signal(6, 0, &fx), (4, 2)); // ILL_ILLOPN
    assert_eq!(codec::fault_signal(0, 0, &fx), (8, 1)); // FPE_INTDIV
    assert_eq!(codec::fault_signal(13, 0, &fx), (11, 128)); // SI_KERNEL
    // x87 unmasked divide by zero: captured SW bit2, CW bit2 clear.
    fx[..2].copy_from_slice(&0x037bu16.to_le_bytes());
    fx[2..4].copy_from_slice(&4u16.to_le_bytes());
    assert_eq!(codec::fault_signal(16, 0, &fx), (8, 3));
    // SIMD unmasked overflow: MXCSR exception3 and mask10 clear.
    fx[24..28].copy_from_slice(&0x1b88u32.to_le_bytes());
    assert_eq!(codec::fault_signal(19, 0, &fx), (8, 4));
    fx[24..28].copy_from_slice(&0x1f88u32.to_le_bytes()); // masked event
    assert_eq!(codec::fault_signal(19, 0, &fx), (8, 0));
}
