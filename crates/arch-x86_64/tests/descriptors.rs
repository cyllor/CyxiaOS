use cyxia_arch_x86_64::trap::TrapFrame;
use cyxia_arch_x86_64::{descriptors::*, paging::*};

#[test]
fn trap_frame_matches_interrupt_entry_assembly_offsets() {
    assert_eq!(core::mem::size_of::<TrapFrame>(), 176);
    assert_eq!(core::mem::align_of::<TrapFrame>(), 8);
    assert_eq!(core::mem::offset_of!(TrapFrame, r15), 0);
    assert_eq!(core::mem::offset_of!(TrapFrame, rdi), 64);
    assert_eq!(core::mem::offset_of!(TrapFrame, rax), 112);
    assert_eq!(core::mem::offset_of!(TrapFrame, vector), 120);
    assert_eq!(core::mem::offset_of!(TrapFrame, error), 128);
    assert_eq!(core::mem::offset_of!(TrapFrame, rip), 136);
    assert_eq!(core::mem::offset_of!(TrapFrame, cs), 144);
    assert_eq!(core::mem::offset_of!(TrapFrame, rflags), 152);
    assert_eq!(core::mem::offset_of!(TrapFrame, rsp), 160);
    assert_eq!(core::mem::offset_of!(TrapFrame, ss), 168);
    assert!(
        !TrapFrame {
            cs: KERNEL_CODE.into(),
            ..TrapFrame::default()
        }
        .from_user()
    );
    assert!(
        TrapFrame {
            cs: USER_CODE.into(),
            ..TrapFrame::default()
        }
        .from_user()
    );
    assert_eq!(
        TrapFrame {
            cs: KERNEL_CODE.into(),
            ..TrapFrame::default()
        }
        .user_stack(),
        None
    );
    assert_eq!(
        TrapFrame {
            cs: USER_CODE.into(),
            rsp: 0x200000,
            ss: USER_DATA.into(),
            ..TrapFrame::default()
        }
        .user_stack(),
        Some((0x200000, USER_DATA.into()))
    );
}

#[test]
fn user_and_kernel_leaves_enforce_wx_and_address_width() {
    let rx = encode_leaf(0x1000, false, true, false).unwrap();
    assert_eq!(rx & (WRITABLE | USER | NX), 0);
    let user = encode_leaf(0x2000, true, false, true).unwrap();
    assert_eq!(user & (WRITABLE | USER | NX), WRITABLE | USER | NX);
    for address in [1, 0x1001, 1 << 52] {
        assert!(encode_leaf(address, false, false, false).is_err());
    }
    assert!(encode_leaf(0x1000, true, true, false).is_err());
    assert!(encode_leaf(0x1000, true, true, true).is_err());
}

#[test]
fn interrupt_gate_preserves_full_handler_and_privilege() {
    let address = 0xffff_8000_1234_5678;
    let gate = Gate::interrupt(address, 0, 1).unwrap();
    assert_eq!(gate.handler(), address);
    assert_eq!(gate.selector(), KERNEL_CODE);
    assert_eq!(gate.attributes(), 0x8e);
    assert_eq!(gate.ist(), 1);
    let syscall = Gate::interrupt(address, 3, 0).unwrap();
    assert_eq!(syscall.attributes(), 0xee);
    assert!(Gate::interrupt(address, 4, 0).is_err());
    assert!(Gate::interrupt(address, 0, 8).is_err());
    assert!(Gate::interrupt(0x0000_8000_0000_0000, 0, 0).is_err());
}

fn layout() -> Layout {
    Layout {
        text_start: 0x100000,
        text_end: 0x104000,
        rodata_start: 0x104000,
        rodata_end: 0x105000,
        user_text_start: 0x105000,
        user_text_end: 0x106000,
        guard_start: 0x106000,
        guard_end: 0x107000,
        user_stack_start: 0x108000,
        user_stack_end: 0x10a000,
    }
}

#[test]
fn page_plan_denies_null_guard_and_user_access_to_kernel() {
    let l = layout();
    l.validate(16 * 1024 * 1024).unwrap();
    assert_eq!(l.entry(0).unwrap(), 0);
    assert_eq!(l.entry(l.guard_start).unwrap(), 0);
    assert_eq!(l.entry(l.text_start).unwrap() & (WRITABLE | USER | NX), 0);
    assert_eq!(
        l.entry(l.rodata_start).unwrap() & (WRITABLE | USER | NX),
        NX
    );
    assert_eq!(
        l.entry(l.user_text_start).unwrap() & (WRITABLE | USER | NX),
        USER
    );
    assert_eq!(
        l.entry(l.user_stack_start).unwrap() & (WRITABLE | USER | NX),
        WRITABLE | USER | NX
    );
    assert_eq!(
        l.entry(0x200000).unwrap() & (WRITABLE | USER | NX),
        WRITABLE | NX
    );
}

#[test]
fn invalid_layout_never_installs_a_partial_plan() {
    let good = layout();
    for bad in [
        Layout {
            user_stack_start: good.text_start,
            ..good
        },
        Layout {
            guard_end: good.guard_start,
            ..good
        },
        Layout {
            text_start: good.text_start + 1,
            ..good
        },
        Layout {
            rodata_end: 1 << 40,
            ..good
        },
    ] {
        assert!(bad.validate(16 * 1024 * 1024).is_err());
    }
    for size in [0, 4095, MAX_MAPPED_BYTES + 4096, 0x100000] {
        assert!(good.validate(size).is_err());
    }
}

#[test]
fn tss_descriptor_carries_both_address_halves_and_exact_limit() {
    let address = 0xffff_8000_1234_5678;
    let [lo, hi] = tss_descriptor(address, 103).unwrap();
    assert_eq!((lo >> 40) & 0xff, 0x89);
    assert_eq!(lo & 0xffff, 103);
    assert_eq!(hi, address >> 32);
    assert_eq!(
        ((lo >> 16) & 0xffff) | ((lo >> 32) & 0xff) << 16 | ((lo >> 56) & 0xff) << 24,
        address & 0xffff_ffff
    );
    assert!(tss_descriptor(address, 1 << 20).is_err());
}
