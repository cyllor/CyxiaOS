use cyxia_arch_x86_64::{apic, paging::*};

fn base() -> Layout {
    Layout {
        text_start: 0x100000,
        text_end: 0x104000,
        rodata_start: 0x104000,
        rodata_end: 0x105000,
        user_text_start: 0x105000,
        user_text_end: 0x106000,
        user_stack_start: 0x108000,
        user_stack_end: 0x10a000,
        guard_start: 0x106000,
        guard_end: 0x107000,
    }
}

// Break caught: allowing writes to AP bootstrap code or user access to LAPIC.
#[test]
fn smp_plan_separates_bootstrap_code_mailbox_mmio_and_guard_permissions() {
    let guards = [(0x200000, 0x201000), (0x210000, 0x211000)];
    let extra = SmpLayout {
        trampoline: 0x8000,
        mailbox: 0x9000,
        lapic: 0xfee00000,
        guards: &guards,
    };
    extra.validate(base(), 0x1000000).unwrap();
    assert_eq!(
        extra.entry(base(), 0x8000).unwrap() & (WRITABLE | USER | NX),
        0
    );
    assert_eq!(
        extra.entry(base(), 0x9000).unwrap() & (WRITABLE | USER | NX),
        WRITABLE | NX
    );
    assert_eq!(extra.entry(base(), 0xfee00000).unwrap(), 0x80000000fee0001b);
    assert_eq!(extra.entry(base(), 0x200000).unwrap(), 0);
    assert_eq!(extra.entry(base(), 0x210000).unwrap(), 0);
}
#[test]
fn overlapping_bootstrap_and_guards_are_rejected_before_mapping() {
    for (trampoline, mailbox, guards) in [
        (0x8000, 0x8000, vec![]),
        (0x100000, 0x9000, vec![]),
        (0x8000, 0x9000, vec![(0x8000, 0x9000)]),
        (
            0x8000,
            0x9000,
            vec![(0x200000, 0x202000), (0x201000, 0x203000)],
        ),
    ] {
        assert!(
            SmpLayout {
                trampoline,
                mailbox,
                lapic: 0xfee00000,
                guards: &guards
            }
            .validate(base(), 0x1000000)
            .is_err()
        );
    }
}
#[test]
fn targeted_ipi_encoding_cannot_broadcast_or_target_exception_vectors() {
    assert_eq!(apic::fixed_command(0xf0).unwrap(), 0xf0);
    assert!(apic::fixed_command(31).is_err());
    assert!(apic::fixed_command(255).is_err());
    assert_eq!(apic::startup_command(0x8000).unwrap(), 0x608);
    for address in [0, 0x8100, 0xa0000, 0x100000] {
        assert!(apic::startup_command(address).is_err());
    }
}

// Break caught: treating physical APIC destination ff as a normal CPU ID,
// which broadcasts an otherwise targeted stop/start command to every CPU.
#[test]
fn targeted_destination_rejects_physical_broadcast_id() {
    assert_eq!(apic::destination_high(17).unwrap(), 0x1100_0000);
    assert_eq!(apic::destination_high(0).unwrap(), 0);
    assert!(apic::destination_high(255).is_err());
}
