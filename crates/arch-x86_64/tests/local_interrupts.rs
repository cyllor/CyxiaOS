use cyxia_arch_x86_64::{trap::TrapFrame, user::PreemptReason};

// A LAPIC spurious interrupt may arrive at either CPL. It must never become a
// synchronous user fault, and issuing EOI would acknowledge an unrelated IRQ.
#[test]
fn spurious_interrupt_preempts_user_without_a_fault_or_eoi() {
    for cs in [8, 0x23] {
        let frame = TrapFrame {
            cs,
            vector: 255,
            rip: 0x10000,
            ..TrapFrame::default()
        };
        let interrupt = frame.local_interrupt().expect("LAPIC interrupt");
        assert_eq!(interrupt.preemption, PreemptReason::Wake);
        assert!(!interrupt.eoi);
    }
}

// The classifier must not suppress real timer/IPI ACKs or swallow exceptions
// and syscall vectors as asynchronous wakeups.
#[test]
fn real_local_interrupts_acknowledge_and_synchronous_entries_stay_distinct() {
    for (vector, reason) in [
        (239, PreemptReason::Timer),
        (240, PreemptReason::Wake),
        (241, PreemptReason::Stop),
    ] {
        let interrupt = TrapFrame {
            vector,
            ..TrapFrame::default()
        }
        .local_interrupt()
        .unwrap();
        assert_eq!(interrupt.preemption, reason);
        assert!(interrupt.eoi);
    }
    for vector in [0, 1, 3, 6, 14, 32, 128, 256] {
        assert!(
            TrapFrame {
                vector,
                ..TrapFrame::default()
            }
            .local_interrupt()
            .is_none()
        );
    }
}
