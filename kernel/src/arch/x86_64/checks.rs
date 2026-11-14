use super::*;

pub(super) fn protection_checks(layout: arch::paging::Layout) {
    unsafe fn probe(
        address: u64,
        error: u64,
        ip: u64,
        resume: u64,
        operation: unsafe extern "C" fn(u64),
    ) {
        EXPECTED_ADDRESS.store(address, Ordering::Relaxed);
        EXPECTED_ERROR.store(error, Ordering::Relaxed);
        RESUME_IP.store(resume, Ordering::Relaxed);
        EXPECTED_IP.store(ip, Ordering::Release);
        let previous = FAULTS.load(Ordering::Relaxed);
        unsafe { operation(address) };
        EXPECTED_IP.store(0, Ordering::Release);
        assert_eq!(
            FAULTS.load(Ordering::Relaxed),
            previous + 1,
            "missing protection fault"
        );
    }
    unsafe {
        probe(
            0,
            0,
            x86_read_fault as *const () as u64,
            x86_read_resume as *const () as u64,
            x86_probe_read,
        );
        probe(
            layout.guard_start,
            0,
            x86_read_fault as *const () as u64,
            x86_read_resume as *const () as u64,
            x86_probe_read,
        );
        probe(
            layout.text_start,
            3,
            x86_write_fault as *const () as u64,
            x86_write_resume as *const () as u64,
            x86_probe_write,
        );
        probe(
            layout.rodata_start,
            3,
            x86_write_fault as *const () as u64,
            x86_write_resume as *const () as u64,
            x86_probe_write,
        );
        let nx_address = core::ptr::addr_of!(NX_PROBE) as u64;
        probe(
            nx_address,
            17,
            nx_address,
            x86_execute_resume as *const () as u64,
            x86_probe_execute,
        );
    }
}

pub(super) fn shared_policy_check() {
    use cyxia_kernel_core::control_plane::{
        Error, Identity,
        budget::{Budget, Lease},
    };
    let lease = Lease {
        thread: Identity {
            id: 1,
            generation: 1,
        },
        sequence: 1,
        window: 1,
        starts_at: 0,
        ends_at: 100,
        quota: 40,
    };
    let mut budget = Budget::new(lease, 0).unwrap();
    assert!(!budget.charge(25, 25).unwrap());
    budget
        .replace(
            Lease {
                sequence: 2,
                ..lease
            },
            25,
        )
        .unwrap();
    assert_eq!(budget.allowance(25, 100), Ok(15));
    assert_eq!(budget.replace(lease, 25), Err(Error::Stale));
    assert!(budget.charge(15, 40).unwrap());
    assert_eq!(budget.allowance(40, 100), Ok(0));
    assert_eq!(budget.allowance(100, 100), Ok(0));
}

#[unsafe(no_mangle)]
extern "C" fn x86_trap(frame: &mut TrapFrame) -> u64 {
    match frame.vector {
        3 if !frame.from_user() => {
            BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
        }
        14 if !frame.from_user()
            && EXPECTED_IP.load(Ordering::Acquire) != 0
            && frame.rip == EXPECTED_IP.load(Ordering::Relaxed)
            && arch::cpu::read_cr2() == EXPECTED_ADDRESS.load(Ordering::Relaxed)
            && frame.error == EXPECTED_ERROR.load(Ordering::Relaxed) =>
        {
            frame.rip = RESUME_IP.load(Ordering::Relaxed);
            FAULTS.fetch_add(1, Ordering::Relaxed);
        }
        14 if frame.from_user()
            && USER_PROBE.load(Ordering::Acquire) == 2
            && arch::cpu::read_cr2() == 0x100000
            && frame.error == 7 =>
        {
            USER_FAULTS.fetch_add(1, Ordering::Release);
            frame.rax = 14;
            return 1;
        }
        32 if !frame.from_user() => {
            TICKS.fetch_add(1, Ordering::Release);
            unsafe { pc::hardware::acknowledge_timer_irq() };
        }
        128 if frame.from_user() && USER_PROBE.load(Ordering::Acquire) == 1 => {
            assert!(frame.user_stack().is_some());
            USER_CALLS.fetch_add(1, Ordering::Release);
            match frame.rax {
                1 => frame.rax = 0x43595831,
                2 => {
                    frame.rax = frame.rdi;
                    return 1;
                }
                _ => panic!("unknown syscall"),
            }
        }
        _ => panic!(
            "trap v={} err={:#x} ip={:#x} cr2={:#x}",
            frame.vector,
            frame.error,
            frame.rip,
            arch::cpu::read_cr2()
        ),
    }
    0
}
