//! Exercise the actual kernel clock and RTC decoder with deterministic CMOS I/O.
//! Only the hardware ports, CPU identity and boot logger are replaced.
extern crate self as cyxia_arch_x86_64;
extern crate self as cyxia_platform_pc;

use cyxia_posix::Errno;
use std::cell::RefCell;

#[path = "../../platform-pc/src/rtc.rs"]
pub mod rtc;
#[path = "../../../kernel/src/platform/pc/clock.rs"]
mod clock;

struct Device {
    registers: [u8; 128],
    selected: u8,
    reads: usize,
    busy_reads: usize,
    elapsed_ns: u64,
    tick_ns: u64,
    clock_calls: usize,
    cpu: usize,
    log: Vec<u8>,
}

impl Device {
    fn new() -> Self {
        let mut registers = [0; 128];
        // 2024-02-29 12:34:56 UTC, valid battery, BCD, 24-hour mode.
        for (register, value) in [
            (0, 0x56), (2, 0x34), (4, 0x12), (7, 0x29),
            (8, 0x02), (9, 0x24), (0x32, 0x20),
            (10, 0x26), (11, 2), (13, 0x80),
        ] {
            registers[register] = value;
        }
        Self { registers, selected: 0, reads: 0, busy_reads: 0,
            elapsed_ns: 0, tick_ns: 10_000, clock_calls: 0, cpu: 0, log: Vec::new() }
    }
}

thread_local! {
    static DEVICE: RefCell<Device> = RefCell::new(Device::new());
}

pub mod io {
    use super::DEVICE;

    /// # Safety
    /// Test substitute for the kernel's CMOS register-selection port.
    pub unsafe fn outb(port: u16, register: u8) {
        assert_eq!(port, 0x70);
        assert!(register < 128, "CMOS reads must preserve the enabled NMI policy");
        DEVICE.with(|device| device.borrow_mut().selected = register);
    }

    /// # Safety
    /// Test substitute for the kernel's CMOS data port.
    pub unsafe fn inb(port: u16) -> u8 {
        assert_eq!(port, 0x71);
        DEVICE.with(|device| {
            let mut device = device.borrow_mut();
            device.reads += 1;
            if device.selected == 10 && device.busy_reads != 0 {
                device.busy_reads -= 1;
                return device.registers[10] | 0x80;
            }
            device.registers[usize::from(device.selected)]
        })
    }
}

pub mod machine {
    pub mod runtime {
        pub fn cpu_slot() -> usize {
            crate::DEVICE.with(|device| device.borrow().cpu)
        }
    }
}

pub mod process_arch {
    pub fn now_ns() -> u64 {
        crate::DEVICE.with(|device| {
            let mut device = device.borrow_mut();
            device.clock_calls += 1;
            let time = device.elapsed_ns;
            device.elapsed_ns = device.elapsed_ns.saturating_add(device.tick_ns);
            time
        })
    }
}

pub fn log(bytes: &[u8]) {
    DEVICE.with(|device| device.borrow_mut().log.extend_from_slice(bytes));
}

const TIME: u64 = 1_709_210_096;

#[test]
fn busy_at_boot_recovers_without_reinitialization() {
    DEVICE.with(|device| device.borrow_mut().registers[10] |= 0x80);
    clock::init();
    assert_eq!(clock::realtime_seconds(), Err(Errno::Again));
    DEVICE.with(|device| {
        let mut device = device.borrow_mut();
        device.registers[10] &= !0x80;
        device.reads = 0;
    });
    assert_eq!(clock::realtime_seconds(), Ok(TIME));
    DEVICE.with(|device| assert!(device.borrow().reads > 0));
}

#[test]
fn runtime_update_never_returns_cached_or_guessed_time() {
    clock::init();
    assert_eq!(clock::realtime_seconds(), Ok(TIME));
    DEVICE.with(|device| device.borrow_mut().registers[10] |= 0x80);
    assert_eq!(clock::realtime_seconds(), Err(Errno::Again));
    DEVICE.with(|device| {
        let mut device = device.borrow_mut();
        device.registers[10] &= !0x80;
        device.registers[0] = 0x57;
    });
    assert_eq!(clock::realtime_seconds(), Ok(TIME + 1));
}

#[test]
fn unavailable_and_invalid_hardware_keep_their_real_errors() {
    for (register, value, expected) in [(13, 0, Errno::Nodev), (0, 0x5a, Errno::Io)] {
        DEVICE.with(|device| device.borrow_mut().registers[register] = value);
        clock::init();
        assert_eq!(clock::realtime_seconds(), Err(expected));
        DEVICE.with(|device| *device.borrow_mut() = Device::new());
        assert_eq!(clock::realtime_seconds(), Ok(TIME));
    }
}

#[test]
fn secondary_cpus_never_access_cmos() {
    clock::init();
    DEVICE.with(|device| {
        let mut device = device.borrow_mut();
        device.cpu = 1;
        device.reads = 0;
    });
    assert_eq!(clock::realtime_seconds(), Err(Errno::Again));
    DEVICE.with(|device| assert_eq!(device.borrow().reads, 0));
}

#[test]
fn transient_update_returns_a_fresh_sample_without_exposing_eagain() {
    clock::init();
    DEVICE.with(|device| {
        let mut device = device.borrow_mut();
        device.registers[0] = 0x57;
        device.busy_reads = 16;
    });
    // The first low-level sampling attempt sees UIP throughout. The next
    // attempt sees a valid, changed RTC value, never the boot-time value.
    assert_eq!(clock::realtime_seconds(), Ok(TIME + 1));
}

#[test]
fn a_stopped_retry_timer_and_busy_rtc_still_return_in_bounded_work() {
    clock::init();
    DEVICE.with(|device| {
        let mut device = device.borrow_mut();
        device.registers[10] |= 0x80;
        device.tick_ns = 0;
        device.reads = 0;
    });
    assert_eq!(clock::realtime_seconds(), Err(Errno::Again));
    DEVICE.with(|device| assert!(device.borrow().reads <= 40_000));
}

#[test]
fn valid_samples_do_not_read_the_retry_timer() {
    clock::init();
    assert_eq!(clock::realtime_seconds(), Ok(TIME));
    DEVICE.with(|device| assert_eq!(device.borrow().clock_calls, 0));
}

#[test]
fn a_progressing_timer_stops_busy_retries_at_the_deadline() {
    clock::init();
    DEVICE.with(|device| {
        let mut device = device.borrow_mut();
        device.registers[10] |= 0x80;
        device.reads = 0;
    });
    assert_eq!(clock::realtime_seconds(), Err(Errno::Again));
    DEVICE.with(|device| {
        let device = device.borrow();
        assert!(device.clock_calls <= 102);
        assert!(device.reads <= 3300);
    });
}

#[test]
fn an_invalid_fresh_sample_after_busy_keeps_its_hardware_error() {
    clock::init();
    DEVICE.with(|device| {
        let mut device = device.borrow_mut();
        device.busy_reads = 16;
        device.registers[0] = 0x5a;
    });
    assert_eq!(clock::realtime_seconds(), Err(Errno::Io));
}
