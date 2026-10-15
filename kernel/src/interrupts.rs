use super::HIGH;
#[cfg(feature = "selftest")]
use super::log;
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_arch_aarch64::timer;
use cyxia_contracts::*;
use cyxia_driver_gicv2::{Gic, IrqAck};
static mut GIC: Option<Gic> = None;
static PERIOD: AtomicU64 = AtomicU64::new(0);
static DEADLINE: AtomicU64 = AtomicU64::new(0);
static TIMER_IRQ: AtomicU64 = AtomicU64::new(0);
#[repr(C, align(4096))]
pub struct Progress {
    pub magic: AtomicU64,
    pub irqs: AtomicU64,
    pub foreground: AtomicU64,
    pub bytes: AtomicU64,
    pub unknown: AtomicU64,
    pub ready: AtomicU64,
}
#[cfg_attr(feature = "selftest", unsafe(no_mangle))]
#[cfg_attr(feature = "selftest", unsafe(link_section = ".test_progress"))]
pub static TEST_PROGRESS: Progress = Progress {
    magic: AtomicU64::new(0),
    irqs: AtomicU64::new(0),
    foreground: AtomicU64::new(0),
    bytes: AtomicU64::new(0),
    unknown: AtomicU64::new(0),
    ready: AtomicU64::new(0),
};
fn gic() -> &'static Gic {
    unsafe { (&*core::ptr::addr_of!(GIC)).as_ref().unwrap() }
}
pub fn handle() {
    let ack = gic().acknowledge();
    if let IrqAck::Active { id, .. } = ack {
        if id as u64 == TIMER_IRQ.load(Ordering::Relaxed) {
            let now = timer::ticks();
            let next = cyxia_kernel_core::time::next_deadline(
                DEADLINE.load(Ordering::Relaxed),
                PERIOD.load(Ordering::Relaxed),
                now,
            )
            .unwrap();
            DEADLINE.store(next, Ordering::Relaxed);
            unsafe { timer::arm(next) };
            TEST_PROGRESS.irqs.fetch_add(1, Ordering::Relaxed);
        } else {
            gic().mask(id).unwrap();
            TEST_PROGRESS.unknown.fetch_add(1, Ordering::Relaxed);
        }
        gic().end(ack);
    }
}
pub fn start(info: &BootInfo) -> ! {
    let mut r = info.gic.unwrap();
    assert_eq!(r.distributor.0, 0x08000000);
    assert_eq!(r.cpu.0, 0x08010000);
    r.distributor.0 += HIGH;
    r.cpu.0 += HIGH;
    unsafe {
        *core::ptr::addr_of_mut!(GIC) = Some(Gic::new(r).unwrap());
    }
    let irq = info.timer_irq.unwrap();
    let freq = timer::frequency();
    assert!(freq >= 1000);
    let period = freq / 1000;
    PERIOD.store(period, Ordering::Relaxed);
    TIMER_IRQ.store(irq as u64, Ordering::Relaxed);
    gic().enable(irq).unwrap();
    TEST_PROGRESS
        .magic
        .store(0x43595850524f4731, Ordering::Relaxed);
    let next = timer::ticks().checked_add(period).unwrap();
    DEADLINE.store(next, Ordering::Relaxed);
    unsafe {
        timer::arm(next);
        timer::enable_irqs();
    }
    #[cfg(feature = "selftest")]
    {
        unsafe extern "C" {
            fn irq_register_probe() -> u64;
        }
        let before = TEST_PROGRESS.irqs.load(Ordering::Relaxed);
        assert_eq!(unsafe { irq_register_probe() }, 1);
        while TEST_PROGRESS.irqs.load(Ordering::Relaxed) <= before {
            timer::idle();
        }
        gic().enable(40).unwrap();
        gic().pend(40).unwrap();
        while TEST_PROGRESS.irqs.load(Ordering::Relaxed) < 100 {
            TEST_PROGRESS.foreground.fetch_add(1, Ordering::Relaxed);
            timer::idle();
        }
        assert!(TEST_PROGRESS.foreground.load(Ordering::Relaxed) > 0);
        assert_eq!(TEST_PROGRESS.unknown.load(Ordering::Relaxed), 1);
        assert!(!gic().enabled(40));
        log(b"MMU_TIMER_OK ticks>=100 foreground>0 MECHANISM\n");
        log(b"IRQ_SELFTEST_OK WFI REGISTERS UNKNOWN_MASKED\n");
        TEST_PROGRESS.ready.store(1, Ordering::Relaxed);
    }
    loop {
        TEST_PROGRESS.foreground.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "selftest")]
        if TEST_PROGRESS.irqs.load(Ordering::Relaxed) >= 300 {
            log(b"LOG_PRESSURE MECHANISM 01234567890123456789012345678901234567890123");
            continue;
        }
        timer::idle();
    }
}
