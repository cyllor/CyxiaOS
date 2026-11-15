#![deny(unsafe_op_in_unsafe_fn)]

use cyxia_arch_x86_64::io::{inb, outb};
use cyxia_contracts::{ConsoleOps, PlatformError};

use crate::{
    COM1_BASE, PIC_MASTER_COMMAND, PIC_SLAVE_COMMAND, PIC_VECTOR_BASE, PIT_100HZ, PIT_CHANNEL_0,
    PIT_COMMAND, PitConfig,
};

const SERIAL_POLLS: usize = 4096;
const SERIAL_CHUNK: usize = 64;

/// An exclusively owned, polled COM1 UART; no UART IRQ is enabled.
pub struct Serial16550 {
    _private: (),
}

impl Serial16550 {
    /// Initialize COM1 to 115200 baud, 8-N-1, with FIFOs enabled.
    ///
    /// # Safety
    /// Call only at CPL0 on the legacy PC profile, with exclusive ownership
    /// of COM1. No other core, interrupt handler or firmware may access this
    /// device for this object's lifetime. Port I/O must be permitted.
    pub unsafe fn init() -> Self {
        unsafe {
            outb(COM1_BASE + 1, 0x00); // Disable UART IRQs.
            outb(COM1_BASE + 3, 0x80); // Divisor latch access.
            outb(COM1_BASE, 0x01);
            outb(COM1_BASE + 1, 0x00);
            outb(COM1_BASE + 3, 0x03);
            outb(COM1_BASE + 2, 0xc7);
            outb(COM1_BASE + 4, 0x03); // DTR and RTS, no IRQ routing.
        }
        Self { _private: () }
    }
    pub fn try_read(&mut self) -> Result<Option<u8>, PlatformError> {
        crate::uart::receive(self)
    }
}

impl crate::uart::Registers for Serial16550 {
    fn read_register(&mut self, offset: u16) -> u8 {
        assert!(offset < 8, "UART register outside owned device");
        // SAFETY: init grants this object sole ownership of the eight COM1 ports.
        unsafe { inb(COM1_BASE + offset) }
    }
}

impl ConsoleOps for Serial16550 {
    fn try_write(&mut self, data: &[u8]) -> Result<usize, PlatformError> {
        let mut written = 0;
        for &byte in data.iter().take(SERIAL_CHUNK) {
            let mut ready = false;
            for _ in 0..SERIAL_POLLS {
                // SAFETY: the constructor establishes exclusive I/O ownership.
                if unsafe { inb(COM1_BASE + 5) } & 0x20 != 0 {
                    ready = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !ready {
                return if written == 0 {
                    Err(PlatformError::Again)
                } else {
                    Ok(written)
                };
            }
            unsafe { outb(COM1_BASE, byte) };
            written += 1;
        }
        Ok(written)
    }
}

unsafe fn pic_write(port: u16, value: u8) {
    unsafe {
        outb(port, value);
        outb(0x80, 0); // Legacy ISA I/O settling delay.
    }
}

/// Remap both 8259 PICs and enable only PIT channel 0 / IRQ0. Program the PIT
/// in periodic rate-generator mode. The returned divisor defines exact time.
///
/// # Safety
/// CPL0, interrupts disabled, exclusive board interrupt-controller ownership,
/// and the timer gate installed at vector 0x20 are required. This profile uses
/// the legacy PIC, with APIC routing disabled. The caller must acknowledge
/// every delivered IRQ0 and must not enable interrupts before its IDT and
/// interrupt stack are ready. No SMP reprogramming is supported here.
pub unsafe fn init_timer_100hz() -> PitConfig {
    unsafe {
        pic_write(PIC_MASTER_COMMAND + 1, 0xff);
        pic_write(PIC_SLAVE_COMMAND + 1, 0xff);
        pic_write(PIC_MASTER_COMMAND, 0x11);
        pic_write(PIC_SLAVE_COMMAND, 0x11);
        pic_write(PIC_MASTER_COMMAND + 1, PIC_VECTOR_BASE);
        pic_write(PIC_SLAVE_COMMAND + 1, PIC_VECTOR_BASE + 8);
        pic_write(PIC_MASTER_COMMAND + 1, 4);
        pic_write(PIC_SLAVE_COMMAND + 1, 2);
        pic_write(PIC_MASTER_COMMAND + 1, 1);
        pic_write(PIC_SLAVE_COMMAND + 1, 1);
        pic_write(PIC_MASTER_COMMAND + 1, 0xff);
        pic_write(PIC_SLAVE_COMMAND + 1, 0xff);
        outb(PIT_COMMAND, 0x34); // Channel 0, low/high byte, mode 2, binary.
        outb(PIT_CHANNEL_0, PIT_100HZ.divisor as u8);
        outb(PIT_CHANNEL_0, (PIT_100HZ.divisor >> 8) as u8);
        pic_write(PIC_MASTER_COMMAND + 1, 0xfe);
    }
    PIT_100HZ
}

/// # Safety
/// Call only from the exclusively owned legacy PIC IRQ0 handler, after its
/// device work, with a real in-service IRQ0. This is not a slave-PIC EOI.
pub unsafe fn acknowledge_timer_irq() {
    unsafe { outb(PIC_MASTER_COMMAND, 0x20) };
}

/// # Safety
/// Caller owns the initialized legacy PIC at CPL0 and excludes concurrent
/// changes to its interrupt mask (including from another CPU).
pub unsafe fn mask_timer_irq() {
    unsafe {
        let mask = inb(PIC_MASTER_COMMAND + 1);
        outb(PIC_MASTER_COMMAND + 1, mask | 1);
    }
}

/// # Safety
/// BSP owns both PICs; interrupts disabled and legacy IRQ work has completed.
pub unsafe fn mask_all_irqs() {
    unsafe {
        pic_write(PIC_MASTER_COMMAND + 1, 0xff);
        pic_write(PIC_SLAVE_COMMAND + 1, 0xff);
    }
}

/// Bounded PIT channel-2 one-shot delay, independent of local CPU/TSC rate.
/// This measures board elapsed time, never execution debit.
///
/// # Safety
/// BSP exclusively owns PIT channel 2 and port 61; no speaker user or other CPU
/// may reprogram them. `micros` is in 1..=20000. Caller does not require IRQs.
pub unsafe fn delay_us(micros: u32) -> Result<(), PlatformError> {
    if micros == 0 || micros > 20000 {
        return Err(PlatformError::Invalid);
    }
    let count = (u64::from(micros) * u64::from(crate::PIT_INPUT_HZ)).div_ceil(1_000_000) as u16;
    unsafe {
        let original = inb(0x61);
        outb(0x61, original & !3); // speaker disconnected, gate low.
        outb(PIT_COMMAND, 0xb0); // channel2, low/high, one-shot mode0.
        outb(0x42, count as u8);
        outb(0x42, (count >> 8) as u8);
        outb(0x61, (original & !2) | 1); // gate high starts the counter.
        for _ in 0..10_000_000 {
            if inb(0x61) & 0x20 != 0 {
                outb(0x61, original);
                return Ok(());
            }
            core::hint::spin_loop();
        }
        outb(0x61, original);
    }
    Err(PlatformError::Again)
}
