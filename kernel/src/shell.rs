use core::fmt::{self, Write};
use core::sync::atomic::Ordering;
use cyxia_contracts::{PhysAddr, UartResource};

// Statically reserved boot memory, separate from future CPU-model and user grants.
static mut SHELL: cyxia_shell::Shell = cyxia_shell::Shell::new();
const _: () = assert!(core::mem::size_of::<cyxia_ai_runtime::Runtime>() < 256 * 1024);
const _: () = assert!(core::mem::size_of::<cyxia_shell::Shell>() < 768 * 1024);

struct Output {
    bytes: [u8; 96],
    len: usize,
}
impl Output {
    fn flush(&mut self) {
        if self.len != 0 {
            super::log(&self.bytes[..self.len]);
            self.len = 0;
        }
    }
}
impl Write for Output {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for byte in text.bytes() {
            self.bytes[self.len] = byte;
            self.len += 1;
            // Supervisor launch/exit records must reach the console before a
            // newly dispatched process writes through its direct console path.
            if self.len == self.bytes.len() || byte == b'\n' {
                self.flush();
            }
        }
        Ok(())
    }
}
struct Devices;
impl cyxia_ai_runtime::DeviceIo for Devices {
    fn uart_write(&mut self, data: &[u8]) -> Result<usize, cyxia_ai_runtime::IoError> {
        // One framed UART record; the receiver only accepts complete CRC-checked records.
        super::try_log(data).map_err(cyxia_ai_runtime::IoError::from)?;
        Ok(data.len())
    }
    fn timer_read(&mut self) -> Result<u64, cyxia_ai_runtime::IoError> {
        Ok(cyxia_arch_aarch64::timer::ticks())
    }
}
pub fn run(info: &cyxia_contracts::BootInfo) -> ! {
    // CPU0 enters once. Interrupt handlers never access the shell or UART RX.
    let shell = unsafe { &mut *core::ptr::addr_of_mut!(SHELL) };
    let mut uart = unsafe {
        cyxia_driver_pl011::Pl011::attach(UartResource {
            base: PhysAddr(super::UART.load(Ordering::Relaxed)),
            len: 4096,
        })
    }
    .unwrap();
    let mut out = Output {
        bytes: [0; 96],
        len: 0,
    };
    shell
        .runtime_mut()
        .bind_devices(info.uart.is_some(), info.timer_irq.is_some())
        .unwrap();
    let mut devices = Devices;
    // Recover committed data before any shell input or EL0 process can create
    // handles. Each turn checks one block completion, with IRQs still enabled.
    while super::storage::recovering() {
        super::storage::poll(shell, &mut out);
        out.flush();
        cyxia_arch_aarch64::timer::idle();
    }
    shell.banner(&mut out).unwrap();
    out.flush();
    loop {
        #[cfg(feature = "graphics")]
        super::graphics::poll();
        // Bounded drain; timer interrupts continue to preempt command handling.
        for _ in 0..64 {
            match uart.try_read() {
                Ok(Some(byte)) => shell.input(byte, &mut out).unwrap(),
                Ok(None) => break,
                Err(_) => {
                    shell.input_error();
                    break;
                }
            }
        }
        out.flush();
        // Elapsed monotonic milliseconds, including periods skipped by IRQ rearming.
        let now = cyxia_kernel_core::time::ticks_to_ns(
            cyxia_arch_aarch64::timer::ticks(),
            cyxia_arch_aarch64::timer::frequency(),
        )
        .unwrap()
        .0 / 1_000_000;
        if let Err(error) = shell.runtime_mut().tick(now, &mut devices) {
            writeln!(out, "resource runtime fault: {error:?}\r").unwrap();
            out.flush();
            super::halt();
        }
        super::user::poll(shell, &mut out);
        super::storage::poll(shell, &mut out);
        super::ai::poll(shell, &mut out);
        out.flush();
        super::interrupts::TEST_PROGRESS
            .foreground
            .fetch_add(1, Ordering::Relaxed);
        cyxia_arch_aarch64::timer::idle();
    }
}
