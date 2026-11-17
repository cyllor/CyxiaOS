//! xAPIC CPU mechanisms; discovery and interrupt routing are board policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Address,
    Vector,
    Unsupported,
    DeliveryTimeout,
}

/// Physical ff is broadcast, never the identity of an admitted target CPU.
pub fn destination_high(destination: u8) -> Result<u32, Error> {
    if destination == 255 {
        return Err(Error::Address);
    }
    Ok((destination as u32) << 24)
}

pub fn fixed_command(vector: u8) -> Result<u32, Error> {
    if vector < 32 || vector == 128 || vector == 255 {
        return Err(Error::Vector);
    }
    Ok(vector as u32)
}
pub fn startup_command(physical_address: u64) -> Result<u32, Error> {
    if physical_address == 0
        || physical_address >= 0x100000
        || !physical_address.is_multiple_of(4096)
        || (0xa0000..0xc0000).contains(&physical_address)
    {
        return Err(Error::Address);
    }
    Ok(0x600 | (physical_address >> 12) as u32)
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod hardware {
    use super::*;
    const DELIVERY_POLLS: usize = 1_000_000;
    #[derive(Clone, Copy)]
    pub struct LocalApic {
        base: u64,
        owner: u8,
        _local: core::marker::PhantomData<*mut ()>,
    }
    pub fn initial_id() -> Result<u8, Error> {
        let cpuid = core::arch::x86_64::__cpuid(1);
        if cpuid.edx & (1 << 9) == 0 {
            return Err(Error::Unsupported);
        }
        Ok((cpuid.ebx >> 24) as u8)
    }
    unsafe fn read_msr(index: u32) -> u64 {
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!("rdmsr",in("ecx")index,out("eax")lo,out("edx")hi,options(nostack));
        }
        lo as u64 | (hi as u64) << 32
    }
    impl LocalApic {
        /// # Safety
        /// This CPU already initialized this exact mapped LAPIC base, and its
        /// register ownership/mapping remain valid for the returned handle.
        pub unsafe fn attach(base: u64) -> Self {
            Self {
                base,
                owner: initial_id().expect("local APIC CPU"),
                _local: core::marker::PhantomData,
            }
        }
        /// # Safety
        /// This CPU exclusively owns its APIC. `base` is a mapped supervisor
        /// UC/RW/NX LAPIC page. IF is clear and valid per-CPU gates are installed.
        pub unsafe fn init(base: u64) -> Result<Self, Error> {
            unsafe { Self::init_mapped(base, base) }
        }
        /// # Safety
        /// `mapped` is the supervisor UC alias of the discovered physical APIC.
        pub unsafe fn init_mapped(physical: u64, mapped: u64) -> Result<Self, Error> {
            initial_id()?;
            if !(4096..(1_u64 << 32)).contains(&physical)
                || !physical.is_multiple_of(4096)
                || !mapped.is_multiple_of(4096)
            {
                return Err(Error::Address);
            }
            let msr = unsafe { read_msr(0x1b) };
            if msr & (1 << 10) != 0 || msr & 0xffff_f000 != physical {
                return Err(Error::Unsupported);
            }
            // PCD|PWT leaf mappings select PAT entry 3. Refuse a non-UC PAT.
            if (unsafe { read_msr(0x277) } >> 24) & 255 != 0 {
                return Err(Error::Unsupported);
            }
            let enabled = msr | (1 << 11);
            unsafe {
                core::arch::asm!("wrmsr",in("ecx")0x1bu32,in("eax")enabled as u32,
                in("edx")(enabled>>32) as u32,options(nostack));
            }
            let lapic = unsafe { Self::attach(mapped) };
            let version = lapic.read(0x30);
            if version & 255 < 0x10 {
                return Err(Error::Unsupported);
            }
            lapic.write(0x80, 0); // TPR: admit fixed IPIs.
            for register in [0x320, 0x350, 0x360, 0x370] {
                lapic.write(register, 1 << 16);
            }
            if version >> 16 & 255 >= 4 {
                lapic.write(0x340, 1 << 16);
            }
            if version >> 16 & 255 >= 5 {
                lapic.write(0x330, 1 << 16);
            }
            lapic.write(0xf0, 0x1ff); // software enable, vector ff.
            lapic.write(0x280, 0);
            let _ = lapic.read(0x280);
            Ok(lapic)
        }
        fn read(self, register: usize) -> u32 {
            unsafe { core::ptr::read_volatile((self.base as usize + register) as *const u32) }
        }
        fn write(self, register: usize, value: u32) {
            unsafe {
                core::ptr::write_volatile((self.base as usize + register) as *mut u32, value);
            }
        }
        pub fn id(self) -> u8 {
            assert_eq!(initial_id().unwrap(), self.owner, "APIC handle CPU");
            (self.read(0x20) >> 24) as u8
        }
        pub fn eoi(self) {
            assert_eq!(initial_id().unwrap(), self.owner, "APIC handle CPU");
            self.write(0xb0, 0);
        }
        fn wait_idle(self) -> Result<(), Error> {
            for _ in 0..DELIVERY_POLLS {
                if self.read(0x300) & (1 << 12) == 0 {
                    return Ok(());
                }
                core::hint::spin_loop();
            }
            Err(Error::DeliveryTimeout)
        }
        fn send(self, destination: u8, command: u32) -> Result<(), Error> {
            let high = destination_high(destination)?;
            if initial_id()? != self.owner {
                return Err(Error::Unsupported);
            }
            // Both ICR halves belong to this CPU. Preserve caller IF even when
            // delivery times out; an interrupt cannot interleave another send.
            let _interrupts = InterruptGuard::new();
            self.wait_idle()?;
            self.write(0x310, high);
            self.write(0x300, command);
            self.wait_idle()
        }
        pub fn send_fixed(self, destination: u8, vector: u8) -> Result<(), Error> {
            self.send(destination, fixed_command(vector)?)
        }
        pub fn send_init(self, destination: u8) -> Result<(), Error> {
            self.send(destination, 0xc500)
        }
        pub fn send_init_deassert(self, destination: u8) -> Result<(), Error> {
            self.send(destination, 0x8500)
        }
        pub fn send_startup(self, destination: u8, physical_address: u64) -> Result<(), Error> {
            self.send(destination, startup_command(physical_address)?)
        }
    }
    struct InterruptGuard {
        enabled: bool,
    }
    impl InterruptGuard {
        fn new() -> Self {
            let flags: u64;
            unsafe {
                core::arch::asm!("pushfq","pop {}","cli",out(reg)flags);
            }
            Self {
                enabled: flags & (1 << 9) != 0,
            }
        }
    }
    impl Drop for InterruptGuard {
        fn drop(&mut self) {
            if self.enabled {
                unsafe {
                    core::arch::asm!("sti", options(nostack));
                }
            }
        }
    }
}
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use hardware::{LocalApic, initial_id};
