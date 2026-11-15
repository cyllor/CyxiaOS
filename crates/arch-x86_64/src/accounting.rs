//! Cyxia QEMU ABI 1 clocks. Execution debit and monotonic deadlines are distinct.
//!
//! The execution source counts host thread CPU ns only inside translated guest
//! code and synchronous helpers. It excludes translation, halted waits, sibling
//! vCPUs and event-loop work after a TB exits. This is a pinned prototype ABI,
//! not an architectural x86 PMU or KVM clock. Live migration is unsupported.

pub const SOURCE_ABI: u32 = 1;
pub const CAPABILITY_LEAF: u32 = 0x4000_0001;
pub const CAPABILITY_WORDS: [u32; 4] = [0x4359_5831, 0x0001_0007, 0x4b59_5801, 1_000_000_000];
pub const EXECUTION_MSR: u32 = CAPABILITY_WORDS[2];
pub const MONOTONIC_MSR: u32 = EXECUTION_MSR + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockError {
    Capability,
    Cpu,
    Source,
    Regression,
    Overflow,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability {
    pub source: u32,
    pub frequency_hz: u32,
}

impl Capability {
    pub fn from_cpuid(words: [u32; 4]) -> Result<Self, ClockError> {
        if words != CAPABILITY_WORDS {
            return Err(ClockError::Capability);
        }
        Ok(Self {
            source: SOURCE_ABI,
            frequency_hz: 1_000_000_000,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionStamp {
    /// Logical CPU slot bound to an observed APIC identity during initialization.
    pub cpu: u32,
    pub source: u32,
    pub ns: u64,
}

/// Cross-CPU/source samples and clock regression never create execution credit.
pub fn elapsed_ns(start: ExecutionStamp, end: ExecutionStamp) -> Result<u64, ClockError> {
    if start.source != SOURCE_ABI || end.source != SOURCE_ABI {
        return Err(ClockError::Source);
    }
    if start.cpu != end.cpu {
        return Err(ClockError::Cpu);
    }
    end.ns.checked_sub(start.ns).ok_or(ClockError::Regression)
}

pub fn add_debit_ns(total: u64, delta: u64) -> Result<u64, ClockError> {
    total.checked_add(delta).ok_or(ClockError::Overflow)
}

/// Shared QEMU virtual monotonic nanoseconds. Pausing the VM pauses this clock.
/// Never use these values to debit execution or to manufacture ExecutionStamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonotonicStamp {
    pub source: u32,
    pub ns: u64,
}

impl MonotonicStamp {
    pub fn deadline_after(self, duration_ns: u64) -> Result<Self, ClockError> {
        if self.source != SOURCE_ABI {
            return Err(ClockError::Source);
        }
        Ok(Self {
            source: self.source,
            ns: self
                .ns
                .checked_add(duration_ns)
                .ok_or(ClockError::Overflow)?,
        })
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod hardware {
    use super::*;
    use core::arch::{asm, x86_64::__cpuid_count};

    fn cpuid(leaf: u32) -> [u32; 4] {
        let value = __cpuid_count(leaf, 0);
        [value.eax, value.ebx, value.ecx, value.edx]
    }

    fn apic_id() -> u8 {
        (cpuid(1)[1] >> 24) as u8
    }

    fn capability() -> Result<Capability, ClockError> {
        let hypervisor = cpuid(0x4000_0000);
        if hypervisor != [0x4000_0001, 0x5447_4354, 0x4354_4743, 0x4743_5447] {
            return Err(ClockError::Capability);
        }
        Capability::from_cpuid(cpuid(CAPABILITY_LEAF))
    }

    unsafe fn rdmsr(index: u32) -> u64 {
        let low: u32;
        let high: u32;
        unsafe {
            asm!("rdmsr", in("ecx") index, out("eax") low, out("edx") high,
                 options(nostack, preserves_flags));
        }
        u64::from(low) | (u64::from(high) << 32)
    }

    /// One owner per CPU. Any detected error permanently invalidates this handle.
    /// Hardware-side failure also stays latched, and direct invalid MSR reads #GP.
    pub struct ExecutionClock {
        cpu: u32,
        apic_id: u8,
        last: ExecutionStamp,
        last_monotonic: MonotonicStamp,
        failed: bool,
    }

    impl ExecutionClock {
        /// # Safety
        /// Run at CPL0 on the CPU mapped to `cpu`/`expected_apic_id`. The caller
        /// must prevent migration until return and use the pinned MTTCG profile.
        /// A fault between capability validation and RDMSR intentionally #GPs;
        /// the kernel exception handler must treat it as a fatal clock failure.
        pub unsafe fn init(cpu: u32, expected_apic_id: u8) -> Result<Self, ClockError> {
            if apic_id() != expected_apic_id {
                return Err(ClockError::Cpu);
            }
            capability()?;
            let ns = unsafe { rdmsr(EXECUTION_MSR) };
            let monotonic_ns = unsafe { rdmsr(MONOTONIC_MSR) };
            if apic_id() != expected_apic_id {
                return Err(ClockError::Cpu);
            }
            Ok(Self {
                cpu,
                apic_id: expected_apic_id,
                last: ExecutionStamp {
                    cpu,
                    source: SOURCE_ABI,
                    ns,
                },
                last_monotonic: MonotonicStamp {
                    source: SOURCE_ABI,
                    ns: monotonic_ns,
                },
                failed: false,
            })
        }

        fn check(&mut self) -> Result<(), ClockError> {
            if self.failed {
                return Err(ClockError::Failed);
            }
            let result = if apic_id() != self.apic_id {
                Err(ClockError::Cpu)
            } else {
                capability().map(|_| ())
            };
            if result.is_err() {
                self.failed = true;
            }
            result
        }

        /// # Safety
        /// CPL0, on this handle's bound CPU, with migration prevented until return.
        pub unsafe fn sample(&mut self) -> Result<ExecutionStamp, ClockError> {
            self.check()?;
            let next = ExecutionStamp {
                cpu: self.cpu,
                source: SOURCE_ABI,
                ns: unsafe { rdmsr(EXECUTION_MSR) },
            };
            let result = if apic_id() != self.apic_id {
                Err(ClockError::Cpu)
            } else {
                elapsed_ns(self.last, next).map(|_| next)
            };
            match result {
                Ok(stamp) => {
                    self.last = stamp;
                    Ok(stamp)
                }
                Err(error) => {
                    self.failed = true;
                    Err(error)
                }
            }
        }

        /// # Safety
        /// Same requirements as `sample`. This is deadline time, never CPU debit.
        pub unsafe fn monotonic(&mut self) -> Result<MonotonicStamp, ClockError> {
            self.check()?;
            let next = MonotonicStamp {
                source: SOURCE_ABI,
                ns: unsafe { rdmsr(MONOTONIC_MSR) },
            };
            let error = if apic_id() != self.apic_id {
                Some(ClockError::Cpu)
            } else if next.ns < self.last_monotonic.ns {
                Some(ClockError::Regression)
            } else {
                None
            };
            if let Some(error) = error {
                self.failed = true;
                return Err(error);
            }
            self.last_monotonic = next;
            Ok(next)
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use hardware::ExecutionClock;
