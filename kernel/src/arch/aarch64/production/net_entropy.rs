//! One CPU0-owned VirtIO entropy source for the authenticated SEC-N turn.
//!
//! The DMA pool is in the pinned FrameMeta Arena. Only `attach` borrows it,
//! once after CPU0 claims it. The driver retains the pool for the lifetime
//! of the device, and errors leave all DMA storage pinned.
use crate::{net_device, virtio_platform::Board};
use core::sync::atomic::{AtomicBool, Ordering};
use cyxia_contracts::BootInfo;
use cyxia_driver_virtio::{Error, Platform, queue::BatchMemory, rng::BatchedRng};

const ENTROPY_DEADLINE_MS: u64 = 250;
const CHUNK_BYTES: usize = 256;
static CLAIMED: AtomicBool = AtomicBool::new(false);
#[unsafe(link_section = ".bss.sec_n")]
static mut MEMORY: BatchMemory = BatchMemory::zeroed();

pub(super) struct Entropy {
    rng: BatchedRng,
    pub(super) supplied: u64,
    pub(super) failed: bool,
}

impl Entropy {
    pub(super) fn attach(info: &BootInfo) -> Result<Self, Error> {
        if cyxia_arch_aarch64::cpu::slot() != 0 || CLAIMED.swap(true, Ordering::AcqRel) {
            return Err(Error::Busy);
        }
        let transport = net_device::find_transport(info, 4)?;
        // SAFETY: the one-shot CPU0 claim above makes this the only borrow
        // of the permanently pinned queue.
        let memory = unsafe { &mut *core::ptr::addr_of_mut!(MEMORY) };
        let rng = BatchedRng::attach(transport, memory, &Board)?;
        Ok(Self {
            rng,
            supplied: 0,
            failed: false,
        })
    }

    pub(super) fn fill(&mut self, out: &mut [u8]) -> bool {
        if self.failed || self.read(out).is_err() {
            self.failed = true;
            out.fill(0);
            return false;
        }
        self.supplied = self.supplied.saturating_add(out.len() as u64);
        true
    }

    /// Apply one deadline to the whole request, including partial fills.
    fn read(&mut self, out: &mut [u8]) -> Result<(), Error> {
        let start = Board.now_ms();
        let mut cursor = 0;
        while cursor < out.len() {
            if Board.now_ms().wrapping_sub(start) >= ENTROPY_DEADLINE_MS {
                return Err(Error::Timeout);
            }
            let end = (cursor + CHUNK_BYTES).min(out.len());
            cursor += self.rng.try_fill(&mut out[cursor..end], &Board)?;
            if Board.now_ms().wrapping_sub(start) >= ENTROPY_DEADLINE_MS {
                return Err(Error::Timeout);
            }
            core::hint::spin_loop();
        }
        Ok(())
    }
}
