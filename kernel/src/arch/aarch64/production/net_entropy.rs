//! CPU0-owned VirtIO entropy and epoch-bound DRBG for authenticated SEC-N.
//! The source's DMA pool stays pinned for the lifetime of the device.
use crate::{net_device, virtio_platform::Board};
use core::sync::atomic::{AtomicBool, Ordering};
use cyxia_contracts::BootInfo;
use cyxia_driver_virtio::{Error, Platform, queue::BatchMemory, rng::BatchedRng};
use cyxia_kernel_core::security::{
    Error as SecurityError,
    network::entropy::{
        Domain, HEALTH_STARTUP_SAMPLES, INIT_SEED_BYTES, MAX_REQUEST_BYTES, NetworkRandom,
        RESEED_BYTES, RawHealth,
    },
};
use zeroize::{Zeroize, Zeroizing};

const ENTROPY_DEADLINE_MS: u64 = 250;
const CHUNK_BYTES: usize = 256;
static CLAIMED: AtomicBool = AtomicBool::new(false);
#[unsafe(link_section = ".bss.sec_n")]
static mut MEMORY: BatchMemory = BatchMemory::zeroed();

struct RawSource {
    rng: BatchedRng,
    health: RawHealth,
    samples: u64,
}

impl RawSource {
    /// Startup and reseed each examine two complete health windows under one
    /// I/O deadline. Only the requested portion of an accepted batch is used.
    fn seed<const N: usize>(&mut self, output: &mut [u8; N]) -> Result<(), Error> {
        let mut samples = Zeroizing::new([0u8; HEALTH_STARTUP_SAMPLES]);
        let start = Board.now_ms();
        let mut cursor = 0;
        while cursor < samples.len() {
            Self::check_deadline(start)?;
            let end = (cursor + CHUNK_BYTES).min(samples.len());
            let count = self.rng.try_fill(&mut samples[cursor..end], &Board)?;
            Self::check_deadline(start)?;
            self.health
                .observe(&samples[cursor..cursor + count])
                .map_err(|_| Error::Response)?;
            cursor += count;
            core::hint::spin_loop();
        }
        self.samples = self
            .samples
            .checked_add(samples.len() as u64)
            .ok_or(Error::Exhausted)?;
        output.copy_from_slice(&samples[samples.len() - N..]);
        Ok(())
    }

    fn check_deadline(start: u64) -> Result<(), Error> {
        match Board.now_ms().checked_sub(start) {
            Some(elapsed) if elapsed < ENTROPY_DEADLINE_MS => Ok(()),
            _ => Err(Error::Timeout),
        }
    }
}

pub(super) struct Entropy {
    source: RawSource,
    drbg: NetworkRandom,
    /// Bytes delivered to TCP/ISN and TLS callers. Excludes raw source bytes.
    pub(super) supplied: u64,
    pub(super) failed: bool,
}

impl Entropy {
    pub(super) fn attach(info: &BootInfo, boot_epoch: u64) -> Result<Self, Error> {
        if boot_epoch == 0 {
            return Err(Error::Response);
        }
        if cyxia_arch_aarch64::cpu::slot() != 0 || CLAIMED.swap(true, Ordering::AcqRel) {
            return Err(Error::Busy);
        }
        let transport = net_device::find_transport(info, 4)?;
        // SAFETY: the one-shot CPU0 claim above makes this the only borrow
        // of the permanently pinned queue.
        let memory = unsafe { &mut *core::ptr::addr_of_mut!(MEMORY) };
        let mut source = RawSource {
            rng: BatchedRng::attach(transport, memory, &Board)?,
            health: RawHealth::default(),
            samples: 0,
        };
        let mut seed = Zeroizing::new([0u8; INIT_SEED_BYTES]);
        source.seed(&mut *seed)?;
        let drbg = NetworkRandom::new(&seed, boot_epoch, Board.now_ms()).map_err(map_error)?;
        Ok(Self {
            source,
            drbg,
            supplied: 0,
            failed: false,
        })
    }

    pub(super) fn fill_tcp_seed(&mut self, out: &mut [u8; 8]) -> Result<(), Error> {
        self.fill_domain(Domain::TcpIsn, out)
    }

    pub(super) fn fill(&mut self, out: &mut [u8]) -> bool {
        self.fill_domain(Domain::Tls, out).is_ok()
    }

    pub(super) fn raw_samples(&self) -> u64 {
        self.source.samples
    }

    pub(super) fn key_epoch(&self) -> u64 {
        self.drbg.key_epoch()
    }

    fn fill_domain(&mut self, domain: Domain, out: &mut [u8]) -> Result<(), Error> {
        let result = self.generate(domain, out);
        if result.is_err() {
            self.drbg.close();
            self.failed = true;
            out.zeroize();
        }
        result
    }

    fn generate(&mut self, domain: Domain, out: &mut [u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Device);
        }
        if out.len() > MAX_REQUEST_BYTES {
            return Err(Error::Address);
        }
        let supplied = self
            .supplied
            .checked_add(out.len() as u64)
            .ok_or(Error::Exhausted)?;
        let mut now_ms = Board.now_ms();
        if self.drbg.reseed_due(now_ms).map_err(map_error)? {
            let mut seed = Zeroizing::new([0u8; RESEED_BYTES]);
            self.source.seed(&mut *seed)?;
            now_ms = Board.now_ms();
            self.drbg.reseed(&seed, now_ms).map_err(map_error)?;
        }
        self.drbg.fill(domain, out, now_ms).map_err(map_error)?;
        self.supplied = supplied;
        Ok(())
    }
}

fn map_error(error: SecurityError) -> Error {
    match error {
        SecurityError::Exhausted => Error::Exhausted,
        SecurityError::Stale => Error::Timeout,
        _ => Error::Response,
    }
}
