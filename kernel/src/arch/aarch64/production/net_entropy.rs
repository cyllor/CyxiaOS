//! CPU0-owned VirtIO entropy and epoch-bound DRBG for native boot and SEC-N.
//! The source's DMA pool stays pinned for the lifetime of the device.
use crate::virtio_platform::{Board, find_transport};
use core::sync::atomic::{AtomicBool, Ordering};
use cyxia_contracts::BootInfo;
use cyxia_driver_virtio::{Error, Platform, queue::BatchMemory, rng::BatchedRng};
use cyxia_kernel_core::security::network::entropy::{
    Domain, HEALTH_STARTUP_SAMPLES, INIT_SEED_BYTES, NetworkRandom, RawHealth,
};
#[cfg(any(feature = "v020-production-authenticated-net", cyxia_resident_net))]
use cyxia_kernel_core::security::{
    Error as SecurityError,
    network::entropy::{MAX_REQUEST_BYTES, RESEED_BYTES},
};
#[cfg(any(feature = "v020-production-authenticated-net", cyxia_resident_net))]
use zeroize::Zeroize;
use zeroize::Zeroizing;

const ENTROPY_DEADLINE_MS: u64 = 250;
const CHUNK_BYTES: usize = 256;
static CLAIMED: AtomicBool = AtomicBool::new(false);
#[unsafe(link_section = ".bss.sec_n.dma")]
#[unsafe(export_name = "V020_DMA_RNG_QUEUE")]
static mut MEMORY: BatchMemory = BatchMemory::zeroed();

struct RawSource {
    rng: BatchedRng,
    health: RawHealth,
    samples: u64,
}

impl RawSource {
    fn attach(
        info: &BootInfo,
        boot_epoch: u64,
        checkpoint: &mut impl FnMut() -> Result<(), Error>,
    ) -> Result<Self, Error> {
        if boot_epoch == 0 {
            return Err(Error::Response);
        }
        if cyxia_arch_aarch64::cpu::slot() != 0 || CLAIMED.swap(true, Ordering::AcqRel) {
            return Err(Error::Busy);
        }
        let transport = find_transport(info, 4)?;
        // SAFETY: the one-shot CPU0 claim above makes this the only borrow
        // of the permanently pinned queue.
        let memory = unsafe { &mut *core::ptr::addr_of_mut!(MEMORY) };
        Ok(Self {
            rng: BatchedRng::attach_native_with_checkpoint(transport, memory, &Board, checkpoint)?,
            health: RawHealth::default(),
            samples: 0,
        })
    }

    /// Startup and reseed each examine two complete health windows under one
    /// I/O deadline. Only the requested portion of an accepted batch is used.
    fn seed<const N: usize>(
        &mut self,
        output: &mut [u8; N],
        mut checkpoint: impl FnMut() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut samples = Zeroizing::new([0u8; HEALTH_STARTUP_SAMPLES]);
        let start = Board.now_ms();
        let mut cursor = 0;
        while cursor < samples.len() {
            checkpoint()?;
            Self::check_deadline(start)?;
            let end = (cursor + CHUNK_BYTES).min(samples.len());
            let count = self.samples_into(&mut samples[cursor..end])?;
            Self::check_deadline(start)?;
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

    fn samples_into(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        let count = self.rng.try_fill(output, &Board)?;
        self.health
            .observe(&output[..count])
            .map_err(|_| Error::Response)?;
        Ok(count)
    }

    fn check_deadline(start: u64) -> Result<(), Error> {
        match Board.now_ms().checked_sub(start) {
            Some(elapsed) if elapsed < ENTROPY_DEADLINE_MS => Ok(()),
            _ => Err(Error::Timeout),
        }
    }
}

#[cfg(cyxia_business_package)]
pub(super) fn startup_aslr(
    info: &BootInfo,
    boot_epoch: u64,
    output: &mut [u8],
    mut checkpoint: impl FnMut() -> Result<(), Error>,
) -> Result<(), Error> {
    // A bounded read may leave prefetch descriptors in flight. Keep their
    // unique driver and pinned DMA ownership even after an error or success.
    static mut SOURCE: core::mem::MaybeUninit<RawSource> = core::mem::MaybeUninit::uninit();
    checkpoint()?;
    let mut source = RawSource::attach(info, boot_epoch, &mut checkpoint)?;
    source.rng.set_completion_interrupts(false, &Board);
    // SAFETY: RawSource::attach privately claims ownership once on CPU0.
    let source = unsafe { (*core::ptr::addr_of_mut!(SOURCE)).write(source) };
    let mut seed = Zeroizing::new([0u8; INIT_SEED_BYTES]);
    source.seed(&mut *seed, &mut checkpoint)?;
    checkpoint()?;
    let mut drbg =
        NetworkRandom::new(&seed, boot_epoch, Board.now_ms()).map_err(|_| Error::Response)?;
    drbg.fill(Domain::Aslr, output, Board.now_ms())
        .map_err(|_| Error::Response)
}

#[cfg(any(feature = "v020-production-authenticated-net", cyxia_resident_net))]
pub(super) struct Entropy {
    source: RawSource,
    drbg: NetworkRandom,
    /// Bytes delivered to TCP/ISN and TLS callers. Excludes raw source bytes.
    pub(super) supplied: u64,
    pub(super) failed: bool,
    #[cfg(cyxia_resident_net)]
    pending_seed: Option<PendingSeed>,
}

#[cfg(cyxia_resident_net)]
struct PendingSeed {
    started: u64,
    used: usize,
    bytes: Zeroizing<[u8; HEALTH_STARTUP_SAMPLES]>,
}

#[cfg(any(feature = "v020-production-authenticated-net", cyxia_resident_net))]
impl Entropy {
    #[cfg(feature = "v020-production-authenticated-net")]
    pub(super) fn attach(info: &BootInfo, boot_epoch: u64) -> Result<Self, Error> {
        Self::attach_checkpointed(info, boot_epoch, &mut || Ok(()))
    }

    pub(super) fn attach_checkpointed(
        info: &BootInfo,
        boot_epoch: u64,
        checkpoint: &mut impl FnMut() -> Result<(), Error>,
    ) -> Result<Self, Error> {
        checkpoint()?;
        let mut source = RawSource::attach(info, boot_epoch, checkpoint)?;
        source.rng.set_completion_interrupts(false, &Board);
        let mut seed = Zeroizing::new([0u8; INIT_SEED_BYTES]);
        source.seed(&mut *seed, &mut *checkpoint)?;
        checkpoint()?;
        let drbg = NetworkRandom::new(&seed, boot_epoch, Board.now_ms()).map_err(map_error)?;
        Ok(Self {
            source,
            drbg,
            supplied: 0,
            failed: false,
            #[cfg(cyxia_resident_net)]
            pending_seed: None,
        })
    }

    pub(super) fn fill_tcp_seed(&mut self, out: &mut [u8; 8]) -> Result<(), Error> {
        self.fill_domain(Domain::TcpIsn, out)
    }

    #[cfg(all(cyxia_resident_net, cyxia_business_package))]
    pub(super) fn fill_aslr(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.fill_domain(Domain::Aslr, out)
    }

    pub(super) fn fill(&mut self, out: &mut [u8]) -> bool {
        self.fill_domain(Domain::Tls, out).is_ok()
    }

    #[cfg(feature = "v020-production-authenticated-net")]
    pub(super) fn raw_samples(&self) -> u64 {
        self.source.samples
    }

    #[cfg(feature = "v020-production-authenticated-net")]
    pub(super) fn key_epoch(&self) -> u64 {
        self.drbg.key_epoch()
    }

    fn fill_domain(&mut self, domain: Domain, out: &mut [u8]) -> Result<(), Error> {
        let result = self.generate(domain, out);
        if result.is_err() {
            out.zeroize();
            #[cfg(cyxia_resident_net)]
            if result == Err(Error::Busy) {
                return result;
            }
            self.close();
        }
        result
    }

    pub(super) fn close(&mut self) {
        self.drbg.close();
        self.failed = true;
        #[cfg(cyxia_resident_net)]
        {
            self.pending_seed = None;
        }
    }

    /// Advance the VirtIO reseed by at most one batch on the network's
    /// business CPU. No waiter can extend the current scheduler grant.
    #[cfg(cyxia_resident_net)]
    pub(super) fn maintain(&mut self) -> Result<bool, Error> {
        let result = self.maintain_seed();
        if result.is_err() {
            self.close();
        }
        result
    }

    #[cfg(cyxia_resident_net)]
    fn maintain_seed(&mut self) -> Result<bool, Error> {
        let now = Board.now_ms();
        if !self.drbg.reseed_due(now).map_err(map_error)? {
            return Ok(true);
        }
        let seed = self.pending_seed.get_or_insert_with(|| PendingSeed {
            started: now,
            used: 0,
            bytes: Zeroizing::new([0; HEALTH_STARTUP_SAMPLES]),
        });
        RawSource::check_deadline(seed.started)?;
        let end = (seed.used + CHUNK_BYTES).min(seed.bytes.len());
        seed.used += self.source.samples_into(&mut seed.bytes[seed.used..end])?;
        RawSource::check_deadline(seed.started)?;
        if seed.used != seed.bytes.len() {
            return Ok(false);
        }
        let seed = self.pending_seed.take().ok_or(Error::Response)?;
        let entropy = seed.bytes[seed.used - RESEED_BYTES..]
            .try_into()
            .map_err(|_| Error::Response)?;
        self.drbg
            .reseed(entropy, Board.now_ms())
            .map_err(map_error)?;
        self.source.samples = self
            .source
            .samples
            .checked_add(seed.used as u64)
            .ok_or(Error::Exhausted)?;
        Ok(true)
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
        #[cfg(not(cyxia_resident_net))]
        if self.drbg.reseed_due(Board.now_ms()).map_err(map_error)? {
            let mut seed = Zeroizing::new([0u8; RESEED_BYTES]);
            self.source.seed(&mut *seed, || Ok(()))?;
            self.drbg.reseed(&seed, Board.now_ms()).map_err(map_error)?;
        }
        self.drbg
            .fill(domain, out, Board.now_ms())
            .map_err(map_error)?;
        self.supplied = supplied;
        Ok(())
    }
}

#[cfg(any(feature = "v020-production-authenticated-net", cyxia_resident_net))]
fn map_error(error: SecurityError) -> Error {
    match error {
        SecurityError::Exhausted => Error::Exhausted,
        SecurityError::Stale => Error::Timeout,
        SecurityError::Busy => Error::Busy,
        _ => Error::Response,
    }
}
