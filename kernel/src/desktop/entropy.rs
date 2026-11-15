//! Shared VirtIO entropy service. Board adapters supply actual transports.
use super::virtio_platform::Board;
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "unified-runtime")]
use core::sync::atomic::AtomicU64;
use cyxia_driver_virtio::{Transport, queue::BatchMemory as QueueMemory, rng::BatchedRng as Rng};
static BUSY: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "unified-runtime")]
static IRQ: AtomicU64 = AtomicU64::new(0);
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}
fn acquire() -> Result<Guard, Errno> {
    #[cfg(target_arch = "aarch64")]
    let slot = cyxia_arch_aarch64::cpu::slot();
    #[cfg(target_arch = "x86_64")]
    let slot = crate::machine::runtime::cpu_slot();
    if slot != 0 {
        return Err(Errno::Again);
    }
    BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Errno::Again)?;
    Ok(Guard)
}
use cyxia_posix::Errno;
static mut MEMORY: QueueMemory = QueueMemory::zeroed();
static mut RNG: Option<Rng> = None;
#[cfg(target_arch = "aarch64")]
pub fn init(info: &cyxia_contracts::BootInfo) {
    for resource in &info.virtio[..info.virtio_count] {
        if resource.base.0 < 0x0a000000
            || resource
                .base
                .0
                .checked_add(resource.len)
                .is_none_or(|e| e > 0x0a200000)
        {
            continue;
        }
        // SAFETY: DTB resource is inside this board's mapped Device window;
        // only CPU0 foreground probes/owns it, and only RNG device 4 is retained.
        let Ok(transport) = (unsafe {
            Transport::attach(
                (super::HIGH + resource.base.0) as usize,
                resource.len as usize,
            )
        }) else {
            continue;
        };
        if transport.device_id() != 4 {
            continue;
        }
        attach(transport, resource.irq, resource.base.0);
        return;
    }
    super::log(b"ENTROPY_UNAVAILABLE MECHANISM\n");
}

#[cfg(target_arch = "x86_64")]
pub fn init_transport(transport: Option<Transport>) {
    if let Some(transport) = transport {
        attach(transport, 0, 0);
    } else {
        super::log(b"ENTROPY_UNAVAILABLE MECHANISM\n");
    }
}
fn attach(transport: Transport, _irq: u32, _base: u64) {
    let result = (|| {
        let memory = unsafe { &mut *core::ptr::addr_of_mut!(MEMORY) };
        Rng::attach(transport, memory, &Board)
    })();
    if let Ok(mut rng) = result {
        #[cfg(feature = "unified-runtime")]
        IRQ.store(u64::from(_irq), Ordering::Release);
        #[cfg(feature = "unified-runtime")]
        {
            if crate::domain_storage::register_notify_device(
                crate::domain_storage::RNG_NOTIFY,
                _base,
                rng.capacity(),
                _irq,
            )
            .is_err()
            {
                super::log(b"ENTROPY_ERROR REGISTRY\n");
                return;
            }
            rng.set_notify_hooks(
                crate::domain_storage::rng_notify_command,
                crate::domain_storage::rng_notify_feedback,
            );
        }
        // Submit at boot; no spin or invented seed. Completion is polled
        // once by a nonblocking consumer or by the bounded blocking fill.
        if rng.prefetch(&Board).is_err() {
            super::log(b"ENTROPY_ERROR MECHANISM\n");
            return;
        }
        // The static handle and queue have one CPU0 foreground owner.
        unsafe {
            *core::ptr::addr_of_mut!(RNG) = Some(rng);
        }
        super::log(b"ENTROPY_READY VIRTIO MECHANISM\n");
    } else {
        super::log(b"ENTROPY_ERROR MECHANISM\n");
    }
}

pub fn fill(out: &mut [u8]) -> Result<(), Errno> {
    let _guard = acquire()?;
    // SAFETY: all calls are serialized by CPU0 foreground; IRQs never use RNG.
    let rng = unsafe { &mut *core::ptr::addr_of_mut!(RNG) }
        .as_mut()
        .ok_or(Errno::Nodev)?;
    rng.fill(out, &Board).map_err(|_| Errno::Io)
}

/// Linux getrandom adapter. Partial nonblocking reads are legal. No device,
/// pending entropy, and failed DMA remain distinct errors; no PRNG fallback.
#[cfg(feature = "ported")]
pub fn read(out: &mut [u8], nonblocking: bool) -> Result<usize, Errno> {
    if out.is_empty() {
        return Ok(0);
    }
    if !nonblocking {
        fill(out)?;
        return Ok(out.len());
    }
    let _guard = acquire()?;
    // SAFETY: CPU0 foreground is the only owner, as in fill/init above.
    let rng = unsafe { &mut *core::ptr::addr_of_mut!(RNG) }
        .as_mut()
        .ok_or(Errno::Nodev)?;
    match rng.try_fill(out, &Board).map_err(|_| Errno::Io)? {
        0 => Err(Errno::Again),
        count => Ok(count),
    }
}

/// Cluster broker fill keeps the independent scheduler progressing while DMA is
/// pending. It accepts the ABI's bounded 4KiB request as <=256-byte pool reads;
/// partial entropy is erased on every failure and never returned as success.
#[cfg(feature = "unified-runtime")]
pub fn fill_progress(out: &mut [u8], progress: &mut dyn FnMut()) -> Result<(), Errno> {
    use cyxia_driver_virtio::Platform;
    let _guard = acquire()?;
    let rng = unsafe { &mut *core::ptr::addr_of_mut!(RNG) }
        .as_mut()
        .ok_or(Errno::Nodev)?;
    if out.len() > 4096 {
        return Err(Errno::Inval);
    }
    let start = Board.now_ms();
    let mut done = 0;
    while done < out.len() {
        progress();
        if Board.now_ms().saturating_sub(start) >= 250 {
            out.fill(0);
            return Err(Errno::Io);
        }
        let end = (done + 256).min(out.len());
        match rng.try_fill(&mut out[done..end], &Board) {
            Ok(n) => done += n,
            Err(_) => {
                out.fill(0);
                return Err(Errno::Io);
            }
        }
    }
    Ok(())
}

#[cfg(feature = "unified-runtime")]
pub fn enable_interrupts() -> Result<(), cyxia_prototype::domains::Error> {
    let _guard = acquire().map_err(|_| cyxia_prototype::domains::Error::Busy)?;
    let rng = unsafe { &mut *core::ptr::addr_of_mut!(RNG) }
        .as_mut()
        .ok_or(cyxia_prototype::domains::Error::NotReady)?;
    rng.set_completion_interrupts(true, &Board);
    crate::domain_platform::enable_device_irq(IRQ.load(Ordering::Acquire) as u32)
}
