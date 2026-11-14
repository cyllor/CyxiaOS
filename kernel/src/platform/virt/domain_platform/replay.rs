//! Future soft timer requests use the production hardware deadline owner and
//! complete only in its real expiry callback.
use super::*;
use cyxia_prototype::learning::capture::RunKey;
#[path = "replay_irq_image.rs"]
mod irq_image;
pub use irq_image::IrqImage;
#[path = "replay_sources.rs"]
mod sources;
pub use sources::outside_source;
pub fn irq_image() -> Result<IrqImage, Error> {
    let key = super::irq_replay::source()?;
    let i = slot(u32::try_from(key.id).map_err(|_| Error::Range)?)?;
    if !LIVE[i].load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    let view = topology(i)?;
    let current = u16::try_from(TARGET[i].load(Ordering::Acquire)).map_err(|_| Error::Range)?;
    if ROUTE_GENERATION[i].load(Ordering::Acquire) != view.route_generation {
        return Err(Error::Busy);
    }
    IrqImage::observed(
        key,
        current,
        IRQ_ALLOWED,
        view.healthy_business,
        view.draining,
    )
}
const COUNT: usize = 101;
const BASE: u64 = 0x5245_5054_0000;
static REGISTERED: AtomicUsize = AtomicUsize::new(0);
static RESET: AtomicUsize = AtomicUsize::new(0);
static IDS: [AtomicU64; COUNT] = [const { AtomicU64::new(0) }; COUNT];
static FIRED: [AtomicU64; COUNT] = [const { AtomicU64::new(0) }; COUNT];
static ARMED: [AtomicBool; COUNT] = [const { AtomicBool::new(false) }; COUNT];
static mut RUN: Option<RunKey> = None;
fn key(i: usize) -> ObjectKey {
    ObjectKey {
        id: BASE + i as u64,
        generation: 1,
    }
}
fn index(id: u64) -> Result<usize, Error> {
    if id == 0 || id >= 256 {
        return Err(Error::Range);
    }
    Ok(if id <= 100 { id as usize - 1 } else { 100 })
}
fn fired(object: ObjectKey, now: u64) {
    let Some(i) = object.id.checked_sub(BASE).filter(|i| *i < COUNT as u64) else {
        return;
    };
    let i = i as usize;
    if object.generation == 1 && ARMED[i].swap(false, Ordering::AcqRel) {
        FIRED[i].store(now, Ordering::Release);
    }
}
pub fn prepare() -> Result<Option<[u8; 32]>, Error> {
    owner();
    if unsafe { *core::ptr::addr_of!(RUN) }.is_some() {
        return Err(Error::Busy);
    }
    let first = REGISTERED.load(Ordering::Acquire);
    for i in first..(first + 8).min(COUNT) {
        register_timer(key(i), TimerClass::Soft, 1_000_000, fired)?;
        REGISTERED.store(i + 1, Ordering::Release);
    }
    if REGISTERED.load(Ordering::Acquire) != COUNT {
        return Ok(None);
    }
    let first = RESET.load(Ordering::Acquire);
    for i in first..(first + 8).min(COUNT) {
        cancel_timer(key(i))?;
        ARMED[i].store(false, Ordering::Release);
        FIRED[i].store(0, Ordering::Release);
        IDS[i].store(0, Ordering::Release);
        RESET.store(i + 1, Ordering::Release);
    }
    if RESET.load(Ordering::Acquire) != COUNT {
        return Ok(None);
    }
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"CYXIA_CLOSED_SOFT_TIMER_WORKING_SET_1.3\0");
    h.update((COUNT as u64).to_le_bytes());
    for i in 0..COUNT {
        h.update(key(i).id.to_le_bytes());
        h.update(1_000_000u64.to_le_bytes());
    }
    Ok(Some(h.finalize().into()))
}
pub fn target() -> Result<ObjectKey, Error> {
    control_target(7, 1, 0).ok_or(Error::NotReady)
}
pub fn activate(run: RunKey) -> Result<(), Error> {
    owner();
    let old = unsafe { *core::ptr::addr_of!(RUN) };
    if old.is_some_and(|v| v != run) || REGISTERED.load(Ordering::Acquire) != COUNT {
        return Err(Error::Stale);
    }
    unsafe {
        *core::ptr::addr_of_mut!(RUN) = Some(run);
    }
    Ok(())
}
pub fn submit(id: u64, deadline: u64) -> Result<(), Error> {
    owner();
    if unsafe { *core::ptr::addr_of!(RUN) }.is_none() {
        return Err(Error::Auth);
    }
    let i = index(id)?;
    if IDS[i].load(Ordering::Acquire) == id {
        return Ok(());
    }
    if ARMED[i].load(Ordering::Acquire) {
        return Err(Error::Busy);
    }
    let now = now_ns();
    arm_timer(key(i), deadline, now)?;
    IDS[i].store(id, Ordering::Relaxed);
    FIRED[i].store(0, Ordering::Relaxed);
    ARMED[i].store(true, Ordering::Release);
    Ok(())
}
pub fn result(id: u64) -> Result<Option<Result<u64, Error>>, Error> {
    owner();
    let i = index(id)?;
    if IDS[i].load(Ordering::Acquire) != id {
        return Err(Error::Stale);
    }
    let at = FIRED[i].load(Ordering::Acquire);
    Ok((at != 0).then_some(Ok(at)))
}
pub fn drain(run: RunKey) -> Result<bool, Error> {
    owner();
    if unsafe { *core::ptr::addr_of!(RUN) } != Some(run) {
        return Err(Error::Stale);
    }
    Ok(ARMED.iter().all(|v| !v.load(Ordering::Acquire)))
}
pub fn release(run: RunKey) -> Result<(), Error> {
    if !drain(run)? {
        return Err(Error::Busy);
    }
    unsafe {
        *core::ptr::addr_of_mut!(RUN) = None;
    }
    RESET.store(0, Ordering::Release);
    Ok(())
}
pub fn abort_prepared() -> Result<bool, Error> {
    owner();
    if unsafe { *core::ptr::addr_of!(RUN) }.is_some() {
        return Err(Error::Auth);
    }
    // No timer can be armed before activation. A nonempty real slot is a
    // retained obligation, not permission to cancel it during preparation.
    Ok(ARMED.iter().all(|v| !v.load(Ordering::Acquire)))
}
pub fn release_prepared() -> Result<(), Error> {
    if !abort_prepared()? {
        return Err(Error::Busy);
    }
    RESET.store(0, Ordering::Release);
    Ok(())
}
