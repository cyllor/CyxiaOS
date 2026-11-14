//! Exclusive read-only echo workload on the actual recoverable EL0 owner.
//! Recovery continues through the ordinary supervisor while probe admission
//! yields to this separately retained caller queue.
use super::*;
use cyxia_prototype::learning::capture::RunKey;
#[path = "replay_core_image.rs"]
mod core_image;
pub use core_image::CoreImage;
static OWNED: AtomicBool = AtomicBool::new(false);
static BOUND: AtomicBool = AtomicBool::new(false);
static ABORTING: AtomicBool = AtomicBool::new(false);
#[derive(Clone, Copy)]
pub struct Image {
    pub target: ObjectKey,
    pub digest: [u8; 32],
}
struct Work {
    run: Option<RunKey>,
    serial: u64,
    pending: Option<(u64, ObjectKey, u64, u64)>,
    completed: Option<(u64, Result<u64, Error>)>,
    warm_at: u64,
    poll_at: u64,
    warm_index: u64,
}
static mut WORK: Work = Work {
    run: None,
    serial: 0,
    pending: None,
    completed: None,
    warm_at: 0,
    poll_at: 0,
    warm_index: 0,
};
fn work() -> &'static mut Work {
    unsafe { &mut *core::ptr::addr_of_mut!(WORK) }
}
pub(crate) fn owns(recipe: u16) -> bool {
    recipe == 2 && OWNED.load(Ordering::Acquire)
}
pub(crate) fn preparing(recipe: u16) -> bool {
    owns(recipe) && !BOUND.load(Ordering::Acquire)
}
pub fn bind_control() {
    BOUND.store(true, Ordering::Release);
}
pub fn core_target() -> Result<ObjectKey, Error> {
    read(|s| Ok(core_view_key(s)))
}
pub fn core_image() -> Result<CoreImage, Error> {
    read(|s| {
        CoreImage::observed(
            core_view_key(s),
            s.cores.control,
            s.cores.business,
            s.cores.healthy,
            s.cores.draining,
            s.core_pending,
        )
    })
}
pub fn prepare() -> Result<Image, Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    if ABORTING.load(Ordering::Acquire) {
        return Err(Error::Busy);
    }
    OWNED.store(true, Ordering::Release);
    let target = with(|s| {
        let service = s
            .services
            .iter()
            .flatten()
            .find(|v| v.recipe == 2)
            .ok_or(Error::NotReady)?;
        if service.active.is_some()
            || service.pending_probe.is_some()
            || work().pending.is_some()
            || work().completed.is_some()
        {
            return Err(Error::Busy);
        }
        Ok(service.key)
    })?;
    let digest = crate::domain_tasks::replay::reset_echo(target)?;
    Ok(Image { target, digest })
}
pub fn activate(run: RunKey) -> Result<(), Error> {
    with(|_| {
        let w = work();
        if !OWNED.load(Ordering::Acquire) || w.run.is_some_and(|old| old != run) {
            return Err(Error::Stale);
        }
        if w.pending.is_some_and(|(id, _, _, _)| id == 0) {
            return Err(Error::Busy);
        }
        w.run = Some(run);
        Ok(())
    })
}
/// Before a one-shot policy, the original owner processes actual immutable
/// echo requests. Polls are paced so raw CPU custody is bounded; a wall wait
/// never counts as a successful request or as executor CPU.
pub fn prewarm_step(seed: u64) -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    let at = crate::domain_platform::now_ns();
    let due = with(|_| {
        let w = work();
        Ok(owns(2)
            && !ABORTING.load(Ordering::Acquire)
            && w.run.is_none()
            && crate::learning_prewarm::active()
            && if w.pending.is_some() {
                at >= w.poll_at
            } else {
                at >= w.warm_at
            })
    })?;
    if !due {
        return Ok(());
    }
    let cpu_started = cyxia_arch_aarch64::timer::cpu_ticks();
    let Some(mut cpu) = crate::learning_prewarm::attempt_service() else {
        return Err(Error::Busy);
    };
    let result = with(|s| {
        let w = work();
        if w.run.is_some() || !crate::learning_prewarm::active() {
            return Ok(false);
        }
        if let Some((id, key, sequence, expected)) = w.pending {
            if id != 0 {
                return Err(Error::Conflict);
            }
            w.poll_at = at.checked_add(20_000_000).ok_or(Error::Overflow)?;
            match crate::domain_tasks::replay::echo_result(key, sequence) {
                Ok((value, _)) if value == expected => {
                    w.pending = None;
                    Ok(true)
                }
                Ok(_) => Err(Error::Io),
                Err(Error::Busy | Error::Again) => Ok(false),
                Err(e) => Err(e),
            }
        } else {
            let service = s
                .services
                .iter()
                .flatten()
                .find(|v| v.recipe == 2)
                .ok_or(Error::NotReady)?;
            if service.active.is_some() || service.pending_probe.is_some() {
                return Err(Error::Busy);
            }
            let serial = w.serial.checked_add(1).ok_or(Error::Overflow)?;
            let request = serial
                .checked_add(0x8000_0000_0000_0000)
                .ok_or(Error::Overflow)?;
            let index = w.warm_index.checked_add(1).ok_or(Error::Overflow)?;
            let value = seed.rotate_left(17) ^ index;
            let sequence = crate::domain_tasks::recoverable_submit(2, request, value)?;
            w.serial = serial;
            w.warm_index = index;
            w.pending = Some((0, service.key, sequence, value));
            w.warm_at = at.checked_add(80_000_000).ok_or(Error::Overflow)?;
            w.poll_at = at.checked_add(20_000_000).ok_or(Error::Overflow)?;
            Ok(false)
        }
    })
    .and_then(|completed| {
        if completed {
            crate::learning_prewarm::completed()
        } else {
            Ok(())
        }
    });
    let (first, last, _) = crate::domain_tasks::finish_cpu_interval(cpu_started);
    let measured = crate::learning_prewarm::finish(&mut cpu, first, last);
    result.and(measured)
}
pub fn freeze_warm(first_ns: u64) -> Result<(), Error> {
    // The root may run this readiness check on C1. It takes the same gate as
    // CPU0 writers but never mutates service state or publishes a snapshot.
    LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    let _guard = Guard;
    let s = unsafe { &*core::ptr::addr_of!(STATE) };
    (|| {
        let w = work();
        if w.run.is_some() || w.pending.is_some() || w.completed.is_some() {
            return Err(Error::Busy);
        }
        let service = s
            .services
            .iter()
            .flatten()
            .find(|v| v.recipe == 2)
            .ok_or(Error::NotReady)?;
        if service.active.is_some()
            || service.pending_probe.is_some()
            || !crate::domain_tasks::replay::echo_idle(service.key)?
        {
            return Err(Error::Busy);
        }
        crate::learning_prewarm::freeze(first_ns)
    })()
}
pub fn submit(id: u64, value: u64) -> Result<(), Error> {
    with(|s| {
        let w = work();
        if w.run.is_none() || !owns(2) {
            return Err(Error::Auth);
        }
        if w.pending.is_some_and(|(old, _, _, _)| old == id)
            || w.completed.is_some_and(|(old, _)| old == id)
        {
            return Ok(());
        }
        if w.pending.is_some() || w.completed.is_some() {
            return Err(Error::Busy);
        }
        let service = s
            .services
            .iter()
            .flatten()
            .find(|v| v.recipe == 2)
            .ok_or(Error::NotReady)?;
        if service.active.is_some() || service.pending_probe.is_some() {
            return Err(Error::Busy);
        }
        let serial = w.serial.checked_add(1).ok_or(Error::Overflow)?;
        // The disjoint caller request range is retained over service restarts.
        let request = serial
            .checked_add(0x8000_0000_0000_0000)
            .ok_or(Error::Overflow)?;
        let sequence = crate::domain_tasks::recoverable_submit(2, request, value)?;
        w.serial = serial;
        w.pending = Some((id, service.key, sequence, value));
        Ok(())
    })
}
pub fn result(id: u64) -> Result<Option<Result<u64, Error>>, Error> {
    with(|s| {
        let w = work();
        if let Some((old, result)) = w.completed {
            return if old == id {
                Ok(Some(result))
            } else {
                Err(Error::Conflict)
            };
        }
        let Some((old, key, sequence, expected)) = w.pending else {
            return Ok(None);
        };
        if old != id {
            return Err(Error::Stale);
        }
        match crate::domain_tasks::replay::echo_result(key, sequence) {
            Ok((value, finished)) if value == expected => {
                let result = Ok(finished);
                w.pending = None;
                w.completed = Some((id, result));
                Ok(Some(result))
            }
            Ok(_) => Err(Error::Io),
            Err(Error::Busy | Error::Again) => Ok(None),
            Err(Error::Stale) => {
                // Only a completed supervisor restart can settle the old
                // generation as rejected; a missing reply alone cannot.
                let current = s
                    .services
                    .iter()
                    .flatten()
                    .find(|v| v.recipe == 2)
                    .ok_or(Error::NotReady)?;
                if current.active.is_some()
                    || current.key.id != key.id
                    || current.key.generation <= key.generation
                {
                    return Ok(None);
                }
                w.pending = None;
                let result = Err(Error::Stale);
                w.completed = Some((id, result));
                Ok(Some(result))
            }
            Err(e) => Err(e),
        }
    })
}
pub fn acknowledge(id: u64) -> Result<(), Error> {
    with(|_| {
        let w = work();
        if w.completed.is_none_or(|(old, _)| old != id) {
            return Err(Error::Stale);
        }
        w.completed = None;
        Ok(())
    })
}
pub fn drain(run: RunKey) -> Result<bool, Error> {
    with(|s| {
        let w = work();
        if w.run != Some(run) {
            return Err(Error::Stale);
        }
        if w.pending.is_some() || w.completed.is_some() {
            return Ok(false);
        }
        let service = s
            .services
            .iter()
            .flatten()
            .find(|v| v.recipe == 2)
            .ok_or(Error::NotReady)?;
        if service.active.is_some() || service.pending_probe.is_some() {
            return Ok(false);
        }
        crate::domain_tasks::replay::echo_idle(service.key)
    })
}
pub fn release(run: RunKey) -> Result<(), Error> {
    if !drain(run)? {
        return Err(Error::Busy);
    }
    with(|_| {
        let w = work();
        w.run = None;
        w.warm_at = 0;
        w.poll_at = 0;
        w.warm_index = 0;
        OWNED.store(false, Ordering::Release);
        BOUND.store(false, Ordering::Release);
        ABORTING.store(false, Ordering::Release);
        Ok(())
    })
}
/// Stop new pre-snapshot echo admission, but continue the exact accepted
/// request until its actual immutable reply or completed generation change.
/// Its terminal receipt remains retained until the failure archive releases it.
pub fn abort_prepared() -> Result<bool, Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    ABORTING.store(true, Ordering::Release);
    let cpu_started = cyxia_arch_aarch64::timer::cpu_ticks();
    let mut measured = if crate::learning_prewarm::active() {
        Some(crate::learning_prewarm::attempt_service().ok_or(Error::Busy)?)
    } else {
        None
    };
    let result = with(|s| {
        let w = work();
        if w.run.is_some() {
            return Err(Error::Auth);
        }
        if !owns(2) {
            return Ok(true);
        }
        if let Some((id, key, sequence, expected)) = w.pending {
            if id != 0 {
                return Err(Error::Conflict);
            }
            let result = match crate::domain_tasks::replay::echo_result(key, sequence) {
                Ok((value, finished)) => Some(if value == expected {
                    Ok(finished)
                } else {
                    Err(Error::Io)
                }),
                Err(Error::Busy | Error::Again) => None,
                Err(Error::Stale) => {
                    let service = s
                        .services
                        .iter()
                        .flatten()
                        .find(|v| v.recipe == 2)
                        .ok_or(Error::NotReady)?;
                    (service.active.is_none()
                        && service.key.id == key.id
                        && service.key.generation > key.generation)
                        .then_some(Err(Error::Stale))
                }
                Err(error) => return Err(error),
            };
            if let Some(result) = result {
                w.pending = None;
                w.completed = Some((id, result));
                if result.is_ok() && crate::learning_prewarm::active() {
                    crate::learning_prewarm::completed()?;
                }
            } else {
                return Ok(false);
            }
        }
        let service = s
            .services
            .iter()
            .flatten()
            .find(|v| v.recipe == 2)
            .ok_or(Error::NotReady)?;
        if service.active.is_some() || service.pending_probe.is_some() {
            return Ok(false);
        }
        crate::domain_tasks::replay::echo_idle(service.key)
    });
    if let Some(cpu) = measured.as_mut() {
        let (first, last, _) = crate::domain_tasks::finish_cpu_interval(cpu_started);
        crate::learning_prewarm::finish(cpu, first, last)?;
    }
    result
}
pub fn release_prepared() -> Result<(), Error> {
    if !ABORTING.load(Ordering::Acquire) || !abort_prepared()? {
        return Err(Error::Busy);
    }
    with(|_| {
        let w = work();
        if w.run.is_some() || w.pending.is_some() {
            return Err(Error::Busy);
        }
        w.completed = None;
        w.warm_at = 0;
        w.poll_at = 0;
        w.warm_index = 0;
        OWNED.store(false, Ordering::Release);
        BOUND.store(false, Ordering::Release);
        ABORTING.store(false, Ordering::Release);
        Ok(())
    })
}
pub fn outside_source(
    key: ObjectKey,
    class: cyxia_prototype::learning::reward::CpuClass,
) -> Result<bool, Error> {
    super::replay_sources::outside_source(key, class)
}
