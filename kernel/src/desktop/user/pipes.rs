//! CPU0 foreground pipe admission and storage, independent of the socket pool.
use core::fmt::Write;
use cyxia_posix::{Errno, pipe::Pipes};

static mut PIPES: Pipes = Pipes::new();

#[cfg(target_arch = "x86_64")]
pub(super) fn set_boot_limit(limit: usize) -> Result<(), Errno> {
    // Initialization runs on CPU0 before any process can access the pool.
    unsafe { (&mut *core::ptr::addr_of_mut!(PIPES)).set_boot_limit(limit) }
}

pub(super) fn status(out: &mut impl Write) {
    // SAFETY: this snapshot runs on the same CPU0 foreground as pool mutation.
    let pool = unsafe { &*core::ptr::addr_of!(PIPES) };
    let free = pool.free();
    let capacity = pool.capacity();
    let _ = writeln!(
        out,
        "PIPE_POOL capacity={} unavailable={} free={} bytes_per_pair={} backing=BOOTSTRAP policy=AI_DIRECT model=8193\r",
        capacity,
        capacity - free,
        free,
        cyxia_posix::pipe::CAPACITY
    );
}

pub(super) fn with<T>(f: impl FnOnce(&mut Pipes) -> Result<T, Errno>) -> Result<T, Errno> {
    let result = observe_with(f);
    // A failing mutation can commit a prefix. Mark even if no FD has an
    // epoll watch, and leave pure queries on the inspection path.
    super::objects::table().publish_poll_change();
    result
}

pub(super) fn inspect<T>(f: impl FnOnce(&Pipes) -> Result<T, Errno>) -> Result<T, Errno> {
    observe_with(|pool| f(pool))
}

fn observe_with<T>(f: impl FnOnce(&mut Pipes) -> Result<T, Errno>) -> Result<T, Errno> {
    // SAFETY: CPU0 foreground serializes all operations. IRQ/DMA cannot access
    // the pool and the callback cannot return a reference to its entries.
    let pool = unsafe { &mut *core::ptr::addr_of_mut!(PIPES) };
    let result = f(pool);
    super::objects::table().observe_backend(cyxia_posix::epoll::Backend::Pipe, |source| {
        let cyxia_posix::epoll::Source::Pipe { owner, handle } = source else {
            return None;
        };
        Some((
            u32::from(pool.poll(owner, handle).ok()?),
            pool.wake_mask(owner, handle).unwrap_or(0),
        ))
    });
    pool.clear_wakes();
    result
}

pub(super) fn poll(owner: u32, handle: u64) -> Result<u16, Errno> {
    // SAFETY: CPU0 foreground serializes this snapshot with pipe mutations.
    let pool = unsafe { &*core::ptr::addr_of!(PIPES) };
    pool.poll(owner, handle)
}

pub(super) fn pair(owner: u32) -> Result<[u64; 2], Errno> {
    let mut attempt = cyxia_ai_runtime::accounting::Attempt::default();
    let result = (|| {
        let free = inspect(|p| Ok(p.free()))?;
        // Fixed backing is BOOTSTRAP; this model grants only logical occupancy.
        attempt.proposed(8193);
        let (allowed, model) =
            cyxia_ai_runtime::user_memory_policy(free as u32, 1).map_err(|_| Errno::Io)?;
        attempt.decided(allowed, model);
        if !allowed {
            return Err(Errno::Again);
        }
        with(|p| p.pair(owner))
    })();
    super::ai::admission(super::ai::Domain::Pipe, attempt, &result);
    if result.is_ok() {
        super::super::log(b"PIPE_ADMISSION AI_DIRECT model=8193 committed=true\n");
    }
    result
}
