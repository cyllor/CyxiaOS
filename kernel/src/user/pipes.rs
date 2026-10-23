//! CPU0 foreground pipe admission and storage, independent of the socket pool.
use cyxia_posix::{Errno, pipe::Pipes};

static mut PIPES: Pipes = Pipes::new();

pub(super) fn with<T>(f: impl FnOnce(&mut Pipes) -> Result<T, Errno>) -> Result<T, Errno> {
    // SAFETY: CPU0 foreground serializes all operations. IRQ/DMA cannot access
    // the pool and the callback cannot return a reference to its entries.
    let pool = unsafe { &mut *core::ptr::addr_of_mut!(PIPES) };
    let result = f(pool);
    super::objects::table().observe_backend(|source| {
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
pub(super) fn pair(owner: u32) -> Result<[u64; 2], Errno> {
    let mut attempt = cyxia_ai_runtime::accounting::Attempt::default();
    let result = (|| {
        let free = with(|p| Ok(p.free()))?;
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
