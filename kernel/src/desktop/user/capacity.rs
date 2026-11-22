//! Effective CPU0 admission limits selected before the first process starts.
use core::sync::atomic::{AtomicUsize, Ordering};
use cyxia_posix::{Errno, limits::ObjectProfile};

#[cfg(feature = "ported")]
const THREADS_PER_PROCESS: usize = super::threads::MAX_THREADS;
#[cfg(not(feature = "ported"))]
const THREADS_PER_PROCESS: usize = 1;
const THREADS: usize = if cfg!(feature = "cosmic-session") {
    256
} else {
    super::SLOTS * THREADS_PER_PROCESS
};
static THREAD_LIMIT: AtomicUsize = AtomicUsize::new(THREADS);
static PER_PROCESS_LIMIT: AtomicUsize = AtomicUsize::new(THREADS_PER_PROCESS);
static LIVE_THREADS: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn scale(maximum: usize, minimum: usize, percent: u64) -> usize {
    let minimum = minimum.min(maximum);
    minimum + (maximum - minimum) * percent as usize / 100
}

pub(crate) fn configure(percent: u64) -> Result<ObjectProfile, Errno> {
    let limit = |maximum, minimum| scale(maximum, minimum, percent);
    let build = cyxia_posix::limits::PROFILE;
    let objects = ObjectProfile {
        fds_per_process: limit(build.fds_per_process, 96),
        open_descriptions: limit(build.open_descriptions, 448),
        epoll_instances: limit(build.epoll_instances, 60),
        inotify_instances: limit(build.inotify_instances, 24),
        ..build
    };
    super::objects::table().set_boot_limits(objects)?;
    #[cfg(feature = "ported")]
    {
        super::pipes::set_boot_limit(limit(cyxia_posix::pipe::PIPES, 36))?;
        super::unix::set_boot_limits(
            limit(cyxia_posix::unix::ENDPOINTS, 112),
            limit(cyxia_posix::unix::CONNECTIONS, 56),
        )?;
    }
    THREAD_LIMIT.store(limit(THREADS, 128), Ordering::Relaxed);
    PER_PROCESS_LIMIT.store(limit(THREADS_PER_PROCESS, 12), Ordering::Relaxed);
    Ok(objects)
}

pub(crate) fn thread_limit() -> usize {
    THREAD_LIMIT.load(Ordering::Relaxed)
}
pub(crate) fn per_process_thread_limit() -> usize {
    PER_PROCESS_LIMIT.load(Ordering::Relaxed)
}
pub(super) fn thread_available() -> bool {
    LIVE_THREADS.load(Ordering::Relaxed) < thread_limit()
}
// CPU0 preflights and publishes in the same service operation. No AP can
// create or tear down a process/thread, including on the local syscall path.
pub(super) fn thread_started() {
    assert!(LIVE_THREADS.fetch_add(1, Ordering::Relaxed) < thread_limit());
}
pub(super) fn threads_released(count: usize) {
    LIVE_THREADS
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
            live.checked_sub(count)
        })
        .expect("published thread accounting");
}
