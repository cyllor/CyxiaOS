//! Ordinary files and device policies share the boot journal's single owner.
//! IRQs and callbacks see atomic facts; they never borrow an active filesystem.
use crate::{prototype_storage as storage, virtio_platform::Board};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_driver_virtio::{
    Platform,
    queue::{NotifyPolicy, NotifyStats},
};
use cyxia_prototype::{
    domains::{
        Action, ApplyId, Error, ObjectKey, PolicyStamp,
        filesystem::{
            BACKGROUND_RESERVATION_BYTES, Entry, FileSystem, FlushReceipt, Handle, Metrics,
            OpenMode, Stat, SyncReceipt,
        },
        io::Class,
    },
    features::TargetFeatures,
    policy::ExecutionState,
};
static READY: AtomicBool = AtomicBool::new(false);
static BUSY: AtomicBool = AtomicBool::new(false);
static mut FILES: FileSystem<4096> = FileSystem::new();
static METRICS: [AtomicU64; 24] = [const { AtomicU64::new(0) }; 24];
static mut SYNC_BINS: [u64; 64] = [0; 64];
static mut SYNC_WINDOW: u64 = 0;
static FS_ID: AtomicU64 = AtomicU64::new(0);
static FS_GENERATION: AtomicU64 = AtomicU64::new(0);
#[derive(Clone, Copy)]
struct FileView {
    at: u64,
    metrics: Metrics,
    cache: [u64; 4],
    action: Action,
    action_until: u64,
    cache_until: Option<u64>,
    backing: Option<(u64, u32)>,
    fsync_p99: u64,
}
static FILE_VIEW: crate::domain_platform::read_snapshot::ReadSnapshot<FileView> =
    crate::domain_platform::read_snapshot::ReadSnapshot::new();
const NOTIFIERS: usize = 2;
pub const NET_NOTIFY: usize = 1;
pub const RNG_NOTIFY: usize = 2;
static DEVICES: [[AtomicU64; 20]; NOTIFIERS] =
    [const { [const { AtomicU64::new(0) }; 20] }; NOTIFIERS];
#[derive(Clone, Copy)]
struct Installed {
    action: Action,
    id: ApplyId,
    stamp: PolicyStamp,
    state: ExecutionState,
}
static mut INSTALLED: [Option<Installed>; 5] = [None; 5];
fn owner() -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::slot() == 0 {
        Ok(())
    } else {
        Err(Error::Auth)
    }
}
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}
fn with_files<R>(f: impl FnOnce(&mut FileSystem<4096>) -> Result<R, Error>) -> Result<R, Error> {
    owner()?;
    BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    let _guard = Guard;
    let files = unsafe { &mut *core::ptr::addr_of_mut!(FILES) };
    files.refresh_cache_partition(Board.now_ns());
    let r = f(files);
    publish(files);
    r
}
/// Loaded inode metadata remains on its actual CPU0 owner. Control workers use
/// FILE_VIEW instead and therefore cannot make the file pump Busy by reading.
fn read_files<R>(f: impl FnOnce(&FileSystem<4096>) -> Result<R, Error>) -> Result<R, Error> {
    owner()?;
    ready_read()?;
    BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    let _guard = Guard;
    unsafe { f(&*core::ptr::addr_of!(FILES)) }
}
fn publish(files: &FileSystem<4096>) {
    let m = files.metrics();
    let c = files.cache_usage();
    let now = Board.now_ns();
    let (action_a, action_b) = match files.current_action(now) {
        Action::Filesystem { readahead, flush } => (readahead, flush),
        _ => (0, 4),
    };
    let vals = [
        c[0] as u64,
        c[1] as u64,
        c[2] as u64,
        c[3] as u64,
        m.read_bytes,
        m.write_bytes,
        m.cache_hits,
        m.cache_misses,
        m.readahead_pages,
        m.readahead_hits,
        m.flushed_pages,
        m.last_read_version,
        m.last_flush_version,
        u64::from(action_a),
        u64::from(action_b),
    ];
    for (i, v) in vals.into_iter().enumerate() {
        METRICS[i].store(v, Ordering::Relaxed);
    }
    METRICS[18].store(now, Ordering::Release);
    let (base, len) = files.cache_backing();
    let backing = Board
        .physical(base, len)
        .ok()
        .map(|pa| (pa, (len / 4096) as u32));
    let _ = FILE_VIEW.publish(FileView {
        at: now,
        metrics: m,
        cache: c.map(|n| n as u64),
        action: files.current_action(now),
        action_until: files.policy_deadline_ns(),
        cache_until: files.cache_partition_deadline_ns(),
        backing,
        fsync_p99: METRICS[15].load(Ordering::Acquire),
    });
}
fn file_view(now: u64) -> Result<FileView, Error> {
    ready_read()?;
    let view = FILE_VIEW
        .read()
        .map_err(|_| Error::Busy)?
        .ok_or(Error::NotReady)?;
    if now < view.at || now - view.at >= 50_000_000 {
        return Err(Error::Busy);
    }
    Ok(view)
}
pub fn init() -> Result<(), Error> {
    owner()?;
    if READY.load(Ordering::Acquire) {
        return Ok(());
    }
    let id = storage::identity().ok_or(Error::NotReady)?;
    with_files(|f| {
        storage::try_with_class(Class::Recovery, &mut || {}, |j, d, s| f.mount(j, d, s))??;
        f.set_cache_partition(192, 16)
    })?;
    FS_ID.store(
        u64::from_le_bytes(id.filesystem[..8].try_into().unwrap()) | 1,
        Ordering::Relaxed,
    );
    FS_GENERATION.store(id.epoch, Ordering::Release);
    for d in &DEVICES {
        if d[0].load(Ordering::Acquire) != 0 {
            d[1].store(id.epoch, Ordering::Release);
        }
    }
    READY.store(true, Ordering::Release);
    Ok(())
}
fn ready() -> Result<(), Error> {
    owner()?;
    ready_read()
}
fn ready_read() -> Result<(), Error> {
    if READY.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err(Error::NotReady)
    }
}
pub fn metrics() -> Metrics {
    Metrics {
        read_bytes: METRICS[4].load(Ordering::Acquire),
        write_bytes: METRICS[5].load(Ordering::Acquire),
        cache_hits: METRICS[6].load(Ordering::Acquire),
        cache_misses: METRICS[7].load(Ordering::Acquire),
        dirty_pages: METRICS[1].load(Ordering::Acquire) as u32,
        readahead_pages: METRICS[8].load(Ordering::Acquire),
        readahead_hits: METRICS[9].load(Ordering::Acquire),
        flushed_pages: METRICS[10].load(Ordering::Acquire),
        last_read_version: METRICS[11].load(Ordering::Acquire),
        last_flush_version: METRICS[12].load(Ordering::Acquire),
    }
}
pub fn cache_usage() -> [u64; 4] {
    core::array::from_fn(|i| METRICS[i].load(Ordering::Acquire))
}
pub fn cache_partition_status() -> Result<[u64; 4], Error> {
    let now = Board.now_ns();
    let view = file_view(now)?;
    if view.cache_until.is_some_and(|until| now >= until) {
        return Err(Error::Busy);
    }
    Ok(view.cache)
}
pub fn cache_backing() -> Result<(u64, u32), Error> {
    ready_read()?;
    // The static physical span cannot change during this boot. Startup may
    // inspect it before periodic service refreshes mutable admission facts.
    FILE_VIEW
        .read()
        .map_err(|_| Error::Busy)?
        .ok_or(Error::NotReady)?
        .backing
        .ok_or(Error::NotReady)
}
pub fn set_cache_partition(pages: u32, batch: u16) -> Result<(), Error> {
    ready()?;
    with_files(|f| f.set_cache_partition(pages as usize, batch as usize))
}
pub fn set_cache_partition_expiring(
    pages: u32,
    batch: u16,
    stamp: PolicyStamp,
) -> Result<(), Error> {
    ready()?;
    with_files(|f| {
        f.set_cache_partition_expiring(pages as usize, batch as usize, stamp, Board.now_ns())
    })
}
pub fn cache_reclaim_turn() -> Result<usize, Error> {
    ready()?;
    let freed = with_files(|f| Ok(f.reclaim_cache()))?;
    storage::refresh_control_observation(Board.now_ns())?;
    Ok(freed)
}
pub fn validate_file_object(key: ObjectKey) -> Result<(), Error> {
    ready_read()?;
    if storage::facts_read()?[31] != 0 {
        return Err(Error::Io);
    }
    read_files(|f| f.stat_object(key).map(|_| ()))
}
pub fn stat_file_object(key: ObjectKey) -> Result<u64, Error> {
    ready_read()?;
    if storage::facts_read()?[31] != 0 {
        return Err(Error::Io);
    }
    read_files(|f| f.stat_object(key).map(|v| v.size))
}
pub fn read_cache_page(key: ObjectKey, page: u64, out: &mut [u8; 4096]) -> Result<(), Error> {
    ready()?;
    with_files(|f| {
        storage::try_with_class(Class::Foreground, &mut || {}, |j, d, s| {
            f.read_cache_page(key, page, out, j, d, s)
        })?
    })
}
pub fn create(path: &str, p: &mut dyn FnMut()) -> Result<ObjectKey, Error> {
    ready()?;
    with_files(|f| storage::try_with_class(Class::Recovery, p, |j, d, s| f.create(path, j, d, s))?)
}
pub fn mkdir(path: &str, p: &mut dyn FnMut()) -> Result<ObjectKey, Error> {
    ready()?;
    with_files(|f| storage::try_with_class(Class::Recovery, p, |j, d, s| f.mkdir(path, j, d, s))?)
}
pub fn stat(path: &str, p: &mut dyn FnMut()) -> Result<Stat, Error> {
    ready()?;
    with_files(|f| storage::try_with_class(Class::Foreground, p, |j, d, s| f.stat(path, j, d, s))?)
}
pub fn open(path: &str, mode: OpenMode, p: &mut dyn FnMut()) -> Result<Handle, Error> {
    ready()?;
    with_files(|f| {
        storage::try_with_class(Class::Foreground, p, |j, d, s| f.open(path, mode, j, d, s))?
    })
}
pub fn handle_object(h: Handle) -> Result<ObjectKey, Error> {
    ready()?;
    with_files(|f| f.handle_object(h))
}
pub fn read(h: Handle, offset: u64, out: &mut [u8], p: &mut dyn FnMut()) -> Result<usize, Error> {
    ready()?;
    let key = enumerate_target(4, 0).ok_or(Error::NotReady)?;
    let prefetch = crate::domain_control::admit_dependencies(4, key).is_ok();
    with_files(|f| {
        storage::try_with_class(Class::Foreground, p, |j, d, s| {
            f.read_admitted(h, offset, out, Board.now_ns(), prefetch, j, d, s)
        })?
    })
}
pub fn write(h: Handle, offset: u64, data: &[u8], p: &mut dyn FnMut()) -> Result<usize, Error> {
    ready()?;
    let (key, n) = with_files(|f| {
        let key = f.handle_object(h)?;
        let n = storage::try_with_class(Class::Foreground, p, |j, d, s| {
            f.write(h, offset, data, j, d, s)
        })??;
        Ok((key, n))
    })?;
    if n != 0 {
        crate::domain_tasks::invalidate_file(key);
    }
    Ok(n)
}
pub fn fsync(h: Handle, p: &mut dyn FnMut()) -> Result<SyncReceipt, Error> {
    ready()?;
    with_files(|f| {
        let start = Board.now_ns();
        let r = storage::try_with_class(Class::Recovery, p, |j, d, s| f.fsync(h, j, d, s))?;
        if r.is_ok() {
            let now = Board.now_ns();
            let ns = now.saturating_sub(start);
            unsafe {
                let bins = &mut *core::ptr::addr_of_mut!(SYNC_BINS);
                if SYNC_WINDOW != now / 100_000_000 {
                    bins.fill(0);
                    SYNC_WINDOW = now / 100_000_000;
                }
                let at = if ns == 0 {
                    0
                } else {
                    (64 - ns.leading_zeros()).min(63) as usize
                };
                bins[at] = bins[at].saturating_add(1);
                let total = bins.iter().sum::<u64>();
                let mut sum = 0;
                for (i, v) in bins.iter().enumerate() {
                    sum += v;
                    if u128::from(sum) * 100 >= u128::from(total) * 99 {
                        METRICS[15].store((1u64 << i).div_ceil(1000), Ordering::Release);
                        break;
                    }
                }
            }
        }
        r
    })
}
pub fn close(h: Handle) -> Result<(), Error> {
    owner()?;
    with_files(|f| f.close(h))
}
pub fn readdir(h: Handle, cookie: u16, p: &mut dyn FnMut()) -> Result<Option<Entry>, Error> {
    ready()?;
    with_files(|f| {
        storage::try_with_class(Class::Foreground, p, |j, d, s| {
            f.readdir(h, cookie, j, d, s)
        })?
    })
}
pub fn unlink(path: &str, p: &mut dyn FnMut()) -> Result<(), Error> {
    ready()?;
    let key = with_files(|f| {
        storage::try_with_class(Class::Recovery, p, |j, d, s| {
            let key = f.stat(path, j, d, s)?.object;
            f.unlink(path, j, d, s)?;
            Ok(key)
        })?
    })?;
    crate::domain_tasks::invalidate_file(key);
    Ok(())
}
pub fn background_flush(now: u64, p: &mut dyn FnMut()) -> Result<Option<FlushReceipt>, Error> {
    ready()?;
    let usage = cache_partition_status()?;
    if usage[1] == 0 {
        storage::cancel_background()?;
        return Ok(None);
    }
    if usage[0] > usage[2] {
        // These pages are already owned obligations of the shrinking cache.
        // Necessary writeback cannot wait for the shrinking grant to become
        // APPLIED, and neither optional policy gets a completion receipt here.
        storage::cancel_background()?;
        return with_files(|f| {
            storage::try_with_class(Class::Recovery, p, |j, d, s| f.reclaim_flush_one(j, d, s))?
        });
    }
    let key = enumerate_target(4, 0).ok_or(Error::NotReady)?;
    let memory = crate::domain_tasks::memory_key()?;
    crate::domain_control::admit_dependency(
        crate::domain_control::Prerequisite {
            domain: 3,
            target: memory,
        },
        4,
        now,
    )?;
    let installed = unsafe { (*core::ptr::addr_of!(INSTALLED))[1] };
    if let Some(old) = installed
        && !old.stamp.live(now)
        && !old.state.terminal()
        && !executed(1, old.stamp)
    {
        storage::cancel_background()?;
        return Err(Error::Again);
    }
    let io_version = installed
        .filter(|i| i.stamp.live(now))
        .map_or(0, |i| i.stamp.version);
    storage::prepare_background(BACKGROUND_RESERVATION_BYTES, io_version, now)?;
    // A retained real byte/DMA/credit grant can now be confirmed by the root.
    // It is consumed only after the exact prerequisite is visible as APPLIED.
    crate::domain_control::admit_dependencies(4, key)?;
    with_files(|f| {
        storage::try_with_class(Class::Background, p, |j, d, s| {
            f.background_flush(now, j, d, s)
        })?
    })
}
pub fn service(now: u64, p: &mut dyn FnMut()) -> Result<usize, Error> {
    let pages = background_flush(now, p)?.map_or(0, |r| usize::from(r.pages));
    cache_reclaim_turn()?;
    Ok(pages)
}

/// Registration may precede filesystem init (the entropy device starts early).
/// Init upgrades only its boot generation, preserving the registered owner.
pub fn register_notify_device(
    slot: usize,
    id: u64,
    capacity: usize,
    irq: u32,
) -> Result<(), Error> {
    owner()?;
    let d = DEVICES
        .get(slot.checked_sub(1).ok_or(Error::Range)?)
        .ok_or(Error::Range)?;
    if id == 0 || capacity == 0 || capacity > 8 {
        return Err(Error::Capacity);
    }
    let old = d[0].load(Ordering::Acquire);
    if old != 0 && old != id {
        return Err(Error::Conflict);
    }
    d[2].store(capacity as u64, Ordering::Relaxed);
    d[3].store(u64::from(irq), Ordering::Relaxed);
    d[1].store(
        storage::identity().map_or(1, |v| v.epoch),
        Ordering::Relaxed,
    );
    d[0].store(id, Ordering::Release);
    Ok(())
}
fn command(slot: usize, now: u64) -> Option<NotifyPolicy> {
    let d = &DEVICES[slot - 1];
    let version = d[4].load(Ordering::Acquire);
    let until = d[5].load(Ordering::Acquire);
    (version != 0 && now < until).then(|| NotifyPolicy {
        batch: d[6].load(Ordering::Acquire) as u8,
        version,
        until_ns: until,
    })
}
fn feedback(slot: usize, s: NotifyStats, now: u64, polled: bool) {
    let d = &DEVICES[slot - 1];
    let window = now / 100_000_000;
    if d[14].load(Ordering::Relaxed) != window {
        d[14].store(window, Ordering::Relaxed);
        d[16].store(d[11].load(Ordering::Relaxed), Ordering::Relaxed);
    }
    d[7].store(
        u64::from(command(slot, now).map_or(1, |v| v.batch)),
        Ordering::Relaxed,
    );
    d[8].store(u64::from(s.pending), Ordering::Relaxed);
    d[9].store(s.errors, Ordering::Relaxed);
    d[10].store(u64::from(s.descriptors), Ordering::Relaxed);
    d[11].store(s.doorbells, Ordering::Relaxed);
    d[12].store(s.last_completed_version, Ordering::Relaxed);
    d[18].store(s.pending_version, Ordering::Relaxed);
    d[15].store(
        s.doorbells
            .saturating_sub(d[16].load(Ordering::Relaxed))
            .saturating_mul(10),
        Ordering::Relaxed,
    );
    d[13].store(now, Ordering::Release);
    if polled && s.errors == 0 {
        let _ = crate::domain_platform::device_polled(d[3].load(Ordering::Acquire) as u32);
    }
}
pub fn net_notify_command(now: u64) -> Option<NotifyPolicy> {
    command(NET_NOTIFY, now)
}
pub fn rng_notify_command(now: u64) -> Option<NotifyPolicy> {
    command(RNG_NOTIFY, now)
}
pub fn net_notify_feedback(s: NotifyStats, now: u64, polled: bool) {
    feedback(NET_NOTIFY, s, now, polled)
}
pub fn rng_notify_feedback(s: NotifyStats, now: u64, polled: bool) {
    feedback(RNG_NOTIFY, s, now, polled)
}
fn device_target(slot: usize) -> Option<ObjectKey> {
    if slot == 0 {
        let f = storage::facts();
        return (f[0] != 0 && f[1] != 0).then_some(ObjectKey {
            id: f[0],
            generation: f[1],
        });
    }
    let d = DEVICES.get(slot - 1)?;
    let id = d[0].load(Ordering::Acquire);
    (id != 0).then_some(ObjectKey {
        id,
        generation: d[1].load(Ordering::Acquire),
    })
}
pub fn enumerate_target(domain: u16, ordinal: usize) -> Option<ObjectKey> {
    if !READY.load(Ordering::Acquire) {
        return None;
    }
    match (domain, ordinal) {
        (4, 0) => Some(ObjectKey {
            id: FS_ID.load(Ordering::Acquire),
            generation: FS_GENERATION.load(Ordering::Acquire),
        }),
        (9, 0) => device_target(0),
        (11, _) => (0..3).filter_map(device_target).nth(ordinal),
        _ => None,
    }
}
fn target(domain: u16, kind: u16, ordinal: usize) -> Option<ObjectKey> {
    if kind != 1 {
        return None;
    }
    enumerate_target(domain, ordinal)
}
fn target_slot(domain: u16, key: ObjectKey) -> Result<usize, Error> {
    if domain == 11 {
        return (0..3)
            .find(|&slot| device_target(slot) == Some(key))
            .ok_or(Error::Stale);
    }
    if enumerate_target(domain, 0) == Some(key) {
        Ok(0)
    } else {
        Err(Error::Stale)
    }
}
pub fn observation(domain: u16, key: ObjectKey) -> Result<[u64; 4], Error> {
    let slot = target_slot(domain, key)?;
    let now = Board.now_ns();
    match domain {
        4 => {
            let view = file_view(now)?;
            let m = view.metrics;
            let total = m.read_bytes.saturating_add(m.write_bytes);
            Ok([
                if total == 0 {
                    0
                } else {
                    ((u128::from(m.read_bytes) * 1000) / u128::from(total)) as u64
                },
                u64::from(m.dirty_pages),
                view.fsync_p99,
                if m.readahead_pages == 0 {
                    0
                } else {
                    ((u128::from(m.readahead_hits) * 1000) / u128::from(m.readahead_pages))
                        .min(1000) as u64
                },
            ])
        }
        9 => {
            let f = storage::facts_read()?;
            let total = f[10].saturating_add(f[11]);
            let recent = now / 100_000_000 == f[28] / 100_000_000;
            Ok([
                f[7],
                if recent { f[25] } else { 0 },
                if recent && total != 0 {
                    ((u128::from(f[11]) * 1000) / u128::from(total)) as u64
                } else {
                    0
                },
                if recent { f[26] } else { 0 },
            ])
        }
        11 if slot == 0 => {
            let f = storage::facts_read()?;
            Ok([
                f[21],
                f[24],
                f[22],
                if now.saturating_sub(f[28]) < 100_000_000 {
                    f[33]
                } else {
                    0
                },
            ])
        }
        11 => {
            let d = &DEVICES[slot - 1];
            Ok([
                d[8].load(Ordering::Acquire),
                d[9].load(Ordering::Acquire),
                d[10].load(Ordering::Acquire),
                if now / 100_000_000 == d[14].load(Ordering::Acquire) {
                    d[15].load(Ordering::Acquire)
                } else {
                    0
                },
            ])
        }
        _ => Err(Error::Unsupported),
    }
}
pub fn current_action(domain: u16, key: ObjectKey) -> Result<Action, Error> {
    let slot = target_slot(domain, key)?;
    let now = Board.now_ns();
    match domain {
        4 => {
            let view = file_view(now)?;
            Ok(if now < view.action_until {
                view.action
            } else {
                Action::Filesystem {
                    readahead: 0,
                    flush: 4,
                }
            })
        }
        9 => storage::current_io_action(now),
        11 if slot == 0 => Ok(Action::NotifyBatch(storage::current_notify_batch(now)?)),
        11 => Ok(Action::NotifyBatch(
            command(slot, now).map_or(1, |c| c.batch),
        )),
        _ => Err(Error::Unsupported),
    }
}
pub fn validate_action(action: Action, key: ObjectKey, now: u64) -> Result<(), Error> {
    ready_read()?;
    action.validate()?;
    let slot = target_slot(action.domain(), key)?;
    match action {
        Action::Filesystem { readahead, flush } => {
            let c = cache_partition_status()?;
            if u64::from(readahead) > c[2] || u64::from(flush) > c[3] {
                return Err(Error::Capacity);
            }
            if storage::facts_read()?[31] != 0 {
                return Err(Error::Io);
            }
        }
        Action::IoShare(_) => {
            let f = storage::facts_read()?;
            if f[2] < 2 {
                return Err(Error::Capacity);
            }
            if f[31] != 0 {
                return Err(Error::Io);
            }
        }
        Action::NotifyBatch(v) => {
            let (cap, failed) = if slot == 0 {
                let f = storage::facts_read()?;
                (f[2], f[31])
            } else {
                let d = &DEVICES[slot - 1];
                (d[2].load(Ordering::Acquire), d[9].load(Ordering::Acquire))
            };
            if u64::from(v) > cap {
                return Err(Error::Capacity);
            }
            if failed != 0 {
                return Err(Error::Io);
            }
        }
        _ => return Err(Error::Unsupported),
    }
    let _ = now;
    Ok(())
}
fn control_current(domain: u16, _kind: u16, key: ObjectKey) -> Result<Action, Error> {
    current_action(domain, key)
}
fn target_features(action: Action, key: ObjectKey) -> Result<TargetFeatures, Error> {
    validate_action(action, key, Board.now_ns())?;
    Ok(TargetFeatures::default())
}
fn index(action: Action, key: ObjectKey) -> Result<usize, Error> {
    let slot = target_slot(action.domain(), key)?;
    match action {
        Action::Filesystem { .. } => Ok(0),
        Action::IoShare(_) => Ok(1),
        Action::NotifyBatch(_) => Ok(2 + slot),
        _ => Err(Error::Unsupported),
    }
}
fn executed(slot: usize, stamp: PolicyStamp) -> bool {
    match slot {
        0 => {
            let m = metrics();
            m.last_read_version == stamp.version || m.last_flush_version == stamp.version
        }
        1 => storage::facts()[15] == stamp.version,
        2 => storage::facts()[23] == stamp.version,
        3 | 4 => DEVICES[slot - 3][12].load(Ordering::Acquire) == stamp.version,
        _ => false,
    }
}
pub fn reconcile(
    action: Action,
    id: ApplyId,
    stamp: PolicyStamp,
    now: u64,
) -> Result<ExecutionState, Error> {
    owner()?;
    let slot = index(action, id.target)?;
    let Some(mut old) = (unsafe { (*core::ptr::addr_of!(INSTALLED))[slot] }) else {
        // Installation and this receipt are one CPU0 non-yielding operation.
        // No record proves a Busy admission never installed this apply_id.
        return Ok(ExecutionState::Failed(Error::Again));
    };
    if old.stamp.version < stamp.version {
        return Ok(ExecutionState::Failed(Error::Again));
    }
    if old.action != action || old.id != id || old.stamp != stamp {
        return Err(Error::Conflict);
    }
    if executed(slot, stamp) {
        old.state = ExecutionState::Applied;
        unsafe {
            (*core::ptr::addr_of_mut!(INSTALLED))[slot] = Some(old);
        }
    }
    if !old.state.terminal() && !stamp.live(now) {
        let quiescent = match slot {
            0 => !BUSY.load(Ordering::Acquire) && storage::facts()[31] == 0,
            1 => {
                let f = storage::facts();
                !storage::borrowed()
                    && f[7] == 0
                    && f[8] == 0
                    && f[9] == 0
                    && f[27] == 0
                    && f[31] == 0
            }
            2 => {
                let f = storage::facts();
                f[31] == 0 && f[32] < stamp.version
            }
            3 | 4 => {
                let d = &DEVICES[slot - 3];
                d[9].load(Ordering::Acquire) == 0 && d[18].load(Ordering::Acquire) < stamp.version
            }
            _ => false,
        };
        if quiescent {
            old.state = ExecutionState::Failed(Error::Expired);
            unsafe {
                (*core::ptr::addr_of_mut!(INSTALLED))[slot] = Some(old);
            }
        }
    }
    Ok(old.state)
}
pub fn apply(
    action: Action,
    id: ApplyId,
    stamp: PolicyStamp,
    now: u64,
) -> Result<ExecutionState, Error> {
    owner()?;
    validate_action(action, id.target, now)?;
    let slot = index(action, id.target)?;
    if let Some(old) = unsafe { (*core::ptr::addr_of!(INSTALLED))[slot] } {
        if old.id == id {
            return reconcile(action, id, stamp, now);
        }
        old.stamp.accepts(stamp, now)?;
        if !old.state.terminal() && !executed(slot, old.stamp) {
            return Err(Error::Busy);
        }
    }
    PolicyStamp::new(stamp.version, stamp.snapshot_ns, now).and_then(|s| {
        if s == stamp {
            Ok(())
        } else {
            Err(Error::Format)
        }
    })?;
    match action {
        Action::Filesystem { .. } => with_files(|f| f.apply(action, stamp, now))?,
        Action::IoShare(_) => storage::install_io(action, stamp, now)?,
        Action::NotifyBatch(batch) => {
            if slot == 2 {
                storage::install_notify(batch, stamp, now)?
            } else {
                let d = &DEVICES[slot - 3];
                d[5].store(stamp.installed_until_ns, Ordering::Relaxed);
                d[6].store(u64::from(batch), Ordering::Relaxed);
                d[4].store(stamp.version, Ordering::Release);
            }
        }
        _ => return Err(Error::Unsupported),
    }
    unsafe {
        (*core::ptr::addr_of_mut!(INSTALLED))[slot] = Some(Installed {
            action,
            id,
            stamp,
            state: ExecutionState::Pending,
        });
    }
    Ok(ExecutionState::Pending)
}
pub fn register_control() -> Result<(), Error> {
    crate::domain_control::register_dependencies(4, dependencies)?;
    for domain in [4, 9, 11] {
        crate::domain_control::register(crate::domain_control::Family {
            domain,
            kind: 1,
            target,
            observe: observation,
            current: control_current,
            legal: validate_action,
            target_features,
            apply,
            reconcile,
        })?;
    }
    Ok(())
}

fn dependencies(key: ObjectKey) -> Result<[Option<crate::domain_control::Prerequisite>; 2], Error> {
    ready_read()?;
    if enumerate_target(4, 0) != Some(key) {
        return Err(Error::Stale);
    }
    let memory = crate::domain_tasks::memory_key()?;
    let disk = enumerate_target(9, 0).ok_or(Error::NotReady)?;
    if storage::facts_read()?[31] != 0 {
        return Err(Error::Io);
    }
    Ok([
        Some(crate::domain_control::Prerequisite {
            domain: 3,
            target: memory,
        }),
        Some(crate::domain_control::Prerequisite {
            domain: 9,
            target: disk,
        }),
    ])
}
