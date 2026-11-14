//! A09 observations from ordinary task admission and yielded user memory.
//! No hook changes memory, cache policy, client results or scheduling credits.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_prototype::domains::{Error, ObjectKey, tasks::MemoryStats};
pub const PROFILE: bool = include!(concat!(env!("OUT_DIR"), "/memory-fault-probe.rs"));
pub const LIFETIME_NS: u64 = 600_000_000_000;
static NOTIFY_ENDPOINT: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
static NOTIFY_GRANTED: AtomicBool = AtomicBool::new(false);
const WORDS: usize = 448;
pub const MAGIC: u64 = 0x4359584130394d45;
pub const CLIENT_MAGIC: u64 = 0x435958413039434c;
#[repr(C, align(64))]
pub struct Evidence([AtomicU64; WORDS]);
#[used]
#[unsafe(no_mangle)]
pub static MEMORY_V15_EVIDENCE: Evidence = Evidence([const { AtomicU64::new(0) }; WORDS]);
static POLLING: AtomicBool = AtomicBool::new(false);
struct PollGuard;
impl Drop for PollGuard {
    fn drop(&mut self) {
        POLLING.store(false, Ordering::Release);
    }
}
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".cyxia.boot")]
pub static MEMORY_V15_PROFILE: [u64; 5] = [1, PROFILE as u64, 2, 4097, WORDS as u64];
fn get(i: usize) -> u64 {
    MEMORY_V15_EVIDENCE.0[i].load(Ordering::Acquire)
}
fn put(i: usize, v: u64) {
    MEMORY_V15_EVIDENCE.0[i].store(v, Ordering::Relaxed)
}
pub fn init(config: &[u64; 64]) {
    if !PROFILE {
        return;
    }
    put(0, MAGIC);
    put(1, 1);
    put(2, 2);
    put(5, 2);
    put(27, cyxia_arch_aarch64::timer::frequency());
    for (n, v) in config[4..18].iter().enumerate() {
        put(8 + n, *v);
    }
}
pub fn activate(boot: u64) -> Result<(), Error> {
    if PROFILE {
        let (base, pages) = crate::domain_storage::cache_backing()?;
        put(22, base);
        put(23, u64::from(pages));
        put(3, boot);
    }
    Ok(())
}
pub fn launch(role: u64) -> [u8; 40] {
    let words = [CLIENT_MAGIC, role, get(8), get(9), LIFETIME_NS];
    let mut out = [0; 40];
    for (n, v) in words.iter().enumerate() {
        out[n * 8..n * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    out
}
pub fn register(role: u64, key: ObjectKey, root: u64) -> Result<(), Error> {
    if !PROFILE || !(1..=2).contains(&role) {
        return Err(Error::Auth);
    }
    let b = 64 + (role as usize - 1) * 192;
    if get(b) != 0 {
        return if get(b) == key.id && get(b + 1) == key.generation {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    }
    for (n, v) in [key.id, key.generation, role, root, 1, 4, 0, 0]
        .iter()
        .enumerate()
    {
        put(b + n, *v);
    }
    Ok(())
}
pub fn selected(key: ObjectKey) -> bool {
    PROFILE && (0..2).any(|r| get(64 + r * 192) == key.id && get(65 + r * 192) == key.generation)
}
pub fn needs_snapshot(key: ObjectKey, stage: u64) -> bool {
    if !(1..=3).contains(&stage) {
        return false;
    }
    (0..2).any(|r| {
        get(64 + r * 192) == key.id
            && get(65 + r * 192) == key.generation
            && get(64 + r * 192 + 32 + (stage as usize - 1) * 48) == 0
    })
}
pub fn observe(
    key: ObjectKey,
    now: u64,
    owner_pages: usize,
    owner_quota: usize,
    owned_frames: [u64; 7],
    stats: MemoryStats,
    leaf: &[u64; 512],
    progress: &[u8; 128],
) {
    if !selected(key) {
        return;
    }
    let Some(role) = (1..=2).find(|r| get(64 + (*r - 1) * 192) == key.id) else {
        return;
    };
    let b = 64 + (role - 1) * 192;
    let p: [u64; 16] = core::array::from_fn(|i| {
        u64::from_le_bytes(progress[i * 8..i * 8 + 8].try_into().unwrap())
    });
    if p[0] != CLIENT_MAGIC || p[1] != role as u64 || p[3] != 0 {
        put(6, 1);
        put(b + 6, p[3].max(1));
        return;
    }
    let stage = p[2] as usize;
    if role == 2 && p[7] != 0 && p[8] != 0 {
        NOTIFY_ENDPOINT[0].store(p[7], Ordering::Relaxed);
        NOTIFY_ENDPOINT[1].store(p[8], Ordering::Release);
    }
    if !(1..=3).contains(&stage) {
        return;
    }
    let at = b + 32 + (stage - 1) * 48;
    if get(at) != 0 {
        return;
    }
    // Snapshot the actual owner and real PTEs while its existing task gate is held.
    put(at, 1);
    for (n, v) in [
        now,
        stage as u64,
        p[3],
        p[4],
        p[5],
        p[6],
        stats.faults,
        stats.zeroed_pages,
        stats.anonymous_pages as u64,
        stats.free_pages as u64,
        stats.cache_pages as u64,
        stats.cache_misses,
        stats.reclaimed_pages,
        owner_pages as u64,
        owner_quota as u64,
    ]
    .iter()
    .enumerate()
    {
        put(at + 1 + n, *v);
    }
    for (n, va) in [
        0x60000, 0x61000, 0x62000, 0x63000, 0x72000, 0x80000, 0x30000,
    ]
    .iter()
    .enumerate()
    {
        put(at + 16 + n, leaf[va / 4096]);
    }
    for n in 0..4 {
        put(at + 24 + n, leaf[16 + n]);
    }
    for (n, pa) in owned_frames.into_iter().enumerate() {
        put(at + 28 + n, pa);
    }
    MEMORY_V15_EVIDENCE.0[at].store(2, Ordering::Release);
    poll();
}
pub fn poll() {
    if !PROFILE || get(6) != 0 {
        return;
    }
    if POLLING
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    let _guard = PollGuard;
    // Ordinary capability setup runs on CPU0 outside the task gate. The IPC
    // implementation authenticates both endpoint owner and generation.
    if cyxia_arch_aarch64::cpu::slot() == 0 && !NOTIFY_GRANTED.load(Ordering::Acquire) {
        let generation = NOTIFY_ENDPOINT[1].load(Ordering::Acquire);
        if generation != 0 && get(64) != 0 && get(256) != 0 {
            let endpoint = ObjectKey {
                id: NOTIFY_ENDPOINT[0].load(Ordering::Relaxed),
                generation,
            };
            let owner = ObjectKey {
                id: get(256),
                generation: get(257),
            };
            let recipient = ObjectKey {
                id: get(64),
                generation: get(65),
            };
            if crate::domain_tasks::grant_endpoint(owner, recipient, endpoint).is_ok() {
                NOTIFY_GRANTED.store(true, Ordering::Release);
            }
        }
    }
    let stage = get(4) as usize + 1;
    if stage > 3 {
        return;
    }
    if !(0..2).all(|r| get(64 + r * 192 + 32 + (stage - 1) * 48) == 2) {
        return;
    }
    let metrics = crate::domain_storage::metrics();
    MEMORY_V15_EVIDENCE.0[2].fetch_add(1, Ordering::AcqRel);
    put(24, crate::domain_storage::cache_evictions());
    put(25, metrics.cache_misses);
    put(26, metrics.read_bytes);
    put(
        28,
        ((u128::from(cyxia_arch_aarch64::timer::ticks()) * 1_000_000_000)
            / u128::from(cyxia_arch_aarch64::timer::frequency())) as u64,
    );
    put(4, stage as u64);
    MEMORY_V15_EVIDENCE.0[2].fetch_add(1, Ordering::Release);
}
