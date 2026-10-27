//! Dedicated A10 profile: observe real delivered file replies and task exits.
//! EL0 cannot map these banks. The host supplies identities, never results.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_prototype::{boot::BootIdentity, domains::ObjectKey};
use sha2::{Digest, Sha256};
mod state;

pub const PROFILE: bool = include!(concat!(env!("OUT_DIR"), "/storage-fault-probe.rs"));
#[used]
#[unsafe(no_mangle)]
static A10_CAPTURE: state::Capture = state::Capture::new();
#[used]
#[unsafe(no_mangle)]
static mut A10_CONFIG: [u64; 64] = [u64::MAX; 64];
#[used]
#[unsafe(no_mangle)]
static A10_CAPTURE_LAYOUT: [u64; 8] = [1, 512, 768, 384, 295424, 299008, 512, 512];
#[used]
#[unsafe(no_mangle)]
static A10_PROGRESS: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn init(boot: BootIdentity) {
    if !PROFILE {
        return;
    }
    let config = unsafe { core::ptr::addr_of!(A10_CONFIG).read_volatile() };
    assert!(
        A10_CAPTURE.begin(&config, boot.epoch, boot.filesystem),
        "invalid A10 run binding"
    );
    ENABLED.store(true, Ordering::Release);
}
pub fn mode() -> u64 {
    A10_CAPTURE.words[6].load(Ordering::Acquire)
}
pub fn selected(owner: ObjectKey) -> bool {
    PROFILE && ENABLED.load(Ordering::Acquire) && A10_CAPTURE.selected([owner.id, owner.generation])
}
pub fn register(role: usize, owner: ObjectKey) -> bool {
    ENABLED.load(Ordering::Acquire) && A10_CAPTURE.owner(role, [owner.id, owner.generation])
}
pub fn launch(role: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (chunk, word) in bytes.chunks_exact_mut(8).zip([
        1,
        mode(),
        role,
        A10_CAPTURE.words[5].load(Ordering::Acquire),
    ]) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}
/// Invoked after successful ABI copyout; retained retries publish exactly once.
pub fn delivered(owner: ObjectKey, frame: &[u8; 640], data: &[u8], misses: u64) {
    if !selected(owner) {
        return;
    }
    let Ok((lsn, reads, writes, flushes)) =
        crate::prototype_storage::try_with_journal(|journal, disk, _| {
            (
                journal.last_commit_lsn(),
                disk.reads,
                disk.writes,
                disk.flushes,
            )
        })
    else {
        A10_CAPTURE.fail();
        return;
    };
    let ticks = cyxia_arch_aarch64::timer::ticks();
    let hz = cyxia_arch_aarch64::timer::frequency();
    let ns = (u128::from(ticks) * 1_000_000_000 / u128::from(hz)) as u64;
    A10_CAPTURE.record(
        [
            ns,
            A10_CAPTURE.words[5].load(Ordering::Acquire),
            owner.id,
            owner.generation,
            lsn,
            reads,
            writes,
            flushes,
            data.len() as u64,
            misses,
        ],
        Sha256::digest(data).into(),
        frame,
    );
}
/// Actual exit syscall, before ordinary memory teardown. This is supplemental
/// consumed-reply evidence, distinct from protected delivered ABI receipts.
pub fn terminal(owner: ObjectKey, code: u64, ns: u64, progress: &[u8; 104]) {
    if !selected(owner) {
        return;
    }
    let Some(role) = A10_CAPTURE.role([owner.id, owner.generation]) else {
        return;
    };
    let words = &A10_PROGRESS[role * 32..];
    if words[0].load(Ordering::Acquire) != 0 {
        A10_CAPTURE.fail();
        return;
    }
    for (slot, value) in words[1..]
        .iter()
        .zip([owner.id, owner.generation, code, ns])
    {
        slot.store(value, Ordering::Relaxed);
    }
    for (slot, chunk) in words[5..].iter().zip(progress.chunks_exact(8)) {
        slot.store(
            u64::from_le_bytes(chunk.try_into().unwrap()),
            Ordering::Relaxed,
        );
    }
    words[0].store(0x4359584131305052, Ordering::Release);
}
