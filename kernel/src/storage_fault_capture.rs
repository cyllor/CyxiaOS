//! Dedicated A10 profile: observe real delivered file replies and task exits.
//! EL0 cannot map these banks. The host supplies identities, never results.
use crate::domain_file_abi::abi::{
    CLOSE, FSYNC, OFF_DURABLE_SEQ, OFF_OPERATION, OFF_REQUEST, OFF_RESULT, OFF_WRITE_SEQ,
};
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
#[used]
#[unsafe(no_mangle)]
static A10_CONSUMPTION: state::Consumption = state::Consumption::new();
static ENABLED: AtomicBool = AtomicBool::new(false);
static FSYNC_EVENT: AtomicU64 = AtomicU64::new(0);
static FSYNC_REQUEST: AtomicU64 = AtomicU64::new(0);

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
    let Some(event) = A10_CAPTURE.record(
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
    ) else {
        return;
    };
    let run_mode = mode();
    let expected = if run_mode == 1 { 2 } else { 3 };
    if run_mode <= 2
        && A10_CAPTURE.role([owner.id, owner.generation]) == Some(0)
        && u16::from_le_bytes(frame[OFF_OPERATION..OFF_OPERATION + 2].try_into().unwrap()) == FSYNC
        && u64::from_le_bytes(frame[OFF_RESULT..OFF_RESULT + 8].try_into().unwrap()) == 0
        && u64::from_le_bytes(frame[OFF_WRITE_SEQ..OFF_WRITE_SEQ + 8].try_into().unwrap())
            == expected
        && u64::from_le_bytes(
            frame[OFF_DURABLE_SEQ..OFF_DURABLE_SEQ + 8]
                .try_into()
                .unwrap(),
        ) == expected
    {
        let request = u64::from_le_bytes(frame[OFF_REQUEST..OFF_REQUEST + 8].try_into().unwrap());
        if request == 0 || FSYNC_EVENT.load(Ordering::Acquire) != 0 {
            A10_CAPTURE.fail();
        } else {
            FSYNC_REQUEST.store(request, Ordering::Relaxed);
            FSYNC_EVENT.store(event, Ordering::Release);
        }
    }
}
/// At the first authorized syscall after the selected writer FSYNC, snapshot
/// the stopped task's progress page. This distinguishes ABI delivery from EL0
/// consumption without granting the task authority to publish the verdict.
pub fn entered(owner: ObjectKey, frame: &[u8; 640]) {
    let run_mode = mode();
    if !selected(owner) || run_mode > 2 || A10_CAPTURE.role([owner.id, owner.generation]) != Some(0)
    {
        return;
    }
    let event = FSYNC_EVENT.load(Ordering::Acquire);
    if event == 0 {
        return;
    }
    let request = u64::from_le_bytes(frame[OFF_REQUEST..OFF_REQUEST + 8].try_into().unwrap());
    let operation = u16::from_le_bytes(frame[OFF_OPERATION..OFF_OPERATION + 2].try_into().unwrap());
    let fsync_request = FSYNC_REQUEST.load(Ordering::Acquire);
    let mut progress = [0; 104];
    let expected = if run_mode == 1 { 2 } else { 3 };
    if operation != CLOSE
        || fsync_request.checked_add(1) != Some(request)
        || crate::domain_tasks::copyin(owner, 0x30000, &mut progress).is_err()
    {
        A10_CAPTURE.fail();
        return;
    }
    let mut words = [0; 13];
    for (word, chunk) in words.iter_mut().zip(progress.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    if words[0] == 0
        || words[0] & 1 != 0
        || words[1] != 0x4359584131305553
        || words[2] != 1
        || words[3] != run_mode
        || words[4] != 1
        || words[5] != A10_CAPTURE.words[5].load(Ordering::Acquire)
        || words[6] != if run_mode == 1 { 4 } else { 7 }
        || words[7] == 0
        || words[8] == 0
        || words[9] != expected
        || words[10] != expected
        || words[11] != 0
        || words[12] != 0
    {
        A10_CAPTURE.fail();
        return;
    }
    let ticks = cyxia_arch_aarch64::timer::ticks();
    let hz = cyxia_arch_aarch64::timer::frequency();
    let ns = (u128::from(ticks) * 1_000_000_000 / u128::from(hz)) as u64;
    if !A10_CONSUMPTION.publish(
        [
            owner.id,
            owner.generation,
            ns,
            event,
            fsync_request,
            request,
            u64::from(operation),
        ],
        &progress,
    ) {
        A10_CAPTURE.fail();
    }
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
