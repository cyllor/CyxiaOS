//! One C1-only, independently mapped and preemptible extra role. This owner
//! retains both CPU bills and all input/page leases until their exact exits are
//! known. Protection/operator probes never become replay samples or models.
use super::*;
use crate::control_pool::{self as pool, Allocation, Lease};
use core::cell::UnsafeCell;
use cyxia_prototype::learning::capture::{CaptureInit, InitComplete, InitValue};
use cyxia_prototype::learning::worker_wire as wire;
use cyxia_prototype::{
    domains::tasks::ControlCredit,
    domains::{Error as DomainError, ObjectKey, WINDOW_NS},
    learning::{
        Error as LearnError,
        governance::{ControlAuthority, ExtraBudget, ExtraCredit, Role, WorkIdentity, WorkReceipt},
    },
};
use sha2::{Digest, Sha256};
#[path = "learning_receipt.rs"]
mod receipt_match;

const CODE_BASE: u64 = 0x80000;
const CODE_PAGES: usize = 128;
const INPUT_BASE: u64 = 0x100000;
const OUTPUT_BASE: u64 = 0x180000;
const SCRATCH_BASE: u64 = 0x184000;
const STACK_BASE: u64 = 0x1f1000;
const STACK_TOP: u64 = 0x200000;
const INPUT_BYTES: usize = 512 * 1024;
const OUTPUT_BYTES: usize = 16 * 1024;
const SCORE_INPUT_PAGES: usize =
    cyxia_prototype::learning::score_wire::MAX_INPUT_BYTES.div_ceil(4096);
const WORK_BYTES: u32 = 1024 * 1024;
const RESERVE_NS: u64 = 2_500_000;
const SLICE_NS: u64 = 250_000;
const OWNER: ObjectKey = ObjectKey {
    id: 0x4c45_4152_4e01,
    generation: 1,
};
const DRIVER_OWNER: ObjectKey = ObjectKey {
    id: 0x4c45_4452_4956,
    generation: 1,
};
const SESSION_OWNER: ObjectKey = ObjectKey {
    id: 0x4c45_5345_5353,
    generation: 1,
};
const DRIVER_PAGES: usize = 4;
const SESSION_PAGES: usize = 6;
const SCRATCH_PAGES: usize = 108 - DRIVER_PAGES - SESSION_PAGES;
const _: () = assert!(
    (128 + 4 + SCRATCH_PAGES + 15 + DRIVER_PAGES + SESSION_PAGES) * 4096 <= WORK_BYTES as usize
);
const MAGIC: u64 = 0x4359_4c45_4152_4e01;
#[used]
#[unsafe(no_mangle)]
static LEARNING_SERVICE_ELF: [u8; include_bytes!(concat!(
    env!("OUT_DIR"),
    "/prototype-learning.elf"
))
.len()] = *include_bytes!(concat!(env!("OUT_DIR"), "/prototype-learning.elf"));
#[repr(C, align(64))]
pub struct Evidence([AtomicU64; 128]);
#[used]
#[unsafe(no_mangle)]
pub static LEARNING_V13_EVIDENCE: Evidence = Evidence([const { AtomicU64::new(0) }; 128]);
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static CLAIMED: AtomicBool = AtomicBool::new(false);
static WORKER_CLAIMED: AtomicBool = AtomicBool::new(false);
static IMAGE_HASH: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static OPERATOR_READY: AtomicBool = AtomicBool::new(false);
static DATA_PRESENT: AtomicBool = AtomicBool::new(false);
static CAPTURE_READY: AtomicBool = AtomicBool::new(false);
static CAPTURE_LOANED: AtomicBool = AtomicBool::new(false);
static CAPTURE_BOOT: AtomicU64 = AtomicU64::new(0);
static HISTORY_READY: AtomicBool = AtomicBool::new(false);
static HISTORY_LOANED: AtomicBool = AtomicBool::new(false);
static EXTRA_ACTIVE: AtomicBool = AtomicBool::new(false);
static INPUT_IDLE: AtomicBool = AtomicBool::new(false);
static INPUT_TOKEN: AtomicU64 = AtomicU64::new(0);
static INPUT_SERIAL: AtomicU64 = AtomicU64::new(0);
static INPUT_SEALED: AtomicBool = AtomicBool::new(false);
static INPUT_SUBMITTED: AtomicBool = AtomicBool::new(false);
struct DriverAllocation(UnsafeCell<Option<Allocation>>);
unsafe impl Sync for DriverAllocation {}
static DRIVER_ALLOCATION: DriverAllocation = DriverAllocation(UnsafeCell::new(None));
static SESSION_ALLOCATION: DriverAllocation = DriverAllocation(UnsafeCell::new(None));
/// CPU0 may initialize the protected producer before Resources is published.
/// Its single backing replaces four EL0 scratch pages; retry never allocates
/// another bank. The producer must hold its own permanent mutable pin.
pub fn driver_workspace() -> Result<Allocation, DomainError> {
    fixed_workspace(&DRIVER_ALLOCATION, DRIVER_OWNER, DRIVER_PAGES)
}
/// Score preparation/result custody replaces EL0 scratch in the same numerical
/// budget. Its long-lived governance history has a separate control-pool loan.
pub fn session_workspace() -> Result<Allocation, DomainError> {
    fixed_workspace(&SESSION_ALLOCATION, SESSION_OWNER, SESSION_PAGES)
}
fn fixed_workspace(
    storage: &DriverAllocation,
    owner: ObjectKey,
    pages: usize,
) -> Result<Allocation, DomainError> {
    if cpu::slot() != 0 {
        return Err(DomainError::Auth);
    }
    let slot = unsafe { &mut *storage.0.get() };
    if let Some(allocation) = *slot {
        return Ok(allocation);
    }
    let allocation = pool::allocate(owner, pages)?;
    *slot = Some(allocation);
    Ok(allocation)
}
/// A kernel producer's unique idle-input loan. Dropping the handle never
/// releases custody: an abandoned or unknown encoder cannot permit page reuse.
pub struct InputLoan {
    allocation: Allocation,
    serial: u64,
    pin: Option<Lease>,
    sealed: bool,
    seal_cursor: Option<usize>,
    seal_end: usize,
}
pub fn borrow_input() -> Result<InputLoan, DomainError> {
    require_extra_caller()?;
    if !INPUT_IDLE.load(Ordering::Acquire) || !OPERATOR_READY.load(Ordering::Acquire) {
        return Err(DomainError::NotReady);
    }
    requests(|s| {
        if s.pending.is_some() || INPUT_TOKEN.load(Ordering::Acquire) != 0 {
            return Err(DomainError::Busy);
        }
        let allocation = resources()?.private[0];
        let serial = INPUT_SERIAL
            .load(Ordering::Relaxed)
            .checked_add(1)
            .ok_or(DomainError::Overflow)?;
        pool::unseal(allocation)?;
        let pin = pool::pin(allocation)?;
        INPUT_SERIAL.store(serial, Ordering::Relaxed);
        INPUT_SEALED.store(false, Ordering::Relaxed);
        INPUT_SUBMITTED.store(false, Ordering::Relaxed);
        INPUT_TOKEN.store(serial, Ordering::Release);
        Ok(InputLoan {
            allocation,
            serial,
            pin: Some(pin),
            sealed: false,
            seal_cursor: None,
            seal_end: 0,
        })
    })
}
pub fn input_span(loan: &InputLoan) -> Result<(usize, usize), DomainError> {
    require_extra_caller()?;
    if INPUT_TOKEN.load(Ordering::Acquire) != loan.serial || loan.serial == 0 {
        return Err(DomainError::Stale);
    }
    if loan.sealed || loan.pin.is_none() || INPUT_SUBMITTED.load(Ordering::Acquire) {
        return Err(DomainError::Auth);
    }
    let (base, _, bytes) = pool::span(loan.allocation)?;
    Ok((base, bytes))
}
/// Encoder must be dropped/finished, ending its mutable slice, before this
/// transition. A Busy retry retains the exact logical loan and any live pin.
pub fn seal_input(loan: &mut InputLoan) -> Result<Allocation, DomainError> {
    require_extra_caller()?;
    if INPUT_TOKEN.load(Ordering::Acquire) != loan.serial || loan.serial == 0 {
        return Err(DomainError::Stale);
    }
    if INPUT_SUBMITTED.load(Ordering::Acquire) {
        return Err(DomainError::Busy);
    }
    if loan.pin.is_some() {
        let (base, _, bytes) = pool::span(loan.allocation)?;
        // Both protected encoders use the same explicit byte length. The
        // producer has ended its slice before sealing; its exclusive mutable
        // pin allows clearing just the last mapped page's unused tail.
        if loan.seal_cursor.is_none() {
            let input_len = unsafe { core::ptr::read_unaligned((base + 12) as *const u32) };
            let input_len = u32::from_le(input_len) as usize;
            let role = unsafe { core::ptr::read_unaligned((base + 10) as *const u16) };
            let role = u16::from_le(role);
            let end = if matches!(role, 3 | 4) {
                SCORE_INPUT_PAGES * 4096
            } else {
                bytes
            };
            if input_len < wire::HEADER_BYTES || input_len > end {
                return Err(DomainError::Format);
            }
            loan.seal_cursor = Some(input_len);
            loan.seal_end = end;
        }
        let cursor = loan.seal_cursor.ok_or(DomainError::Conflict)?;
        let end = cursor.saturating_add(4096).min(loan.seal_end);
        unsafe {
            core::ptr::write_bytes((base + cursor) as *mut u8, 0, end - cursor);
        }
        loan.seal_cursor = Some(end);
        if end != loan.seal_end {
            return Err(DomainError::Again);
        }
    }
    if let Some(pin) = loan.pin.as_ref() {
        pool::unpin(pin)?;
        loan.pin = None;
    }
    if !loan.sealed {
        pool::seal(loan.allocation)?;
        loan.sealed = true;
        INPUT_SEALED.store(true, Ordering::Release);
    }
    Ok(loan.allocation)
}
/// Only an unpublished, known-stopped encoder can abandon this loan. Published
/// jobs retire it through their exact stopped-and-settled acknowledgement.
pub fn abandon_input(loan: &mut InputLoan) -> Result<(), DomainError> {
    require_extra_caller()?;
    if INPUT_TOKEN.load(Ordering::Acquire) != loan.serial || loan.serial == 0 {
        return Err(DomainError::Stale);
    }
    if INPUT_SUBMITTED.load(Ordering::Acquire) {
        return Err(DomainError::Busy);
    }
    if let Some(pin) = loan.pin.as_ref() {
        pool::unpin(pin)?;
        loan.pin = None;
    }
    pool::unseal(loan.allocation)?;
    INPUT_SEALED.store(false, Ordering::Relaxed);
    INPUT_TOKEN.store(0, Ordering::Release);
    loan.serial = 0;
    Ok(())
}

static DRIVER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
pub type DriverTurn = fn() -> Result<bool, DomainError>;
pub fn register_driver(turn: DriverTurn) -> Result<(), DomainError> {
    if cpu::slot() != 0 {
        return Err(DomainError::Auth);
    }
    let address = turn as usize;
    match DRIVER.compare_exchange(0, address, Ordering::Release, Ordering::Acquire) {
        Ok(_) => Ok(()),
        Err(old) if old == address => Ok(()),
        Err(_) => Err(DomainError::Conflict),
    }
}
pub(super) fn require_extra_caller() -> Result<(), DomainError> {
    if cpu::slot() != 1 || !EXTRA_ACTIVE.load(Ordering::Acquire) {
        return Err(DomainError::Auth);
    }
    crate::domain_tasks::control_owner_context(1).map(|_| ())
}
static CAPTURE_NODE: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration {
    pub role_context: ObjectKey,
    pub image_hash: [u8; 32],
    pub core_generation: u64,
    pub ledger_generation: u64,
}
fn role_context(role: wire::Role) -> ObjectKey {
    ObjectKey {
        id: 0x4c45_4152_1000 + role as u64,
        generation: 1,
    }
}
fn image_hash() -> [u8; 32] {
    let mut hash = [0; 32];
    for (i, word) in IMAGE_HASH.iter().enumerate() {
        hash[i * 8..i * 8 + 8].copy_from_slice(&word.load(Ordering::Acquire).to_le_bytes());
    }
    hash
}
pub fn registration(role: wire::Role) -> Result<Registration, DomainError> {
    if !OPERATOR_READY.load(Ordering::Acquire) {
        return Err(DomainError::NotReady);
    }
    let (core_generation, ledger_generation) = native::learning_context()?;
    Ok(Registration {
        role_context: role_context(role),
        image_hash: image_hash(),
        core_generation,
        ledger_generation,
    })
}

#[derive(Clone, Copy)]
struct ImagePlan {
    entry: u64,
    segments: [cyxia_kernel_core::control_plane::image::Segment; 8],
    count: usize,
}
struct Resources {
    code: Allocation,
    private: [Allocation; 4],
    tables: Allocation,
    plan: ImagePlan,
    root: u64,
    score_root: u64,
    capture: Allocation,
    history: Allocation,
    driver: Allocation,
    session: Allocation,
}
struct ResourceCell(UnsafeCell<Option<Resources>>);
unsafe impl Sync for ResourceCell {}
static RESOURCES: ResourceCell = ResourceCell(UnsafeCell::new(None));
static mut TABLE_PIN: Option<Lease> = None;
static mut CAPTURE_PIN: Option<Lease> = None;
static mut HISTORY_PIN: Option<Lease> = None;
fn resources() -> Result<&'static Resources, DomainError> {
    if !INITIALIZED.load(Ordering::Acquire) {
        return Err(DomainError::NotReady);
    }
    unsafe { (&*RESOURCES.0.get()).as_ref().ok_or(DomainError::NotReady) }
}
fn parse_image() -> Result<ImagePlan, DomainError> {
    let b = &LEARNING_SERVICE_ELF[..];
    if b.len() > CODE_PAGES * 4096 {
        return Err(DomainError::Capacity);
    }
    let word = |at: usize| -> Result<u64, DomainError> {
        Ok(u64::from_le_bytes(
            b.get(at..at + 8)
                .ok_or(DomainError::Format)?
                .try_into()
                .map_err(|_| DomainError::Format)?,
        ))
    };
    let half = |at: usize| -> Result<u16, DomainError> {
        Ok(u16::from_le_bytes(
            b.get(at..at + 2)
                .ok_or(DomainError::Format)?
                .try_into()
                .map_err(|_| DomainError::Format)?,
        ))
    };
    if b.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || half(16)? != 2
        || half(18)? != 183
        || half(52)? != 64
        || half(54)? != 56
    {
        return Err(DomainError::Format);
    }
    let ph = usize::try_from(word(32)?).map_err(|_| DomainError::Range)?;
    let count = usize::from(half(56)?);
    if count == 0 || count > 8 {
        return Err(DomainError::Format);
    }
    let mut plan = ImagePlan {
        entry: word(24)?,
        segments: [cyxia_kernel_core::control_plane::image::Segment::default(); 8],
        count: 0,
    };
    let mut seen = 0u128;
    let mut entry = false;
    for i in 0..count {
        let at = ph.checked_add(i * 56).ok_or(DomainError::Range)?;
        let kind = u32::from_le_bytes(
            b.get(at..at + 4)
                .ok_or(DomainError::Format)?
                .try_into()
                .map_err(|_| DomainError::Format)?,
        );
        if matches!(kind, 0 | 4 | 6 | 0x6474e551) {
            continue;
        }
        if kind != 1 {
            return Err(DomainError::Auth);
        }
        let flags = u32::from_le_bytes(
            b.get(at + 4..at + 8)
                .ok_or(DomainError::Format)?
                .try_into()
                .map_err(|_| DomainError::Format)?,
        );
        let address = word(at + 16)?;
        let offset = usize::try_from(word(at + 8)?).map_err(|_| DomainError::Range)?;
        let file_size = usize::try_from(word(at + 32)?).map_err(|_| DomainError::Range)?;
        let memory_size = usize::try_from(word(at + 40)?).map_err(|_| DomainError::Range)?;
        let end = address
            .checked_add(memory_size as u64)
            .ok_or(DomainError::Range)?;
        if !matches!(flags, 4 | 5)
            || memory_size == 0
            || file_size > memory_size
            || address < CODE_BASE
            || end > INPUT_BASE
            || !address.is_multiple_of(4096)
            || !offset.is_multiple_of(4096)
            || word(at + 48)? != 4096
            || b.get(offset..offset.checked_add(file_size).ok_or(DomainError::Range)?)
                .is_none()
        {
            return Err(DomainError::Format);
        }
        for page in
            ((address - CODE_BASE) / 4096) as usize..((end - CODE_BASE).div_ceil(4096)) as usize
        {
            let bit = 1u128 << page;
            if seen & bit != 0 {
                return Err(DomainError::Conflict);
            }
            seen |= bit;
        }
        entry |= flags == 5
            && plan.entry >= address
            && plan.entry < address + file_size as u64
            && plan.entry.is_multiple_of(4);
        plan.segments[plan.count] = cyxia_kernel_core::control_plane::image::Segment {
            offset,
            address,
            file_size,
            memory_size,
            executable: flags == 5,
        };
        plan.count += 1;
    }
    if !entry {
        return Err(DomainError::Format);
    }
    Ok(plan)
}
pub(super) fn init() -> Result<(), DomainError> {
    if cpu::slot() != 0 {
        return Err(DomainError::Auth);
    }
    CLAIMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| DomainError::Exists)?;
    let plan = parse_image()?;
    let code = pool::allocate(OWNER, CODE_PAGES)?;
    let private = [
        pool::allocate(OWNER, 128)?,
        pool::allocate(OWNER, 4)?,
        pool::allocate(OWNER, SCRATCH_PAGES)?,
        pool::allocate(OWNER, 15)?,
    ];
    let driver = driver_workspace()?;
    let session = session_workspace()?;
    let tables = pool::allocate(OWNER, 6)?;
    let capture = pool::allocate(
        ObjectKey {
            id: 0x4c45_4341_5054,
            generation: 1,
        },
        crate::learning_evidence::STORAGE_BYTES.div_ceil(4096),
    )?;
    let capture_pin = pool::pin(capture)?;
    let history = pool::allocate(
        ObjectKey {
            id: 0x4c45_4849_5354,
            generation: 1,
        },
        crate::learning_history::STORAGE_BYTES.div_ceil(4096),
    )?;
    let history_pin = pool::pin(history)?;
    for page in 0..6 {
        pool::zero_chunk(tables, page * 4096, 4096)?;
    }
    let (table_va, table_pa, _) = pool::span(tables)?;
    let (_, code_pa, _) = pool::span(code)?;
    unsafe {
        for score in [false, true] {
            let first = if score { 3 } else { 0 };
            let root = (table_va as *mut Page).add(first);
            let middle = root.add(1);
            let leaf = root.add(2);
            (*root).0[0] = (table_pa + (first as u64 + 1) * 4096) | 3;
            (*middle).0[0] = (table_pa + (first as u64 + 2) * 4096) | 3;
            for segment in plan.segments[..plan.count].iter() {
                let offset = (segment.address - CODE_BASE) as usize;
                for page in offset / 4096..(offset + segment.memory_size).div_ceil(4096) {
                    (*leaf).0[CODE_BASE as usize / 4096 + page] = mmu::encode_user_leaf(
                        PhysAddr(code_pa + page as u64 * 4096),
                        false,
                        segment.executable,
                    )
                    .map_err(|_| DomainError::Range)?;
                }
            }
            for (index, base) in [INPUT_BASE, OUTPUT_BASE, SCRATCH_BASE, STACK_BASE]
                .into_iter()
                .enumerate()
            {
                let (_, physical, _) = pool::span(private[index])?;
                let pages = if score {
                    [SCORE_INPUT_PAGES, 1, 0, 15][index]
                } else {
                    private[index].pages()
                };
                for page in 0..pages {
                    (*leaf).0[base as usize / 4096 + page] = mmu::encode_user_leaf(
                        PhysAddr(physical + page as u64 * 4096),
                        index != 0,
                        false,
                    )
                    .map_err(|_| DomainError::Range)?;
                }
            }
        }
        core::arch::asm!("dsb ishst", "isb", options(nostack));
    }
    pool::seal(tables)?;
    let pin = pool::pin_readonly(tables)?;
    unsafe {
        TABLE_PIN = Some(pin);
        CAPTURE_PIN = Some(capture_pin);
        HISTORY_PIN = Some(history_pin);
        *RESOURCES.0.get() = Some(Resources {
            code,
            private,
            tables,
            plan,
            root: table_pa,
            score_root: table_pa + 3 * 4096,
            capture,
            history,
            driver,
            session,
        });
    }
    INITIALIZED.store(true, Ordering::Release);
    Ok(())
}
fn capture_check(
    key: ObjectKey,
    base: usize,
    bytes: usize,
) -> Result<(), crate::learning_evidence::Error> {
    let r = resources().map_err(|_| crate::learning_evidence::Error::NotReady)?;
    if key != r.capture.key() || bytes != crate::learning_evidence::STORAGE_BYTES {
        return Err(crate::learning_evidence::Error::Owner);
    }
    pool::validate_span(key, base, bytes).map_err(|error| {
        if error == DomainError::Busy {
            crate::learning_evidence::Error::Busy
        } else {
            crate::learning_evidence::Error::Owner
        }
    })
}
fn install_cpu_capture(node: [u8; 32], boot: u64) -> Result<(), DomainError> {
    if cpu::slot() != 0 || node == [0; 32] || boot == 0 {
        return Err(DomainError::Auth);
    }
    if !CAPTURE_READY.load(Ordering::Acquire) {
        return Err(DomainError::NotReady);
    }
    if CAPTURE_LOANED.load(Ordering::Acquire) {
        let same = CAPTURE_BOOT.load(Ordering::Acquire) == boot
            && node.chunks_exact(8).enumerate().all(|(i, word)| {
                CAPTURE_NODE[i].load(Ordering::Acquire)
                    == u64::from_le_bytes(word.try_into().unwrap())
            });
        return if same {
            Ok(())
        } else {
            Err(DomainError::Stale)
        };
    }
    let a = resources()?.capture;
    let (base, _, _) = pool::span(a)?;
    CAPTURE_LOANED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| DomainError::Busy)?;
    // Every field was initialized by the checked typed recipe under one
    // permanent mutable allocation pin; no Storage reference existed earlier.
    let storage = unsafe { &mut *(base as *mut crate::learning_evidence::Storage) };
    match crate::learning_evidence::install(storage, node, boot, a.key(), capture_check) {
        Ok(()) => {
            for (i, word) in node.chunks_exact(8).enumerate() {
                CAPTURE_NODE[i].store(
                    u64::from_le_bytes(word.try_into().unwrap()),
                    Ordering::Release,
                );
            }
            CAPTURE_BOOT.store(boot, Ordering::Release);
            Ok(())
        }
        Err((error, _loan)) => {
            CAPTURE_LOANED.store(false, Ordering::Release);
            Err(match error {
                crate::learning_evidence::Error::Busy => DomainError::Busy,
                crate::learning_evidence::Error::NotReady => DomainError::NotReady,
                _ => DomainError::Conflict,
            })
        }
    }
}

fn history_check(
    key: ObjectKey,
    base: usize,
    bytes: usize,
) -> Result<(), crate::learning_evidence::Error> {
    let r = resources().map_err(|_| crate::learning_evidence::Error::NotReady)?;
    if key != r.history.key() || bytes != crate::learning_history::STORAGE_BYTES {
        return Err(crate::learning_evidence::Error::Owner);
    }
    pool::validate_span(key, base, bytes).map_err(|e| {
        if e == DomainError::Busy {
            crate::learning_evidence::Error::Busy
        } else {
            crate::learning_evidence::Error::Owner
        }
    })
}
pub fn install_capture(node: [u8; 32], boot: u64) -> Result<(), DomainError> {
    install_cpu_capture(node, boot)?;
    if HISTORY_LOANED.load(Ordering::Acquire) {
        return Ok(());
    }
    if !HISTORY_READY.load(Ordering::Acquire) {
        return Err(DomainError::NotReady);
    }
    let a = resources()?.history;
    let (base, _, _) = pool::span(a)?;
    // The lifetime pin exclusively loans this byte storage; every byte was
    // cleared in bounded C1 pieces and no aliasing Storage reference exists.
    let storage = unsafe { &mut *(base as *mut crate::learning_history::Storage) };
    match crate::learning_history::install(storage, node, boot, a.key(), history_check) {
        Ok(()) => {
            HISTORY_LOANED.store(true, Ordering::Release);
            Ok(())
        }
        Err((e, _loan)) => Err(match e {
            crate::learning_evidence::Error::Busy => DomainError::Busy,
            crate::learning_evidence::Error::NotReady => DomainError::NotReady,
            _ => DomainError::Conflict,
        }),
    }
}

/// Kernel-only custody request. The frozen source allocation is pinned before
/// publication; arbitrary EL0 input cannot allocate this request or labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: wire::JobIdentity,
    pub input: Allocation,
    pub input_len: usize,
}
impl Request {
    pub const fn key(self) -> ObjectKey {
        ObjectKey {
            id: self.identity.binding.job_id,
            generation: self.identity.binding.boot_epoch,
        }
    }
    fn extra_role(self) -> Role {
        match self.identity.role {
            wire::Role::Training => Role::Training,
            wire::Role::Validation => Role::Validation,
            wire::Role::ShadowScore => Role::Shadow,
            wire::Role::CanaryScore => Role::Canary,
        }
    }
    fn is_score(self) -> bool {
        matches!(
            self.identity.role,
            wire::Role::ShadowScore | wire::Role::CanaryScore
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pending,
    Running,
    Complete { bytes: usize },
    DataIncomplete,
    Failed(u64),
    Cancelled,
}
struct Pending {
    request: Request,
    lease: Lease,
    status: Status,
    cancel: bool,
    proof: Option<CompletionProof>,
    consumed: bool,
    receipt: Option<WorkReceipt>,
    receipt_taken: bool,
}
#[derive(Clone, Copy)]
struct CompletionProof {
    identity: wire::JobIdentity,
    hash: [u8; 32],
    bytes: u32,
    steps: u64,
    cpu_ns: u64,
    first_sequence: u64,
    last_sequence: u64,
    work: Option<WorkIdentity>,
}
struct Requests {
    pending: Option<Pending>,
    boot: u64,
    last: u64,
}
struct RequestCell(UnsafeCell<Requests>);
unsafe impl Sync for RequestCell {}
static REQUESTS: RequestCell = RequestCell(UnsafeCell::new(Requests {
    pending: None,
    boot: 0,
    last: 0,
}));
static REQUEST_GATE: AtomicBool = AtomicBool::new(false);
struct RequestGuard;
impl Drop for RequestGuard {
    fn drop(&mut self) {
        REQUEST_GATE.store(false, Ordering::Release);
    }
}
fn requests<R>(f: impl FnOnce(&mut Requests) -> Result<R, DomainError>) -> Result<R, DomainError> {
    REQUEST_GATE
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| DomainError::Busy)?;
    let _guard = RequestGuard;
    f(unsafe { &mut *REQUESTS.0.get() })
}
pub fn submit(request: Request) -> Result<ObjectKey, DomainError> {
    require_extra_caller()?;
    if request.key().id == 0
        || request.key().generation != request.identity.binding.boot_epoch
        || request.identity.binding.boot_epoch == 0
        || request.identity.binding.controller_epoch == 0
        || request.identity.binding.model_generation == 0
        || request.identity.binding.data_generation == 0
    {
        return Err(DomainError::Auth);
    }
    if request.input_len == 0
        || request.input_len > INPUT_BYTES
        || request.input_len > request.input.bytes()
    {
        return Err(DomainError::Range);
    }
    resources()?;
    request
        .identity
        .binding
        .validate()
        .map_err(|_| DomainError::Auth)?;
    let registration = registration(request.identity.role)?;
    if request.identity.binding.role_context != registration.role_context
        || request.identity.binding.image_hash != registration.image_hash
        || request.identity.binding.core_generation != registration.core_generation
        || request.identity.binding.ledger_generation != registration.ledger_generation
    {
        return Err(DomainError::Stale);
    }
    requests(|owner| {
        if let Some(old) = &owner.pending {
            return if old.request == request {
                Ok(request.key())
            } else {
                Err(DomainError::Busy)
            };
        }
        if owner.boot != 0 && owner.boot != request.identity.binding.boot_epoch
            || request.key().id <= owner.last
        {
            return Err(DomainError::Stale);
        }
        let inplace = request.input == resources()?.private[0];
        if inplace
            && (INPUT_TOKEN.load(Ordering::Acquire) == 0
                || !INPUT_SEALED.load(Ordering::Acquire)
                || INPUT_SUBMITTED.load(Ordering::Acquire))
        {
            return Err(DomainError::Auth);
        }
        if !inplace && INPUT_TOKEN.load(Ordering::Acquire) != 0 {
            return Err(DomainError::Busy);
        }
        let lease = pool::pin_readonly(request.input)?;
        if inplace {
            INPUT_SUBMITTED.store(true, Ordering::Release);
        }
        INPUT_IDLE.store(false, Ordering::Release);
        owner.boot = request.identity.binding.boot_epoch;
        owner.pending = Some(Pending {
            request,
            lease,
            status: Status::Pending,
            cancel: false,
            proof: None,
            consumed: false,
            receipt: None,
            receipt_taken: false,
        });
        DATA_PRESENT.store(true, Ordering::Release);
        Ok(request.key())
    })
}
pub fn query(key: ObjectKey) -> Result<Status, DomainError> {
    requests(|s| {
        s.pending
            .as_ref()
            .filter(|p| p.request.key() == key)
            .map(|p| p.status)
            .ok_or(DomainError::Stale)
    })
}
pub fn cancel(key: ObjectKey) -> Result<(), DomainError> {
    if cpu::slot() != 0 {
        require_extra_caller()?;
    }
    requests(|s| {
        let p = s
            .pending
            .as_mut()
            .filter(|p| p.request.key() == key)
            .ok_or(DomainError::Stale)?;
        p.cancel = true;
        Ok(())
    })
}
pub fn read_result(key: ObjectKey, offset: usize, out: &mut [u8]) -> Result<(), DomainError> {
    require_extra_caller()?;
    requests(|s| {
        let p = s
            .pending
            .as_ref()
            .filter(|p| p.request.key() == key)
            .ok_or(DomainError::Stale)?;
        let Status::Complete { bytes } = p.status else {
            return Err(DomainError::NotReady);
        };
        if offset.checked_add(out.len()).is_none_or(|end| end > bytes) {
            return Err(DomainError::Range);
        }
        pool::read(resources()?.private[1], offset, out)
    })
}
pub fn acknowledge(key: ObjectKey) -> Result<(), DomainError> {
    require_extra_caller()?;
    requests(|s| {
        let p = s
            .pending
            .as_ref()
            .filter(|p| p.request.key() == key)
            .ok_or(DomainError::Stale)?;
        if matches!(p.status, Status::Pending | Status::Running) {
            return Err(DomainError::Busy);
        }
        let inplace = p.request.input == resources()?.private[0];
        pool::unpin(&p.lease)?;
        if inplace {
            INPUT_SUBMITTED.store(false, Ordering::Relaxed);
            INPUT_SEALED.store(false, Ordering::Relaxed);
            INPUT_TOKEN.store(0, Ordering::Release);
        }
        s.last = key.id;
        s.pending = None;
        DATA_PRESENT.store(false, Ordering::Release);
        Ok(())
    })
}
fn claim_request() -> Result<Option<Request>, DomainError> {
    requests(|s| {
        let Some(p) = s.pending.as_mut() else {
            return Ok(None);
        };
        if p.status != Status::Pending {
            return Ok(None);
        }
        p.status = Status::Running;
        Ok(Some(p.request))
    })
}
fn request_cancelled(key: ObjectKey) -> Result<bool, DomainError> {
    requests(|s| {
        s.pending
            .as_ref()
            .filter(|p| p.request.key() == key)
            .map(|p| p.cancel)
            .ok_or(DomainError::Stale)
    })
}
fn complete_request(key: ObjectKey, status: Status) -> Result<(), DomainError> {
    requests(|s| {
        let p = s
            .pending
            .as_mut()
            .filter(|p| p.request.key() == key)
            .ok_or(DomainError::Stale)?;
        if p.status != Status::Running {
            return Err(DomainError::Conflict);
        }
        p.status = status;
        Ok(())
    })
}
fn complete_proven(
    request: Request,
    status: Status,
    proof: Option<CompletionProof>,
    receipt: &mut Option<WorkReceipt>,
) -> Result<(), DomainError> {
    requests(|s| {
        let p = s
            .pending
            .as_mut()
            .filter(|p| p.request == request)
            .ok_or(DomainError::Stale)?;
        if p.status != Status::Running {
            return Err(DomainError::Conflict);
        }
        if matches!(status, Status::Complete { .. }) {
            let proof = proof.ok_or(DomainError::Conflict)?;
            let actual = receipt.as_ref().ok_or(DomainError::Conflict)?;
            if !receipt_match::matches(
                proof.work,
                actual,
                request.extra_role(),
                request.identity.binding.core_generation,
            ) {
                return Err(DomainError::Auth);
            }
        }
        p.proof = proof;
        p.receipt = receipt.take();
        p.status = status;
        Ok(())
    })
}
/// This authenticates native custody and exact execution only. The caller's
/// CompletionAuthority must also hold the model/data-generation commit gate.
pub fn verify_completion(
    claim: &cyxia_prototype::learning::worker::CompletionClaim,
) -> Result<(), LearnError> {
    if !matches!(
        claim.identity.role,
        wire::Role::Training | wire::Role::Validation
    ) {
        return Err(LearnError::Evidence);
    }
    verify_with_receipt(claim, None)
}
pub fn take_score_receipt(key: ObjectKey) -> Result<WorkReceipt, DomainError> {
    require_extra_caller()?;
    requests(|s| {
        let p = s
            .pending
            .as_mut()
            .filter(|p| p.request.key() == key)
            .ok_or(DomainError::Stale)?;
        if !p.request.is_score() || p.consumed || p.receipt_taken {
            return Err(DomainError::Auth);
        }
        if !matches!(p.status, Status::Complete { .. }) {
            return Err(DomainError::NotReady);
        }
        let proof = p.proof.ok_or(DomainError::NotReady)?;
        let receipt = p.receipt.as_ref().ok_or(DomainError::NotReady)?;
        if !receipt_match::matches(
            proof.work,
            receipt,
            p.request.extra_role(),
            p.request.identity.binding.core_generation,
        ) {
            return Err(DomainError::Auth);
        }
        p.receipt_taken = true;
        p.receipt.take().ok_or(DomainError::Conflict)
    })
}
pub fn verify_score_completion(
    claim: &cyxia_prototype::learning::worker::CompletionClaim,
    receipt: &WorkReceipt,
) -> Result<(), LearnError> {
    if !matches!(
        claim.identity.role,
        wire::Role::ShadowScore | wire::Role::CanaryScore
    ) {
        return Err(LearnError::Evidence);
    }
    verify_with_receipt(claim, Some(receipt))
}
fn verify_with_receipt(
    claim: &cyxia_prototype::learning::worker::CompletionClaim,
    receipt: Option<&WorkReceipt>,
) -> Result<(), LearnError> {
    require_extra_caller().map_err(|e| {
        if matches!(e, DomainError::Busy | DomainError::NotReady) {
            LearnError::Unknown
        } else {
            LearnError::State
        }
    })?;
    requests(|s| {
        let p = s
            .pending
            .as_mut()
            .filter(|p| p.request.identity == claim.identity)
            .ok_or(DomainError::Stale)?;
        if p.consumed
            || p.status
                != (Status::Complete {
                    bytes: claim.output_bytes as usize,
                })
        {
            return Err(DomainError::Stale);
        }
        let proof = p.proof.ok_or(DomainError::NotReady)?;
        let actual = match receipt {
            Some(actual) if p.request.is_score() && p.receipt_taken && p.receipt.is_none() => {
                actual
            }
            None if !p.request.is_score() && !p.receipt_taken => {
                p.receipt.as_ref().ok_or(DomainError::NotReady)?
            }
            _ => return Err(DomainError::Auth),
        };
        if !receipt_match::matches(
            proof.work,
            actual,
            p.request.extra_role(),
            p.request.identity.binding.core_generation,
        ) {
            return Err(DomainError::Auth);
        }
        if proof.identity != claim.identity
            || proof.hash != claim.output_hash
            || proof.bytes != claim.output_bytes
            || proof.steps != claim.completed_steps
            || proof.cpu_ns == 0
            || proof.first_sequence == 0
            || proof.last_sequence < proof.first_sequence
        {
            return Err(DomainError::Auth);
        }
        let (core, ledger) = native::learning_context()?;
        if core != claim.identity.binding.core_generation
            || ledger != claim.identity.binding.ledger_generation
        {
            return Err(DomainError::Stale);
        }
        let (base, _, bytes) = pool::span(p.request.input)?;
        pool::validate_span(p.request.input.key(), base, bytes)?;
        if !OPERATOR_READY.load(Ordering::Acquire)
            || claim.identity.binding.image_hash != image_hash()
            || claim.identity.binding.role_context != role_context(claim.identity.role)
        {
            return Err(DomainError::Auth);
        }
        p.consumed = true;
        Ok(())
    })
    .map_err(|error| match error {
        DomainError::Busy | DomainError::NotReady => LearnError::Unknown,
        DomainError::Stale => LearnError::Stale,
        _ => LearnError::Evidence,
    })
}

struct Bill {
    physical: ControlCredit,
    extra: Option<ExtraCredit>,
    actual: u64,
    finished: u64,
    physical_done: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Capture,
    History,
    Code,
    Clear,
    Pin,
    Run,
    Release,
    Idle,
}
pub(super) struct Worker {
    budget: Option<ExtraBudget>,
    bill: Option<Bill>,
    receipt: Option<WorkReceipt>,
    phase: Phase,
    code_page: usize,
    history_page: usize,
    driver_wait_until: u64,
    image_digest: Option<Sha256>,
    capture_init: Option<CaptureInit<8192, 4096>>,
    capture_complete: Option<InitComplete<8192, 4096>>,
    payload_digest: Option<Sha256>,
    payload_hash: Option<[u8; 32]>,
    proof: Option<CompletionProof>,
    job_ns: u64,
    job_steps: u64,
    first_sequence: u64,
    last_sequence: u64,
    clear_part: usize,
    clear_page: usize,
    pin_cursor: usize,
    code_pin: Option<Lease>,
    pins: [Option<Lease>; 4],
    context: Option<user::Context>,
    probe: u8,
    operator_pass: bool,
    request: Option<Request>,
    completion: Option<Status>,
    publish_pending: bool,
    mandatory_window: u64,
    mandatory_ns: u64,
    extra_window: u64,
    extra_ns: u64,
    total_ns: u64,
    max_slice: u64,
    preemptions: u64,
    yields: u64,
    jobs: u64,
    completed: u64,
    copy_bytes: u64,
    failed: u64,
    last_bill: [u64; 6],
}
impl Worker {
    pub(super) const fn new() -> Self {
        Self {
            budget: None,
            bill: None,
            receipt: None,
            phase: Phase::Capture,
            code_page: 0,
            history_page: 0,
            driver_wait_until: 0,
            image_digest: None,
            capture_init: None,
            capture_complete: None,
            payload_digest: None,
            payload_hash: None,
            proof: None,
            job_ns: 0,
            job_steps: 0,
            first_sequence: 0,
            last_sequence: 0,
            clear_part: 0,
            clear_page: 0,
            pin_cursor: 0,
            code_pin: None,
            pins: [const { None }; 4],
            context: None,
            probe: 0,
            operator_pass: false,
            request: None,
            completion: None,
            publish_pending: false,
            mandatory_window: u64::MAX,
            mandatory_ns: 0,
            extra_window: u64::MAX,
            extra_ns: 0,
            total_ns: 0,
            max_slice: 0,
            preemptions: 0,
            yields: 0,
            jobs: 0,
            completed: 0,
            copy_bytes: 0,
            failed: 0,
            last_bill: [0; 6],
        }
    }
    fn budget(&mut self) -> Result<&mut ExtraBudget, DomainError> {
        if self.budget.is_none() {
            WORKER_CLAIMED
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| DomainError::Conflict)?;
            self.budget = Some(ExtraBudget::new());
        }
        self.budget.as_mut().ok_or(DomainError::NotReady)
    }
    fn evidence(&self) {
        // C1 is the sole writer. A stopped QMP sample which observes an odd
        // sequence must not combine a partially refreshed window/probe tuple.
        LEARNING_V13_EVIDENCE.0[127].fetch_add(1, Ordering::AcqRel);
        let r = self.request;
        let values = [
            1,
            self.phase as u64,
            1,
            self.extra_ns,
            self.mandatory_ns,
            self.total_ns,
            self.max_slice,
            self.preemptions,
            self.yields,
            self.failed,
            self.code_page as u64,
            (self.clear_part * 128 + self.clear_page) as u64,
            u64::from(self.probe),
            u64::from(self.operator_pass),
            u64::from(self.operator_pass && !DATA_PRESENT.load(Ordering::Acquire)),
            self.jobs,
            self.completed,
            r.map_or(0, |r| r.key().id),
            r.map_or(0, |r| r.key().generation),
            r.map_or(0, |r| r.extra_role() as u64 + 1),
            self.copy_bytes,
            WORK_BYTES as u64,
        ];
        for (i, value) in values.into_iter().enumerate() {
            LEARNING_V13_EVIDENCE.0[i + 1].store(value, Ordering::Relaxed);
        }
        for (i, value) in self.last_bill.into_iter().enumerate() {
            LEARNING_V13_EVIDENCE.0[32 + i].store(value, Ordering::Relaxed);
        }
        LEARNING_V13_EVIDENCE.0[24].store(
            self.capture_init
                .as_ref()
                .map_or(0, |init| init.completed_pieces() as u64),
            Ordering::Relaxed,
        );
        LEARNING_V13_EVIDENCE.0[25].store(
            u64::from(CAPTURE_READY.load(Ordering::Acquire)),
            Ordering::Relaxed,
        );
        LEARNING_V13_EVIDENCE.0[26].store(
            u64::from(CAPTURE_LOANED.load(Ordering::Acquire)),
            Ordering::Relaxed,
        );
        LEARNING_V13_EVIDENCE.0[27].store(self.extra_window, Ordering::Relaxed);
        LEARNING_V13_EVIDENCE.0[28].store(self.mandatory_window, Ordering::Relaxed);
        LEARNING_V13_EVIDENCE.0[0].store(MAGIC, Ordering::Release);
        LEARNING_V13_EVIDENCE.0[127].fetch_add(1, Ordering::Release);
    }
    fn fail(&mut self, error: u64) {
        if self.failed == 0 {
            self.failed = error.max(1);
        }
        self.evidence();
    }
}
pub(super) fn allow_mandatory(worker: &Worker, required: u64, now: u64) -> bool {
    if cpu::slot() != 1 {
        return true;
    }
    let spent = if worker.mandatory_window == now / WINDOW_NS {
        worker.mandatory_ns
    } else {
        0
    };
    spent.checked_add(required).is_some_and(|n| n <= 61_000_000)
}
pub(super) fn mandatory(worker: &mut Worker, started: u64, actual: u64) {
    if cpu::slot() != 1 {
        return;
    }
    let window = started / WINDOW_NS;
    if worker.mandatory_window != window {
        worker.mandatory_window = window;
        worker.mandatory_ns = 0;
    }
    worker.mandatory_ns = worker.mandatory_ns.saturating_add(actual);
    match worker.budget() {
        Ok(b) => {
            if let Err(error) = b.record_mandatory(started, actual) {
                worker.fail(0x200 + error as u64);
            }
        }
        Err(error) => worker.fail(0x300 + error as u64),
    }
}
struct Authority {
    credit: ControlCredit,
    capture: bool,
}
impl ControlAuthority for Authority {
    fn authorize(&self, _: Role, slot: u16, generation: u64, bytes: u32) -> Result<(), LearnError> {
        if slot != 1
            || cpu::slot() != 1
            || self.credit.cpu != slot
            || self.credit.core_generation != generation
            || bytes != WORK_BYTES
        {
            return Err(LearnError::State);
        }
        let r = resources().map_err(|_| LearnError::State)?;
        if self.capture {
            let (_, _, bytes) = pool::span(r.capture).map_err(|_| LearnError::Unknown)?;
            return if bytes <= WORK_BYTES as usize {
                Ok(())
            } else {
                Err(LearnError::Capacity)
            };
        }
        if r.private.iter().map(|a| a.bytes()).sum::<usize>() + r.driver.bytes() + r.session.bytes()
            > WORK_BYTES as usize
            || r.driver.pages() != DRIVER_PAGES
            || r.driver.owner() != DRIVER_OWNER
            || r.session.pages() != SESSION_PAGES
            || r.session.owner() != SESSION_OWNER
        {
            return Err(LearnError::Capacity);
        }
        pool::span(r.driver).map_err(|_| LearnError::Unknown)?;
        pool::span(r.session).map_err(|_| LearnError::Unknown)?;
        for a in r.private {
            if a.owner() != OWNER {
                return Err(LearnError::State);
            }
            pool::span(a).map_err(|_| LearnError::Unknown)?;
        }
        Ok(())
    }
}
pub(super) fn settle(worker: &mut Worker) -> bool {
    if cpu::slot() != 1 {
        return true;
    }
    let Some(bill) = worker.bill.as_mut() else {
        return publish_completion(worker);
    };
    if !bill.physical_done {
        match crate::domain_tasks::complete_control(bill.physical, bill.actual, bill.finished) {
            Ok(()) => bill.physical_done = true,
            Err(DomainError::Busy | DomainError::NotReady) => return false,
            Err(DomainError::Budget) => {
                bill.physical_done = true;
                worker.failed = worker.failed.max(0x401);
            }
            Err(error) => {
                worker.failed = worker.failed.max(0x410 + error as u64);
                worker.evidence();
                return false;
            }
        }
    }
    let mut bill = worker.bill.take().unwrap();
    if let Some(extra) = bill.extra.take() {
        let Some(budget) = worker.budget.as_mut() else {
            worker.bill = Some(bill);
            worker.fail(0x402);
            return false;
        };
        match budget.settle(extra, bill.actual, bill.finished) {
            Ok(receipt) => worker.receipt = Some(receipt),
            Err(error) => worker.failed = worker.failed.max(0x500 + error as u64),
        }
    }
    if worker.extra_window != bill.physical.window {
        worker.extra_window = bill.physical.window;
        worker.extra_ns = 0;
    }
    worker.extra_ns = worker.extra_ns.saturating_add(bill.actual);
    worker.last_bill = [
        bill.physical.sequence,
        bill.physical.started_ns,
        bill.finished,
        bill.physical.reserved_ns,
        bill.actual,
        bill.physical.window,
    ];
    worker.evidence();
    if worker.failed == 0 && worker.capture_complete.is_some() {
        CAPTURE_READY.store(true, Ordering::Release);
    }
    if worker.failed == 0 && resources().is_ok_and(|r| worker.history_page == r.history.pages()) {
        HISTORY_READY.store(true, Ordering::Release);
    }
    publish_completion(worker)
}
fn initialize_capture(worker: &mut Worker) -> Result<(), DomainError> {
    if worker.capture_init.is_none() {
        worker.capture_init = Some(CaptureInit::new().map_err(|_| DomainError::Capacity)?);
    }
    let a = resources()?.capture;
    let (base, _, bytes) = pool::span(a)?;
    let init = worker.capture_init.as_mut().ok_or(DomainError::Conflict)?;
    if init.bytes() > bytes
        || init.bytes() > WORK_BYTES as usize
        || !base.is_multiple_of(init.alignment())
    {
        return Err(DomainError::Range);
    }
    for _ in 0..32 {
        let Some(piece) = init.peek() else {
            worker.capture_complete = Some(
                worker
                    .capture_init
                    .take()
                    .ok_or(DomainError::Conflict)?
                    .finish()
                    .map_err(|_| DomainError::Conflict)?,
            );
            worker.phase = Phase::History;
            return Ok(());
        };
        if piece
            .offset
            .checked_add(piece.value.byte_len())
            .is_none_or(|end| end > init.bytes())
            || !(base + piece.offset).is_multiple_of(piece.value.alignment())
        {
            return Err(DomainError::Range);
        }
        let destination = (base + piece.offset) as *mut u8;
        // Values contain no user pointers. Each typed write is <=256 bytes;
        // padding is neither observed nor hashed, and no giant value is copied.
        unsafe {
            match piece.value {
                InitValue::Config(v) => core::ptr::write(destination.cast(), v),
                InitValue::U64(v) => core::ptr::write(destination.cast(), v),
                InitValue::Usize(v) => core::ptr::write(destination.cast(), v),
                InitValue::Raw(v) => core::ptr::write(destination.cast(), v),
                InitValue::Source(v) => core::ptr::write(destination.cast(), v),
                InitValue::Open(v) => core::ptr::write(destination.cast(), v),
                InitValue::Cpu(v) => core::ptr::write(destination.cast(), v),
                InitValue::Request(v) => core::ptr::write(destination.cast(), v),
                InitValue::Work(v) => core::ptr::write(destination.cast(), v),
                InitValue::Fault(v) => core::ptr::write(destination.cast(), v),
                InitValue::Hash(v) => core::ptr::write(destination.cast(), v),
                InitValue::Seal(v) => core::ptr::write(destination.cast(), v),
            }
        }
        init.commit(piece.sequence)
            .map_err(|_| DomainError::Conflict)?;
    }
    Ok(())
}
fn publish_completion(worker: &mut Worker) -> bool {
    if !worker.publish_pending || worker.failed != 0 {
        return true;
    }
    let Some(completion) = worker.completion else {
        worker.fail(0x403);
        return false;
    };
    if let Some(request) = worker.request {
        let proof = worker.proof.map(|mut proof| {
            proof.cpu_ns = worker.job_ns;
            proof.first_sequence = worker.first_sequence;
            proof.last_sequence = worker.last_sequence;
            proof.work = worker.receipt.as_ref().map(WorkReceipt::identity);
            proof
        });
        match complete_proven(request, completion, proof, &mut worker.receipt) {
            Ok(()) => {}
            Err(DomainError::Busy) => return false,
            Err(error) => {
                worker.fail(0x420 + error as u64);
                return false;
            }
        }
        worker.completed = worker.completed.saturating_add(1);
        worker.request = None;
        worker.proof = None;
    } else {
        worker.operator_pass = true;
        OPERATOR_READY.store(true, Ordering::Release);
    }
    worker.completion = None;
    worker.publish_pending = false;
    worker.phase = Phase::Idle;
    INPUT_IDLE.store(true, Ordering::Release);
    worker.evidence();
    true
}
fn fresh_extra(mode: u64, len: usize) -> Result<user::Context, DomainError> {
    let mut context = user::Context::empty();
    context.pc = resources()?.plan.entry;
    context.sp = STACK_TOP;
    context.regs[2] = OUTPUT_BYTES as u64;
    context.regs[0] = mode;
    context.regs[1] = len as u64;
    Ok(context)
}
fn copy_code(worker: &mut Worker) -> Result<(), DomainError> {
    let r = resources()?;
    if worker.code_page == CODE_PAGES {
        pool::seal(r.code)?;
        worker.code_pin = Some(pool::pin_readonly(r.code)?);
        let hash: [u8; 32] = worker
            .image_digest
            .take()
            .ok_or(DomainError::Conflict)?
            .finalize()
            .into();
        for (i, word) in hash.chunks_exact(8).enumerate() {
            IMAGE_HASH[i].store(
                u64::from_le_bytes(word.try_into().unwrap()),
                Ordering::Release,
            );
        }
        worker.phase = Phase::Clear;
        return Ok(());
    }
    let page = worker.code_page;
    pool::zero_chunk(r.code, page * 4096, 4096)?;
    let first = CODE_BASE as usize + page * 4096;
    for segment in r.plan.segments[..r.plan.count].iter() {
        let start = first.max(segment.address as usize);
        let end = (first + 4096).min(segment.address as usize + segment.file_size);
        if start < end {
            let source = segment.offset + start - segment.address as usize;
            pool::write(
                r.code,
                start - CODE_BASE as usize,
                &LEARNING_SERVICE_ELF[source..source + end - start],
            )?;
            worker.copy_bytes += (end - start) as u64;
        }
    }
    let (base, _, _) = pool::span(r.code)?;
    unsafe {
        for off in (page * 4096..(page + 1) * 4096).step_by(64) {
            core::arch::asm!("dc cvau, {}",in(reg)base+off,options(nostack));
        }
        core::arch::asm!("dsb ish", "ic iallu", "dsb ish", "isb", options(nostack));
    }
    let digest = worker.image_digest.get_or_insert_with(Sha256::new);
    let first = page * 4096;
    if first < LEARNING_SERVICE_ELF.len() {
        digest.update(&LEARNING_SERVICE_ELF[first..(first + 4096).min(LEARNING_SERVICE_ELF.len())]);
    }
    worker.code_page += 1;
    Ok(())
}
#[inline(never)]
fn clear_page(worker: &mut Worker) -> Result<(), DomainError> {
    let r = resources()?;
    let inplace = worker
        .request
        .is_some_and(|request| request.input == r.private[0]);
    if worker.clear_part == 4 {
        if !inplace {
            pool::seal(r.private[0])?;
        }
        worker.phase = Phase::Pin;
        worker.pin_cursor = 0;
        return Ok(());
    }
    let a = r.private[worker.clear_part];
    let pages = if worker.request.is_some_and(Request::is_score) {
        [SCORE_INPUT_PAGES, 1, 0, 15][worker.clear_part]
    } else {
        a.pages()
    };
    if pages == 0 {
        worker.clear_part += 1;
        worker.clear_page = 0;
        return Ok(());
    }
    if !(inplace && worker.clear_part == 0) {
        if worker.clear_page == 0 {
            pool::unseal(a)?;
        }
        pool::zero_chunk(a, worker.clear_page * 4096, 4096)?;
    }
    let offset = worker.clear_page * 4096;
    if worker.clear_part == 0 {
        if let Some(request) = worker.request {
            if offset < request.input_len {
                let n = (request.input_len - offset).min(4096);
                let mut bytes = [0u8; 4096];
                pool::read(request.input, offset, &mut bytes[..n])?;
                if !inplace {
                    pool::write(a, offset, &bytes[..n])?;
                }
                if offset + n > wire::HEADER_BYTES {
                    let start = wire::HEADER_BYTES.saturating_sub(offset);
                    worker
                        .payload_digest
                        .as_mut()
                        .ok_or(DomainError::Conflict)?
                        .update(&bytes[start..n]);
                }
                if !inplace {
                    worker.copy_bytes += n as u64;
                }
            }
        }
    }
    worker.clear_page += 1;
    if worker.clear_page == pages {
        if worker.clear_part == 0 && worker.request.is_some() {
            worker.payload_hash = Some(
                worker
                    .payload_digest
                    .take()
                    .ok_or(DomainError::Conflict)?
                    .finalize()
                    .into(),
            );
        }
        worker.clear_part += 1;
        worker.clear_page = 0;
    }
    Ok(())
}
fn pin_pages(worker: &mut Worker) -> Result<(), DomainError> {
    if worker.pin_cursor < 4 {
        let a = resources()?.private[worker.pin_cursor];
        worker.pins[worker.pin_cursor] = Some(if worker.pin_cursor == 0 {
            pool::pin_readonly(a)?
        } else {
            pool::pin(a)?
        });
        worker.pin_cursor += 1;
        return Ok(());
    }
    if let Some(request) = worker.request {
        let (base, _, _) = pool::span(resources()?.private[0])?;
        // The exact readonly pin above prevents any pool writer from changing
        // this input; only the header and its bounded identity hash are read.
        let input = unsafe { core::slice::from_raw_parts(base as *const u8, request.input_len) };
        let (identity, workspace_bytes) =
            wire::input_identity(input).map_err(|_| DomainError::Format)?;
        if identity != request.identity
            || workspace_bytes != WORK_BYTES
            || worker.payload_hash != Some(request.identity.payload_hash)
            || request.identity.binding.role_context != role_context(request.identity.role)
            || request.identity.binding.image_hash != image_hash()
        {
            return Err(DomainError::Auth);
        }
    }
    let mode = if worker.request.is_some() {
        0
    } else if worker.probe < 5 {
        u64::from(worker.probe) + 1
    } else {
        0x10
    };
    worker.context = Some(fresh_extra(
        mode,
        worker.request.map_or(0, |r| r.input_len),
    )?);
    if worker.request.is_some_and(Request::is_score) {
        worker.context.as_mut().ok_or(DomainError::Conflict)?.regs[2] = wire::RESULT_BYTES as u64;
    }
    worker.phase = Phase::Run;
    Ok(())
}
fn exit_context(worker: &mut Worker) -> Result<bool, DomainError> {
    let Some(context) = worker.context.as_ref() else {
        return Err(DomainError::Conflict);
    };
    if context.kind == 0 {
        return Ok(false);
    }
    if worker.request.is_none() && worker.probe < 4 {
        let (address, fsc) = [
            (INPUT_BASE, 0x4f),
            (CODE_BASE, 0x4f),
            (0x1f0000, 0x47),
            (0x30000, 0x07),
        ][worker.probe as usize];
        if context.kind == 9 {
            return Ok(false);
        }
        if context.kind != 8
            || context.esr >> 26 != 0x24
            || context.esr & 0x7f != fsc
            || context.far != address
        {
            return Err(DomainError::Auth);
        }
        worker.probe += 1;
        worker.context = Some(fresh_extra(u64::from(worker.probe) + 1, 0)?);
        return Ok(false);
    }
    if context.kind == 9 {
        if worker.request.is_none() && worker.probe == 4 {
            worker.probe = 5;
            worker.context = Some(fresh_extra(0x10, 0)?);
        }
        return Ok(false);
    }
    if context.kind != 8 || context.esr >> 26 != 0x15 {
        return Err(DomainError::Auth);
    }
    match context.esr & 0xffff {
        0x551 => {
            if worker.request.is_some() {
                if context.regs[0] <= worker.job_steps {
                    return Err(DomainError::Conflict);
                }
                worker.job_steps = context.regs[0];
            }
            worker.yields = worker.yields.saturating_add(1);
            Ok(false)
        }
        0x552
            if context.regs[0] == OUTPUT_BASE
                && context.regs[1] > 0
                && context.regs[1] as usize <= OUTPUT_BYTES =>
        {
            worker.completion = Some(Status::Complete {
                bytes: context.regs[1] as usize,
            });
            worker.context = None;
            worker.phase = Phase::Release;
            worker.pin_cursor = 0;
            Ok(true)
        }
        0x553 => {
            let code = context.regs[0];
            if worker.request.is_none() {
                return Err(DomainError::Auth);
            }
            worker.completion = Some(if code == 0x100 + LearnError::DataIncomplete as u64 {
                Status::DataIncomplete
            } else {
                Status::Failed(code)
            });
            worker.context = None;
            worker.phase = Phase::Release;
            worker.pin_cursor = 0;
            Ok(true)
        }
        _ => Err(DomainError::Auth),
    }
}
fn release(worker: &mut Worker) -> Result<(), DomainError> {
    if worker.pin_cursor < 4 {
        if let Some(pin) = worker.pins[worker.pin_cursor].as_ref() {
            pool::unpin(pin)?;
            worker.pins[worker.pin_cursor] = None;
        }
        worker.pin_cursor += 1;
        return Ok(());
    }
    let completion = worker.completion.ok_or(DomainError::Conflict)?;
    if let Some(request) = worker.request {
        if let Status::Complete { bytes } = completion {
            if bytes != wire::RESULT_BYTES {
                return Err(DomainError::Format);
            }
            let proof = pool::inspect(resources()?.private[1], 0, bytes, |bytes| {
                let (identity, steps) =
                    wire::output_identity(bytes).map_err(|_| DomainError::Format)?;
                if identity != request.identity
                    || steps != worker.job_steps
                    || worker.job_steps == 0
                {
                    return Err(DomainError::Auth);
                }
                Ok(CompletionProof {
                    identity: request.identity,
                    hash: Sha256::digest(bytes).into(),
                    bytes: bytes.len() as u32,
                    steps,
                    cpu_ns: 0,
                    first_sequence: 0,
                    last_sequence: 0,
                    work: None,
                })
            })??;
            pool::seal(resources()?.private[1])?;
            worker.proof = Some(proof);
        }
    } else {
        if completion != (Status::Complete { bytes: 32 }) {
            return Err(DomainError::Auth);
        }
        let mut bytes = [0u8; 32];
        pool::read(resources()?.private[1], 0, &mut bytes)?;
        let values = core::array::from_fn::<_, 4, _>(|i| {
            u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap())
        });
        if values != [u64::from_le_bytes(*b"CXSELF01"), 1, 14, 0] {
            return Err(DomainError::Auth);
        }
    }
    // The publication occurs only after this turn's two exact bills settle.
    worker.publish_pending = true;
    Ok(())
}
fn turn(worker: &mut Worker, credit: ControlCredit, begin: u64) -> Result<(), DomainError> {
    if let Some(request) = worker.request {
        if request.identity.binding.core_generation != credit.core_generation
            && worker.phase != Phase::Release
        {
            worker.context = None;
            worker.completion = Some(Status::Failed(0x700 + DomainError::Stale as u64));
            worker.phase = Phase::Release;
            worker.pin_cursor = 0;
        }
        if request_cancelled(request.key())? && worker.phase != Phase::Release {
            worker.context = None;
            worker.completion = Some(Status::Cancelled);
            worker.phase = Phase::Release;
            worker.pin_cursor = 0;
        }
    }
    match worker.phase {
        Phase::Capture => initialize_capture(worker),
        Phase::History => {
            let allocation = resources()?.history;
            let (base, _, _) = pool::span(allocation)?;
            if worker.history_page < allocation.pages() {
                unsafe {
                    core::ptr::write_bytes((base + worker.history_page * 4096) as *mut u8, 0, 4096);
                }
                worker.history_page += 1;
            }
            if worker.history_page == allocation.pages() {
                worker.phase = Phase::Code;
            }
            Ok(())
        }
        Phase::Code => copy_code(worker),
        Phase::Clear => {
            // Bounded pages, not one full-workspace temporary. Score maps only
            // its compact input, one result page and guarded stack; the other
            // private pages stay inaccessible and need no per-score clearing.
            for _ in 0..16 {
                if native::ns(timer::ticks().saturating_sub(begin)).saturating_add(1_000_000)
                    > credit.reserved_ns
                {
                    break;
                }
                clear_page(worker)?;
                if worker.phase != Phase::Clear {
                    break;
                }
            }
            Ok(())
        }
        Phase::Pin => pin_pages(worker),
        Phase::Release => release(worker),
        Phase::Idle => {
            let driver = DRIVER.load(Ordering::Acquire);
            if driver != 0 && native::ns(timer::ticks()) >= worker.driver_wait_until {
                let turn: DriverTurn = unsafe { core::mem::transmute(driver) };
                match turn() {
                    Ok(true) => {}
                    Ok(false) => {
                        worker.driver_wait_until =
                            native::ns(timer::ticks()).saturating_add(WINDOW_NS)
                    }
                    Err(DomainError::Busy | DomainError::Again | DomainError::NotReady) => {}
                    Err(error) => return Err(error),
                }
            }
            if let Some(request) = claim_request()? {
                worker.request = Some(request);
                worker.payload_digest = Some(Sha256::new());
                worker.payload_hash = None;
                worker.proof = None;
                worker.job_ns = 0;
                worker.job_steps = 0;
                worker.first_sequence = credit.sequence;
                worker.last_sequence = credit.sequence;
                worker.jobs += 1;
                worker.clear_part = 0;
                worker.clear_page = 0;
                worker.phase = Phase::Clear;
            }
            Ok(())
        }
        Phase::Run => {
            if exit_context(worker)? {
                return Ok(());
            }
            let entered = timer::ticks();
            if native::ns(entered.saturating_sub(begin)).saturating_add(1_000_000)
                > credit.reserved_ns
            {
                return Ok(());
            }
            let context = worker.context.as_mut().ok_or(DomainError::Conflict)?;
            context.kind = 0;
            let slice =
                ((u128::from(SLICE_NS) * u128::from(timer::frequency())) / 1_000_000_000) as u64;
            unsafe {
                enter_service(
                    context,
                    if worker.request.is_some_and(Request::is_score) {
                        resources()?.score_root
                    } else {
                        resources()?.root
                    },
                    entered.saturating_add(slice.max(1)),
                );
            }
            let end = timer::ticks();
            worker.max_slice = worker.max_slice.max(native::ns(end - entered));
            if context.kind == 9 {
                worker.preemptions += 1;
            }
            Ok(())
        }
    }
}
#[inline(never)]
pub(super) fn step(worker: &mut Worker) {
    if cpu::slot() != 1
        || !INITIALIZED.load(Ordering::Acquire)
        || !settle(worker)
        || worker.failed != 0
    {
        return;
    }
    if worker.phase == Phase::Idle {
        // Inspect only the mailbox; absence of real data is DataIncomplete.
        if !requests(|s| {
            Ok(s.pending
                .as_ref()
                .is_some_and(|p| p.status == Status::Pending))
        })
        .unwrap_or(false)
            && (DRIVER.load(Ordering::Acquire) == 0
                || native::ns(timer::ticks()) < worker.driver_wait_until)
        {
            worker.evidence();
            return;
        }
    }
    let now = native::ns(timer::ticks());
    let spent = if worker.extra_window == now / WINDOW_NS {
        worker.extra_ns
    } else {
        0
    };
    if spent.saturating_add(RESERVE_NS) > 9_000_000 {
        return;
    }
    let Ok(Some(credit)) = crate::domain_tasks::begin_control(RESERVE_NS, false) else {
        return;
    };
    let begin = timer::ticks();
    let role = worker.request.map_or_else(
        || {
            requests(|s| {
                Ok(s.pending
                    .as_ref()
                    .filter(|p| p.status == Status::Pending)
                    .map(|p| p.request.extra_role()))
            })
            .ok()
            .flatten()
            .unwrap_or(Role::Training)
        },
        Request::extra_role,
    );
    let capture = matches!(worker.phase, Phase::Capture | Phase::History);
    let extra = match worker.budget().and_then(|budget| {
        budget
            .reserve(
                role,
                1,
                credit.core_generation,
                WORK_BYTES,
                credit.started_ns,
                RESERVE_NS,
                &Authority { credit, capture },
            )
            .map_err(|_| DomainError::Budget)
    }) {
        Ok(extra) => Some(extra),
        Err(_) => None,
    };
    let mut capture = crate::learning_evidence::attempt(
        OWNER,
        cyxia_prototype::learning::reward::CpuClass::Policy,
    )
    .ok()
    .flatten();
    if extra.is_some() {
        EXTRA_ACTIVE.store(true, Ordering::Release);
        if let Err(error) = turn(worker, credit, begin) {
            if !matches!(
                error,
                DomainError::Busy | DomainError::Again | DomainError::NotReady
            ) {
                if worker.request.is_some() {
                    worker.context = None;
                    worker.completion = Some(Status::Failed(0x600 + error as u64));
                    worker.phase = Phase::Release;
                    worker.pin_cursor = 0;
                } else {
                    worker.fail(0x600 + error as u64);
                }
            }
        }
    }
    EXTRA_ACTIVE.store(false, Ordering::Release);
    let end = timer::ticks();
    let actual = native::ns(end - begin);
    if let Some(attempt) = capture.as_mut() {
        let _ =
            crate::learning_evidence::finish_attempt(attempt, native::ns(begin), native::ns(end));
    }
    drop(capture);
    worker.total_ns = worker.total_ns.saturating_add(actual);
    if worker.request.is_some() {
        worker.job_ns = worker.job_ns.saturating_add(actual);
        worker.last_sequence = credit.sequence;
    }
    CONTROL_TICKS.fetch_add(end - begin, Ordering::Relaxed);
    worker.bill = Some(Bill {
        physical: credit,
        extra,
        actual,
        finished: native::ns(end),
        physical_done: false,
    });
    let _ = settle(worker);
}
pub(super) fn quiescent(worker: &mut Worker) -> bool {
    if cpu::slot() != 1 {
        return true;
    }
    settle(worker)
        && worker.bill.is_none()
        && worker.context.is_none()
        && worker.pins.iter().all(Option::is_none)
}
