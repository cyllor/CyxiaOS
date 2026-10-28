//! Immutable image identity and bounded address-space installation for the
//! independent EL0 learning-governance coordinator.
//!
//! This module deliberately stops before dispatch or command authorization.
//! Installing an RX/RO image and private mappings does not create a second
//! publication authority and does not allocate a separate 9 ms surplus budget.
use super::*;
use crate::control_pool::{self as pool, Allocation, Lease};
use core::cell::UnsafeCell;
use cyxia_prototype::domains::{Error, ObjectKey};
use sha2::{Digest, Sha256};

const CODE_BASE: u64 = 0x80000;
const CODE_LIMIT: u64 = 0x100000;
const CODE_PAGES: usize = ((CODE_LIMIT - CODE_BASE) / 4096) as usize;
const INPUT_BASE: u64 = 0x100000;
const OUTPUT_BASE: u64 = 0x101000;
const STACK_BASE: u64 = 0x102000;
const STACK_PAGES: usize = 4;
const STACK_TOP: u64 = STACK_BASE + STACK_PAGES as u64 * 4096;
const TABLE_PAGES: usize = 3;
const OWNER: ObjectKey = ObjectKey {
    id: 0x474f_5645_524e_0001,
    generation: 1,
};
const ROLE_CONTEXT: ObjectKey = ObjectKey {
    id: 0x474f_5643_4f4f_0001,
    generation: 1,
};
const MAGIC: u64 = 0x4359_474f_5645_5201;

#[used]
#[unsafe(no_mangle)]
static GOVERNANCE_SERVICE_ELF: [u8; include_bytes!(concat!(
    env!("OUT_DIR"),
    "/prototype-governance.elf"
))
.len()] = *include_bytes!(concat!(env!("OUT_DIR"), "/prototype-governance.elf"));

#[repr(C, align(64))]
pub struct Evidence([AtomicU64; 16]);
#[used]
#[unsafe(no_mangle)]
pub static GOVERNANCE_V13_EVIDENCE: Evidence = Evidence([const { AtomicU64::new(0) }; 16]);

#[derive(Clone, Copy)]
struct ImagePlan {
    entry: u64,
    segments: [cyxia_kernel_core::control_plane::image::Segment; 8],
    count: usize,
    pages: usize,
}

struct Resources {
    code: Allocation,
    input: Allocation,
    output: Allocation,
    stack: Allocation,
    tables: Allocation,
    _code_pin: Lease,
    _table_pin: Lease,
    plan: ImagePlan,
    root: u64,
    image_hash: [u8; 32],
}
struct ResourceCell(UnsafeCell<Option<Resources>>);
unsafe impl Sync for ResourceCell {}
static RESOURCES: ResourceCell = ResourceCell(UnsafeCell::new(None));
static CLAIMED: AtomicBool = AtomicBool::new(false);
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// This identity is necessary but not sufficient authority. A future dispatch
/// ticket must additionally bind the actual C owner, credit and trap context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration {
    pub role_context: ObjectKey,
    pub image_hash: [u8; 32],
    pub entry: u64,
    pub root: u64,
    pub input: ObjectKey,
    pub output: ObjectKey,
    pub stack: ObjectKey,
    pub stack_top: u64,
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at.checked_add(2).ok_or(Error::Range)?)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?,
    ))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at.checked_add(4).ok_or(Error::Range)?)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?,
    ))
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at.checked_add(8).ok_or(Error::Range)?)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?,
    ))
}

fn parse_image(bytes: &[u8]) -> Result<ImagePlan, Error> {
    if bytes.len() > CODE_PAGES * 4096
        || bytes.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || u16_at(bytes, 16)? != 2
        || u16_at(bytes, 18)? != 183
        || u32_at(bytes, 20)? != 1
        || u16_at(bytes, 52)? != 64
        || u16_at(bytes, 54)? != 56
    {
        return Err(Error::Format);
    }
    let entry = u64_at(bytes, 24)?;
    let headers = usize::try_from(u64_at(bytes, 32)?).map_err(|_| Error::Range)?;
    let headers_count = usize::from(u16_at(bytes, 56)?);
    if headers_count == 0 || headers_count > 8 {
        return Err(Error::Format);
    }
    let mut plan = ImagePlan {
        entry,
        segments: [cyxia_kernel_core::control_plane::image::Segment::default(); 8],
        count: 0,
        pages: 0,
    };
    let mut seen = 0u128;
    let mut entry_found = false;
    for index in 0..headers_count {
        let at = headers
            .checked_add(index.checked_mul(56).ok_or(Error::Range)?)
            .ok_or(Error::Range)?;
        bytes
            .get(at..at.checked_add(56).ok_or(Error::Range)?)
            .ok_or(Error::Format)?;
        match u32_at(bytes, at)? {
            0 | 4 | 6 | 0x6474_e551 => continue,
            1 => {}
            _ => return Err(Error::Auth),
        }
        let flags = u32_at(bytes, at + 4)?;
        let offset = usize::try_from(u64_at(bytes, at + 8)?).map_err(|_| Error::Range)?;
        let address = u64_at(bytes, at + 16)?;
        let file_size = usize::try_from(u64_at(bytes, at + 32)?).map_err(|_| Error::Range)?;
        let memory_size = usize::try_from(u64_at(bytes, at + 40)?).map_err(|_| Error::Range)?;
        let end = address
            .checked_add(memory_size as u64)
            .ok_or(Error::Range)?;
        if !matches!(flags, 4 | 5)
            || memory_size == 0
            || file_size > memory_size
            || address < CODE_BASE
            || end > CODE_LIMIT
            || !address.is_multiple_of(4096)
            || !offset.is_multiple_of(4096)
            || u64_at(bytes, at + 48)? != 4096
            || bytes
                .get(offset..offset.checked_add(file_size).ok_or(Error::Range)?)
                .is_none()
        {
            return Err(Error::Format);
        }
        let first = usize::try_from((address - CODE_BASE) / 4096).map_err(|_| Error::Range)?;
        let last = usize::try_from((end - CODE_BASE).div_ceil(4096)).map_err(|_| Error::Range)?;
        for page in first..last {
            let bit = 1u128.checked_shl(page as u32).ok_or(Error::Range)?;
            if seen & bit != 0 {
                return Err(Error::Conflict);
            }
            seen |= bit;
        }
        entry_found |= flags == 5
            && entry >= address
            && entry < address + file_size as u64
            && entry.is_multiple_of(4);
        plan.segments[plan.count] = cyxia_kernel_core::control_plane::image::Segment {
            offset,
            address,
            file_size,
            memory_size,
            executable: flags == 5,
        };
        plan.count += 1;
        plan.pages = plan.pages.max(last);
    }
    if !entry_found || plan.count == 0 || plan.pages == 0 || plan.pages > CODE_PAGES {
        return Err(Error::Format);
    }
    Ok(plan)
}

fn copy_image(plan: ImagePlan, code: Allocation) -> Result<Lease, Error> {
    for page in 0..plan.pages {
        pool::zero_chunk(code, page * 4096, 4096)?;
        let page_start = CODE_BASE as usize + page * 4096;
        for segment in &plan.segments[..plan.count] {
            let start = page_start.max(segment.address as usize);
            let end = (page_start + 4096).min(segment.address as usize + segment.file_size);
            if start < end {
                let source = segment.offset + start - segment.address as usize;
                pool::write(
                    code,
                    start - CODE_BASE as usize,
                    &GOVERNANCE_SERVICE_ELF[source..source + end - start],
                )?;
            }
        }
    }
    let (base, _, _) = pool::span(code)?;
    unsafe {
        for offset in (0..plan.pages * 4096).step_by(64) {
            core::arch::asm!("dc cvau, {}", in(reg) base + offset, options(nostack));
        }
        core::arch::asm!("dsb ish", "ic iallu", "dsb ish", "isb", options(nostack));
    }
    pool::seal(code)?;
    pool::pin_readonly(code)
}

fn build_tables(
    plan: ImagePlan,
    code: Allocation,
    input: Allocation,
    output: Allocation,
    stack: Allocation,
    tables: Allocation,
) -> Result<(u64, Lease), Error> {
    for page in 0..TABLE_PAGES {
        pool::zero_chunk(tables, page * 4096, 4096)?;
    }
    let (table_va, table_pa, _) = pool::span(tables)?;
    let (_, code_pa, _) = pool::span(code)?;
    let (_, input_pa, _) = pool::span(input)?;
    let (_, output_pa, _) = pool::span(output)?;
    let (_, stack_pa, _) = pool::span(stack)?;
    unsafe {
        let root = table_va as *mut Page;
        let middle = root.add(1);
        let leaf = root.add(2);
        (*root).0[0] = (table_pa + 4096) | 3;
        (*middle).0[0] = (table_pa + 8192) | 3;
        for segment in &plan.segments[..plan.count] {
            let first =
                usize::try_from((segment.address - CODE_BASE) / 4096).map_err(|_| Error::Range)?;
            let last = (first * 4096 + segment.memory_size).div_ceil(4096);
            for page in first..last {
                (*leaf).0[CODE_BASE as usize / 4096 + page] = mmu::encode_user_leaf(
                    PhysAddr(code_pa + page as u64 * 4096),
                    false,
                    segment.executable,
                )
                .map_err(|_| Error::Range)?;
            }
        }
        (*leaf).0[INPUT_BASE as usize / 4096] =
            mmu::encode_user_leaf(PhysAddr(input_pa), false, false).map_err(|_| Error::Range)?;
        (*leaf).0[OUTPUT_BASE as usize / 4096] =
            mmu::encode_user_leaf(PhysAddr(output_pa), true, false).map_err(|_| Error::Range)?;
        for page in 0..STACK_PAGES {
            (*leaf).0[STACK_BASE as usize / 4096 + page] =
                mmu::encode_user_leaf(PhysAddr(stack_pa + page as u64 * 4096), true, false)
                    .map_err(|_| Error::Range)?;
        }
        core::arch::asm!("dsb ishst", "isb", options(nostack));
    }
    pool::seal(tables)?;
    let pin = pool::pin_readonly(tables)?;
    Ok((table_pa, pin))
}

fn publish_evidence(resources: &Resources) {
    let values = [
        MAGIC,
        1,
        resources.plan.entry,
        resources.root,
        resources.plan.pages as u64,
        1,
        1,
        STACK_PAGES as u64,
        TABLE_PAGES as u64,
        ROLE_CONTEXT.id,
        ROLE_CONTEXT.generation,
    ];
    for (index, value) in values.into_iter().enumerate() {
        GOVERNANCE_V13_EVIDENCE.0[index].store(value, Ordering::Relaxed);
    }
    for (index, word) in resources.image_hash.chunks_exact(8).enumerate() {
        GOVERNANCE_V13_EVIDENCE.0[11 + index].store(
            u64::from_le_bytes(word.try_into().unwrap()),
            Ordering::Relaxed,
        );
    }
    GOVERNANCE_V13_EVIDENCE.0[15].store(1, Ordering::Release);
}

pub(super) fn init() -> Result<(), Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    CLAIMED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| Error::Exists)?;
    let plan = parse_image(&GOVERNANCE_SERVICE_ELF)?;
    let code = pool::allocate(OWNER, plan.pages)?;
    let input = pool::allocate(OWNER, 1)?;
    let output = pool::allocate(OWNER, 1)?;
    let stack = pool::allocate(OWNER, STACK_PAGES)?;
    let tables = pool::allocate(OWNER, TABLE_PAGES)?;
    pool::zero_chunk(input, 0, 4096)?;
    pool::zero_chunk(output, 0, 4096)?;
    for page in 0..STACK_PAGES {
        pool::zero_chunk(stack, page * 4096, 4096)?;
    }
    let code_pin = copy_image(plan, code)?;
    let (root, table_pin) = build_tables(plan, code, input, output, stack, tables)?;
    let image_hash: [u8; 32] = Sha256::digest(&GOVERNANCE_SERVICE_ELF).into();
    let resources = Resources {
        code,
        input,
        output,
        stack,
        tables,
        _code_pin: code_pin,
        _table_pin: table_pin,
        plan,
        root,
        image_hash,
    };
    unsafe {
        *RESOURCES.0.get() = Some(resources);
    }
    let resources = unsafe { (&*RESOURCES.0.get()).as_ref().ok_or(Error::NotReady)? };
    publish_evidence(resources);
    INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

pub fn registration() -> Result<Registration, Error> {
    if !INITIALIZED.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    let resources = unsafe { (&*RESOURCES.0.get()).as_ref().ok_or(Error::NotReady)? };
    Ok(Registration {
        role_context: ROLE_CONTEXT,
        image_hash: resources.image_hash,
        entry: resources.plan.entry,
        root: resources.root,
        input: resources.input.key(),
        output: resources.output.key(),
        stack: resources.stack.key(),
        stack_top: STACK_TOP,
    })
}
