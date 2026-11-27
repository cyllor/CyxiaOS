//! Shared CPU0 loader for the compiled-in ABI3 PIE role packages.
//! CPU0 is the only writer of role backing and page tables. The published
//! RX mappings have their writable aliases removed before first entry.
use super::{Page, mmu, phys, ram_l3, timer, user};
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_contracts::PhysAddr;
use cyxia_kernel_core::control_plane::{
    Identity, cpu0_v0199 as profile,
    pie_image_v0199::{
        ROLE_STACK_BYTES, RelativeRelocation, RolePackageInput, RolePackageSpec,
        VerifiedRolePackage,
    },
    role_manifest_v0199::{NativeRole, PrivateRegion, ROLE_COUNT, ROLES},
};

// PIE loader layout (mirrors v0199_control_bringup).
const PAGE: usize = 4096;
const IMAGE: usize = 64 * 1024;
pub(super) const COPY: usize = 128 * 1024;
const BASE: u64 = 0x10000;
const STACK_BASE: u64 = 0x30000;
const STACK_END: u64 = STACK_BASE + ROLE_STACK_BYTES as u64;

pub(super) static PIE_CAP: [AtomicU64; ROLE_COUNT] = [const { AtomicU64::new(0) }; ROLE_COUNT];

// ---- PIE role backing / page tables (CPU0 sole loader) ----
struct BootPackage {
    role_id: u16,
    bytes: &'static [u8],
    image_sha256: [u8; 32],
    relative_sha256: [u8; 32],
    relative: &'static [RelativeRelocation],
}
static CATALOG: [BootPackage; ROLE_COUNT] =
    include!(concat!(env!("OUT_DIR"), "/v0199-role-catalog.rs"));

#[cfg(feature = "v020-production-diagnostic")]
pub(super) fn image_digest(index: usize) -> [u8; 32] {
    CATALOG[index].image_sha256
}
#[repr(C, align(4096))]
pub(super) struct Backing {
    image: [u8; IMAGE],
    stack: [u8; ROLE_STACK_BYTES],
}
impl Backing {
    const ZERO: Self = Self {
        image: [0; IMAGE],
        stack: [0; ROLE_STACK_BYTES],
    };
}
#[repr(C, align(4096))]
pub(super) struct Tables {
    root: Page,
    mid: Page,
    leaf: Page,
}
impl Tables {
    const ZERO: Self = Self {
        root: Page::ZERO,
        mid: Page::ZERO,
        leaf: Page::ZERO,
    };
}
#[repr(align(4096))]
pub(super) struct CopyBuffer(pub(super) [u8; COPY]);
pub(super) static mut BACKING: [Backing; ROLE_COUNT] = [const { Backing::ZERO }; ROLE_COUNT];
pub(super) static mut TABLES: [Tables; ROLE_COUNT] = [const { Tables::ZERO }; ROLE_COUNT];
pub(super) static mut COPY_BUFFER: CopyBuffer = CopyBuffer([0; COPY]);
const _: () = assert!(core::mem::size_of::<Backing>() == IMAGE + ROLE_STACK_BYTES);
const _: () = assert!(core::mem::size_of::<Tables>() == 3 * PAGE);

pub(super) fn now_ns() -> u64 {
    ns_from_ticks(timer::ticks())
}
pub(super) fn ns_from_ticks(ticks: u64) -> u64 {
    let f = timer::frequency();
    assert!(f != 0);
    u64::try_from(u128::from(ticks) * 1_000_000_000 / u128::from(f)).expect("monotonic ns")
}
/// The vector's saved root/ASID from the current lower-EL exception.
pub(super) fn trapped_ttbr0() -> u64 {
    cyxia_arch_aarch64::user::captured_user_root()
}

// ---- PIE loader (mirrors v0199_control_bringup::load, no PMU metering) ----
fn backing(index: usize) -> *mut Backing {
    assert!(index < ROLE_COUNT);
    unsafe {
        core::ptr::addr_of_mut!(BACKING)
            .cast::<Backing>()
            .add(index)
    }
}
fn tables(index: usize) -> *mut Tables {
    assert!(index < ROLE_COUNT);
    unsafe { core::ptr::addr_of_mut!(TABLES).cast::<Tables>().add(index) }
}
pub(super) fn root_pa(index: usize) -> u64 {
    phys(tables(index) as u64)
}
pub(super) fn role_asid(index: usize) -> u8 {
    (0xA0 + index) as u8
}
pub(super) fn high_leaf(pa: u64) -> *mut u64 {
    assert!(pa.is_multiple_of(PAGE as u64) && pa >= cyxia_platform_virt::RAM_BASE);
    let offset = (pa - cyxia_platform_virt::RAM_BASE) / PAGE as u64;
    assert!(offset < (cyxia_platform_virt::RAM_MIB * 1024 * 1024 / PAGE as u64));
    unsafe { ((core::ptr::addr_of!(ram_l3) as u64 + crate::HIGH) as *mut u64).add(offset as usize) }
}
fn sync_code(addr: u64, bytes: usize) {
    let ctr: u64;
    unsafe {
        core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack));
    }
    let line = 4usize << ((ctr >> 16) & 15);
    assert!(line.is_power_of_two() && line <= PAGE);
    for off in (0..bytes).step_by(line) {
        unsafe {
            core::arch::asm!("dc cvau, {}", in(reg) addr + off as u64, options(nostack));
        }
    }
    unsafe {
        core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb", options(nostack));
    }
}
pub(super) fn tlbi() {
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack)
        );
    }
}
fn seal_page(pa: u64) {
    let leaf = high_leaf(pa);
    let old = unsafe { core::ptr::read_volatile(leaf) };
    assert_eq!(old, pa | 0x0060_0000_0000_0703);
    unsafe {
        core::ptr::write_volatile(leaf, 0);
    }
    tlbi();
    unsafe {
        core::ptr::write_volatile(leaf, old | (1 << 7));
    }
    tlbi();
}
pub(super) enum RoleLaunch {
    #[cfg(cyxia_signed_resident)]
    Lifecycle,
    #[cfg(feature = "v020-production-diagnostic")]
    Diagnostic {
        cap_selector: u64,
        target_selector: u64,
    },
}

pub(super) fn load_role_with_identity(
    index: usize,
    generation: u64,
    launch: RoleLaunch,
) -> NativeRole {
    let role = ROLES[index];
    let pkg = &CATALOG[index];
    assert_eq!(pkg.role_id, role.id());
    assert!(pkg.bytes.len() <= COPY);
    let actor = Identity {
        id: u64::from(role.id()),
        generation,
    };
    let (cap_selector, target_selector, caps, endpoint_id) = match launch {
        #[cfg(cyxia_signed_resident)]
        RoleLaunch::Lifecycle => (0u64, 0u64, 0, 0),
        #[cfg(feature = "v020-production-diagnostic")]
        RoleLaunch::Diagnostic {
            cap_selector,
            target_selector,
        } => (
            cap_selector,
            target_selector,
            role.allowed_caps(),
            0xC000 + index as u64,
        ),
    };
    let b = backing(index);
    let t = tables(index);
    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(COPY_BUFFER.0) };
    scratch[..pkg.bytes.len()].copy_from_slice(pkg.bytes);
    let spec = RolePackageSpec {
        role,
        package_id: u64::from(role.id()),
        abi: 3,
        image_bytes: pkg.bytes.len(),
        image_sha256: pkg.image_sha256,
        relative_count: pkg.relative.len(),
        relative_sha256: pkg.relative_sha256,
        stack_bytes: ROLE_STACK_BYTES,
    };
    let verified = VerifiedRolePackage::verify_checkpointed(
        spec,
        RolePackageInput {
            package_id: spec.package_id,
            bytes: &scratch[..pkg.bytes.len()],
            relative: pkg.relative,
        },
        &mut || {},
    )
    .expect("trusted ABI3 role package");
    let relro = verified.relro();
    let image = unsafe { &mut *core::ptr::addr_of_mut!((*b).image) };
    let entry = verified
        .stage(image, BASE, BASE, BASE + IMAGE as u64)
        .expect("private PIE stage");
    let stack = unsafe { &mut *core::ptr::addr_of_mut!((*b).stack) };
    let mut args = [0u8; 24];
    args[..8].copy_from_slice(&cap_selector.to_le_bytes());
    args[8..16].copy_from_slice(&target_selector.to_le_bytes());
    args[16..24].copy_from_slice(&actor.generation.to_le_bytes());
    let startup =
        cyxia_kernel_core::security::syscall_v3::stage_spawn_args(stack, STACK_BASE, &args)
            .expect("private ABI3 startup arguments");
    assert_eq!(startup.sp, STACK_END - 32);
    let mut map = [0u8; IMAGE / PAGE];
    for seg in verified.load_segments() {
        let start = seg.virtual_address as usize / PAGE;
        let end = (seg.virtual_address + seg.memory_bytes).div_ceil(PAGE as u64) as usize;
        assert!(start < end && end <= map.len());
        for page in &mut map[start..end] {
            assert_eq!(*page, 0);
            *page = seg.flags as u8;
        }
    }
    if let Some((start, len)) = relro {
        assert_eq!(start % PAGE as u64, 0);
        let end = start.checked_add(len).unwrap().div_ceil(PAGE as u64);
        assert!(end <= map.len() as u64);
        for page in &mut map[start as usize / PAGE..end as usize] {
            assert_eq!(*page, 6);
            *page = 4;
        }
    }
    scratch.fill(0);
    let image_base = b as u64;
    for (i, flags) in map.iter().copied().enumerate() {
        if flags & 1 != 0 {
            sync_code(image_base + i as u64 * PAGE as u64, PAGE);
        }
    }
    unsafe {
        (*t).root.0[0] = phys(core::ptr::addr_of!((*t).mid) as u64) | 3;
        (*t).mid.0[0] = phys(core::ptr::addr_of!((*t).leaf) as u64) | 3;
    }
    for (i, flags) in map.into_iter().enumerate() {
        if flags == 0 {
            continue;
        }
        let pa = phys(image_base + i as u64 * PAGE as u64);
        let write = flags & 2 != 0;
        let execute = flags & 1 != 0;
        if !write {
            seal_page(pa);
        }
        let desc = mmu::encode_user_leaf(PhysAddr(pa), write, execute).unwrap();
        unsafe {
            (*t).leaf.0[BASE as usize / PAGE + i] = desc;
        }
    }
    let stack_base = unsafe { core::ptr::addr_of!((*b).stack) as u64 };
    for i in 0..ROLE_STACK_BYTES / PAGE {
        let pa = phys(stack_base + i as u64 * PAGE as u64);
        unsafe {
            (*t).leaf.0[STACK_BASE as usize / PAGE + i] =
                mmu::encode_user_leaf(PhysAddr(pa), true, false).unwrap();
        }
    }
    assert_eq!(unsafe { (*t).leaf.0[STACK_BASE as usize / PAGE - 1] }, 0);
    tlbi();
    PIE_CAP[index].store(cap_selector, Ordering::Release);
    // Stash the entry/SP for the turn loop in the member's private region base
    // is not possible; keep a separate context array instead (see pie_context).
    PIE_ENTRY[index].store(entry, Ordering::Release);
    PIE_SP[index].store(startup.sp, Ordering::Release);
    PIE_X0[index].store(startup.x0, Ordering::Release);
    PIE_X1[index].store(startup.x1, Ordering::Release);
    NativeRole {
        role,
        actor,
        ttbr0_root: root_pa(index),
        private_rw: PrivateRegion {
            base: phys(b as u64),
            bytes: core::mem::size_of::<Backing>() as u64,
        },
        caps,
        control_ns_per_100ms: 2_000_000,
        cpu_mask: profile::CONTROL_MASK,
        thread_count: 1,
        endpoint_id,
    }
}
static PIE_ENTRY: [AtomicU64; ROLE_COUNT] = [const { AtomicU64::new(0) }; ROLE_COUNT];
static PIE_SP: [AtomicU64; ROLE_COUNT] = [const { AtomicU64::new(0) }; ROLE_COUNT];
static PIE_X0: [AtomicU64; ROLE_COUNT] = [const { AtomicU64::new(0) }; ROLE_COUNT];
static PIE_X1: [AtomicU64; ROLE_COUNT] = [const { AtomicU64::new(0) }; ROLE_COUNT];

pub(super) fn pie_context(index: usize) -> user::Context {
    let mut ctx = user::Context::empty();
    ctx.pc = PIE_ENTRY[index].load(Ordering::Acquire);
    ctx.sp = PIE_SP[index].load(Ordering::Acquire);
    ctx.regs[0] = PIE_X0[index].load(Ordering::Acquire);
    ctx.regs[1] = PIE_X1[index].load(Ordering::Acquire);
    ctx
}
#[cfg(feature = "v020-production-diagnostic")]
/// The sole accepted pointer range for a PIE role is its private stack.
pub(super) fn stack_span(index: usize, va: u64, n: usize, write: bool) -> Option<u64> {
    if n == 0 {
        return None;
    }
    let end = va.checked_add(n as u64)?;
    if va < STACK_BASE || end > STACK_END {
        return None;
    }
    let t = tables(index);
    let b = backing(index);
    let stack = unsafe { core::ptr::addr_of!((*b).stack) as u64 };
    let root = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*t).root.0[0])) };
    let mid = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*t).mid.0[0])) };
    if root != (phys(unsafe { core::ptr::addr_of!((*t).mid) } as u64) | 3)
        || mid != (phys(unsafe { core::ptr::addr_of!((*t).leaf) } as u64) | 3)
    {
        return None;
    }
    let mut cur = va;
    while cur < end {
        let page = cur & !4095;
        let owned = PhysAddr(phys(stack + page - STACK_BASE));
        let pte = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(
                (*t).leaf.0[(page / PAGE as u64) as usize]
            ))
        };
        let length = (end - cur).min(PAGE as u64 - (cur & 4095)) as usize;
        mmu::checked_user_leaf_span(pte, owned, cur & 4095, length, write).ok()?;
        cur += length as u64;
    }
    Some(stack + va - STACK_BASE)
}
