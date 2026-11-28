//! Boot-admitted ABI3 business contexts on the fixed business CPUs.
//!
//! CPU0 stages and seals the operator's signed immutable package once per
//! core. Publication hands each private context to exactly one secondary.
//! Closing the shared epoch denies new turns without discarding live grants.
//! Only a separately signed task group may create a child or map owned pages.
use super::super::{GATES, ONLINE, Page, fatal, signed_exec_trap};
use super::role_loader::{COPY_BUFFER, high_leaf, now_ns, sync_code, tlbi};
#[cfg(cyxia_resident_net)]
use super::{net_entropy::Entropy, network_worker};
use super::{recovery, startup_catalog};
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_arch_aarch64::{cpu, mmu, timer, user};
use cyxia_contracts::{BootInfo, PagePermissions, PhysAddr};
use cyxia_kernel_core::{
    control_plane::{
        Error, Identity, Plane,
        cpu0_v0199::{
            BUSINESS_MASK, BUSINESS_THREAD_ID_BASE, CONTROL_WINDOW_NS as WINDOW_NS,
            ONLINE as REQUIRED_ONLINE,
        },
        dispatch::Token,
        pie_image_v0199::{PieImage, ROLE_STACK_BYTES},
    },
    security::{
        Error as SvcError,
        durable_role_epoch_v0199::ConfirmedBootPolicy,
        offline_config_v1::VerifiedOfflineConfig,
        process::authorize_business_core,
        syscall::Syscall,
        syscall_v3::{
            ABI_VERSION, decode_aarch64_lifecycle_svc_v3, preflight_errno, stage_spawn_args,
        },
    },
};
use cyxia_prototype::domains::{
    ObjectKey,
    tasks::{CPU_BUDGET_NS, CpuLayout, RunState, Scheduler, ThreadSpec},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[cfg(cyxia_business_task_services)]
mod task_services;
#[cfg(cyxia_business_task_services)]
pub(super) use task_services::GROUP_CPU;

const BUSINESS_CORES: usize = 3;
const PAGE: usize = 4096;
const IMAGE_BYTES: usize = 64 * 1024;
const IMAGE_MIN: u64 = 0x0000_0001_0000_0000;
const STACK_MIN: u64 = 0x0000_0060_0000_0000;
const SLOT_BYTES: u64 = 2 * 1024 * 1024;
const SLOT_MASK: u64 = (1 << 13) - 1;
const CLOSED: u64 = u64::MAX;
const MAX_SLICE_NS: u64 = 2_000_000;
const EXIT_MARGIN_NS: u64 = 100_000;
// Signed task services reserve extra time within the same D01 charge for
// checked copies, synchronous page-table changes and dispatch settlement.
#[cfg(cyxia_business_task_services)]
const TASK_SERVICE_EXIT_MARGIN_NS: u64 = 500_000;
const HEADROOM_NS: u64 = 5_000_000;
const POLL_NS: u64 = 2_000_000;
const STARTUP_POLL_NS: u64 = 100_000_000;
const BUSINESS_FAULT: u64 = 0x5342_0001;
const PACKAGE: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/startup-catalog/business-package.elf"
));
const SIGNATURE: &[u8; 64] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/startup-catalog/business-package.sig"
));

pub(super) struct ApprovedPackage {
    config: [u8; 32],
    digest: [u8; 32],
    #[cfg(cyxia_business_task_services)]
    grant: task_services::Grant,
}

#[derive(Clone, Copy)]
pub(super) struct Layout {
    image: u64,
    stack_top: u64,
    #[cfg(cyxia_business_task_services)]
    child: Option<(u64, u64)>,
}

#[repr(C, align(4096))]
struct Backing {
    image: [u8; IMAGE_BYTES],
    stack: [u8; ROLE_STACK_BYTES],
    root: Page,
    image_middle: Page,
    stack_middle: Page,
    image_leaf: Page,
    stack_leaf: Page,
}

impl Backing {
    const ZERO: Self = Self {
        image: [0; IMAGE_BYTES],
        stack: [0; ROLE_STACK_BYTES],
        root: Page::ZERO,
        image_middle: Page::ZERO,
        stack_middle: Page::ZERO,
        image_leaf: Page::ZERO,
        stack_leaf: Page::ZERO,
    };
}

// All user backing is permanently registered by the linker arena inventory.
// CPU0 owns it through preparation. Only the appointed secondary acquires
// its context and retires its root after the release publication.
#[unsafe(link_section = ".bss.sec_n")]
static mut BACKING: [Backing; BUSINESS_CORES] = [const { Backing::ZERO }; BUSINESS_CORES];
static mut CONTEXTS: [user::Context; BUSINESS_CORES] =
    [const { user::Context::empty() }; BUSINESS_CORES];
static PREPARED: AtomicU64 = AtomicU64::new(0);
static PUBLISHED: AtomicU64 = AtomicU64::new(0);
static EPOCH: AtomicU64 = AtomicU64::new(0);
#[used]
#[unsafe(export_name = "V020_SIGNED_BUSINESS_RETIRED")]
static RETIRED: AtomicU64 = AtomicU64::new(0);
static ACTIVE: [AtomicU64; BUSINESS_CORES] = [const { AtomicU64::new(0) }; BUSINESS_CORES];
static IDLE_ARMED: [AtomicBool; BUSINESS_CORES] =
    [const { AtomicBool::new(false) }; BUSINESS_CORES];
static TURNS: [AtomicU64; BUSINESS_CORES] = [const { AtomicU64::new(0) }; BUSINESS_CORES];
static SCHEDULER_HELD: AtomicBool = AtomicBool::new(false);
static mut SCHEDULER: Scheduler = Scheduler::new();

pub(super) fn is_live_epoch(epoch: u64) -> bool {
    epoch != 0 && epoch != CLOSED && EPOCH.load(Ordering::Acquire) == epoch
}

#[cfg(cyxia_business_task_services)]
pub(super) fn is_group_child_identity(slot: usize, actor: Identity) -> bool {
    slot == GROUP_CPU
        && PUBLISHED.load(Ordering::Acquire) == actor.generation
        && task_services::is_child(actor)
}

pub(super) fn authorize(config: &VerifiedOfflineConfig<'_>) -> Result<ApprovedPackage, Error> {
    let digest = Sha256::digest(PACKAGE).into();
    startup_catalog::qualify_business_package(config, digest, SIGNATURE)
        .map_err(|_| Error::Denied)?;
    Ok(ApprovedPackage {
        config: config.digest(),
        digest,
        #[cfg(cyxia_business_task_services)]
        grant: task_services::qualify(config, digest)?,
    })
}

pub(super) fn addresses(
    info: &BootInfo,
    policy: &ConfirmedBootPolicy<'_>,
    #[cfg(cyxia_resident_net)] network_entropy: Option<&mut Entropy>,
    checkpoint: &mut impl FnMut() -> Result<(), SvcError>,
) -> Result<[Layout; BUSINESS_CORES], Error> {
    const LAYOUTS: usize = BUSINESS_CORES + cfg!(cyxia_business_task_services) as usize;
    let mut randomness = Zeroizing::new([0u8; LAYOUTS * 16]);
    let mut standalone = || {
        super::net_entropy::startup_aslr(info, policy.boot_epoch(), &mut randomness[..], || {
            checkpoint().map_err(|_| cyxia_driver_virtio::Error::Busy)
        })
    };
    #[cfg(cyxia_resident_net)]
    if let Some(entropy) = network_entropy {
        checkpoint().map_err(|_| Error::NotReady)?;
        entropy
            .fill_aslr(&mut randomness[..])
            .map_err(|_| Error::NotReady)?;
    } else {
        standalone().map_err(|_| Error::NotReady)?;
    }
    #[cfg(not(cyxia_resident_net))]
    standalone().map_err(|_| Error::NotReady)?;
    let limits = |index| {
        let offset = index * 16;
        let image = u64::from_le_bytes(randomness[offset..offset + 8].try_into().unwrap());
        let stack = u64::from_le_bytes(randomness[offset + 8..offset + 16].try_into().unwrap());
        // Nominating 8192 distinct 2 MiB bases keeps the entire PIE in the
        // architectural range. Separate entropy selects a disjoint stack table
        // and offset with room for its private guard page in the same table.
        (
            IMAGE_MIN + (image & SLOT_MASK) * SLOT_BYTES,
            STACK_MIN
                + (stack & SLOT_MASK) * SLOT_BYTES
                + ((stack >> 13 & 0xff) + 1) * PAGE as u64
                + ROLE_STACK_BYTES as u64,
        )
    };
    Ok(core::array::from_fn(|index| {
        let (image, stack_top) = limits(index);
        Layout {
            image,
            stack_top,
            #[cfg(cyxia_business_task_services)]
            child: (index + 1 == GROUP_CPU).then(|| limits(BUSINESS_CORES)),
        }
    }))
}

fn pa(ptr: *const u8) -> PhysAddr {
    PhysAddr(super::super::phys(ptr as u64))
}

// CPU0 is the single staging writer; each worker accesses only its appointed
// pinned record after publication. The pointer itself grants no ownership.
fn backing(index: usize) -> *mut Backing {
    // SAFETY: all callers prove `index < BUSINESS_CORES` before use.
    unsafe { addr_of_mut!(BACKING).cast::<Backing>().add(index) }
}

fn encode_tables(
    storage: *mut Backing,
    layout: Layout,
    image_flags: [u32; IMAGE_BYTES / PAGE],
) -> Result<u64, Error> {
    // SAFETY: this record is private to the CPU0 staging path. Descriptors
    // are not visible to an EL0 walker until the whole epoch is published.
    let (root, image_mid, stack_mid, image_l3, stack_l3, image, stack) = unsafe {
        (
            &mut (*storage).root.0,
            &mut (*storage).image_middle.0,
            &mut (*storage).stack_middle.0,
            &mut (*storage).image_leaf.0,
            &mut (*storage).stack_leaf.0,
            addr_of!((*storage).image).cast::<u8>(),
            addr_of!((*storage).stack).cast::<u8>(),
        )
    };
    let stack_va = layout.stack_top - ROLE_STACK_BYTES as u64;
    let top_index = |va: u64| (va >> 30 & 511) as usize;
    let middle_index = |va: u64| (va >> 21 & 511) as usize;
    let leaf_index = |va: u64| (va >> 12 & 511) as usize;
    let image_root_index = top_index(layout.image);
    let stack_root_index = top_index(stack_va);
    if image_root_index == stack_root_index || leaf_index(stack_va) == 0 {
        return Err(Error::Denied);
    }
    root[image_root_index] = pa(image_mid.as_ptr().cast()).0 | 3;
    root[stack_root_index] = pa(stack_mid.as_ptr().cast()).0 | 3;
    image_mid[middle_index(layout.image)] = pa(image_l3.as_ptr().cast()).0 | 3;
    stack_mid[middle_index(stack_va)] = pa(stack_l3.as_ptr().cast()).0 | 3;
    for (index, flags) in image_flags.into_iter().enumerate() {
        if flags == 0 {
            continue;
        }
        let address = image.wrapping_add(index * PAGE);
        if flags & 1 != 0 {
            sync_code(address as u64, PAGE);
        }
        install_page(
            &mut image_l3[index],
            pa(address),
            flags & 2 != 0,
            flags & 1 != 0,
        )?;
    }
    for i in 0..ROLE_STACK_BYTES / PAGE {
        install_page(
            &mut stack_l3[leaf_index(stack_va) + i],
            pa(stack.wrapping_add(i * PAGE)),
            true,
            false,
        )?;
    }
    tlbi();
    Ok(pa(root.as_ptr().cast()).0)
}

fn install_page(slot: &mut u64, frame: PhysAddr, write: bool, exec: bool) -> Result<(), Error> {
    let permissions = PagePermissions::new(write, exec).map_err(|_| Error::Denied)?;
    let leaf = high_leaf(frame.0);
    let direct = |writable| {
        let p = PagePermissions::new(writable, false).map_err(|_| Error::Denied)?;
        mmu::encode_leaf(frame, p, mmu::MemoryAttr::Normal).map_err(|_| Error::Denied)
    };
    // SAFETY: the loader exclusively owns the page until publication and
    // has already synchronized any instruction bytes to the point of unification.
    // Clearing the direct alias and its stale translation precedes any break to RO.
    let old = unsafe { leaf.read_volatile() };
    if old != direct(true)? || *slot != 0 {
        return Err(Error::Denied);
    }
    unsafe { leaf.write_volatile(0) };
    if !write {
        tlbi();
        unsafe { leaf.write_volatile(direct(false)?) };
    }
    *slot = mmu::encode_user_leaf(frame, write, exec).map_err(|_| Error::Denied)?;
    mmu::checked_private_role_leaf(frame, permissions, *slot, unsafe { leaf.read_volatile() })
        .map_err(|_| Error::Denied)
}

fn stage_package(
    storage: *mut Backing,
    package: &ApprovedPackage,
    layout: Layout,
    args: &[u8],
) -> Result<user::Context, Error> {
    // SAFETY: boot's serial CPU0 loader owns this registered scratch buffer.
    let scratch = unsafe { &mut *addr_of_mut!(COPY_BUFFER.0) };
    scratch[..PACKAGE.len()].copy_from_slice(PACKAGE);
    let result = (|| {
        let pie = PieImage::parse_verified(&scratch[..PACKAGE.len()], package.digest)?;
        // This profile only accepts statically self-relative packages. No
        // unbound relocations, dynamic symbols or loaders are consumed.
        let mut flags = [0u32; IMAGE_BYTES / PAGE];
        // SAFETY: CPU0 has the only access to this unpublished record.
        let image = unsafe { &mut *addr_of_mut!((*storage).image) };
        pie.stage_private_image(
            image,
            layout.image,
            layout.image,
            layout.image + IMAGE_BYTES as u64,
            &[],
        )?;
        for segment in pie.loads[..pie.load_count].iter().flatten() {
            let start = (segment.virtual_address / PAGE as u64) as usize;
            let end =
                (segment.virtual_address + segment.memory_bytes).div_ceil(PAGE as u64) as usize;
            flags[start..end].fill(segment.flags);
        }
        if let Some((start, bytes)) = pie.relro {
            let end = (start + bytes).div_ceil(PAGE as u64) as usize;
            flags[(start / PAGE as u64) as usize..end].fill(4);
        }
        let stack = unsafe { &mut *addr_of_mut!((*storage).stack) };
        let stack = stage_spawn_args(stack, layout.stack_top - ROLE_STACK_BYTES as u64, args)
            .map_err(|_| Error::Invalid)?;
        let mut context = user::Context::empty();
        context.pc = layout.image + pie.entry;
        context.sp = stack.sp;
        context.regs[0] = stack.x0;
        context.regs[1] = stack.x1;
        encode_tables(storage, layout, flags)?;
        Ok(context)
    })();
    scratch.fill(0);
    result
}

fn layout(epoch: u64) -> CpuLayout {
    CpuLayout {
        business_mask: BUSINESS_MASK,
        healthy_mask: ONLINE.load(Ordering::Acquire),
        generation: epoch,
    }
}

fn thread(cpu: usize, epoch: u64) -> ObjectKey {
    // The ordinary business namespace is distinct from privileged role ids.
    ObjectKey {
        id: BUSINESS_THREAD_ID_BASE + cpu as u64,
        generation: epoch,
    }
}

pub(super) fn try_scheduler<T>(access: impl FnOnce(&mut Scheduler) -> T) -> Option<T> {
    if SCHEDULER_HELD
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return None;
    }
    // SAFETY: the lock is acquired only in foreground code. An IRQ never
    // reenters it and no closure retains an address into the scheduler.
    let result = access(unsafe { &mut *addr_of_mut!(SCHEDULER) });
    SCHEDULER_HELD.store(false, Ordering::Release);
    Some(result)
}

pub(super) fn prepare(
    policy: &ConfirmedBootPolicy<'_>,
    package: &ApprovedPackage,
    slot: usize,
    addresses: Layout,
) -> Result<(), Error> {
    let epoch = policy.boot_epoch();
    if cpu::slot() != 0
        || !(1..=BUSINESS_CORES).contains(&slot)
        || epoch == CLOSED
        || !policy.matches_config_digest(package.config)
        || EPOCH.load(Ordering::Acquire) != 0
    {
        return Err(Error::Denied);
    }
    let bit = 1 << slot;
    let placement = layout(epoch);
    authorize_business_core(
        slot as u16,
        epoch,
        placement.business_mask,
        placement.healthy_mask,
        0,
        0,
    )
    .map_err(|_| Error::Denied)?;
    if PREPARED.load(Ordering::Acquire) & bit != 0 {
        return Err(Error::Stale);
    }
    let storage = backing(slot - 1);
    let args = &[][..];
    #[cfg(cyxia_business_task_services)]
    let bootstrap;
    #[cfg(cyxia_business_task_services)]
    let args = if slot == GROUP_CPU {
        bootstrap = package.grant.bootstrap(epoch)?;
        &bootstrap[..]
    } else {
        args
    };
    let context = stage_package(storage, package, addresses, args)?;
    let ordinary_group = ObjectKey {
        id: BUSINESS_THREAD_ID_BASE,
        generation: epoch,
    };
    let group = ordinary_group;
    #[cfg(cyxia_business_task_services)]
    let group = if slot == GROUP_CPU {
        task_services::prepare(policy, package.grant, addresses, storage)?;
        package.grant.group(epoch)
    } else {
        group
    };
    let budget_ns = CPU_BUDGET_NS;
    #[cfg(cyxia_resident_net)]
    let budget_ns = if slot == network_worker::CPU && network_worker::staged(epoch) {
        budget_ns - network_worker::BUDGET_NS
    } else {
        budget_ns
    };
    #[cfg(cyxia_business_task_services)]
    let budget_ns = if slot == GROUP_CPU {
        budget_ns - package.grant.child_budget_ns
    } else {
        budget_ns
    };
    try_scheduler(|scheduler| {
        if PREPARED.load(Ordering::Relaxed) == 0 {
            scheduler.register_group(ordinary_group)?;
        }
        if group != ordinary_group {
            scheduler.register_group(group)?;
        }
        scheduler.admit(
            ThreadSpec {
                key: thread(slot, epoch),
                group,
                cpu: slot as u16,
                allowed_mask: bit,
                minimum_ns: 0,
                budget_ns,
            },
            placement,
            now_ns(),
        )
    })
    .ok_or(Error::Busy)?
    .map_err(|_| Error::Denied)?;
    // SAFETY: CPU0 is the only writer before the epoch is opened.
    unsafe {
        addr_of_mut!(CONTEXTS)
            .cast::<user::Context>()
            .add(slot - 1)
            .write(context)
    };
    PREPARED.fetch_or(bit, Ordering::Release);
    Ok(())
}

#[cfg(cyxia_business_task_services)]
pub(super) fn prepare_group_child(
    policy: &ConfirmedBootPolicy<'_>,
    package: &ApprovedPackage,
) -> Result<(), Error> {
    task_services::prepare_child(policy, package)
}

pub(super) fn open(policy: &ConfirmedBootPolicy<'_>) -> Result<u64, Error> {
    let epoch = policy.boot_epoch();
    if cpu::slot() != 0
        || epoch == 0
        || epoch == CLOSED
        || ONLINE.load(Ordering::Acquire) != REQUIRED_ONLINE
        || PREPARED.load(Ordering::Acquire) != BUSINESS_MASK
        || EPOCH.load(Ordering::Acquire) != 0
    {
        return Err(Error::Denied);
    }
    #[cfg(cyxia_business_task_services)]
    if !task_services::prepared(epoch) {
        return Err(Error::Denied);
    }
    let token = Token {
        generation: epoch,
        plane: Plane::Business,
    };
    #[cfg(cyxia_resident_net)]
    if network_worker::staged(epoch) {
        try_scheduler(|scheduler| network_worker::admit(scheduler, layout(epoch)))
            .ok_or(Error::Busy)??;
    }
    for gate in &GATES[1..=BUSINESS_CORES] {
        gate.open(token)?;
    }
    // The shared handoff is after all roots, scheduler admissions and target
    // gates have been published. No secondary can observe a partial roster.
    #[cfg(cyxia_resident_net)]
    network_worker::publish(epoch);
    PUBLISHED.store(epoch, Ordering::Relaxed);
    EPOCH.store(epoch, Ordering::Release);
    Ok(BUSINESS_MASK)
}

pub(super) fn close() {
    #[cfg(cyxia_resident_net)]
    network_worker::close();
    // EPOCH is rechecked after acquiring each individual gate. A grant that
    // entered before this store still owns its exact completion and pages.
    let epoch = EPOCH.swap(CLOSED, Ordering::AcqRel);
    if epoch == 0 || epoch == CLOSED {
        return;
    }
    let token = Token {
        generation: epoch,
        plane: Plane::Business,
    };
    for gate in &GATES[1..=BUSINESS_CORES] {
        // At most one already-selected dispatch may race the close on this
        // core. Its entry and return are each a potential CAS collision.
        for _ in 0..3 {
            if gate.close(token) != Err(Error::Busy) {
                break;
            }
        }
    }
}

pub(super) fn progress() -> [u64; BUSINESS_CORES] {
    core::array::from_fn(|i| TURNS[i].load(Ordering::Acquire))
}

pub(crate) fn verify_captured_root(slot: usize) {
    let expected = ACTIVE[slot - 1].swap(0, Ordering::AcqRel);
    if expected == 0 || expected != user::captured_user_root() {
        fatal(BUSINESS_FAULT);
    }
}

fn park() -> ! {
    // SAFETY: per-CPU vector and GIC interface are already installed.
    unsafe { timer::enable_irqs() };
    loop {
        timer::idle()
    }
}

fn sleep_until(deadline_ns: u64) {
    let ticks = (u128::from(deadline_ns) * u128::from(timer::frequency())).div_ceil(1_000_000_000);
    if let Ok(deadline) = u64::try_from(ticks) {
        let armed = &IDLE_ARMED[cpu::slot() - 1];
        armed.store(true, Ordering::Relaxed);
        // SAFETY: the work loop owns the private timer and runs no task here.
        unsafe {
            timer::arm(deadline);
            timer::enable_irqs();
        }
        timer::idle();
        // A periodic EL1 rearm makes the WFI safe even if the first tick
        // is delivered just before the idle instruction. Mask it before
        // disabling the timer and before any following EL0 transition.
        unsafe {
            core::arch::asm!(
                "msr daifset, #2",
                "isb",
                options(nomem, nostack, preserves_flags)
            );
            cpu::disable_timer();
        }
        armed.store(false, Ordering::Relaxed);
    }
}

/// The SMP PPI handler re-arms a secondary's idle wait. EL0 return never
/// rearms its slice. The worker masks and disables the idle timer before entry.
pub(crate) fn rearm_idle_timer(slot: usize) {
    if IDLE_ARMED[slot - 1].load(Ordering::Relaxed) {
        let interval = timer::frequency().div_ceil(500).max(1);
        // SAFETY: this is the same CPU's acknowledged private timer IRQ.
        unsafe { timer::arm(timer::ticks().saturating_add(interval)) };
    }
}

fn poll_later() {
    sleep_until(now_ns().saturating_add(POLL_NS));
}

fn invalidate_user_asid(asid: u8) {
    let operand = u64::from(asid) << 48;
    // SAFETY: these ASIDs were uniquely reserved for the pinned business
    // contexts. The completion barriers cover all PEs before backing reuse.
    unsafe {
        core::arch::asm!(
            "dsb ishst", "tlbi aside1is, {}", "dsb ish", "isb",
            in(reg) operand, options(nostack, preserves_flags),
        );
    }
}

fn retire(
    slot: usize,
    task: ObjectKey,
    storage: *mut Backing,
    context: &mut user::Context,
    #[cfg(cyxia_business_task_services)] group: &mut Option<&mut task_services::Group>,
) -> ! {
    #[cfg(cyxia_business_task_services)]
    if let Some(group) = group {
        group.retire();
    }
    // SAFETY: the sole owner has returned to EL1. This root and ASID are
    // never used again; there are no protected async calls. The scheduler
    // still owns any unanswered receipt independently from this root.
    unsafe { addr_of_mut!((*storage).root).write_volatile(Page::ZERO) };
    invalidate_user_asid(0xB0 + slot as u8);
    *context = user::Context::empty();
    loop {
        if let Some(result) = try_scheduler(|scheduler| scheduler.remove(task)) {
            if result.is_ok() {
                RETIRED.fetch_or(1 << slot, Ordering::Release);
            }
            break;
        }
        poll_later();
    }
    recovery::stop_business_writer();
    #[cfg(cyxia_resident_net)]
    if slot == network_worker::CPU {
        network_worker::after_business_exit();
    }
    park()
}

fn enter(
    index: usize,
    context: &mut user::Context,
    root: u64,
    asid: u8,
    exec: signed_exec_trap::Execution,
    deadline: u64,
) -> signed_exec_trap::Return {
    context.kind = 0;
    ACTIVE[index].store(root | u64::from(asid) << 48, Ordering::Release);
    // SAFETY: this is the pinned, uniquely assigned address space and
    // ASID. The interrupt bounds the outstanding dispatch grant.
    unsafe {
        timer::arm(deadline);
        user::enter_pinned_until_retired(context, root, asid);
        cpu::disable_timer();
    }
    if ACTIVE[index].swap(0, Ordering::AcqRel) != 0 || context.kind == 0 {
        fatal(BUSINESS_FAULT);
    }
    exec.handle_return(context)
}

pub(crate) fn worker(slot: usize) -> ! {
    assert!((1..=BUSINESS_CORES).contains(&slot) && cpu::slot() == slot);
    // SAFETY: this registered secondary alone initializes its PMU counter.
    unsafe { timer::init_cpu_accounting() };
    let epoch = loop {
        match EPOCH.load(Ordering::Acquire) {
            0 => sleep_until(now_ns().saturating_add(STARTUP_POLL_NS)),
            CLOSED => match PUBLISHED.load(Ordering::Acquire) {
                0 => {
                    #[cfg(cyxia_resident_net)]
                    if slot == network_worker::CPU {
                        network_worker::retire_owned();
                    }
                    park()
                }
                retired_epoch => break retired_epoch,
            },
            epoch => break epoch,
        }
    };
    let index = slot - 1;
    let storage = backing(index);
    // SAFETY: the epoch publication handed this secondary its private context.
    let context = unsafe { &mut *addr_of_mut!(CONTEXTS).cast::<user::Context>().add(index) };
    let root = pa(unsafe { addr_of!((*storage).root).cast() }).0;
    let asid = 0xB0 + slot as u8;
    let token = Token {
        generation: epoch,
        plane: Plane::Business,
    };
    let thread = thread(slot, epoch);
    #[cfg(cyxia_business_task_services)]
    let mut group = task_services::take(slot, epoch);
    let exit_margin = EXIT_MARGIN_NS;
    #[cfg(cyxia_business_task_services)]
    let exit_margin = if group.is_some() {
        TASK_SERVICE_EXIT_MARGIN_NS
    } else {
        exit_margin
    };
    if EPOCH.load(Ordering::Acquire) != epoch {
        retire(
            slot,
            thread,
            storage,
            context,
            #[cfg(cyxia_business_task_services)]
            &mut group,
        );
    }
    let exec = signed_exec_trap::Execution::configure().unwrap_or_else(|| fatal(BUSINESS_FAULT));
    let mut sleeping_until = None;
    loop {
        if EPOCH.load(Ordering::Acquire) != epoch {
            retire(
                slot,
                thread,
                storage,
                context,
                #[cfg(cyxia_business_task_services)]
                &mut group,
            );
        }
        #[cfg(cyxia_business_task_services)]
        if let Some(group) = group.as_mut() {
            group.wake();
        }
        let start_ns = now_ns();
        if let Some(wake_ns) = sleeping_until {
            if start_ns < wake_ns {
                #[cfg(cyxia_resident_net)]
                let network_ready = network_worker::running_on(slot, epoch);
                #[cfg(not(cyxia_resident_net))]
                let network_ready = false;
                let other_ready = network_ready;
                #[cfg(cyxia_business_task_services)]
                let other_ready =
                    other_ready || group.as_ref().is_some_and(|group| group.has_child());
                if !other_ready {
                    sleep_until(wake_ns.min(start_ns.saturating_add(POLL_NS)));
                    continue;
                }
            } else {
                match try_scheduler(|scheduler| scheduler.set_runnable(thread, true, now_ns())) {
                    Some(Ok(())) => sleeping_until = None,
                    Some(Err(_)) => fatal(BUSINESS_FAULT),
                    None => {
                        poll_later();
                        continue;
                    }
                }
            }
        }
        let Ok(permit) = GATES[slot].try_enter(token) else {
            poll_later();
            continue;
        };
        if EPOCH.load(Ordering::Acquire) != epoch {
            drop(permit);
            retire(
                slot,
                thread,
                storage,
                context,
                #[cfg(cyxia_business_task_services)]
                &mut group,
            );
        }
        let placement = layout(epoch);
        let started = timer::cpu_ticks();
        let dispatched = try_scheduler(|scheduler| {
            let dispatch = scheduler.dispatch_with_window_headroom(
                slot,
                placement,
                now_ns(),
                MAX_SLICE_NS,
                HEADROOM_NS,
            )?;
            #[cfg(cyxia_resident_net)]
            let dispatch = dispatch.map(|grant| {
                if grant.thread == network_worker::thread(epoch)
                    && grant.reserved_ns == MAX_SLICE_NS
                {
                    scheduler
                        .resize_dispatch(grant, network_worker::MAX_SLICE_NS)
                        .unwrap_or(grant)
                } else {
                    grant
                }
            });
            if let Some(grant) = dispatch
                && grant.reserved_ns <= exit_margin
            {
                scheduler.cancel_unstarted(grant, now_ns())?;
                return Ok::<_, cyxia_prototype::domains::Error>(None);
            }
            Ok(dispatch)
        });
        let Some(Ok(Some(dispatch))) = dispatched else {
            drop(permit);
            if matches!(dispatched, Some(Err(_))) {
                retire(
                    slot,
                    thread,
                    storage,
                    context,
                    #[cfg(cyxia_business_task_services)]
                    &mut group,
                );
            }
            poll_later();
            continue;
        };
        #[cfg(cyxia_resident_net)]
        if dispatch.thread == network_worker::thread(epoch) {
            let state = network_worker::advance(dispatch, started);
            let settled = loop {
                if let Some(result) = try_scheduler(|scheduler| {
                    scheduler.complete(dispatch, timer::cpu_elapsed_ns(started), state, now_ns())
                }) {
                    break result;
                }
                core::hint::spin_loop();
            };
            drop(permit);
            if settled.is_err() {
                network_worker::close();
                retire(
                    slot,
                    thread,
                    storage,
                    context,
                    #[cfg(cyxia_business_task_services)]
                    &mut group,
                );
            }
            if state == RunState::Exited {
                network_worker::retire_owned();
            }
            continue;
        }
        #[cfg(cyxia_business_task_services)]
        if dispatch.thread == thread
            && EPOCH.load(Ordering::Acquire) == epoch
            && let Some(group) = group.as_mut()
        {
            group.finish_join(context);
        }
        let remaining = dispatch
            .reserved_ns
            .saturating_sub(exit_margin)
            .saturating_sub(timer::cpu_elapsed_ns(started));
        let now = now_ns();
        let latest = (dispatch.started_ns - dispatch.started_ns % WINDOW_NS)
            .saturating_add(WINDOW_NS)
            .saturating_sub(exit_margin);
        let wall = remaining.min(latest.saturating_sub(now));
        let deadline =
            (u128::from(now.saturating_add(wall)) * u128::from(timer::frequency())) / 1_000_000_000;
        let entered = wall != 0 && EPOCH.load(Ordering::Acquire) == epoch;
        let mut failed = false;
        #[cfg(cyxia_business_task_services)]
        let mut child_exit = 0;
        let next = 'turn: {
            if !entered {
                break 'turn RunState::Runnable;
            }
            let deadline = u64::try_from(deadline).unwrap_or_else(|_| fatal(BUSINESS_FAULT));
            #[cfg(cyxia_business_task_services)]
            if dispatch.thread != thread {
                let group = group
                    .as_mut()
                    .filter(|group| group.child_key() == dispatch.thread)
                    .unwrap_or_else(|| fatal(BUSINESS_FAULT));
                let (state, code) = group.drive_child(exec, deadline);
                child_exit = code;
                break 'turn state;
            }
            match enter(index, context, root, asid, exec, deadline) {
                signed_exec_trap::Return::Timer
                | signed_exec_trap::Return::Yield
                | signed_exec_trap::Return::Emulated => RunState::Runnable,
                signed_exec_trap::Return::TerminateTask => {
                    #[cfg(cyxia_business_task_services)]
                    if group.as_mut().is_some_and(|group| group.fault(context)) {
                        break 'turn RunState::Runnable;
                    }
                    let actor = Identity {
                        id: thread.id,
                        generation: thread.generation,
                    };
                    recovery::record_business_failure(actor, context.esr, context.far)
                        .unwrap_or_else(|_| fatal(BUSINESS_FAULT));
                    failed = true;
                    RunState::Exited
                }
                signed_exec_trap::Return::FailStop => fatal(BUSINESS_FAULT),
                signed_exec_trap::Return::Syscall => {
                    #[cfg(cyxia_business_task_services)]
                    if let Some(group) = group.as_mut() {
                        break 'turn group.syscall(context, &mut sleeping_until);
                    }
                    lifecycle_syscall(context, &mut sleeping_until)
                }
            }
        };
        let settled = loop {
            if let Some(settled) = try_scheduler(|scheduler| {
                let cost = timer::cpu_elapsed_ns(started);
                scheduler.complete(dispatch, cost, next, now_ns())
            }) {
                break settled;
            }
            poll_later();
        };
        drop(permit);
        if settled.is_err() {
            retire(
                slot,
                thread,
                storage,
                context,
                #[cfg(cyxia_business_task_services)]
                &mut group,
            );
        }
        if entered && !failed && dispatch.thread == thread {
            let _ = TURNS[index].fetch_update(Ordering::Release, Ordering::Relaxed, |turns| {
                turns.checked_add(1)
            });
        }
        if next == RunState::Exited {
            #[cfg(cyxia_business_task_services)]
            if dispatch.thread != thread {
                group
                    .as_mut()
                    .unwrap_or_else(|| fatal(BUSINESS_FAULT))
                    .retire_child(child_exit);
                continue;
            }
            retire(
                slot,
                thread,
                storage,
                context,
                #[cfg(cyxia_business_task_services)]
                &mut group,
            );
        }
    }
}

fn lifecycle_syscall(context: &mut user::Context, sleeping_until: &mut Option<u64>) -> RunState {
    let call = match decode_aarch64_lifecycle_svc_v3(ABI_VERSION, context.esr, &context.regs) {
        Ok(call) => call,
        Err(error) => {
            context.regs[0] = preflight_errno(error) as u64;
            return RunState::Runnable;
        }
    };
    lifecycle_call(context, sleeping_until, call)
}

fn lifecycle_call(
    context: &mut user::Context,
    sleeping_until: &mut Option<u64>,
    call: cyxia_kernel_core::security::syscall_v3::ValidatedCall,
) -> RunState {
    context.regs[0] = 0;
    match call.operation {
        Syscall::Exit => return RunState::Exited,
        Syscall::Clock => context.regs[0] = now_ns().min(i64::MAX as u64),
        Syscall::Sleep if call.args[0] > now_ns() => {
            *sleeping_until = Some(call.args[0]);
            return RunState::Blocked;
        }
        _ => (),
    }
    RunState::Runnable
}
