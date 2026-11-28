//! An independently approved ABI3 FILE_SERVICE process on a business core.

use super::{
    Backing, CPU_BUDGET_NS, Error, Identity, Layout, ObjectKey, PAGE, ROLE_STACK_BYTES, RunState,
    ThreadSpec, VerifiedOfflineConfig, addr_of, addr_of_mut, cpu, enter, high_leaf,
    invalidate_user_asid, layout, lifecycle_call, mmu, now_ns, pa, poll_later, signed_exec_trap,
    stage_isolated_pie, startup_catalog, try_scheduler, user,
};
use core::{
    mem::MaybeUninit,
    sync::atomic::{AtomicU64, Ordering},
};
use cyxia_contracts::{PagePermissions, PhysAddr};
use cyxia_kernel_core::security::{
    durable_role_epoch_v0199::ConfirmedBootPolicy,
    file_auth_v3::{
        ADMIT_REPLY_BYTES, ADMIT_REQUEST_BYTES, AdmitRequestV3, COMPLETE_REPLY_BYTES,
        COMPLETE_REQUEST_BYTES, CompleteRequestV1, E_SCHEMA, FILE_SERVICE_ROLE,
    },
    startup_catalog_v0199::file_owner::{BYTES, FileOwnerGrant},
    syscall::Syscall,
    syscall_v3::{ABI_VERSION, decode_aarch64_authorized_svc_v3, preflight_errno},
};
use sha2::{Digest, Sha256};

pub(super) use cyxia_kernel_core::security::startup_catalog_v0199::file_owner::CPU;

#[cfg(cyxia_file_read_client)]
pub(super) mod client_read;
#[cfg(cyxia_file_read_client)]
pub(super) mod durable;

const ASID: u8 = 0xB5;
const AUTH_TAG: u64 = 0xf200;
pub(super) const EXIT_MARGIN_NS: u64 = 500_000;
const PACKAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/startup-catalog/file-owner.elf"));
const GRANT: &[u8; BYTES] =
    include_bytes!(concat!(env!("OUT_DIR"), "/startup-catalog/file-owner.bin"));
const SIGNATURE: &[u8; 64] =
    include_bytes!(concat!(env!("OUT_DIR"), "/startup-catalog/file-owner.sig"));

pub(super) struct ApprovedPackage {
    config: [u8; 32],
    image: [u8; 32],
    grant: FileOwnerGrant,
}

impl ApprovedPackage {
    pub(super) fn budget_ns(&self) -> u64 {
        self.grant.budget_ns
    }

    #[cfg(cyxia_file_read_client)]
    pub(super) fn image_digest(&self) -> [u8; 32] {
        self.image
    }
}

pub(super) fn qualify(config: &VerifiedOfflineConfig<'_>) -> Result<ApprovedPackage, Error> {
    let image = Sha256::digest(PACKAGE).into();
    let grant = startup_catalog::qualify_file_owner(config, image, GRANT, SIGNATURE)
        .map_err(|_| Error::Denied)?;
    // Leave at least one full normal dispatch credit for each colocated task.
    if !(super::MAX_SLICE_NS..=CPU_BUDGET_NS - super::MAX_SLICE_NS).contains(&grant.budget_ns) {
        return Err(Error::Denied);
    }
    Ok(ApprovedPackage {
        config: config.digest(),
        image,
        grant,
    })
}

struct Owner {
    actor: Identity,
    window: Layout,
    root: u64,
    selector: u64,
    context: user::Context,
    sleeping_until: Option<u64>,
}

#[unsafe(link_section = ".bss.sec_n")]
static mut BACKING: Backing = Backing::ZERO;
static mut OWNER: MaybeUninit<Owner> = MaybeUninit::uninit();
static PREPARED: AtomicU64 = AtomicU64::new(0);
static LIVE: AtomicU64 = AtomicU64::new(0);

/// Boot, role, generation, verified root/ASID, accepted transport frames
/// without pending authority, and final retire status. All fields describe
/// observations made by the native scheduler or syscall adapter.
#[unsafe(export_name = "V020_SIGNED_FILE_OWNER_EVIDENCE")]
static EVIDENCE: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];

fn backing() -> *mut Backing {
    addr_of_mut!(BACKING)
}

pub(super) fn prepare(
    policy: &ConfirmedBootPolicy<'_>,
    package: &ApprovedPackage,
    window: Layout,
) -> Result<(), Error> {
    let epoch = policy.boot_epoch();
    let selector = epoch.checked_mul(1 << 16).ok_or(Error::Exhausted)? | AUTH_TAG;
    if cpu::registered_slot() != Some(0)
        || epoch == 0
        || PREPARED.load(Ordering::Acquire) != 0
        || !policy.matches_config_digest(package.config)
    {
        return Err(Error::Denied);
    }
    let generation = policy
        .file_service_generation()
        .map_err(|_| Error::Denied)?;
    let actor = Identity {
        id: FILE_SERVICE_ROLE,
        generation,
    };
    let mut args = [0; 24];
    args[..8].copy_from_slice(&epoch.to_le_bytes());
    args[8..16].copy_from_slice(&generation.to_le_bytes());
    args[16..].copy_from_slice(&selector.to_le_bytes());
    let context = stage_isolated_pie(backing(), PACKAGE, package.image, window, &args)?;
    let root = pa(unsafe { addr_of!((*backing()).root).cast() }).0;
    let key = ObjectKey {
        id: actor.id,
        generation,
    };
    try_scheduler(|scheduler| {
        scheduler.register_group(key)?;
        scheduler.admit(
            ThreadSpec {
                key,
                group: key,
                cpu: CPU as u16,
                allowed_mask: 1 << CPU,
                minimum_ns: 0,
                budget_ns: package.budget_ns(),
            },
            layout(epoch),
            now_ns(),
        )
    })
    .ok_or(Error::Busy)?
    .map_err(|_| Error::Denied)?;
    #[cfg(cyxia_file_read_client)]
    client_read::bind_owner(epoch, actor)?;
    // SAFETY: CPU0 writes this owner once before opening the business epoch.
    unsafe {
        (*addr_of_mut!(OWNER)).write(Owner {
            actor,
            window,
            root,
            selector,
            context,
            sleeping_until: None,
        })
    };
    PREPARED.store(epoch, Ordering::Release);
    Ok(())
}

pub(super) fn prepared(epoch: u64) -> bool {
    epoch != 0 && PREPARED.load(Ordering::Acquire) == epoch
}

pub(super) fn active(epoch: u64) -> bool {
    epoch != 0 && LIVE.load(Ordering::Acquire) == epoch
}

fn with_owner<T>(slot: usize, epoch: u64, work: impl FnOnce(&mut Owner) -> T) -> Option<T> {
    if slot != CPU || cpu::registered_slot() != Some(CPU) || !prepared(epoch) {
        return None;
    }
    // SAFETY: after opening the business epoch only the assigned secondary
    // can enter these non-reentrant scheduler operations.
    Some(work(unsafe { (*addr_of_mut!(OWNER)).assume_init_mut() }))
}

impl Owner {
    fn key(&self) -> ObjectKey {
        ObjectKey {
            id: self.actor.id,
            generation: self.actor.generation,
        }
    }

    fn stack(&self) -> StoppedStack {
        StoppedStack::new(
            backing(),
            self.window.stack_top,
            self.root,
            self.actor,
            ASID,
        )
    }
}

/// Exact private stack registration for a pinned task. Both file endpoints
/// use this only while that task is stopped on CPU3.
#[derive(Clone, Copy)]
pub(super) struct StoppedStack {
    storage: *mut Backing,
    top: u64,
    root: u64,
    actor: Identity,
    asid: u8,
}

impl StoppedStack {
    pub(super) const fn new(
        storage: *mut Backing,
        top: u64,
        root: u64,
        actor: Identity,
        asid: u8,
    ) -> Self {
        Self {
            storage,
            top,
            root,
            actor,
            asid,
        }
    }

    fn visit_stack(
        &self,
        address: u64,
        bytes: usize,
        mut visit: impl FnMut(u64, usize, usize) -> Result<(), i64>,
    ) -> Result<(), i64> {
        use super::super::EFAULT;
        let base = self.top - ROLE_STACK_BYTES as u64;
        if bytes == 0
            || address < base
            || address
                .checked_add(bytes as u64)
                .is_none_or(|end| end > self.top)
        {
            return Err(EFAULT);
        }
        let store = self.storage;
        // SAFETY: the current worker owns its stopped context and these
        // pinned tables. EL0 cannot write any table or change either root.
        let (upper, lower, middle, leaf, stack) = unsafe {
            let middle = addr_of!((*store).stack_middle);
            let leaf = addr_of!((*store).stack_leaf);
            (
                addr_of!((*store).root.0[(base >> 30 & 511) as usize]).read_volatile(),
                addr_of!((*middle).0[(base >> 21 & 511) as usize]).read_volatile(),
                middle,
                leaf,
                addr_of!((*store).stack).cast::<u8>(),
            )
        };
        if self.root != pa(unsafe { addr_of!((*store).root).cast() }).0
            || upper != pa(middle.cast()).0 | 3
            || lower != pa(leaf.cast()).0 | 3
        {
            return Err(EFAULT);
        }
        let permissions = PagePermissions::new(true, false).map_err(|_| EFAULT)?;
        let mut done = 0;
        while done < bytes {
            let va = address + done as u64;
            let offset = (va - base) as usize;
            let phys = pa(stack.wrapping_add(offset)).0;
            let page = PhysAddr(phys & !(PAGE as u64 - 1));
            let len = (PAGE - (offset % PAGE)).min(bytes - done);
            let (entry, alias) = unsafe {
                (
                    addr_of!((*leaf).0[(va >> 12 & 511) as usize]).read_volatile(),
                    high_leaf(page.0).read_volatile(),
                )
            };
            mmu::checked_private_role_leaf(page, permissions, entry, alias).map_err(|_| EFAULT)?;
            visit(phys, done, len)?;
            done += len;
        }
        Ok(())
    }

    fn copy_in(&self, address: u64, bytes: &mut [u8]) -> Result<(), i64> {
        self.visit_stack(address, bytes.len(), |phys, at, len| {
            // SAFETY: visit_stack verified the pinned mapping and the
            // scheduler held the single writer stopped on this core.
            unsafe {
                crate::machine::copy_window::copy_in(
                    phys,
                    self.actor,
                    self.asid,
                    &mut bytes[at..at + len],
                )
            }
            .map_err(|_| super::super::EFAULT)
        })
    }

    #[cfg(cyxia_file_read_client)]
    fn copy_out(&self, address: u64, bytes: &[u8]) -> Result<(), i64> {
        self.visit_stack(address, bytes.len(), |phys, at, len| {
            // SAFETY: same stopped, pinned stack and disjoint EL1 buffer.
            match unsafe {
                crate::machine::copy_window::copy_out_and_check(
                    phys,
                    self.actor,
                    self.asid,
                    &bytes[at..at + len],
                )
            } {
                Ok(true) => Ok(()),
                _ => Err(super::super::EFAULT),
            }
        })
    }
}

impl Owner {
    fn file_auth(&self, epoch: u64, args: [u64; 6]) -> Result<(), i64> {
        use super::super::{E_AUTH, EFAULT};
        let [_, input, bytes, selector, output, capacity] = args;
        if selector != 0 {
            return Err(E_AUTH);
        }
        let bytes = usize::try_from(bytes).map_err(|_| i64::from(E_SCHEMA))?;
        let reply_bytes = match bytes {
            ADMIT_REQUEST_BYTES => ADMIT_REPLY_BYTES,
            COMPLETE_REQUEST_BYTES => COMPLETE_REPLY_BYTES,
            _ => return Err(i64::from(E_SCHEMA)),
        };
        let capacity = usize::try_from(capacity).map_err(|_| EFAULT)?;
        if capacity < reply_bytes {
            return Err(EFAULT);
        }
        let stack = self.stack();
        stack.visit_stack(output, capacity, |_, _, _| Ok(()))?;
        let mut copied = [0; ADMIT_REQUEST_BYTES];
        stack.copy_in(input, &mut copied[..bytes])?;
        let frame = &copied[..bytes];
        if bytes == ADMIT_REQUEST_BYTES {
            let request = AdmitRequestV3::decode(frame).map_err(|_| i64::from(E_SCHEMA))?;
            #[cfg(cyxia_file_read_client)]
            {
                let mut reply = [0; ADMIT_REPLY_BYTES];
                client_read::admit(epoch, self.actor, &request)?
                    .encode(&mut reply)
                    .map_err(client_read::errno)?;
                return stack.copy_out(output, &reply);
            }
            #[cfg(not(cyxia_file_read_client))]
            {
                let _ = (request, epoch);
                EVIDENCE[5].fetch_add(1, Ordering::Release);
            }
        } else {
            let request = CompleteRequestV1::decode(frame).map_err(|_| i64::from(E_SCHEMA))?;
            #[cfg(cyxia_file_read_client)]
            {
                client_read::complete(epoch, self.actor, &request)?;
                return stack.copy_out(output, &[0; COMPLETE_REPLY_BYTES]);
            }
            #[cfg(not(cyxia_file_read_client))]
            {
                let _ = (request, epoch);
                EVIDENCE[6].fetch_add(1, Ordering::Release);
            }
        }
        #[cfg(not(cyxia_file_read_client))]
        Err(i64::from(
            cyxia_kernel_core::security::file_auth_v3::E_STALE,
        ))
    }

    fn syscall(&mut self, epoch: u64) -> RunState {
        let result = decode_aarch64_authorized_svc_v3(
            ABI_VERSION,
            self.context.esr,
            &self.context.regs,
            |op, selector| match op {
                Syscall::Exit | Syscall::Yield | Syscall::Sleep | Syscall::Clock => true,
                Syscall::ServiceCall => selector == self.selector,
                #[cfg(cyxia_file_read_client)]
                Syscall::IpcRecv => client_read::work_selector(epoch) == Ok(selector),
                _ => false,
            },
        );
        match result {
            Ok(call) if call.operation == Syscall::ServiceCall => {
                #[cfg(cyxia_file_read_client)]
                let start = super::timer::cpu_ticks();
                self.context.regs[0] = self.file_auth(epoch, call.args).err().unwrap_or(0) as u64;
                #[cfg(cyxia_file_read_client)]
                client_read::meter_auth(call.args[2], start);
                RunState::Runnable
            }
            #[cfg(cyxia_file_read_client)]
            Ok(call) if call.operation == Syscall::IpcRecv => {
                let start = super::timer::cpu_ticks();
                let result = client_read::receive(epoch, self.stack(), call.args);
                self.context.regs[0] = result.unwrap_or_else(|error| error) as u64;
                client_read::meter_work(start);
                RunState::Runnable
            }
            Ok(call) => {
                if call.operation == Syscall::Exit {
                    EVIDENCE[7].store(u64::from(call.args[0] as u32) + 1, Ordering::Release);
                }
                lifecycle_call(&mut self.context, &mut self.sleeping_until, call)
            }
            Err(error) => {
                self.context.regs[0] = preflight_errno(error) as u64;
                RunState::Runnable
            }
        }
    }
}

pub(super) fn thread(slot: usize, epoch: u64) -> Option<ObjectKey> {
    with_owner(slot, epoch, |owner| owner.key())
}

pub(super) fn wake(slot: usize, epoch: u64) {
    with_owner(slot, epoch, |owner| {
        let now = now_ns();
        if owner.sleeping_until.is_some_and(|until| until <= now)
            && matches!(
                try_scheduler(|sched| sched.set_runnable(owner.key(), true, now)),
                Some(Ok(()))
            )
        {
            owner.sleeping_until = None;
        }
    });
}

pub(super) fn drive(
    slot: usize,
    epoch: u64,
    exec: signed_exec_trap::Execution,
    deadline: u64,
) -> RunState {
    let mut fault = None;
    let state = with_owner(slot, epoch, |owner| {
        let state = match enter(
            CPU - 1,
            &mut owner.context,
            owner.root,
            ASID,
            exec,
            deadline,
        ) {
            signed_exec_trap::Return::Timer
            | signed_exec_trap::Return::Yield
            | signed_exec_trap::Return::Emulated => RunState::Runnable,
            signed_exec_trap::Return::Syscall => owner.syscall(epoch),
            signed_exec_trap::Return::TerminateTask => {
                fault = Some((owner.actor, owner.context.esr, owner.context.far));
                RunState::Exited
            }
            signed_exec_trap::Return::FailStop => super::fatal(super::BUSINESS_FAULT),
        };
        if state == RunState::Exited || !super::is_live_epoch(epoch) {
            LIVE.store(0, Ordering::Release);
        } else if !super::file_owner_active(epoch) {
            for (row, value) in [
                owner.actor.id,
                owner.actor.generation,
                owner.root,
                u64::from(ASID),
            ]
            .into_iter()
            .enumerate()
            {
                EVIDENCE[row + 1].store(value, Ordering::Relaxed);
            }
            EVIDENCE[0].store(epoch, Ordering::Release);
            LIVE.store(epoch, Ordering::Release);
        }
        state
    })
    .unwrap_or_else(|| super::fatal(super::BUSINESS_FAULT));
    if let Some((actor, esr, far)) = fault {
        // The stopped context borrow ended. Recovery can check the owner
        // identity from its scheduler binding before the caller retires it.
        super::recovery::record_business_failure(actor, esr, far)
            .unwrap_or_else(|_| super::fatal(super::BUSINESS_FAULT));
    }
    state
}

pub(super) fn retire(slot: usize, epoch: u64) {
    let Some(key) = thread(slot, epoch) else {
        return;
    };
    LIVE.store(0, Ordering::Release);
    #[cfg(cyxia_file_read_client)]
    client_read::fence(epoch, key.generation);
    PREPARED.store(0, Ordering::Release);
    // SAFETY: the only CPU that could enter this owner has returned to EL1
    // and stopped the scheduler path. This backing is never restaged in boot.
    unsafe { addr_of_mut!((*backing()).root).write_volatile(super::Page::ZERO) };
    invalidate_user_asid(ASID);
    unsafe { (*addr_of_mut!(OWNER)).assume_init_drop() };
    loop {
        if let Some(result) = try_scheduler(|scheduler| scheduler.remove(key)) {
            if result.is_ok() {
                EVIDENCE[8].store(1, Ordering::Release);
            }
            break;
        }
        poll_later();
    }
}
