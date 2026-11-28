//! CPU2 owns the signed GROUP_OWNER root, the admitted BUSINESS child and
//! every mutation of their local task/VM registries. No rights are inherited.
use super::*;
use crate::machine::copy_window;
use cyxia_kernel_core::{
    control_plane::{control_rpc_v1::Error as Errno, d02_owner_v0199 as d02},
    security::{
        memory::checked_user_span, startup_catalog_v0199::TASK_SERVICES_BYTES,
        syscall_v3::decode_aarch64_authorized_svc_v3,
    },
};

#[path = "task_vm.rs"]
mod vm;

pub(in super::super) const GROUP_CPU: usize = 2;
const CHILD_ASID: u8 = 0xB4;
const OWNER_ASID: u8 = 0xB0 + GROUP_CPU as u8;
const CHILD_ID: u64 = BUSINESS_THREAD_ID_BASE + 0x20;
// These protected slots name the signed owner's SPAWN_GROUP/bit 0 grant,
// its child's TASK/QUERY+JOIN grant, and its own rights-zero page set.
const SPAWN_SLOT: u32 = 0x400;
const TASK_SLOT: u32 = 0x401;
const OWNED_PAGE_SLOT: u32 = 0x402;
const BOOTSTRAP_BYTES: usize = 40;
const TASK_INFO_BYTES: usize = 48;
const SPAWN_HEADER_BYTES: usize = 32;
const MAX_ARGS_BYTES: usize = 256;
const GRANTS: &[u8; TASK_SERVICES_BYTES] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/startup-catalog/business-task-services.bin"
));
const GRANT_SIGNATURE: &[u8; 64] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/startup-catalog/business-task-services.sig"
));

#[derive(Clone, Copy)]
pub(super) struct Grant {
    group_id: u32,
    package_id: u64,
    pub(super) child_budget_ns: u64,
    owned_pages: u16,
    vm_pages: u16,
}

pub(super) fn qualify(
    config: &VerifiedOfflineConfig<'_>,
    digest: [u8; 32],
) -> Result<Grant, Error> {
    startup_catalog::qualify_business_task_services(config, digest, GRANTS, GRANT_SIGNATURE)
        .map_err(|_| Error::Denied)?;
    let group_id = u32::from_le_bytes(GRANTS[..4].try_into().unwrap());
    let package_id = word(GRANTS, 8);
    let child_budget_ns = word(GRANTS, 16);
    let slot = u16::from_le_bytes(GRANTS[24..26].try_into().unwrap());
    let owned_pages = u16::from_le_bytes(GRANTS[26..28].try_into().unwrap());
    let vm_pages = u32::from_le_bytes(GRANTS[28..32].try_into().unwrap());
    if u64::from(group_id) <= CHILD_ID
        || package_id == 0
        || GRANTS[4..8] != [0; 4]
        || usize::from(slot) != GROUP_CPU
        || !(MAX_SLICE_NS..=CPU_BUDGET_NS - MAX_SLICE_NS).contains(&child_budget_ns)
        || !(1..=vm::MAX_PAGES as u32).contains(&vm_pages)
        || !(1..=vm_pages).contains(&u32::from(owned_pages))
    {
        return Err(Error::Invalid);
    }
    Ok(Grant {
        group_id,
        package_id,
        child_budget_ns,
        owned_pages,
        vm_pages: vm_pages as u16,
    })
}

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn selector(epoch: u64, slot: u32) -> u64 {
    (epoch << 32) | u64::from(slot)
}

fn check_selector(cap: u64, epoch: u64, slot: u32) -> Result<(), Errno> {
    if cap as u32 != slot {
        return Err(Errno::Auth);
    }
    if cap >> 32 != epoch {
        return Err(Errno::Stale);
    }
    Ok(())
}

impl Grant {
    pub(super) fn group(self, epoch: u64) -> ObjectKey {
        ObjectKey {
            id: u64::from(self.group_id),
            generation: epoch,
        }
    }

    pub(super) fn bootstrap(self, epoch: u64) -> Result<[u8; BOOTSTRAP_BYTES], Error> {
        if !(1..=u64::from(u32::MAX)).contains(&epoch) {
            return Err(Error::Exhausted);
        }
        let mut out = [0; BOOTSTRAP_BYTES];
        out[..8].copy_from_slice(b"CYXTASK1");
        out[8..12].copy_from_slice(&self.group_id.to_le_bytes());
        out[12..14].copy_from_slice(&self.owned_pages.to_le_bytes());
        out[14..16].copy_from_slice(&self.vm_pages.to_le_bytes());
        out[16..24].copy_from_slice(&self.package_id.to_le_bytes());
        out[24..32].copy_from_slice(&selector(epoch, SPAWN_SLOT).to_le_bytes());
        out[32..40].copy_from_slice(&selector(epoch, OWNED_PAGE_SLOT).to_le_bytes());
        Ok(out)
    }
}

#[derive(Clone, Copy)]
struct Space {
    actor: Identity,
    backing: *mut Backing,
    layout: Layout,
    asid: u8,
}

impl Space {
    fn root(self) -> u64 {
        pa(self
            .backing
            .wrapping_byte_add(core::mem::offset_of!(Backing, root))
            .cast())
        .0
    }

    fn fragment(
        self,
        vm: Option<&vm::Vm>,
        address: u64,
        count: usize,
        write: bool,
    ) -> Result<Fragment, Errno> {
        let virtual_page = address & !(PAGE as u64 - 1);
        let offset = address - virtual_page;
        let stack_base = self.layout.stack_top - ROLE_STACK_BYTES as u64;
        if vm::contains(virtual_page) {
            return vm
                .ok_or(Errno::Fault)?
                .fragment(self, address, count, write);
        }
        let (base, bytes, middle, leaf, backing) = if virtual_page < stack_base {
            (
                self.layout.image,
                IMAGE_BYTES,
                unsafe { addr_of!((*self.backing).image_middle) },
                unsafe { addr_of!((*self.backing).image_leaf) },
                unsafe { addr_of!((*self.backing).image).cast::<u8>() },
            )
        } else {
            (
                stack_base,
                ROLE_STACK_BYTES,
                unsafe { addr_of!((*self.backing).stack_middle) },
                unsafe { addr_of!((*self.backing).stack_leaf) },
                unsafe { addr_of!((*self.backing).stack).cast::<u8>() },
            )
        };
        checked_user_span(address, count, base, base + bytes as u64).map_err(|_| Errno::Fault)?;
        let entry = self.leaf(virtual_page, middle, leaf)?;
        let owned = pa(backing.wrapping_add((virtual_page - base) as usize));
        let physical = mmu::checked_user_leaf_span(entry, owned, offset, count, write)
            .map_err(|_| Errno::Fault)?;
        Ok(Fragment {
            physical: physical.0,
            managed: None,
        })
    }

    fn leaf(self, address: u64, middle: *const Page, leaf: *const Page) -> Result<u64, Errno> {
        // SAFETY: both tables and the root are pinned and exclusively curated
        // by this owner. Their direct aliases contain page-table descriptors.
        let (upper, lower, entry) = unsafe {
            (
                addr_of!((*self.backing).root.0)
                    .cast::<u64>()
                    .add((address >> 30 & 511) as usize)
                    .read_volatile(),
                addr_of!((*middle).0)
                    .cast::<u64>()
                    .add((address >> 21 & 511) as usize)
                    .read_volatile(),
                addr_of!((*leaf).0)
                    .cast::<u64>()
                    .add((address >> 12 & 511) as usize)
                    .read_volatile(),
            )
        };
        if upper != (pa(middle.cast()).0 | 3) || lower != (pa(leaf.cast()).0 | 3) {
            return Err(Errno::Fault);
        }
        Ok(entry)
    }
}

struct Fragment {
    physical: u64,
    managed: Option<cyxia_kernel_core::frame_meta_v0199::Handle>,
}

fn visit_span(
    space: Space,
    vm: Option<&vm::Vm>,
    address: u64,
    count: u64,
    write: bool,
    mut visit: impl FnMut(Fragment, usize, usize) -> Result<(), Errno>,
) -> Result<(), Errno> {
    let n = usize::try_from(count).map_err(|_| Errno::Fault)?;
    if n == 0 || n > IMAGE_BYTES.max(ROLE_STACK_BYTES) || address.checked_add(count).is_none() {
        return Err(Errno::Fault);
    }
    let mut done = 0;
    while done < n {
        let at = address + done as u64;
        let count = (n - done).min(PAGE - (at as usize & (PAGE - 1)));
        visit(space.fragment(vm, at, count, write)?, done, count)?;
        done += count;
    }
    Ok(())
}

fn copy_in(space: Space, vm: &vm::Vm, address: u64, out: &mut [u8]) -> Result<(), Errno> {
    visit_span(
        space,
        Some(vm),
        address,
        out.len() as u64,
        false,
        |fragment, start, len| {
            vm::pinned(fragment, |pa| {
                // SAFETY: root, owner and the exact leaf were checked, and this
                // stopped root cannot change mappings until the window is closed.
                unsafe {
                    copy_window::copy_in(pa, space.actor, space.asid, &mut out[start..start + len])
                }
            })
        },
    )
}

fn copy_out(space: Space, vm: Option<&vm::Vm>, address: u64, bytes: &[u8]) -> Result<(), Errno> {
    visit_span(
        space,
        vm,
        address,
        bytes.len() as u64,
        true,
        |fragment, start, len| {
            let exact = vm::pinned(fragment, |pa| {
                // SAFETY: same exclusive custody as copy_in, with an actual RW leaf.
                unsafe {
                    copy_window::copy_out_and_check(
                        pa,
                        space.actor,
                        space.asid,
                        &bytes[start..start + len],
                    )
                }
            })?;
            if exact { Ok(()) } else { Err(Errno::Fault) }
        },
    )
}

#[derive(Clone, Copy)]
struct ChildReceipt {
    request_id: u64,
    digest: [u8; 32],
    terminal: Option<(i32, u64)>,
}

#[derive(Clone, Copy)]
struct Join {
    cap: u64,
    generation: u64,
    deadline_ns: u64,
    reply: u64,
    capacity: u64,
    ready: bool,
}

pub(super) struct Group {
    grant: Grant,
    owner: Space,
    child: Space,
    child_context: user::Context,
    child_sleep: Option<u64>,
    receipt: Option<ChildReceipt>,
    pending: Option<d02::Request>,
    last_spawn_id: u64,
    join: Option<Join>,
    vm: vm::Vm,
}

#[unsafe(link_section = ".bss.sec_n")]
static mut CHILD_BACKING: Backing = Backing::ZERO;
static mut GROUP: core::mem::MaybeUninit<Group> = core::mem::MaybeUninit::uninit();
static mut D02: d02::Owner = d02::Owner::empty();
static GROUP_READY: AtomicU64 = AtomicU64::new(0);
static GROUP_TAKEN: AtomicBool = AtomicBool::new(false);

pub(super) fn prepare(
    policy: &ConfirmedBootPolicy<'_>,
    grant: Grant,
    root_layout: Layout,
    storage: *mut Backing,
) -> Result<(), Error> {
    let epoch = policy.boot_epoch();
    let (image, stack_top) = root_layout.child.ok_or(Error::Denied)?;
    let owner_key = thread(GROUP_CPU, epoch);
    let owner = Space {
        actor: Identity {
            id: owner_key.id,
            generation: epoch,
        },
        backing: storage,
        layout: root_layout,
        asid: OWNER_ASID,
    };
    let child = Space {
        actor: Identity {
            id: CHILD_ID,
            generation: epoch,
        },
        backing: addr_of_mut!(CHILD_BACKING),
        layout: Layout {
            image,
            stack_top,
            child: None,
        },
        asid: CHILD_ASID,
    };
    let vm = vm::Vm::prepare(owner, grant).map_err(|_| Error::Denied)?;
    // SAFETY: only CPU0 initializes signed registries before publishing the
    // epoch. The unique GROUP_CPU then owns both statics until retirement.
    unsafe {
        addr_of_mut!(GROUP).write(core::mem::MaybeUninit::new(Group {
            grant,
            owner,
            child,
            child_context: user::Context::empty(),
            child_sleep: None,
            receipt: None,
            pending: None,
            last_spawn_id: 0,
            join: None,
            vm,
        }));
        let d02 = &mut *addr_of_mut!(D02);
        d02.bind(epoch, epoch, || Ok(()))?;
        d02.register_group(
            Identity {
                id: u64::from(grant.group_id),
                generation: epoch,
            },
            || Ok(()),
        )?;
    }
    Ok(())
}

pub(super) fn prepare_child(
    policy: &ConfirmedBootPolicy<'_>,
    package: &ApprovedPackage,
) -> Result<(), Error> {
    let epoch = policy.boot_epoch();
    if cpu::slot() != 0
        || epoch == 0
        || !policy.matches_config_digest(package.config)
        || GROUP_READY.load(Ordering::Acquire) != 0
        || PREPARED.load(Ordering::Acquire) & (1 << GROUP_CPU) == 0
    {
        return Err(Error::Denied);
    }
    // SAFETY: the parent root and grant were staged by this CPU, and the
    // EPOCH is closed to every secondary until this child image is sealed.
    let group = unsafe { (&mut *addr_of_mut!(GROUP)).assume_init_mut() };
    group.child_context = stage_package(group.child.backing, package, group.child.layout, &[])?;
    GROUP_READY.store(epoch, Ordering::Release);
    Ok(())
}

pub(super) fn prepared(epoch: u64) -> bool {
    GROUP_READY.load(Ordering::Acquire) == epoch
}

pub(super) fn is_child(actor: Identity) -> bool {
    actor.id == CHILD_ID && actor.valid() && prepared(actor.generation)
}

pub(super) fn take(slot: usize, epoch: u64) -> Option<&'static mut Group> {
    if slot != GROUP_CPU
        || cpu::registered_slot() != Some(slot)
        || !prepared(epoch)
        || GROUP_TAKEN.swap(true, Ordering::AcqRel)
    {
        return None;
    }
    // SAFETY: this runs once in the designated secondary's non-returning
    // worker, after the epoch handoff. No other CPU dereferences the group.
    Some(unsafe { (&mut *addr_of_mut!(GROUP)).assume_init_mut() })
}

fn control_errno(error: Error) -> Errno {
    match error {
        Error::Denied => Errno::Auth,
        Error::Stale => Errno::Stale,
        Error::Invalid => Errno::Format,
        Error::Exhausted => Errno::Capacity,
        Error::Clock | Error::Expired => Errno::Expired,
        Error::Busy | Error::NotReady => Errno::Again,
    }
}

impl Group {
    pub(super) fn child_key(&self) -> ObjectKey {
        ObjectKey {
            id: self.child.actor.id,
            generation: self.child.actor.generation,
        }
    }

    pub(super) fn has_child(&self) -> bool {
        self.receipt.is_some_and(|task| task.terminal.is_none())
    }

    fn allowed(&self, operation: Syscall, cap: u64) -> bool {
        if super::super::signed_control::publications_fenced()
            && matches!(
                operation,
                Syscall::Spawn | Syscall::ReserveVm | Syscall::MapOwned
            )
        {
            return false;
        }
        match operation {
            Syscall::Exit
            | Syscall::Yield
            | Syscall::Sleep
            | Syscall::Clock
            | Syscall::ReserveVm => true,
            Syscall::Spawn => cap as u32 == SPAWN_SLOT,
            Syscall::Join | Syscall::QueryTask => self.receipt.is_some() && cap as u32 == TASK_SLOT,
            Syscall::MapOwned | Syscall::Unmap => self.vm.possesses(cap as u32),
            _ => false,
        }
    }

    pub(super) fn syscall(
        &mut self,
        context: &mut user::Context,
        sleeping_until: &mut Option<u64>,
    ) -> RunState {
        let epoch = self.owner.actor.generation;
        if !is_live_epoch(epoch) {
            context.regs[0] = Errno::Stale as i64 as u64;
            return RunState::Runnable;
        }
        let call = match decode_aarch64_authorized_svc_v3(
            ABI_VERSION,
            context.esr,
            &context.regs,
            |op, cap| self.allowed(op, cap),
        ) {
            Ok(call) => call,
            Err(error) => {
                context.regs[0] = preflight_errno(error) as u64;
                return RunState::Runnable;
            }
        };
        let result = match call.operation {
            Syscall::Exit | Syscall::Yield | Syscall::Sleep | Syscall::Clock => {
                return lifecycle_call(context, sleeping_until, call);
            }
            Syscall::Spawn => self.spawn(call.args),
            Syscall::QueryTask => self.query(call.args),
            Syscall::Join => match self.join(call.args) {
                Ok(Some(wait)) => {
                    self.join = Some(wait);
                    return RunState::Blocked;
                }
                Ok(None) => Ok(()),
                Err(error) => Err(error),
            },
            Syscall::ReserveVm => self.vm.reserve(self.owner, call.args),
            Syscall::MapOwned => self.vm.map(call.args),
            Syscall::Unmap => self.vm.unmap(call.args),
            _ => Err(Errno::Auth),
        };
        context.regs[0] = result.map_or_else(|errno| errno as i64 as u64, |()| 0);
        RunState::Runnable
    }

    fn spawn(&mut self, args: [u64; 6]) -> Result<(), Errno> {
        let epoch = self.owner.actor.generation;
        check_selector(args[0], epoch, SPAWN_SLOT)?;
        let mut bytes = Zeroizing::new([0; SPAWN_HEADER_BYTES + MAX_ARGS_BYTES]);
        let bytes = &mut bytes[..args[2] as usize];
        copy_in(self.owner, &self.vm, args[1], bytes)?;
        let package = word(bytes, 0);
        let group = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let request_id = word(bytes, 16);
        let arg_bytes = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
        if bytes[12..16] != [0; 4]
            || bytes[28..32] != [0; 4]
            || request_id == 0
            || arg_bytes != bytes.len() - SPAWN_HEADER_BYTES
        {
            return Err(Errno::Format);
        }
        if package != self.grant.package_id || group != self.grant.group_id {
            return Err(Errno::Auth);
        }
        visit_span(
            self.owner,
            Some(&self.vm),
            args[3],
            args[4],
            true,
            |_, _, _| Ok(()),
        )?;
        let digest = Sha256::digest(&*bytes).into();
        if let Some(receipt) = self.receipt {
            if request_id != receipt.request_id {
                return Err(if request_id < receipt.request_id {
                    Errno::Stale
                } else {
                    Errno::Capacity
                });
            }
            if digest != receipt.digest {
                return Err(Errno::Conflict);
            }
            return self.task_info_out(args[3]);
        }
        let child = self.child_key();
        let group = self.grant.group(epoch);
        let req = d02::Request {
            caller: self.owner.actor,
            request_id,
            package: Identity {
                id: package,
                generation: epoch,
            },
            group: Identity {
                id: group.id,
                generation: group.generation,
            },
            digest,
        };
        if let Some(pending) = self.pending
            && pending != req
        {
            return Err(if pending.request_id == request_id {
                Errno::Conflict
            } else {
                Errno::Again
            });
        }
        let registers = self.write_child_args(&bytes[SPAWN_HEADER_BYTES..])?;
        let budget_ns = self.grant.child_budget_ns;
        let outcome = try_scheduler(|scheduler| {
            let now = now_ns();
            let placement = layout(epoch);
            let authorize = |_: &d02::Request| {
                if !is_live_epoch(epoch)
                    || placement.business_mask & placement.healthy_mask & (1 << GROUP_CPU) == 0
                {
                    return Err(Error::Denied);
                }
                Ok(())
            };
            // SAFETY: the group owner is the only business constructor. No
            // interrupt can acquire this registry or re-enter the dispatch.
            let d02 = unsafe { &mut *addr_of_mut!(D02) };
            authorize(&req).map_err(control_errno)?;
            let retained = d02.query(req.caller, req.request_id).is_ok();
            if req.request_id < self.last_spawn_id && !retained {
                return Err(Errno::Stale);
            }
            if !retained && recovery::audit_degraded() {
                return Err(Errno::Again);
            }
            let admitted = d02.submit(req, now, authorize).map_err(|error| {
                if retained && is_live_epoch(epoch) && error == Error::Denied {
                    Errno::Conflict
                } else {
                    control_errno(error)
                }
            })?;
            match admitted {
                d02::State::Queued => self.pending = Some(req),
                d02::State::Rejected => return Err(Errno::Busy),
                _ => fatal(BUSINESS_FAULT),
            }
            self.last_spawn_id = self.last_spawn_id.max(req.request_id);
            let started = match d02.start_one(now, scheduler.thread_count(), authorize) {
                Ok(Some(ticket)) => ticket,
                Ok(None) => return Err(Errno::Again),
                Err(error) => {
                    if d02.query(req.caller, req.request_id) == Ok(d02::State::Rejected) {
                        self.pending = None;
                    }
                    return Err(control_errno(error));
                }
            };
            if started.request != req {
                fatal(BUSINESS_FAULT);
            }
            self.pending = None;
            let result = (|| {
                if !is_live_epoch(epoch) {
                    return Err(Errno::Stale);
                }
                self.child_context.sp = registers.sp;
                self.child_context.regs[0] = registers.x0;
                self.child_context.regs[1] = registers.x1;
                scheduler
                    .admit(
                        ThreadSpec {
                            key: child,
                            group,
                            cpu: GROUP_CPU as u16,
                            allowed_mask: 1 << GROUP_CPU,
                            minimum_ns: 0,
                            budget_ns,
                        },
                        placement,
                        now_ns(),
                    )
                    .map_err(|_| Errno::Busy)
            })();
            let done = now_ns();
            let outcome = if result.is_ok() {
                d02::Outcome::Created(self.child.actor)
            } else {
                d02::Outcome::NoEffect
            };
            d02.complete_started(
                started,
                d02::Completion {
                    outcome,
                    completed_ns: done,
                },
                done,
                |ticket, completion| {
                    let placement = scheduler.thread_affinity(child);
                    let exact = match completion.outcome {
                        d02::Outcome::Created(actor) => {
                            actor == self.child.actor && placement == Ok(1 << GROUP_CPU)
                        }
                        d02::Outcome::NoEffect => placement.is_err(),
                        d02::Outcome::Unknown => false,
                    };
                    if ticket.request != req || !exact {
                        return Err(Error::Stale);
                    }
                    Ok(())
                },
            )
            .unwrap_or_else(|_| fatal(BUSINESS_FAULT));
            result
        })
        .ok_or(Errno::Again)?;
        outcome?;
        self.receipt = Some(ChildReceipt {
            request_id,
            digest,
            terminal: None,
        });
        self.task_info_out(args[3])
    }

    fn write_child_args(
        &self,
        args: &[u8],
    ) -> Result<cyxia_kernel_core::security::syscall_v3::StartupRegisters, Errno> {
        // The rest of the sealed child's private stack was cleared at boot.
        // Refresh the entire argument area even after a deferred admission.
        let base = self.child.layout.stack_top - PAGE as u64;
        let mut page = Zeroizing::new([0; PAGE]);
        let registers = stage_spawn_args(&mut page[..], base, args).map_err(|_| Errno::Format)?;
        let start = PAGE - MAX_ARGS_BYTES;
        copy_out(self.child, None, base + start as u64, &page[start..])?;
        Ok(registers)
    }

    fn task_info_out(&self, addr: u64) -> Result<(), Errno> {
        let entry = self.receipt.ok_or(Errno::Stale)?;
        let epoch = self.owner.actor.generation;
        let state: u16 = if entry.terminal.is_some() {
            8
        } else if self.child_sleep.is_some() {
            5
        } else {
            3
        };
        let cpu = if entry.terminal.is_some() {
            u32::MAX
        } else {
            GROUP_CPU as u32
        };
        let mut row = [0; TASK_INFO_BYTES];
        row[..8].copy_from_slice(&selector(epoch, TASK_SLOT).to_le_bytes());
        row[8..16].copy_from_slice(&epoch.to_le_bytes());
        row[16..20].copy_from_slice(&self.grant.group_id.to_le_bytes());
        row[20..22].copy_from_slice(&state.to_le_bytes());
        row[24..28].copy_from_slice(&entry.terminal.map_or(0, |(code, _)| code).to_le_bytes());
        row[32..36].copy_from_slice(&cpu.to_le_bytes());
        row[40..48].copy_from_slice(&entry.request_id.to_le_bytes());
        copy_out(self.owner, Some(&self.vm), addr, &row)
    }

    fn check_child(&self, cap: u64, generation: u64) -> Result<(), Errno> {
        let epoch = self.owner.actor.generation;
        check_selector(cap, epoch, TASK_SLOT)?;
        if generation != epoch || !is_live_epoch(epoch) || self.receipt.is_none() {
            return Err(Errno::Stale);
        }
        Ok(())
    }

    fn query(&self, [cap, generation, address, capacity, _, _]: [u64; 6]) -> Result<(), Errno> {
        self.check_child(cap, generation)?;
        visit_span(
            self.owner,
            Some(&self.vm),
            address,
            capacity,
            true,
            |_, _, _| Ok(()),
        )?;
        self.task_info_out(address)
    }

    fn join(
        &self,
        [cap, generation, deadline_ns, reply, capacity, _]: [u64; 6],
    ) -> Result<Option<Join>, Errno> {
        self.check_child(cap, generation)?;
        visit_span(
            self.owner,
            Some(&self.vm),
            reply,
            capacity,
            true,
            |_, _, _| Ok(()),
        )?;
        if !self.has_child() {
            self.task_info_out(reply)?;
            return Ok(None);
        }
        if now_ns() >= deadline_ns {
            return Err(Errno::Timeout);
        }
        Ok(Some(Join {
            cap,
            generation,
            deadline_ns,
            reply,
            capacity,
            ready: false,
        }))
    }

    pub(super) fn wake(&mut self) {
        let now = now_ns();
        let child = self.child_key();
        if self.child_sleep.is_some_and(|deadline| now >= deadline)
            && let Some(result) =
                try_scheduler(|scheduler| scheduler.set_runnable(child, true, now_ns()))
        {
            result.unwrap_or_else(|_| fatal(BUSINESS_FAULT));
            self.child_sleep = None;
        }
        let Some(wait) = self.join else { return };
        if wait.ready || (self.has_child() && now < wait.deadline_ns) {
            return;
        }
        let key = thread(GROUP_CPU, self.owner.actor.generation);
        if let Some(result) = try_scheduler(|scheduler| scheduler.set_runnable(key, true, now_ns()))
        {
            result.unwrap_or_else(|_| fatal(BUSINESS_FAULT));
            self.join = Some(Join {
                ready: true,
                ..wait
            });
        }
    }

    /// The waiter still owns this context when its next exact D01 credit
    /// begins. Charge re-authorizing and copying the deferred reply to it.
    pub(super) fn finish_join(&mut self, owner: &mut user::Context) {
        let Some(wait) = self.join.take_if(|wait| wait.ready) else {
            return;
        };
        let result = if self
            .receipt
            .and_then(|r| r.terminal)
            .is_some_and(|(_, when)| when <= wait.deadline_ns)
        {
            self.query([wait.cap, wait.generation, wait.reply, wait.capacity, 0, 0])
        } else {
            Err(Errno::Timeout)
        };
        owner.regs[0] = result.map_or_else(|errno| errno as i64 as u64, |()| 0);
    }

    pub(super) fn drive_child(
        &mut self,
        exec: signed_exec_trap::Execution,
        deadline: u64,
    ) -> (RunState, i32) {
        if !self.has_child() || self.child_sleep.is_some() {
            fatal(BUSINESS_FAULT);
        }
        let context = &mut self.child_context;
        let root = self.child.root();
        let returned = enter(GROUP_CPU - 1, context, root, CHILD_ASID, exec, deadline);
        let exit = context.regs[0] as i32;
        let state = match returned {
            signed_exec_trap::Return::Syscall => lifecycle_syscall(context, &mut self.child_sleep),
            signed_exec_trap::Return::TerminateTask => {
                recovery::record_business_failure(self.child.actor, context.esr, context.far)
                    .unwrap_or_else(|_| fatal(BUSINESS_FAULT));
                return (RunState::Exited, Errno::Fault as i32);
            }
            signed_exec_trap::Return::FailStop => fatal(BUSINESS_FAULT),
            _ => RunState::Runnable,
        };
        (state, exit)
    }

    pub(super) fn fault(&mut self, context: &user::Context) -> bool {
        self.vm.fault(self.owner, context)
    }

    fn disconnect_child(&mut self) {
        // SAFETY: the same core owns the root and observed the child's return
        // from EL0, or never opened it. No other core or DMA path can hold a
        // reference to it.
        unsafe { addr_of_mut!((*self.child.backing).root).write_volatile(Page::ZERO) };
        invalidate_user_asid(CHILD_ASID);
        self.child_context = user::Context::empty();
        self.child_sleep = None;
    }

    pub(super) fn retire_child(&mut self, code: i32) {
        let key = self.child_key();
        self.disconnect_child();
        loop {
            if let Some(result) = try_scheduler(|scheduler| scheduler.remove(key)) {
                result.unwrap_or_else(|_| fatal(BUSINESS_FAULT));
                break;
            }
            poll_later();
        }
        let now = now_ns();
        let task = self
            .receipt
            .as_mut()
            .expect("retired child has an exact admission receipt");
        task.terminal = Some((code, now));
        // SAFETY: this is the same sole D02 constructor and retirement owner.
        unsafe { &mut *addr_of_mut!(D02) }
            .exited(self.child.actor, now, || Ok(()))
            .unwrap_or_else(|_| fatal(BUSINESS_FAULT));
    }

    pub(super) fn retire(&mut self) {
        if self.has_child() {
            self.retire_child(Errno::Stale as i32);
        } else if self.receipt.is_none() {
            self.disconnect_child();
        }
        if let Some(req) = self.pending.take() {
            // SAFETY: this exact queued request belongs to the retiring
            // owner and has no started constructor or installed task.
            unsafe { &mut *addr_of_mut!(D02) }
                .cancel_queued(req.caller, req.request_id, now_ns(), |_| Ok(()))
                .unwrap_or_else(|_| fatal(BUSINESS_FAULT));
        }
        self.vm.retire();
    }
}
