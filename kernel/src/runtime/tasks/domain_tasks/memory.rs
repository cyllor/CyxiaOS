use super::*;
use crate::machine::copy_window;
use core::ops::Range;
use cyxia_contracts::PagePermissions;
use cyxia_kernel_core::{
    control_plane::Identity,
    frame_meta_v0199::{FrameMeta, Owner as FrameOwner},
    security::{Error as FrameError, syscall::user_copy_span},
};

static mut FRAME_ROWS: [FrameMeta; PAGES] = [FrameMeta::ZERO; PAGES];

unsafe extern "C" {
    static ram_l3: u8;
}

pub(super) fn initialize_frame_meta() -> Result<RuntimePool<'static>, Error> {
    // SAFETY: CPU0 initializes the backing under the task owner gate, before
    // publication of the runtime. All later access uses State::frame_meta.
    let rows = unsafe { &mut *core::ptr::addr_of_mut!(FRAME_ROWS) };
    RuntimePool::initialize(rows, frame_phys(0)?, TABLE_PAGES + CODE_PAGES).map_err(frame_error)
}

fn frame_error(error: FrameError) -> Error {
    match error {
        FrameError::Invalid => Error::Range,
        FrameError::Unauthorized => Error::Auth,
        FrameError::Stale => Error::Stale,
        FrameError::Conflict => Error::Conflict,
        FrameError::Capacity | FrameError::Exhausted => Error::Capacity,
        FrameError::Busy => Error::Busy,
        FrameError::Unknown => Error::Io,
    }
}

fn frame_owner(owner: ObjectKey) -> Result<FrameOwner, Error> {
    Ok(FrameOwner {
        slot: u32::try_from(owner.id).map_err(|_| Error::Auth)?,
        generation: owner.generation,
    })
}

pub(super) fn frame_ptr(frame: usize) -> Result<*mut u8, Error> {
    if frame >= PAGES {
        return Err(Error::Range);
    }
    Ok(unsafe {
        core::ptr::addr_of_mut!(POOL)
            .cast::<Page>()
            .add(frame)
            .cast::<u8>()
    })
}
pub(super) fn frame_phys(frame: usize) -> Result<u64, Error> {
    (frame_ptr(frame)? as u64)
        .checked_sub(crate::HIGH)
        .ok_or(Error::Range)
}

fn ram_leaf(physical: u64) -> Result<*mut u64, Error> {
    let offset = physical
        .checked_sub(cyxia_platform_virt::RAM_BASE)
        .filter(|_| physical < cyxia_platform_virt::USER_RAM_END && physical.is_multiple_of(4096))
        .ok_or(Error::Range)?;
    let table = (crate::HIGH + core::ptr::addr_of!(ram_l3) as u64) as *mut u64;
    // SAFETY: boot installs a descriptor for each page of this RAM range.
    Ok(unsafe { table.add((offset / 4096) as usize) })
}

fn direct_leaf(physical: u64, writable: bool) -> Result<u64, Error> {
    let permissions = PagePermissions::new(writable, false).map_err(|_| Error::Auth)?;
    mmu::encode_leaf(PhysAddr(physical), permissions, mmu::MemoryAttr::Normal)
        .map_err(|_| Error::Range)
}

pub(super) fn synchronize() {
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
pub(super) fn load_code(elf: &[u8], frame: usize, pages: usize) -> Result<(), Error> {
    let word = |at: usize| -> Result<u64, Error> {
        Ok(u64::from_le_bytes(
            elf.get(at..at + 8)
                .ok_or(Error::Format)?
                .try_into()
                .map_err(|_| Error::Format)?,
        ))
    };
    if elf.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || elf.get(16..24) != Some(&[2, 0, 183, 0, 1, 0, 0, 0])
        || word(24)? != 0x10000
    {
        return Err(Error::Format);
    }
    let ph = usize::try_from(word(32)?).map_err(|_| Error::Format)?;
    if elf.get(ph..ph + 8) != Some(&[1, 0, 0, 0, 5, 0, 0, 0]) || word(ph + 16)? != 0x10000 {
        return Err(Error::Format);
    }
    let offset = usize::try_from(word(ph + 8)?).map_err(|_| Error::Format)?;
    let len = usize::try_from(word(ph + 32)?).map_err(|_| Error::Format)?;
    if len == 0
        || len > pages * 4096
        || word(ph + 40)? != len as u64
        || frame.checked_add(pages).is_none_or(|end| end > PAGES)
    {
        return Err(Error::Format);
    }
    let input = elf
        .get(offset..offset.checked_add(len).ok_or(Error::Format)?)
        .ok_or(Error::Format)?;
    for page in frame..frame + pages {
        let physical = frame_phys(page)?;
        if unsafe { ram_leaf(physical)?.read_volatile() } != direct_leaf(physical, true)? {
            return Err(Error::Conflict);
        }
    }
    unsafe {
        let out = frame_ptr(frame)?;
        core::ptr::write_bytes(out, 0, pages * 4096);
        core::ptr::copy_nonoverlapping(input.as_ptr(), out, len);
        for offset in (0..pages * 4096).step_by(64) {
            core::arch::asm!("dc cvau, {}",in(reg)out.add(offset),options(nostack));
        }
        core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb", options(nostack));
    }
    // Nobody has a user mapping yet. Seal the permanent code pages' direct
    // aliases before any task can enter EL0 with one of these pages executable.
    for page in frame..frame + pages {
        unsafe { ram_leaf(frame_phys(page)?)?.write_volatile(0) };
    }
    synchronize();
    for page in frame..frame + pages {
        let physical = frame_phys(page)?;
        unsafe { ram_leaf(physical)?.write_volatile(direct_leaf(physical, false)?) };
    }
    synchronize();
    Ok(())
}
pub(super) struct Pages<'a> {
    pub tasks: &'a [Task; TASKS],
    pub remote: Option<Remote>,
    pub load: Option<LoadCache>,
    pub frame_meta: &'a mut Option<RuntimePool<'static>>,
}
impl Pages<'_> {
    fn frames(&mut self) -> Result<&mut RuntimePool<'static>, Error> {
        self.frame_meta.as_mut().ok_or(Error::NotReady)
    }

    fn entry(&self, owner: ObjectKey, address: u64) -> Result<*mut u64, Error> {
        if address >= USER_LIMIT || !address.is_multiple_of(4096) {
            return Err(Error::Range);
        }
        let root = if let Some(remote) = self.remote.filter(|r| r.key == owner) {
            remote.root
        } else {
            let index = task_index(self.tasks, owner)?;
            frame_ptr(index * 3)? as u64
        };
        let middle = root + 4096;
        let leaf = middle + 4096;
        // SAFETY: these are the three contiguous, permanently reserved tables
        // for the live task. USER_LIMIT restricts the walk to child index zero.
        unsafe {
            if (root as *const u64).read_volatile() != ((middle - crate::HIGH) | 3)
                || (middle as *const u64).read_volatile() != ((leaf - crate::HIGH) | 3)
            {
                return Err(Error::Auth);
            }
            Ok((leaf as *mut u64).add(address as usize / 4096))
        }
    }
}
impl MemoryBackend for Pages<'_> {
    fn zero(&mut self, frame: usize) -> Result<(), Error> {
        let physical = frame_phys(frame)?;
        if unsafe { ram_leaf(physical)?.read_volatile() } != direct_leaf(physical, true)? {
            return Err(Error::Conflict);
        }
        unsafe {
            core::ptr::write_bytes(frame_ptr(frame)?, 0, 4096);
        }
        Ok(())
    }
    fn map(
        &mut self,
        owner: ObjectKey,
        address: u64,
        frame: usize,
        writable: bool,
    ) -> Result<(), Error> {
        // SEC-M01: an ordinary EL0 mapping must never draw a frame from
        // the kernel's boot-time page-table or executable loader pool.
        // The memory owner ledger separately proves owner, quota and zeroing.
        cyxia_kernel_core::security::memory::authorize_data_frame_slot(
            frame,
            TABLE_PAGES + CODE_PAGES,
            PAGES,
        )
        .map_err(|_| Error::Auth)?;
        let entry = self.entry(owner, address)?;
        let physical = frame_phys(frame)?;
        let value =
            mmu::encode_user_leaf(PhysAddr(physical), writable, false).map_err(|_| Error::Range)?;
        let alias = ram_leaf(physical)?;
        if unsafe {
            entry.read_volatile() != 0 || alias.read_volatile() != direct_leaf(physical, true)?
        } {
            return Err(Error::Conflict);
        }
        self.frames()?
            .map_zeroed(physical, frame_owner(owner)?, || {
                // The task gate excludes other table writers. Remove the
                // privileged direct alias before publishing the user leaf.
                unsafe { alias.write_volatile(0) };
                synchronize();
                unsafe { entry.write_volatile(value) };
                synchronize();
            })
            .map_err(frame_error)
    }
    fn revoke(&mut self, owner: ObjectKey, address: u64, frame: usize) -> Result<(), Error> {
        // SEC-M04: a corrupted protected-frame index must fail closed;
        // the caller retains ledger custody when this check rejects.
        cyxia_kernel_core::security::memory::authorize_data_frame_slot(
            frame,
            TABLE_PAGES + CODE_PAGES,
            PAGES,
        )
        .map_err(|_| Error::Auth)?;
        let entry = self.entry(owner, address)?;
        let physical = frame_phys(frame)?;
        let alias = ram_leaf(physical)?;
        let direct = direct_leaf(physical, true)?;
        let readonly =
            mmu::encode_user_leaf(PhysAddr(physical), false, false).map_err(|_| Error::Range)?;
        let writable =
            mmu::encode_user_leaf(PhysAddr(physical), true, false).map_err(|_| Error::Range)?;
        self.frames()?
            .revoke(physical, frame_owner(owner)?, |owned| {
                let (current, alias_value) =
                    unsafe { (entry.read_volatile(), alias.read_volatile()) };
                if !owned {
                    // A failed map may have left the slot empty throughout.
                    return if current == 0 && alias_value == direct {
                        Ok(())
                    } else {
                        Err(FrameError::Conflict)
                    };
                }
                if (current != 0 && current != readonly && current != writable) || alias_value != 0
                {
                    return Err(FrameError::Conflict);
                }
                unsafe { entry.write_volatile(0) };
                synchronize();
                // Only now can the ordinary allocator clear or reuse it.
                unsafe { alias.write_volatile(direct) };
                synchronize();
                Ok(())
            })
            .map_err(frame_error)
    }
    fn load_cache(&mut self, object: ObjectKey, page: u64, frame: usize) -> Result<(), Error> {
        let load = self.load.ok_or(Error::NotReady)?;
        unsafe { load(object, page, &mut *frame_ptr(frame)?.cast::<[u8; 4096]>()) }
    }
    fn drop_cache(&mut self, _: CacheHandle) -> Result<(), Error> {
        Ok(())
    }
}
pub(super) fn fault_page(
    memory: &mut Memory<PAGES, 512>,
    owner: ObjectKey,
    address: u64,
    write: bool,
    backend: &mut Pages<'_>,
) -> Result<usize, Error> {
    match memory.fault(owner, address, write, backend) {
        Err(Error::Capacity) => {
            memory.reclaim_step(1, now_ns(), backend)?;
            memory.fault(owner, address, write, backend)
        }
        result => result,
    }
}
fn code_frame(tasks: &[Task; TASKS], owner: ObjectKey, address: u64) -> Option<usize> {
    let task = &tasks[task_index(tasks, owner).ok()?];
    let (first, pages) = if task.package == MEMORY_PACKAGE && crate::memory_fault_capture::PROFILE {
        (MEMORY_CODE_FRAME, 4)
    } else if task.package == CLIENT_PACKAGE {
        (CLIENT_CODE_FRAME, 4)
    } else if task.package == PACKAGE {
        (CODE_FRAME, 1)
    } else {
        return None;
    };
    let offset = address.checked_sub(0x10000)? as usize;
    (offset < pages * 4096).then_some(first + offset / 4096)
}

fn copy_end(address: u64, len: usize) -> Result<u64, Error> {
    // SEC-S01/S02: check pointer arithmetic before touching any page or
    // user-owned memory. The syscall adapter still enforces task ownership,
    // mappings, PTE permissions and reclaim/TLB synchronization.
    if len == 0 {
        return Ok(address);
    }
    user_copy_span(address, len, 0, USER_LIMIT, usize::MAX)
        .map(|(_, end)| end)
        .map_err(|_| Error::Range)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
    LaunchInput,
}

/// A bounded memory-only borrow. It cannot escape the task gate or be held
/// across device/file work, progress callbacks, or user execution.
pub(crate) struct UserMemoryAccess<'a> {
    memory: &'a mut Memory<PAGES, 512>,
    pages: Pages<'a>,
    owner: ObjectKey,
}
impl UserMemoryAccess<'_> {
    pub(super) fn new<'a>(
        memory: &'a mut Memory<PAGES, 512>,
        pages: Pages<'a>,
        owner: ObjectKey,
    ) -> UserMemoryAccess<'a> {
        UserMemoryAccess {
            memory,
            pages,
            owner,
        }
    }

    pub(crate) fn probe(&mut self, address: u64, len: usize, writable: bool) -> Result<(), Error> {
        let end = copy_end(address, len)?;
        let access = if writable {
            Access::Write
        } else {
            Access::Read
        };
        let mut at = address;
        while at < end {
            let code = code_frame(self.pages.tasks, self.owner, at);
            let frame = match code {
                Some(frame) => frame,
                None => fault_page(self.memory, self.owner, at, writable, &mut self.pages)?,
            };
            self.fragment(at, 1, frame, code.is_some(), access)?;
            at = (at & !4095) + 4096;
        }
        Ok(())
    }

    pub(crate) fn copyin(&mut self, address: u64, out: &mut [u8]) -> Result<(), Error> {
        self.probe(address, out.len(), false)?;
        self.copyin_resident(address, out)
    }

    pub(crate) fn copyout(&mut self, address: u64, input: &[u8]) -> Result<(), Error> {
        self.probe(address, input.len(), true)?;
        self.copyout_resident(address, input)
    }

    pub(super) fn copyin_resident(&mut self, address: u64, out: &mut [u8]) -> Result<(), Error> {
        self.transfer(
            address,
            out.len(),
            Access::Read,
            |physical, owner, asid, range| {
                // SAFETY: transfer verifies the user leaf and holds the frame
                // until the window returns. The destination is an EL1 borrow.
                unsafe { copy_window::copy_in(physical, owner, asid, &mut out[range]) }
            },
        )
    }

    pub(super) fn copyout_resident(&mut self, address: u64, input: &[u8]) -> Result<(), Error> {
        self.write_resident(address, input, Access::Write)
    }

    /// Populate the two EL0-read-only data pages used for kernel launch and
    /// recovery input, with the task stopped under the owner gate.
    pub(super) fn write_launch_input(&mut self, address: u64, input: &[u8]) -> Result<(), Error> {
        if !matches!(address, 0x20000 | 0x21000) || input.len() > 4096 {
            return Err(Error::Range);
        }
        self.write_resident(address, input, Access::LaunchInput)
    }

    fn write_resident(&mut self, address: u64, input: &[u8], access: Access) -> Result<(), Error> {
        self.transfer(
            address,
            input.len(),
            access,
            |physical, owner, asid, range| {
                // SAFETY: transfer holds the exact page with write access
                // authorized for this operation. The source is an EL1 borrow.
                unsafe { copy_window::copy_out(physical, owner, asid, &input[range]) }
            },
        )
    }

    fn fragment(
        &self,
        at: u64,
        bytes: usize,
        frame: usize,
        code: bool,
        access: Access,
    ) -> Result<u64, Error> {
        let physical = frame_phys(frame)?;
        let offset = at & 4095;
        let entry = self.pages.entry(self.owner, at - offset)?;
        let pte = unsafe { entry.read_volatile() };
        let rx =
            mmu::encode_user_leaf(PhysAddr(physical), false, true).map_err(|_| Error::Range)?;
        let alias = if code {
            if access != Access::Read || pte != rx {
                return Err(Error::Auth);
            }
            direct_leaf(physical, false)?
        } else {
            let ro = mmu::encode_user_leaf(PhysAddr(physical), false, false)
                .map_err(|_| Error::Range)?;
            if pte == rx || (access == Access::LaunchInput && pte != ro) {
                return Err(Error::Auth);
            }
            0
        };
        if unsafe { ram_leaf(physical)?.read_volatile() } != alias {
            return Err(Error::Conflict);
        }
        mmu::checked_user_leaf_span(
            pte,
            PhysAddr(physical),
            offset,
            bytes,
            access == Access::Write,
        )
        .map(|physical| physical.0)
        .map_err(|_| Error::Auth)
    }

    fn transfer(
        &mut self,
        address: u64,
        length: usize,
        access: Access,
        mut copy: impl FnMut(u64, Identity, u8, Range<usize>) -> Result<(), FrameError>,
    ) -> Result<(), Error> {
        copy_end(address, length)?;
        let owner = Identity {
            id: self.owner.id,
            generation: self.owner.generation,
        };
        let frame_owner = frame_owner(self.owner)?;
        let asid = user::dynamic_asid();
        let mut done = 0;
        while done < length {
            let at = address + done as u64;
            let code = code_frame(self.pages.tasks, self.owner, at);
            let frame = match code {
                Some(frame) => frame,
                None => self.memory.resident(self.owner, at)?,
            };
            let count = (4096 - (at & 4095) as usize).min(length - done);
            let physical = self.fragment(at, count, frame, code.is_some(), access)?;
            let range = done..done + count;
            if code.is_some() {
                // The sealed code page has a permanent reservation.
                copy(physical, owner, asid, range).map_err(frame_error)?;
            } else {
                let frames = self.pages.frames()?;
                let pin = frames
                    .pin(physical & !4095, frame_owner)
                    .map_err(frame_error)?;
                let transferred = copy(physical, owner, asid, range);
                frames.unpin(pin).map_err(frame_error)?;
                transferred.map_err(frame_error)?;
            }
            done += count;
        }
        Ok(())
    }
}

impl State {
    pub(super) fn user_memory(&mut self, owner: ObjectKey) -> Result<UserMemoryAccess<'_>, Error> {
        if !self.remote.is_some_and(|remote| remote.key == owner) {
            task_index(&self.tasks, owner)?;
        }
        Ok(UserMemoryAccess::new(
            &mut self.memory,
            Pages {
                tasks: &self.tasks,
                remote: self.remote,
                load: None,
                frame_meta: &mut self.frame_meta,
            },
            owner,
        ))
    }
}

pub(crate) fn with_user_memory<R>(
    owner: ObjectKey,
    body: impl FnOnce(&mut UserMemoryAccess<'_>) -> Result<R, Error>,
) -> Result<R, Error> {
    locked(|s| {
        let i = task_index(&s.tasks, owner)?;
        if s.tasks[i].life == Life::Exiting {
            return Err(Error::Stale);
        }
        body(&mut s.user_memory(owner)?)
    })
}
pub fn copyin(owner: ObjectKey, address: u64, out: &mut [u8]) -> Result<(), Error> {
    with_user_memory(owner, |memory| memory.copyin(address, out))
}
pub fn copyout(owner: ObjectKey, address: u64, input: &[u8]) -> Result<(), Error> {
    with_user_memory(owner, |memory| memory.copyout(address, input))
}
pub fn set_file_service(validate: ValidateFile, stat: StatFile) -> Result<(), Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    locked(|s| {
        s.validate_file = Some(validate);
        s.stat_file = Some(stat);
        Ok(())
    })
}
pub fn set_cache_loader(load: LoadCache) -> Result<(), Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    locked(|s| {
        s.load_cache = Some(load);
        Ok(())
    })
}
pub fn invalidate_file(_object: ObjectKey) {
    let _ = CACHE_EPOCH.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
        value.checked_add(1)
    });
}
pub(super) fn synchronize_cache(s: &mut State) -> u64 {
    let epoch = CACHE_EPOCH.load(Ordering::Acquire);
    if epoch != s.cache_epoch {
        s.memory.invalidate_all_cache();
        s.cache_epoch = epoch;
    }
    epoch
}
struct Staged<'a> {
    bytes: &'a [u8; 4096],
}
impl MemoryBackend for Staged<'_> {
    fn zero(&mut self, _: usize) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn map(&mut self, _: ObjectKey, _: u64, _: usize, _: bool) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn revoke(&mut self, _: ObjectKey, _: u64, _: usize) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn load_cache(&mut self, _: ObjectKey, _: u64, frame: usize) -> Result<(), Error> {
        unsafe {
            core::ptr::copy_nonoverlapping(self.bytes.as_ptr(), frame_ptr(frame)?, 4096);
        }
        Ok(())
    }
    fn drop_cache(&mut self, _: CacheHandle) -> Result<(), Error> {
        Ok(())
    }
}
pub fn cache_read(object: ObjectKey, page: u64, out: &mut [u8; 4096]) -> Result<(), Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    let (epoch, validate, load) = locked(|s| {
        Ok((
            synchronize_cache(s),
            s.validate_file.ok_or(Error::NotReady)?,
            s.load_cache.ok_or(Error::NotReady)?,
        ))
    })?;
    if epoch == u64::MAX {
        return Err(Error::Overflow);
    }
    validate(object)?;
    let hit = locked(|s| {
        if synchronize_cache(s) != epoch {
            return Err(Error::Stale);
        }
        if let Some(h) = s.memory.lookup_cache(object, page, now_ns())? {
            s.memory.hold_cache(h)?;
            unsafe {
                core::ptr::copy_nonoverlapping(frame_ptr(h.frame)?, out.as_mut_ptr(), 4096);
            }
            s.memory.release_cache(h)?;
            Ok(true)
        } else {
            Ok(false)
        }
    })?;
    if hit {
        return if CACHE_EPOCH.load(Ordering::Acquire) == epoch {
            Ok(())
        } else {
            Err(Error::Stale)
        };
    }
    // The loader can block; neither task metadata nor page references are lent
    // to it. Only the completed private staging page enters the locked pool.
    let mut bytes = [0u8; 4096];
    load(object, page, &mut bytes)?;
    validate(object)?;
    locked(|s| {
        if synchronize_cache(s) != epoch {
            return Err(Error::Stale);
        }
        let h = s
            .memory
            .cache_page(object, page, now_ns(), &mut Staged { bytes: &bytes })?;
        s.memory.hold_cache(h)?;
        unsafe {
            core::ptr::copy_nonoverlapping(frame_ptr(h.frame)?, out.as_mut_ptr(), 4096);
        }
        s.memory.release_cache(h)?;
        if CACHE_EPOCH.load(Ordering::Acquire) == epoch {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    })
}
