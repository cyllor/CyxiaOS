use super::*;

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
    unsafe {
        let out = frame_ptr(frame)?;
        core::ptr::write_bytes(out, 0, pages * 4096);
        core::ptr::copy_nonoverlapping(input.as_ptr(), out, len);
        for offset in (0..pages * 4096).step_by(64) {
            core::arch::asm!("dc cvau, {}",in(reg)out.add(offset),options(nostack));
        }
        core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb", options(nostack));
    }
    Ok(())
}
pub(super) struct Pages<'a> {
    pub tasks: &'a [Task; TASKS],
    pub remote: Option<Remote>,
    pub load: Option<LoadCache>,
}
impl Pages<'_> {
    fn entry(&self, owner: ObjectKey, address: u64) -> Result<*mut u64, Error> {
        if address >= USER_LIMIT || !address.is_multiple_of(4096) {
            return Err(Error::Range);
        }
        let leaf = if let Some(remote) = self.remote.filter(|r| r.key == owner) {
            remote.leaf as *mut u64
        } else {
            let index = task_index(self.tasks, owner)?;
            frame_ptr(index * 3 + 2)?.cast::<u64>()
        };
        Ok(unsafe { leaf.add(address as usize / 4096) })
    }
}
impl MemoryBackend for Pages<'_> {
    fn zero(&mut self, frame: usize) -> Result<(), Error> {
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
        let entry = self.entry(owner, address)?;
        let value = mmu::encode_user_leaf(PhysAddr(frame_phys(frame)?), writable, false)
            .map_err(|_| Error::Range)?;
        unsafe {
            if entry.read_volatile() != 0 {
                return Err(Error::Conflict);
            }
            entry.write_volatile(value);
        }
        synchronize();
        Ok(())
    }
    fn revoke(&mut self, owner: ObjectKey, address: u64, frame: usize) -> Result<(), Error> {
        let entry = self.entry(owner, address)?;
        let physical = frame_phys(frame)?;
        unsafe {
            let current = entry.read_volatile();
            if current != 0 && current & 0x0000_ffff_ffff_f000 != physical {
                return Err(Error::Conflict);
            }
            entry.write_volatile(0);
        }
        synchronize();
        Ok(())
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
    let (first, pages) = if task.package == CLIENT_PACKAGE {
        (CLIENT_CODE_FRAME, 4)
    } else if task.package == PACKAGE {
        (CODE_FRAME, 1)
    } else {
        return None;
    };
    let offset = address.checked_sub(0x10000)? as usize;
    (offset < pages * 4096).then_some(first + offset / 4096)
}
pub(super) fn prepare(
    memory: &mut Memory<PAGES, 512>,
    tasks: &[Task; TASKS],
    remote: Option<Remote>,
    owner: ObjectKey,
    address: u64,
    len: usize,
    write: bool,
) -> Result<(), Error> {
    let end = address
        .checked_add(len as u64)
        .filter(|end| *end <= USER_LIMIT)
        .ok_or(Error::Range)?;
    if len == 0 {
        return Ok(());
    }
    let mut backend = Pages {
        tasks,
        remote,
        load: None,
    };
    let mut page = address / 4096 * 4096;
    while page < end {
        if code_frame(tasks, owner, page).is_some() {
            if write {
                return Err(Error::Auth);
            }
        } else {
            fault_page(memory, owner, page, write, &mut backend)?;
        }
        page += 4096;
    }
    Ok(())
}
pub(super) fn copy_from(
    memory: &Memory<PAGES, 512>,
    tasks: &[Task; TASKS],
    owner: ObjectKey,
    address: u64,
    out: &mut [u8],
) -> Result<(), Error> {
    let mut done = 0;
    while done < out.len() {
        let at = address.checked_add(done as u64).ok_or(Error::Range)?;
        let frame = match code_frame(tasks, owner, at) {
            Some(frame) => frame,
            None => memory.resident(owner, at)?,
        };
        let offset = at as usize % 4096;
        let n = (4096 - offset).min(out.len() - done);
        unsafe {
            core::ptr::copy_nonoverlapping(
                frame_ptr(frame)?.add(offset),
                out.as_mut_ptr().add(done),
                n,
            );
        }
        done += n;
    }
    Ok(())
}
pub(super) fn copy_to(
    memory: &Memory<PAGES, 512>,
    owner: ObjectKey,
    address: u64,
    input: &[u8],
) -> Result<(), Error> {
    let mut done = 0;
    while done < input.len() {
        let at = address.checked_add(done as u64).ok_or(Error::Range)?;
        let frame = memory.resident(owner, at)?;
        let offset = at as usize % 4096;
        let n = (4096 - offset).min(input.len() - done);
        unsafe {
            core::ptr::copy_nonoverlapping(
                input.as_ptr().add(done),
                frame_ptr(frame)?.add(offset),
                n,
            );
        }
        done += n;
    }
    Ok(())
}
pub fn probe_user(owner: ObjectKey, address: u64, len: usize, writable: bool) -> Result<(), Error> {
    locked(|s| {
        let i = task_index(&s.tasks, owner)?;
        if s.tasks[i].life == Life::Exiting {
            return Err(Error::Stale);
        }
        prepare(
            &mut s.memory,
            &s.tasks,
            s.remote,
            owner,
            address,
            len,
            writable,
        )
    })
}
pub fn copyin(owner: ObjectKey, address: u64, out: &mut [u8]) -> Result<(), Error> {
    locked(|s| {
        let i = task_index(&s.tasks, owner)?;
        if s.tasks[i].life == Life::Exiting {
            return Err(Error::Stale);
        }
        prepare(
            &mut s.memory,
            &s.tasks,
            s.remote,
            owner,
            address,
            out.len(),
            false,
        )?;
        copy_from(&s.memory, &s.tasks, owner, address, out)
    })
}
pub fn copyout(owner: ObjectKey, address: u64, input: &[u8]) -> Result<(), Error> {
    locked(|s| {
        let i = task_index(&s.tasks, owner)?;
        if s.tasks[i].life == Life::Exiting {
            return Err(Error::Stale);
        }
        prepare(
            &mut s.memory,
            &s.tasks,
            s.remote,
            owner,
            address,
            input.len(),
            true,
        )?;
        copy_to(&s.memory, owner, address, input)
    })
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
