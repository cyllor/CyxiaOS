//! Per-process virtual aliases of the independent shared backing pool.
use super::ai::{self, Domain};
use super::{Errno, Runner};
use cyxia_ai_runtime::accounting::Attempt;
use cyxia_arch_aarch64::mmu;
use cyxia_contracts::PhysAddr;
pub(super) use cyxia_posix::shared_memory::{BASE, END};
use cyxia_posix::{
    FileInfo,
    shared_memory::{Mapping, Maps, PAGE_SIZE, PAGES},
};
#[repr(C, align(4096))]
struct Table([u64; 512]);
pub(super) struct SharedMappings {
    maps: Maps,
    tables: [Table; PAGES / 512],
}
impl SharedMappings {
    pub const fn new() -> Self {
        Self {
            maps: Maps::new(),
            tables: [const { Table([0; 512]) }; PAGES / 512],
        }
    }
    pub fn roots(&self) -> [(usize, u64); PAGES / 512] {
        core::array::from_fn(|i| {
            (
                (BASE / 0x200000) as usize + i,
                (&self.tables[i] as *const Table as u64 - crate::HIGH) | 3,
            )
        })
    }
    fn publish(&mut self, m: Mapping) -> Result<(), Errno> {
        // All slots and addresses are already proved by hold_mapping. No EL0
        // execution occurs between validation and PTE publication.
        for page in 0..m.pages() {
            let i = ((m.start - BASE) / PAGE_SIZE as u64) as usize + page;
            self.tables[i / 512].0[i % 512] = if m.protection == 0 {
                0
            } else {
                let pa = crate::shared_memory::physical(m.handle, m.offset / PAGE_SIZE + page)?;
                mmu::encode_user_leaf(PhysAddr(pa), m.protection & 2 != 0, false)
                    .map_err(|_| Errno::Io)?
            };
        }
        Ok(())
    }
    fn map(
        &mut self,
        handle: u64,
        offset: usize,
        len: usize,
        protection: u8,
        fd_writable: bool,
    ) -> Result<u64, Errno> {
        let mut attempt = Attempt::default();
        let result = (|| {
            let may_write =
                crate::shared_memory::mapping_permissions(handle, protection, fd_writable)?;
            let m = self
                .maps
                .prepare(handle, offset, len, protection, may_write)?;
            let info = crate::shared_memory::info(handle)?;
            if offset.checked_add(len).is_none_or(|end| end > info.size) {
                return Err(Errno::Inval);
            }
            attempt.proposed(8193);
            let (allowed, model) = cyxia_ai_runtime::user_memory_policy(self.maps.free() as u32, 1)
                .map_err(|_| Errno::Io)?;
            attempt.decided(allowed, model);
            if !allowed {
                return Err(Errno::Nomem);
            }
            crate::shared_memory::hold_mapping(handle, offset, len, may_write)?;
            self.maps.insert(m).expect("preflighted shared mapping");
            self.publish(m).expect("validated shared RAM PTE");
            ai::record(Domain::SharedMappings, |c| c.grant(1));
            Ok(m.start)
        })();
        ai::admission(Domain::SharedMappings, attempt, &result);
        result
    }
    pub fn unmap(&mut self, address: u64, pages: usize) -> Result<(), Errno> {
        let m = self.maps.whole(address, pages)?;
        for page in 0..m.pages() {
            let i = ((m.start - BASE) / PAGE_SIZE as u64) as usize + page;
            self.tables[i / 512].0[i % 512] = 0;
        }
        // CPU0 has disabled TTBR0 and completed a global TLBI on EL0 return.
        // Revoke first; another process's alias retains its mapping reference.
        self.maps.remove(address, pages)?;
        crate::shared_memory::drop_mapping(m.handle, m.may_write)?;
        ai::record(Domain::SharedMappings, |c| c.release(1));
        Ok(())
    }
    pub fn clear(&mut self) {
        loop {
            let next = self.maps.iter().next();
            let Some(m) = next else {
                break;
            };
            self.unmap(m.start, m.pages())
                .expect("owned shared mapping after revoke");
        }
    }
    pub fn validate(&self, address: u64, len: usize, write: bool) -> Result<(), Errno> {
        self.maps.access(address, len, write).map(|_| ())
    }
    pub fn read(&self, address: u64, out: &mut [u8]) -> Result<(), Errno> {
        if out.is_empty() {
            return Ok(());
        }
        let m = self.maps.access(address, out.len(), false)?;
        crate::shared_memory::copy_mapping(
            m.handle,
            m.offset + (address - m.start) as usize,
            out,
            false,
        )
    }
    pub fn write(&self, address: u64, data: &[u8]) -> Result<(), Errno> {
        if data.is_empty() {
            return Ok(());
        }
        let m = self.maps.access(address, data.len(), true)?;
        crate::shared_memory::write_mapping(m.handle, m.offset + (address - m.start) as usize, data)
    }
    fn protect(&mut self, address: u64, len: usize, protection: u8) -> Result<(), Errno> {
        let m = self.maps.protect(address, len, protection)?;
        self.publish(m)
    }
}
impl Runner {
    pub(super) fn memfd_create(&mut self, name: u64, flags: u64) -> Result<u64, Errno> {
        if flags & !3 != 0 {
            return Err(Errno::Inval);
        }
        let mut terminated = false;
        for i in 0..250u64 {
            let mut byte = [0];
            self.copy_from(name.checked_add(i).ok_or(Errno::Fault)?, &mut byte)?;
            if byte[0] == 0 {
                terminated = true;
                break;
            }
        }
        if !terminated {
            return Err(Errno::Inval);
        }
        let owner = self.lease.ok_or(Errno::Perm)?.0;
        let handle = crate::shared_memory::create(owner, flags & 2 != 0)?;
        match self.process.install_memfd(
            handle,
            if flags & 1 != 0 {
                cyxia_posix::O_CLOEXEC
            } else {
                0
            },
        ) {
            Ok(fd) => Ok(fd as u64),
            Err(error) => {
                crate::shared_memory::release_description(handle)?;
                Err(error)
            }
        }
    }
    fn memfd_handle(&self, fd: i32) -> Result<u64, Errno> {
        self.process.memfd(fd)?.ok_or(Errno::Inval)
    }
    pub(super) fn memfd_resize(&mut self, fd: i32, length: u64) -> Result<u64, Errno> {
        let (handle, _, _) = self.process.memfd_position(fd, true)?;
        crate::shared_memory::resize(handle, usize::try_from(length).map_err(|_| Errno::Inval)?)?;
        Ok(0)
    }
    pub(super) fn memfd_control(&mut self, fd: i32, command: u64, arg: u64) -> Result<u64, Errno> {
        let handle = self.memfd_handle(fd)?;
        match command {
            1033 => {
                if self.process.flags(fd)? & 3 == cyxia_posix::O_RDONLY {
                    return Err(Errno::Perm);
                }
                crate::shared_memory::add_seals(
                    handle,
                    u32::try_from(arg).map_err(|_| Errno::Inval)?,
                )?;
                Ok(0)
            }
            1034 => Ok(u64::from(crate::shared_memory::info(handle)?.seals)),
            _ => Err(Errno::Inval),
        }
    }
    pub(super) fn memfd_info(&self, fd: i32) -> Result<FileInfo, Errno> {
        let h = self.memfd_handle(fd)?;
        let info = crate::shared_memory::info(h)?;
        Ok(FileInfo {
            inode: 0x8000_0000_0000_0000 | h,
            size: info.size as u64,
            mode: 0o100600,
            links: 0,
        })
    }
    pub(super) fn read_memfd(&mut self, fd: i32, out: &mut [u8]) -> Result<usize, Errno> {
        let (handle, offset, _) = self.process.memfd_position(fd, false)?;
        let n = crate::shared_memory::read(
            handle,
            usize::try_from(offset).map_err(|_| Errno::Overflow)?,
            out,
        )?;
        self.process.set_memfd_position(fd, offset + n as u64)?;
        Ok(n)
    }
    fn positioned_memfd(&self, fd: i32, writing: bool) -> Result<(u64, u32), Errno> {
        if self.process.memfd(fd)?.is_some() {
            let (handle, _, flags) = self.process.memfd_position(fd, writing)?;
            return Ok((handle, flags));
        }
        if self.process.socket(fd)?.is_some()
            || self.process.pipe(fd)?.is_some()
            || self.process.pty(fd)?.is_some()
            || self.process.is_eventfd(fd)?
            || self.process.is_timerfd(fd)?
            || self.process.is_epoll(fd)?
        {
            return Err(Errno::Spipe);
        }
        // Positioned I/O for other filesystem objects is not implemented by
        // this bounded path. Never emulate it by changing a shared OFD offset.
        Err(Errno::Nosys)
    }
    pub(super) fn read_memfd_at(
        &self,
        fd: i32,
        offset: usize,
        out: &mut [u8],
    ) -> Result<usize, Errno> {
        let (handle, _) = self.positioned_memfd(fd, false)?;
        crate::shared_memory::read(handle, offset, out)
    }
    pub(super) fn write_memfd_at(
        &self,
        fd: i32,
        mut offset: usize,
        bytes: &[u8],
    ) -> Result<usize, Errno> {
        let (handle, flags) = self.positioned_memfd(fd, true)?;
        // The Linux pwrite64 syscall honors O_APPEND without advancing the
        // OFD offset. musl's POSIX pwrite wrapper rejects that fallback when
        // RWF_NOAPPEND is unavailable. Zero-length writes never grow the file.
        if !bytes.is_empty() && flags & cyxia_posix::O_APPEND != 0 {
            offset = crate::shared_memory::info(handle)?.size;
        }
        crate::shared_memory::write(handle, offset, bytes)
    }
    pub(super) fn write_memfd(&mut self, fd: i32, bytes: &[u8]) -> Result<usize, Errno> {
        let (handle, mut offset, flags) = self.process.memfd_position(fd, true)?;
        // Validate access even for zero bytes, but do not apply append or move
        // the shared OFD offset when no data is written.
        if bytes.is_empty() {
            return Ok(0);
        }
        if flags & cyxia_posix::O_APPEND != 0 {
            offset = crate::shared_memory::info(handle)?.size as u64;
        }
        let n = crate::shared_memory::write(
            handle,
            usize::try_from(offset).map_err(|_| Errno::Overflow)?,
            bytes,
        )?;
        self.process.set_memfd_position(fd, offset + n as u64)?;
        Ok(n)
    }
    pub(super) fn seek_memfd(&mut self, fd: i32, offset: i64, whence: u32) -> Result<u64, Errno> {
        let (handle, current, _) = self.process.memfd_position(fd, false)?;
        let base = match whence {
            0 => 0,
            1 => current,
            2 => crate::shared_memory::info(handle)?.size as u64,
            _ => return Err(Errno::Inval),
        };
        let next = i128::from(base) + i128::from(offset);
        if next < 0 || next > i128::from(i64::MAX) {
            return Err(Errno::Inval);
        }
        self.process.set_memfd_position(fd, next as u64)?;
        Ok(next as u64)
    }
    pub(super) fn map_shared(
        &mut self,
        fd: i32,
        offset: u64,
        len: usize,
        protection: u8,
    ) -> Result<u64, Errno> {
        let (handle, _, flags) = self.process.memfd_position(fd, false)?;
        self.shared.map(
            handle,
            usize::try_from(offset).map_err(|_| Errno::Inval)?,
            len,
            protection,
            flags & 3 != cyxia_posix::O_RDONLY,
        )
    }
    /// Bounded MAP_PRIVATE of a fully immutable memfd. Eager copying uses the
    /// existing anonymous AI grant, PTE, mprotect and unmap ownership paths.
    /// This is not general mutable-file mmap or lazy copy-on-write.
    #[cfg(feature = "ported")]
    pub(super) fn map_private_sealed(
        &mut self,
        fd: i32,
        offset: u64,
        len: usize,
        protection: u8,
    ) -> Result<u64, Errno> {
        let (handle, _, _) = self.process.memfd_position(fd, false)?;
        let offset = usize::try_from(offset).map_err(|_| Errno::Inval)?;
        let copy_len =
            crate::shared_memory::private_snapshot_bytes(handle, offset, len, protection)?;
        let pages = len.div_ceil(PAGE_SIZE);
        let address = self.heap.allocate(pages)?;
        let result = (|| {
            // CPU0 is serialized and EL0 remains stopped. The validated OFD
            // retains immutable backing until this syscall completes. Copy in
            // bounded chunks without a page-sized exception-stack allocation.
            let mut bytes = [0; 256];
            let mut done = 0;
            while done < copy_len {
                let n = (copy_len - done).min(bytes.len());
                let read = crate::shared_memory::read(handle, offset + done, &mut bytes[..n])?;
                if read != n {
                    return Err(Errno::Io);
                }
                self.heap.write(address + done as u64, &bytes[..n])?;
                done += n;
            }
            // Heap allocation zeroed the tail beyond EOF. Apply requested
            // permissions only after every byte is initialized.
            self.heap.protect(address, pages * PAGE_SIZE, protection)?;
            Ok(address)
        })();
        if result.is_err() {
            self.heap.unmap(address, pages)?;
        }
        result
    }
    pub(super) fn unmap_shared(&mut self, address: u64, pages: usize) -> Result<(), Errno> {
        self.shared.unmap(address, pages)
    }
    pub(super) fn protect_shared(
        &mut self,
        address: u64,
        len: usize,
        protection: u8,
    ) -> Result<(), Errno> {
        self.shared.protect(address, len, protection)
    }
}
