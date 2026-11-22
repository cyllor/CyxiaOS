//! Bounded RAMFS rename adapter; CPU0 serializes validation and publication.
use super::{Errno, FileSystem, Runner};

impl Runner {
    pub(super) fn symlink_at(
        &mut self,
        fs: &mut FileSystem,
        target_address: u64,
        directory: i32,
        name_address: u64,
    ) -> Result<u64, Errno> {
        let mut target = [0; cyxia_ai_fs::PATH_BYTES];
        let mut name = [0; cyxia_ai_fs::PATH_BYTES];
        let target_len = self.path(target_address, &mut target)?;
        let name_len = self.path(name_address, &mut name)?;
        let target = core::str::from_utf8(&target[..target_len]).map_err(|_| Errno::Inval)?;
        let name = core::str::from_utf8(&name[..name_len]).map_err(|_| Errno::Inval)?;
        let link = self
            .process
            .path_at_with_follow(fs, directory, name, false)?;
        if self.readonly_asset(link).is_some() {
            return Err(Errno::Exist);
        }
        match super::unix::inspect(|s| s.pathname_stat(link.as_str().as_bytes())) {
            Ok(_) => return Err(Errno::Exist),
            Err(Errno::Noent) => {}
            Err(error) => return Err(error),
        }
        self.process.symlink_resolved(fs, target, link)?;
        Ok(0)
    }

    pub(super) fn readlink_at(
        &mut self,
        fs: &FileSystem,
        directory: i32,
        name_address: u64,
        output: u64,
        size: u64,
    ) -> Result<u64, Errno> {
        if size == 0 || size > isize::MAX as u64 {
            return Err(Errno::Inval);
        }
        let mut name = [0; cyxia_ai_fs::PATH_BYTES];
        let mut target = [0; cyxia_ai_fs::PATH_BYTES];
        let length = self.path(name_address, &mut name)?;
        let name = core::str::from_utf8(&name[..length]).map_err(|_| Errno::Inval)?;
        let capacity = (size as usize).min(target.len());
        let link = self
            .process
            .path_at_with_follow(fs, directory, name, false)?;
        if link.as_str() == "/dev/null" || self.readonly_asset(link).is_some() {
            return Err(Errno::Inval);
        }
        match super::unix::inspect(|s| s.pathname_stat(link.as_str().as_bytes())) {
            Ok(_) => return Err(Errno::Inval),
            Err(Errno::Noent) => {}
            Err(error) => return Err(error),
        }
        let length = fs.readlink(link, &mut target[..capacity])?;
        // Linux copies only the returned bytes and does not append a NUL.
        self.copy_to(output, &target[..length])?;
        Ok(length as u64)
    }

    pub(super) fn sync_file(&mut self, fs: &FileSystem, descriptor: u64) -> Result<u64, Errno> {
        let fd = super::fd(descriptor)?;
        let info = self.descriptor_stat(fs, fd)?;
        if !matches!(info.mode & 0o170000, 0o100000 | 0o040000) {
            return Err(Errno::Inval);
        }
        // Immutable boot bytes have no dirty state. Anonymous memfd storage
        // has no persistent backing, matching Linux's in-memory sync behavior.
        if self.process.readonly_file(fd)?.is_some() || self.process.memfd(fd)?.is_some() {
            return Ok(0);
        }
        // Both fsync and fdatasync use the stronger whole-RAMFS checkpoint.
        // Staging copies the data and namespace synchronously on CPU0, so a
        // later close/reuse cannot change the admitted generation's contents.
        match super::super::storage::start_checkpoint(fs) {
            Ok(generation) => {
                self.block(super::Wait::Checkpoint(generation));
                Ok(0)
            }
            Err(Errno::Busy) => {
                // An older snapshot may predate this caller's writes. Wait
                // for admission, then capture a fresh snapshot; never claim
                // that merely completing another caller's generation suffices.
                let identity = self.process.description_identity(fd)?;
                self.thread.context.restart_syscall()?;
                self.thread.retry_syscall = true;
                self.thread.retry_descriptor = Some((fd, identity));
                self.block(super::Wait::Retry(super::now().saturating_add(1)));
                Ok(descriptor)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn flock(&mut self, descriptor: u64, operation: u64) -> Result<u64, Errno> {
        let fd = descriptor as i32;
        let operation = u32::try_from(operation).map_err(|_| Errno::Inval)?;
        let result = self.process.flock(fd, operation);
        if result == Err(Errno::Again) && operation & cyxia_posix::flock::LOCK_NB == 0 {
            let identity = self.process.description_identity(fd)?;
            self.thread.context.restart_syscall()?;
            self.thread.retry_syscall = true;
            self.thread.retry_descriptor = Some((fd, identity));
            // Shared OFDs are serialized by CPU0. Yield until the next service
            // tick and validate the exact descriptor generation before replay.
            // Signal delivery chooses replay or EINTR from the caught action.
            self.block(super::Wait::Retry(super::now().saturating_add(1)));
            return Ok(descriptor);
        }
        result.map(|()| 0)
    }

    pub(super) fn rename_at(
        &mut self,
        fs: &mut FileSystem,
        old_fd: i32,
        old_name: u64,
        new_fd: i32,
        new_name: u64,
        flags: u64,
    ) -> Result<u64, Errno> {
        if flags & !1 != 0 {
            return Err(Errno::Inval);
        }
        let mut old = [0; cyxia_ai_fs::PATH_BYTES];
        let mut new = [0; cyxia_ai_fs::PATH_BYTES];
        let old_len = self.path(old_name, &mut old)?;
        let new_len = self.path(new_name, &mut new)?;
        let from = self.process.path_at_with_follow(
            fs,
            old_fd,
            core::str::from_utf8(&old[..old_len]).map_err(|_| Errno::Inval)?,
            false,
        )?;
        let to = self.process.path_at_with_follow(
            fs,
            new_fd,
            core::str::from_utf8(&new[..new_len]).map_err(|_| Errno::Inval)?,
            false,
        )?;
        if super::ROOT_FILES
            .iter()
            .any(|(path, _)| *path == from.as_str() || *path == to.as_str())
        {
            return Err(Errno::Rofs);
        }
        // Moving either socket entry requires one atomic update across both
        // namespaces. Until that exists, reject before touching either name.
        for path in [from, to] {
            match super::unix::inspect(|s| s.pathname_stat(path.as_str().as_bytes())) {
                Ok(_) => return Err(Errno::Opnotsupp),
                Err(Errno::Noent) => {}
                Err(error) => return Err(error),
            }
        }
        self.process
            .rename_file_resolved(fs, from, to, flags != 0)?;
        Ok(0)
    }
}
