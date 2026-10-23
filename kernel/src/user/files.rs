//! Bounded RAMFS rename adapter; CPU0 serializes validation and publication.
use super::{Errno, FileSystem, Runner};

impl Runner {
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
        let from = self.process.path_at(
            fs,
            old_fd,
            core::str::from_utf8(&old[..old_len]).map_err(|_| Errno::Inval)?,
        )?;
        let to = self.process.path_at(
            fs,
            new_fd,
            core::str::from_utf8(&new[..new_len]).map_err(|_| Errno::Inval)?,
        )?;
        if super::ROOT_FILES
            .iter()
            .any(|(path, _)| *path == from.as_str() || *path == to.as_str())
        {
            return Err(Errno::Rofs);
        }
        self.process
            .rename_file_resolved(fs, from, to, flags != 0)?;
        Ok(0)
    }
}
