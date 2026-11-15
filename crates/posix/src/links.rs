//! Bounded symbolic-link expansion without lexically collapsing unwalked '..'.
use super::*;
use cyxia_ai_fs::PATH_BYTES;

const MAX_LINKS: usize = 40;

/// The base is already authorized by the cwd/directory descriptor. Only
/// directories actually traversed from that base are checked for search access.
pub(super) fn resolve(
    fs: &FileSystem,
    base: Path,
    input: &str,
    follow_final: bool,
) -> Result<Path, Errno> {
    if input.is_empty() {
        return Err(Errno::Noent);
    }
    if input.len() >= PATH_BYTES {
        return Err(Errno::Nametoolong);
    }
    let mut pending = [0; PATH_BYTES];
    pending[..input.len()].copy_from_slice(input.as_bytes());
    let mut len = input.len();
    let mut cursor = 0;
    let mut followed = 0;
    let mut path = if input.starts_with('/') {
        Path::ROOT
    } else {
        base
    };
    loop {
        while cursor < len && pending[cursor] == b'/' {
            cursor += 1;
        }
        if cursor == len {
            if pending[len - 1] == b'/'
                && (path.as_str() == NULL_DEVICE_PATH || fs.stat(path)?.kind != Kind::Directory)
            {
                return Err(Errno::Notdir);
            }
            return Ok(path);
        }
        if path.as_str() == NULL_DEVICE_PATH {
            return Err(Errno::Notdir);
        }
        let parent = fs.stat(path)?;
        if parent.kind != Kind::Directory {
            return Err(Errno::Notdir);
        }
        if parent.mode & 0o100 == 0 {
            return Err(Errno::Access);
        }
        let start = cursor;
        while cursor < len && pending[cursor] != b'/' {
            cursor += 1;
        }
        let component = core::str::from_utf8(&pending[start..cursor]).map_err(|_| Errno::Inval)?;
        let next = Path::resolve(path, component)?;
        let follow = follow_final || cursor < len;
        let is_link = if follow {
            match fs.stat(next) {
                Ok(info) => info.kind == Kind::Symlink,
                Err(Error::NotFound) => false,
                Err(error) => return Err(error.into()),
            }
        } else {
            false
        };
        if !is_link {
            path = next;
            continue;
        }
        if followed == MAX_LINKS {
            return Err(Errno::Loop);
        }
        followed += 1;
        let mut target = [0; PATH_BYTES];
        let target_len = fs.readlink(next, &mut target)?;
        let remaining = len - cursor;
        if target_len == 0 {
            return Err(Errno::Noent);
        }
        if target_len + remaining >= PATH_BYTES {
            return Err(Errno::Nametoolong);
        }
        let target_text = core::str::from_utf8(&target[..target_len]).map_err(|_| Errno::Inval)?;
        if target_text.starts_with('/') {
            path = Path::ROOT;
        }
        // Relative targets start at the link's parent, which is still `path`.
        // The untouched suffix retains separators, trailing '/', and '..'.
        pending.copy_within(cursor..len, target_len);
        pending[..target_len].copy_from_slice(&target[..target_len]);
        len = target_len + remaining;
        cursor = 0;
    }
}

impl Process<'_> {
    /// The caller resolves the destination with final-component nofollow and
    /// rejects collisions with any separate immutable boot-file catalog.
    pub fn symlink_resolved(
        &self,
        fs: &mut FileSystem,
        target: &str,
        link: Path,
    ) -> Result<(), Errno> {
        if target.is_empty() {
            return Err(Errno::Noent);
        }
        self.change_parent(fs, link)?;
        if link.as_str() == NULL_DEVICE_PATH {
            return Err(Errno::Exist);
        }
        fs.symlink(link, target)?;
        Ok(())
    }

    pub fn symlink_at(
        &self,
        fs: &mut FileSystem,
        target: &str,
        fd: i32,
        link: &str,
    ) -> Result<(), Errno> {
        let link = self.path_at_with_follow(fs, fd, link, false)?;
        self.symlink_resolved(fs, target, link)
    }

    pub fn readlink_at(
        &self,
        fs: &FileSystem,
        fd: i32,
        path: &str,
        out: &mut [u8],
    ) -> Result<usize, Errno> {
        if out.is_empty() {
            return Err(Errno::Inval);
        }
        let path = self.path_at_with_follow(fs, fd, path, false)?;
        if path.as_str() == NULL_DEVICE_PATH {
            return Err(Errno::Inval);
        }
        fs.readlink(path, out).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;
