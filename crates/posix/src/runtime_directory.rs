//! Boot lifecycle of the current single-UID session's writable runtime files.
//! Reset only before user processes start, after durable filesystem recovery.
use crate::Errno;
use cyxia_ai_fs::{FileSystem, Kind, Path};

pub const DIRECTORY: &str = "/run/user/0";
pub const ENVIRONMENT: &[u8] = b"XDG_RUNTIME_DIR=/run/user/0";

pub fn reset_at_boot(fs: &mut FileSystem) -> Result<(), Errno> {
    for (name, mode) in [("/run", 0o755), ("/run/user", 0o755), (DIRECTORY, 0o700)] {
        let path = Path::resolve(Path::ROOT, name)?;
        match fs.stat(path) {
            Ok(entry) if entry.kind == Kind::Directory => {}
            Ok(_) => return Err(Errno::Notdir),
            Err(cyxia_ai_fs::Error::NotFound) => fs.mkdir(path)?,
            Err(error) => return Err(error.into()),
        }
        fs.set_mode(path, mode)?;
    }
    // There are at most NODES linked entries. Removing the deepest descendant
    // each time handles nested directories without recursion or allocation.
    while let Some(entry) = fs
        .entries()
        .filter(|entry| {
            entry
                .path
                .as_str()
                .strip_prefix(DIRECTORY)
                .is_some_and(|suffix| suffix.starts_with('/'))
        })
        .max_by_key(|entry| entry.path.as_str().len())
    {
        fs.remove(entry.path, entry.kind == Kind::Directory)?;
    }
    validate(fs)
}

/// Launch-time validation must not remove another live listener's lock file.
pub fn validate(fs: &FileSystem) -> Result<(), Errno> {
    let entry = fs.stat(Path::resolve(Path::ROOT, DIRECTORY)?)?;
    if entry.kind != Kind::Directory {
        return Err(Errno::Notdir);
    }
    if entry.mode != 0o700 {
        return Err(Errno::Access);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{O_CREAT, O_RDWR, OpenDescriptions, Process};

    fn path(name: &str) -> Path {
        Path::resolve(Path::ROOT, name).unwrap()
    }

    #[test]
    fn boot_prepares_private_runtime_and_launch_validation_preserves_live_files() {
        let mut fs = FileSystem::new();
        reset_at_boot(&mut fs).unwrap();
        assert_eq!(fs.stat(path(DIRECTORY)).unwrap().mode, 0o700);
        let objects = OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let fd = p
            .open(
                &mut fs,
                "/run/user/0/wayland-0.lock",
                O_CREAT | O_RDWR,
                0o660,
            )
            .unwrap();
        let inode = p.fstat(&fs, fd).unwrap().inode;
        validate(&fs).unwrap();
        assert_eq!(
            p.stat(&fs, "/run/user/0/wayland-0.lock").unwrap().inode,
            inode
        );
        assert_eq!(fs.stat(path(DIRECTORY)).unwrap().mode, 0o700);
        p.close_all(&mut fs).unwrap();
    }

    #[test]
    fn boot_removes_nested_runtime_state_but_preserves_neighbor_and_durable_files() {
        let mut fs = FileSystem::new();
        reset_at_boot(&mut fs).unwrap();
        fs.mkdir(path("/run/user/0/nested")).unwrap();
        fs.write(path("/run/user/0/nested/stale"), b"session", false)
            .unwrap();
        fs.write(path("/run/user/0/wayland-0.lock"), b"stale", false)
            .unwrap();
        fs.mkdir(path("/run/user/00")).unwrap();
        fs.write(path("/run/user/00/keep"), b"neighbor", false)
            .unwrap();
        fs.write(path("/keep"), b"durable", false).unwrap();
        let runtime_inode = fs.identity(path(DIRECTORY)).unwrap();
        reset_at_boot(&mut fs).unwrap();
        assert_eq!(
            fs.stat(path("/run/user/0/nested")).err(),
            Some(cyxia_ai_fs::Error::NotFound)
        );
        assert_eq!(
            fs.stat(path("/run/user/0/wayland-0.lock")).err(),
            Some(cyxia_ai_fs::Error::NotFound)
        );
        assert_eq!(fs.identity(path(DIRECTORY)).unwrap(), runtime_inode);
        let mut bytes = [0; 16];
        assert_eq!(fs.read(path("/run/user/00/keep"), &mut bytes).unwrap(), 8);
        assert_eq!(&bytes[..8], b"neighbor");
        assert_eq!(fs.read(path("/keep"), &mut bytes).unwrap(), 7);
        assert_eq!(&bytes[..7], b"durable");
    }

    #[test]
    fn runtime_validation_rejects_missing_nonprivate_or_non_directory_paths() {
        let mut fs = FileSystem::new();
        assert_eq!(validate(&fs), Err(Errno::Noent));
        fs.write(path("/run"), b"not a directory", false).unwrap();
        assert_eq!(reset_at_boot(&mut fs), Err(Errno::Notdir));
        assert_eq!(fs.stat(path("/run")).unwrap().kind, Kind::File);
        fs.remove(path("/run"), false).unwrap();
        reset_at_boot(&mut fs).unwrap();
        fs.set_mode(path(DIRECTORY), 0o755).unwrap();
        assert_eq!(validate(&fs), Err(Errno::Access));
        fs.remove(path(DIRECTORY), true).unwrap();
        fs.write(path(DIRECTORY), b"wrong kind", false).unwrap();
        assert_eq!(validate(&fs), Err(Errno::Notdir));
        assert_eq!(reset_at_boot(&mut fs), Err(Errno::Notdir));
    }
}
