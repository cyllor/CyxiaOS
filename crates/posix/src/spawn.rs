//! Explicit spawn table construction over shared open descriptions.
//! All sources are validated before reference acquisition; FD flags are private.
use super::open_description::Handle;
use super::{Description, Errno, O_RDWR, OPEN_MAX, Object, Process};
use cyxia_ai_fs::FileSystem;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub source: i32,
    pub target: i32,
}

struct Prepared {
    fds: [Option<Handle>; OPEN_MAX],
    cwd: cyxia_ai_fs::Path,
    nulls: [Handle; OPEN_MAX],
}

impl<'a> Process<'a> {
    fn prepare_spawn(
        &self,
        fs: &FileSystem,
        cwd: Option<&str>,
        mappings: &[Mapping],
    ) -> Result<Prepared, Errno> {
        if mappings.len() > OPEN_MAX {
            return Err(Errno::Inval);
        }
        let mut directory = Self::empty(self.objects, self.owner);
        directory.cwd = self.cwd;
        if let Some(cwd) = cwd {
            directory.chdir(fs, cwd)?;
        }
        let mut prepared = Prepared {
            fds: [None; OPEN_MAX],
            cwd: directory.cwd,
            nulls: [Handle {
                slot: 0,
                generation: 0,
            }; OPEN_MAX],
        };
        let mut used = [false; OPEN_MAX];
        let mut null_count = 0;
        for map in mappings {
            let target = usize::try_from(map.target)
                .ok()
                .filter(|v| *v < OPEN_MAX)
                .ok_or(Errno::Badf)?;
            if used[target] {
                return Err(Errno::Inval);
            }
            used[target] = true;
            if map.source == -1 {
                continue;
            }
            if map.source == -2 {
                null_count += 1;
                continue;
            }
            let handle = self.description(map.source)?;
            self.objects
                .references(handle)?
                .checked_add(OPEN_MAX as u16)
                .ok_or(Errno::Overflow)?;
            prepared.fds[target] = Some(handle);
        }
        self.objects.free_into(&mut prepared.nulls[..null_count])?;
        Ok(prepared)
    }
    /// Validate before process admission/publication. No references are acquired.
    /// Commit validates again under the same serialized supervisor execution.
    pub fn validate_spawn_descriptors(
        &self,
        fs: &FileSystem,
        cwd: Option<&str>,
        mappings: &[Mapping],
    ) -> Result<(), Errno> {
        self.prepare_spawn(fs, cwd, mappings).map(|_| ())
    }
    /// Read only from the parent table, so remapping cycles do not overwrite
    /// sources. Omissions/-1 close; -2 creates an independent /dev/null OFD.
    /// The returned table owns references and must be closed on launch failure.
    pub fn spawn_descriptors(
        &self,
        fs: &FileSystem,
        cwd: Option<&str>,
        mappings: &[Mapping],
        child_owner: u32,
    ) -> Result<Self, Errno> {
        if child_owner == 0 {
            return Err(Errno::Inval);
        }
        let prepared = self.prepare_spawn(fs, cwd, mappings)?;
        let mut child = Self::empty(self.objects, child_owner);
        child.cwd = prepared.cwd;
        child.mask = self.mask;
        // No callbacks/interleaving from preflight through commit. Each create
        // uses a distinct free generation; retain cannot overflow after preflight.
        for handle in prepared.fds.iter().flatten() {
            self.objects.retain(*handle)?;
        }
        child.fds = prepared.fds;
        for (map, handle) in mappings
            .iter()
            .filter(|m| m.source == -2)
            .zip(prepared.nulls)
        {
            self.objects.create(
                handle,
                child_owner,
                Description {
                    object: Object::Null,
                    offset: 0,
                    flags: O_RDWR,
                },
            )?;
            child.fds[map.target as usize] = Some(handle);
        }
        Ok(child)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{O_CLOEXEC, O_CREAT, O_NONBLOCK, O_RDWR};
    #[test]
    fn mappings_preserve_aliases_cwd_and_parent_without_unrequested_inheritance() {
        let mut fs = FileSystem::new();
        let objects = crate::OpenDescriptions::new();
        let mut parent = Process::new(&objects, 1).unwrap();
        parent.mkdir(&mut fs, "/work", 0o755).unwrap();
        parent.chdir(&fs, "/work").unwrap();
        let [r, w] = parent
            .install_pipe([256, 257], O_CLOEXEC | O_NONBLOCK)
            .unwrap();
        let child = parent
            .spawn_descriptors(
                &fs,
                None,
                &[
                    Mapping {
                        source: r,
                        target: 1,
                    },
                    Mapping {
                        source: r,
                        target: 2,
                    },
                    Mapping {
                        source: -2,
                        target: 0,
                    },
                ],
                2,
            )
            .unwrap();
        assert_eq!(child.pipe(1), Ok(Some(256)));
        assert_eq!(child.pipe(2), Ok(Some(256)));
        assert_eq!(child.last_reference(1), Ok(false));
        assert_eq!(child.close_on_exec(1), Ok(false));
        assert_eq!(child.pipe(w), Err(Errno::Badf));
        assert_eq!(child.backend_owner(1), Ok(1));
        assert_eq!(parent.close_on_exec(r), Ok(true));
        let mut path = [0; 96];
        assert_eq!(child.getcwd(&mut path), Ok(6));
        assert_eq!(&path[..6], b"/work\0");
    }
    #[test]
    fn invalid_maps_fail_without_parent_mutation() {
        let mut fs = FileSystem::new();
        let objects = crate::OpenDescriptions::new();
        let mut parent = Process::new(&objects, 1).unwrap();
        let file = parent
            .open(&mut fs, "/file", O_CREAT | O_RDWR, 0o600)
            .unwrap();
        assert!(matches!(
            parent.spawn_descriptors(
                &fs,
                None,
                &[Mapping {
                    source: 100,
                    target: 0
                }],
                2
            ),
            Err(Errno::Badf)
        ));
        assert!(matches!(
            parent.spawn_descriptors(
                &fs,
                None,
                &[
                    Mapping {
                        source: 1,
                        target: 0
                    },
                    Mapping {
                        source: 2,
                        target: 0
                    }
                ],
                2
            ),
            Err(Errno::Inval)
        ));
        assert!(matches!(
            parent.spawn_descriptors(&fs, Some("/missing"), &[], 2),
            Err(Errno::Noent)
        ));
        assert!(parent.fstat(&fs, file).is_ok());
        assert_eq!(parent.flags(1), Ok(crate::O_WRONLY));
    }
}
