//! Advisory locks owned by shared open file descriptions. Lock modes occupy
//! existing bounded OFD entries; no lock allocation or admission pool is needed.
use crate::{Errno, Object, Process};

pub const LOCK_SH: u32 = 1;
pub const LOCK_EX: u32 = 2;
pub const LOCK_NB: u32 = 4;
pub const LOCK_UN: u32 = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Unlocked,
    Shared,
    Exclusive,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Identity {
    // Pinned RAM handles include the inode generation. Other backends have
    // distinct identity namespaces even if their numeric inode values match.
    Ram(cyxia_ai_fs::Inode),
    Root,
    ReadOnly(u64),
    Memfd(u64),
}

fn identity(object: Object) -> Result<Identity, Errno> {
    match object {
        Object::File(inode)
        | Object::Directory {
            inode: Some(inode), ..
        } => Ok(Identity::Ram(inode)),
        Object::Directory { inode: None, .. } => Ok(Identity::Root),
        Object::ReadOnly(inode, ..) => Ok(Identity::ReadOnly(inode)),
        Object::Memfd(handle) => Ok(Identity::Memfd(handle)),
        _ => Err(Errno::Nosys),
    }
}

impl Process<'_> {
    /// Attempt one shared/exclusive lock transition or explicit unlock.
    ///
    /// Conflicts return `Again` with or without `LOCK_NB`; the supervisor owns
    /// interruptible yielding/retries and validates the saved OFD identity.
    /// `O_NONBLOCK` and the open access mode do not alter flock behavior.
    /// RAM files/directories, immutable boot files and memfds are supported.
    /// Other descriptor types return `Nosys`, including unlock requests.
    pub fn flock(&self, fd: i32, operation: u32) -> Result<(), Errno> {
        let handle = self.description(fd)?;
        let mut table = self.objects.inner.borrow_mut();
        let entry = table.entry(handle)?;
        let mode = match operation & !LOCK_NB {
            LOCK_SH => Mode::Shared,
            LOCK_EX => Mode::Exclusive,
            LOCK_UN => Mode::Unlocked,
            _ => return Err(Errno::Inval),
        };
        let inode = identity(entry.value.ok_or(Errno::Badf)?.object)?;
        if entry.flock == mode {
            return Ok(());
        }
        // Linux conversion first drops the old lock. A conflicting upgrade
        // therefore leaves this description unlocked, including with LOCK_NB.
        table.entries[handle.slot].flock = Mode::Unlocked;
        if mode != Mode::Unlocked
            && table.entries.iter().enumerate().any(|(slot, other)| {
                slot != handle.slot
                    && other.flock != Mode::Unlocked
                    && (mode == Mode::Exclusive || other.flock == Mode::Exclusive)
                    && matches!(other.value, Some(description)
                        if identity(description.object) == Ok(inode))
            })
        {
            return Err(Errno::Again);
        }
        table.entries[handle.slot].flock = mode;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{O_CREAT, O_RDWR, OpenDescriptions};
    use cyxia_ai_fs::FileSystem;

    #[test]
    fn exclusive_lock_conflicts_between_independent_opens_until_unlock() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut process = Process::new(&objects, 1).unwrap();
        let first = process
            .open(&mut fs, "/lock", O_CREAT | O_RDWR, 0o600)
            .unwrap();
        let second = process.open(&mut fs, "/lock", O_RDWR, 0).unwrap();

        assert_eq!(process.flock(first, LOCK_EX | LOCK_NB), Ok(()));
        assert_eq!(process.flock(second, LOCK_EX | LOCK_NB), Err(Errno::Again));
        assert_eq!(process.flock(first, LOCK_UN), Ok(()));
        assert_eq!(process.flock(second, LOCK_EX | LOCK_NB), Ok(()));
        process.close_all(&mut fs).unwrap();
    }

    #[test]
    fn shared_locks_coexist_and_exclude_exclusive_lock_regardless_of_open_mode() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut first = Process::new(&objects, 1).unwrap();
        let mut second = Process::new(&objects, 2).unwrap();
        let a = first
            .open(&mut fs, "/lock", O_CREAT | O_RDWR, 0o600)
            .unwrap();
        let b = second.open(&mut fs, "/lock", crate::O_RDONLY, 0).unwrap();
        let exclusive = first.open(&mut fs, "/lock", crate::O_RDONLY, 0).unwrap();

        assert_eq!(first.flock(a, LOCK_SH), Ok(()));
        assert_eq!(second.flock(b, LOCK_SH | LOCK_NB), Ok(()));
        assert_eq!(first.flock(a, LOCK_SH | LOCK_NB), Ok(()));
        assert_eq!(first.flock(exclusive, LOCK_EX | LOCK_NB), Err(Errno::Again));
        first.flock(a, LOCK_UN).unwrap();
        assert_eq!(first.flock(exclusive, LOCK_EX | LOCK_NB), Err(Errno::Again));
        second.flock(b, LOCK_UN).unwrap();
        assert_eq!(first.flock(exclusive, LOCK_EX | LOCK_NB), Ok(()));
        assert_eq!(second.flock(b, LOCK_SH | LOCK_NB), Err(Errno::Again));
        first.close_all(&mut fs).unwrap();
        second.close_all(&mut fs).unwrap();
    }

    #[test]
    fn failed_upgrade_releases_old_lock_and_downgrade_admits_shared_waiter() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut process = Process::new(&objects, 1).unwrap();
        let first = process
            .open(&mut fs, "/lock", O_CREAT | O_RDWR, 0o600)
            .unwrap();
        let second = process.open(&mut fs, "/lock", O_RDWR, 0).unwrap();

        process.flock(first, LOCK_SH).unwrap();
        process.flock(second, LOCK_SH).unwrap();
        assert_eq!(process.flock(first, LOCK_EX | LOCK_NB), Err(Errno::Again));
        // The failed upgrade dropped the first description's shared lock.
        assert_eq!(process.flock(second, LOCK_EX | LOCK_NB), Ok(()));
        assert_eq!(process.flock(first, LOCK_SH | LOCK_NB), Err(Errno::Again));
        assert_eq!(process.flock(second, LOCK_EX), Ok(()));
        assert_eq!(process.flock(second, LOCK_SH), Ok(()));
        assert_eq!(process.flock(first, LOCK_SH | LOCK_NB), Ok(()));
        process.close_all(&mut fs).unwrap();
    }

    #[test]
    fn directory_and_root_locks_use_stable_distinct_inodes_after_replacement() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut process = Process::new(&objects, 1).unwrap();
        process.mkdir(&mut fs, "/directory", 0o700).unwrap();
        let first = process
            .open(&mut fs, "/directory", crate::O_DIRECTORY, 0)
            .unwrap();
        let second = process
            .open(&mut fs, "/directory", crate::O_DIRECTORY, 0)
            .unwrap();
        let root = process.open(&mut fs, "/", crate::O_DIRECTORY, 0).unwrap();
        let root_again = process.open(&mut fs, "/", crate::O_DIRECTORY, 0).unwrap();

        assert_eq!(process.flock(first, LOCK_EX), Ok(()));
        assert_eq!(process.flock(second, LOCK_SH | LOCK_NB), Err(Errno::Again));
        assert_eq!(process.flock(root, LOCK_EX), Ok(()));
        assert_eq!(
            process.flock(root_again, LOCK_EX | LOCK_NB),
            Err(Errno::Again)
        );
        process.rmdir(&mut fs, "/directory").unwrap();
        process.mkdir(&mut fs, "/directory", 0o700).unwrap();
        let replacement = process
            .open(&mut fs, "/directory", crate::O_DIRECTORY, 0)
            .unwrap();
        assert_eq!(process.flock(replacement, LOCK_EX), Ok(()));
        assert_eq!(process.flock(second, LOCK_EX | LOCK_NB), Err(Errno::Again));
        process.close(&mut fs, first).unwrap();
        assert_eq!(process.flock(second, LOCK_EX | LOCK_NB), Ok(()));
        process.close_all(&mut fs).unwrap();
    }

    #[test]
    fn readonly_assets_share_locks_by_inode_without_aliasing_ram_or_root() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut process = Process::new(&objects, 1).unwrap();
        let ram = process
            .open(&mut fs, "/lock", O_CREAT | O_RDWR, 0o600)
            .unwrap();
        let root = process.open(&mut fs, "/", crate::O_DIRECTORY, 0).unwrap();
        let inode = process.fstat(&fs, ram).unwrap().inode;
        let first = process.open_readonly(inode, b"asset", 0).unwrap();
        let second = process.open_readonly(inode, b"asset", 0).unwrap();
        let other = process.open_readonly(1, b"other asset", 0).unwrap();

        process.flock(ram, LOCK_EX).unwrap();
        process.flock(root, LOCK_EX).unwrap();
        assert_eq!(process.flock(first, LOCK_EX), Ok(()));
        assert_eq!(process.flock(second, LOCK_EX | LOCK_NB), Err(Errno::Again));
        assert_eq!(process.flock(other, LOCK_EX), Ok(()));
        process.close(&mut fs, first).unwrap();
        assert_eq!(process.flock(second, LOCK_EX | LOCK_NB), Ok(()));
        process.close_all(&mut fs).unwrap();
    }

    #[test]
    fn memfd_locks_follow_shared_description_and_do_not_alias_readonly_inodes() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut backings = crate::shared_memory::Backings::new();
        let mut process = Process::new(&objects, 1).unwrap();
        let handle = backings.create(false).unwrap();
        let first = process.install_memfd(handle, 0).unwrap();
        let alias = process.dup(first).unwrap();
        let readonly = process.open_readonly(handle, b"asset", 0).unwrap();
        let other_handle = backings.create(false).unwrap();
        let other = process.install_memfd(other_handle, 0).unwrap();

        assert_eq!(process.flock(first, LOCK_EX), Ok(()));
        assert_eq!(process.flock(alias, LOCK_EX | LOCK_NB), Ok(()));
        assert_eq!(process.flock(readonly, LOCK_EX), Ok(()));
        assert_eq!(process.flock(other, LOCK_EX), Ok(()));
        assert_eq!(process.close(&mut fs, first), Ok(None));
        assert_eq!(process.flock(alias, LOCK_SH), Ok(()));
        assert_eq!(process.flock(alias, LOCK_UN), Ok(()));
        let released = process.close_all(&mut fs).unwrap();
        let mut batch = crate::shared_memory::Batch::new();
        for release in released.into_iter().flatten() {
            if let crate::Released::Memfd { handle } = release {
                backings.close_description(handle, &mut batch).unwrap();
            }
        }
        assert_eq!(backings.live_objects(), 0);
    }

    #[test]
    fn duplicate_and_inherited_descriptions_share_unlock_and_retain_until_last_close() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut parent = Process::new(&objects, 1).unwrap();
        let mut contender = Process::new(&objects, 3).unwrap();
        let file = parent
            .open(&mut fs, "/lock", O_CREAT | O_RDWR, 0o600)
            .unwrap();
        let alias = parent.dup(file).unwrap();
        let mut child = parent
            .spawn_descriptors(
                &fs,
                None,
                &[crate::spawn::Mapping {
                    source: alias,
                    target: 8,
                }],
                2,
            )
            .unwrap();
        let separate = contender.open(&mut fs, "/lock", O_RDWR, 0).unwrap();

        parent.flock(file, LOCK_EX).unwrap();
        assert_eq!(child.flock(8, LOCK_EX | LOCK_NB), Ok(()));
        parent.close(&mut fs, file).unwrap();
        assert_eq!(
            contender.flock(separate, LOCK_EX | LOCK_NB),
            Err(Errno::Again)
        );
        parent.flock(alias, LOCK_UN).unwrap();
        assert_eq!(contender.flock(separate, LOCK_EX | LOCK_NB), Ok(()));
        contender.flock(separate, LOCK_UN).unwrap();
        child.flock(8, LOCK_EX).unwrap();
        parent.close_all(&mut fs).unwrap();
        assert_eq!(
            contender.flock(separate, LOCK_EX | LOCK_NB),
            Err(Errno::Again)
        );
        child.close_all(&mut fs).unwrap();
        assert_eq!(contender.flock(separate, LOCK_EX | LOCK_NB), Ok(()));
        contender.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
    }

    #[test]
    fn queued_rights_retain_lock_until_discard_truncation_or_received_final_close() {
        for scenario in 0..4 {
            let objects = OpenDescriptions::new();
            let mut fs = FileSystem::new();
            let mut sender = Process::new(&objects, 1).unwrap();
            let mut receiver = Process::new(&objects, 2).unwrap();
            let mut contender = Process::new(&objects, 3).unwrap();
            let file = sender
                .open(&mut fs, "/lock", O_CREAT | O_RDWR, 0o600)
                .unwrap();
            let separate = contender.open(&mut fs, "/lock", O_RDWR, 0).unwrap();
            sender.flock(file, LOCK_EX).unwrap();
            let ticket = sender.stage_rights(&[file]).unwrap();
            sender.close_all(&mut fs).unwrap();
            assert_eq!(
                contender.flock(separate, LOCK_EX | LOCK_NB),
                Err(Errno::Again)
            );
            if scenario != 0 {
                objects.commit_rights(ticket).unwrap();
                assert_eq!(
                    contender.flock(separate, LOCK_EX | LOCK_NB),
                    Err(Errno::Again)
                );
            }
            if scenario < 2 {
                objects.discard_rights(&mut fs, ticket).unwrap();
            } else {
                let received = receiver
                    .receive_rights(&mut fs, ticket, if scenario == 2 { 1 } else { 0 }, false)
                    .unwrap();
                if scenario == 2 {
                    assert_eq!(received.count, 1);
                    assert_eq!(receiver.flock(received.fds[0], LOCK_EX), Ok(()));
                    assert_eq!(
                        contender.flock(separate, LOCK_EX | LOCK_NB),
                        Err(Errno::Again)
                    );
                    receiver.close(&mut fs, received.fds[0]).unwrap();
                } else {
                    assert!(received.truncated);
                    assert_eq!(received.count, 0);
                }
            }
            assert_eq!(contender.flock(separate, LOCK_EX | LOCK_NB), Ok(()));
            receiver.close_all(&mut fs).unwrap();
            contender.close_all(&mut fs).unwrap();
            assert_eq!(objects.snapshot().references, 0);
        }
    }

    #[test]
    fn rename_and_unlink_recreate_keep_locks_attached_to_original_inodes() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut process = Process::new(&objects, 1).unwrap();
        let source = process
            .open(&mut fs, "/source", O_CREAT | O_RDWR, 0o600)
            .unwrap();
        let replaced = process
            .open(&mut fs, "/target", O_CREAT | O_RDWR, 0o600)
            .unwrap();
        let source_inode = process.fstat(&fs, source).unwrap().inode;
        process.flock(source, LOCK_EX).unwrap();
        process.flock(replaced, LOCK_EX).unwrap();
        let from = process.resolved_path(&fs, "/source").unwrap();
        let to = process.resolved_path(&fs, "/target").unwrap();
        process
            .rename_file_resolved(&mut fs, from, to, false)
            .unwrap();
        let renamed = process.open(&mut fs, "/target", O_RDWR, 0).unwrap();
        assert_eq!(process.fstat(&fs, renamed).unwrap().inode, source_inode);
        assert_eq!(process.flock(renamed, LOCK_EX | LOCK_NB), Err(Errno::Again));
        assert_eq!(process.fstat(&fs, replaced).unwrap().links, 0);
        process.flock(source, LOCK_UN).unwrap();
        assert_eq!(process.flock(renamed, LOCK_EX | LOCK_NB), Ok(()));

        process.unlink(&mut fs, "/target").unwrap();
        let replacement = process
            .open(&mut fs, "/target", O_CREAT | O_RDWR, 0o600)
            .unwrap();
        assert_ne!(process.fstat(&fs, replacement).unwrap().inode, source_inode);
        assert_eq!(process.flock(replacement, LOCK_EX | LOCK_NB), Ok(()));
        assert_eq!(process.flock(source, LOCK_EX | LOCK_NB), Err(Errno::Again));
        process.close(&mut fs, renamed).unwrap();
        assert_eq!(process.flock(source, LOCK_EX | LOCK_NB), Ok(()));
        process.close_all(&mut fs).unwrap();
    }

    #[test]
    fn reused_descriptors_and_inode_slots_start_unlocked_and_reject_stale_retry_identity() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut first = Process::empty(&objects, 1);
        let mut second = Process::empty(&objects, 2);
        for _ in 0..32 {
            let file = first
                .open(&mut fs, "/lock", O_CREAT | O_RDWR, 0o600)
                .unwrap();
            let identity = first.description_identity(file).unwrap();
            let old_inode = first.fstat(&fs, file).unwrap().inode;
            first.flock(file, LOCK_EX).unwrap();
            let old = second.open(&mut fs, "/lock", O_RDWR, 0).unwrap();
            assert_eq!(second.flock(old, LOCK_EX | LOCK_NB), Err(Errno::Again));
            first.unlink(&mut fs, "/lock").unwrap();
            first.close(&mut fs, file).unwrap();
            assert_eq!(second.flock(old, LOCK_EX | LOCK_NB), Ok(()));

            let fresh = first
                .open(&mut fs, "/lock", O_CREAT | O_RDWR, 0o600)
                .unwrap();
            assert_eq!(file, fresh);
            assert_ne!(first.fstat(&fs, fresh).unwrap().inode, old_inode);
            assert_eq!(
                first.validate_description_identity(fresh, identity),
                Err(Errno::Badf)
            );
            let contender = second.open(&mut fs, "/lock", O_RDWR, 0).unwrap();
            second.flock(contender, LOCK_EX).unwrap();
            assert_eq!(first.flock(fresh, LOCK_EX | LOCK_NB), Err(Errno::Again));
            second.close(&mut fs, contender).unwrap();
            assert_eq!(first.flock(fresh, LOCK_EX | LOCK_NB), Ok(()));
            first.close(&mut fs, fresh).unwrap();
            second.close(&mut fs, old).unwrap();
            first.unlink(&mut fs, "/lock").unwrap();
            assert_eq!(objects.snapshot().references, 0);
        }
    }

    #[test]
    fn invalid_operations_preserve_lock_and_nonblocking_status_does_not_change_conflicts() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut process = Process::new(&objects, 1).unwrap();
        let file = process
            .open(&mut fs, "/lock", O_CREAT | O_RDWR, 0o600)
            .unwrap();
        let other = process
            .open(&mut fs, "/lock", O_RDWR | crate::O_NONBLOCK, 0)
            .unwrap();
        process.flock(file, LOCK_EX).unwrap();
        for operation in [
            0,
            LOCK_NB,
            LOCK_SH | LOCK_EX,
            LOCK_SH | LOCK_UN,
            LOCK_EX | LOCK_UN,
            16,
            LOCK_EX | 0x8000_0000,
        ] {
            assert_eq!(process.flock(file, operation), Err(Errno::Inval));
            assert_eq!(process.flock(other, LOCK_EX | LOCK_NB), Err(Errno::Again));
        }
        assert_eq!(process.flock(-1, LOCK_EX), Err(Errno::Badf));
        assert_eq!(
            process.flock(crate::OPEN_MAX as i32, LOCK_EX),
            Err(Errno::Badf)
        );
        // Process::flock performs one attempt; only the supervisor may wait.
        assert_eq!(process.flock(other, LOCK_EX), Err(Errno::Again));
        process.set_flags(other, 0).unwrap();
        assert_eq!(process.flock(other, LOCK_EX), Err(Errno::Again));
        assert_eq!(process.flock(file, LOCK_UN | LOCK_NB), Ok(()));
        assert_eq!(process.flock(file, LOCK_UN), Ok(()));
        assert_eq!(process.flock(other, LOCK_EX), Ok(()));
        process.close(&mut fs, other).unwrap();
        assert_eq!(process.flock(other, LOCK_UN), Err(Errno::Badf));
        process.close_all(&mut fs).unwrap();
    }

    #[test]
    fn unsupported_descriptor_types_return_explicit_error_even_when_unlocking() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut process = Process::new(&objects, 1).unwrap();
        let socket = process.install_socket(1, 0).unwrap();
        let [read, write] = process.install_pipe([2, 3], 0).unwrap();
        let pty = process.install_pty(4, 0).unwrap();
        let event = process.eventfd(0, 0).unwrap();
        let timer = process.timerfd_create(1, 0).unwrap();
        let epoll = process.epoll_create(0).unwrap();
        for fd in [0, 1, 2, socket, read, write, pty, event, timer, epoll] {
            for operation in [LOCK_SH, LOCK_EX | LOCK_NB, LOCK_UN] {
                assert_eq!(process.flock(fd, operation), Err(Errno::Nosys));
            }
        }
        process.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
    }

    #[test]
    fn exclusive_lock_is_advisory_and_does_not_prevent_other_description_io() {
        struct Sink;
        impl crate::Console for Sink {
            fn write(&mut self, bytes: &[u8]) -> Result<usize, Errno> {
                Ok(bytes.len())
            }
        }
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut process = Process::new(&objects, 1).unwrap();
        let holder = process
            .open(&mut fs, "/lock", O_CREAT | O_RDWR, 0o600)
            .unwrap();
        let other = process.open(&mut fs, "/lock", O_RDWR, 0).unwrap();
        process.flock(holder, LOCK_EX).unwrap();
        assert_eq!(process.write(&mut fs, &mut Sink, other, b"data"), Ok(4));
        let mut bytes = [0; 4];
        assert_eq!(process.read(&mut fs, holder, &mut bytes), Ok(4));
        assert_eq!(&bytes, b"data");
        assert_eq!(process.flock(other, LOCK_EX | LOCK_NB), Err(Errno::Again));
        process.close_all(&mut fs).unwrap();
    }
}
