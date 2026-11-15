//! Runtime-only filesystem observations. This bounded journal records committed
//! changes for independent consumers; it neither admits writes nor pins inodes.
use super::{Error, FileSystem, Inode, Kind, Path};

pub const CAPACITY: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Create,
    Modify,
    Attrib,
    /// Link count changed on the inode itself, not its old parent directory.
    Unlink,
    Delete,
    DeleteSelf,
    MoveFrom,
    MoveTo,
    MoveSelf,
    Access,
    Open,
    CloseWrite,
    CloseRead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub sequence: u64,
    pub action: Action,
    pub inode: u64,
    pub parent: u64,
    pub path: Path,
    pub kind: Kind,
    pub cookie: u32,
    pub linked: bool,
}

pub(crate) struct Journal {
    records: [Option<Record>; CAPACITY],
    start: usize,
    len: usize,
    sequence: u64,
    lost: bool,
    cookie: u32,
}
impl Journal {
    pub(crate) const fn new() -> Self {
        Self {
            records: [None; CAPACITY],
            start: 0,
            len: 0,
            sequence: 0,
            lost: false,
            cookie: 0,
        }
    }

    pub(crate) fn push(&mut self, mut record: Record) {
        let Some(next) = self.sequence.checked_add(1) else {
            self.lost = true;
            return;
        };
        self.sequence = next;
        record.sequence = next;
        if self.len == CAPACITY {
            self.start = (self.start + 1) % CAPACITY;
        } else {
            self.len += 1;
        }
        self.records[(self.start + self.len - 1) % CAPACITY] = Some(record);
    }

    pub(crate) fn lose(&mut self) {
        self.sequence = self.sequence.saturating_add(1);
        self.lost = true;
    }

    pub(crate) fn rename_cookie(&mut self) -> u32 {
        self.cookie = self.cookie.wrapping_add(1).max(1);
        self.cookie
    }
}

impl FileSystem {
    /// A successful open, including the permanent root directory. Retaining a
    /// pin or duplicating an OFD is not itself another open notification.
    pub fn notify_open(&mut self, inode: Option<Inode>) -> Result<(), Error> {
        self.notify_activity(inode, Action::Open)
    }
    /// Directory traversal has no file-byte read but is still an access.
    pub fn notify_directory_access(&mut self, inode: Option<Inode>) -> Result<(), Error> {
        self.notify_activity(inode, Action::Access)
    }

    /// Called immediately before releasing the final OFD's inode pin.
    pub fn notify_close(&mut self, inode: Option<Inode>, writable: bool) -> Result<(), Error> {
        self.notify_activity(
            inode,
            if writable {
                Action::CloseWrite
            } else {
                Action::CloseRead
            },
        )
    }

    fn notify_activity(&mut self, inode: Option<Inode>, action: Action) -> Result<(), Error> {
        if let Some(inode) = inode {
            self.record_change(self.inode_index(inode)?, action, 0);
        } else {
            self.changes.push(Record {
                sequence: 0,
                action,
                inode: 1,
                parent: 1,
                path: Path::ROOT,
                kind: Kind::Directory,
                cookie: 0,
                linked: true,
            });
        }
        Ok(())
    }

    pub(crate) fn record_change(&mut self, index: usize, action: Action, cookie: u32) {
        let node = &self.nodes[index];
        let Some(inode) = node.serial.checked_add(1) else {
            self.changes.lose();
            return;
        };
        self.changes.push(Record {
            sequence: 0,
            action,
            inode,
            parent: node.parent,
            path: node.path,
            kind: node.kind,
            cookie,
            linked: node.linked,
        });
    }

    pub fn change_sequence(&self) -> u64 {
        self.changes.sequence
    }

    /// Reconcile weak consumers after journal overflow. Unlinked but pinned
    /// inodes stay alive, independently of their former pathname's reuse.
    pub fn identity_alive(&self, identity: u64) -> bool {
        identity == 1
            || self
                .nodes
                .iter()
                .any(|node| node.used && node.serial.checked_add(1) == Some(identity))
    }

    /// A lagging cursor must report overflow rather than infer absent changes.
    /// Exhausted observation identities remain explicitly lost until reboot.
    pub fn changes_lost(&self, after: u64) -> bool {
        self.changes.lost
            || after > self.changes.sequence
            || (self.changes.len != 0
                && after
                    < self.changes.records[self.changes.start]
                        .unwrap()
                        .sequence
                        .saturating_sub(1))
    }

    pub fn changes_after(&self, after: u64) -> impl Iterator<Item = Record> + '_ {
        (0..self.changes.len)
            .map(|i| self.changes.records[(self.changes.start + i) % CAPACITY].unwrap())
            .filter(move |record| record.sequence > after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn path(name: &str) -> Path {
        Path::resolve(Path::ROOT, name).unwrap()
    }

    #[test]
    fn committed_create_modify_and_metadata_keep_order_and_real_identities() {
        let mut fs = FileSystem::new();
        fs.mkdir(path("/config")).unwrap();
        let parent = fs.identity(path("/config")).unwrap();
        let before = fs.change_sequence();
        fs.write(path("/config/key"), b"value", false).unwrap();
        let inode = fs.identity(path("/config/key")).unwrap();
        fs.set_mode(path("/config/key"), 0o600).unwrap();
        let mut records = fs.changes_after(before);
        for action in [Action::Create, Action::Modify, Action::Attrib] {
            let record = records.next().expect("committed change was not recorded");
            assert_eq!(record.action, action);
            assert_eq!(record.inode, inode);
            assert_eq!(record.parent, parent);
            assert_eq!(record.path, path("/config/key"));
            assert_eq!(record.kind, Kind::File);
            assert!(record.linked);
            assert_eq!(record.cookie, 0);
        }
        assert!(records.next().is_none());
    }

    #[test]
    fn unlink_retains_parent_identity_and_delays_self_deletion_until_last_pin() {
        let mut fs = FileSystem::new();
        fs.mkdir(path("/old")).unwrap();
        fs.write(path("/old/file"), b"data", false).unwrap();
        let old_parent = fs.identity(path("/old")).unwrap();
        let inode = fs.identity(path("/old/file")).unwrap();
        let handle = fs.pin(path("/old/file")).unwrap();
        let before = fs.change_sequence();
        fs.remove(path("/old/file"), false).unwrap();
        let mut records = fs.changes_after(before);
        let deleted = records.next().expect("missing parent deletion");
        assert_eq!(deleted.action, Action::Delete);
        assert_eq!(deleted.inode, inode);
        assert_eq!(deleted.parent, old_parent);
        assert!(deleted.linked);
        let unlinked = records.next().expect("missing inode link count change");
        assert_eq!(unlinked.action, Action::Unlink);
        assert!(!unlinked.linked);
        assert!(records.next().is_none());
        drop(records);
        fs.remove(path("/old"), true).unwrap();
        fs.mkdir(path("/old")).unwrap();
        assert_ne!(fs.identity(path("/old")).unwrap(), old_parent);
        let before = fs.change_sequence();
        fs.write_at(handle, 0, b"next").unwrap();
        fs.unpin(handle).unwrap();
        let mut records = fs.changes_after(before);
        for action in [Action::Modify, Action::DeleteSelf] {
            let record = records.next().expect("missing orphan activity");
            assert_eq!(record.action, action);
            assert_eq!(record.inode, inode);
            assert_eq!(record.parent, old_parent);
            assert!(!record.linked);
        }
        assert!(records.next().is_none());
    }

    #[test]
    fn actual_open_read_and_final_close_have_distinct_inode_activity() {
        let mut fs = FileSystem::new();
        fs.write(path("/file"), b"data", false).unwrap();
        let handle = fs.pin(path("/file")).unwrap();
        let before = fs.change_sequence();
        fs.notify_open(Some(handle)).unwrap();
        fs.read_at(handle, 0, &mut [0; 2]).unwrap();
        fs.notify_close(Some(handle), false).unwrap();
        fs.notify_open(None).unwrap();
        fs.notify_close(None, false).unwrap();
        let mut records = fs.changes_after(before);
        for action in [
            Action::Open,
            Action::Access,
            Action::CloseRead,
            Action::Open,
            Action::CloseRead,
        ] {
            assert_eq!(
                records
                    .next()
                    .expect("missing actual inode activity")
                    .action,
                action
            );
        }
        assert!(records.next().is_none());
        drop(records);
        let before = fs.change_sequence();
        fs.read_at(handle, 0, &mut []).unwrap();
        fs.read_at(handle, 100, &mut [0; 8]).unwrap();
        assert_eq!(fs.change_sequence(), before);
        fs.notify_close(Some(handle), true).unwrap();
        assert_eq!(
            fs.changes_after(before).next().unwrap().action,
            Action::CloseWrite
        );
        fs.unpin(handle).unwrap();
        let before = fs.change_sequence();
        assert_eq!(fs.notify_open(Some(handle)), Err(Error::Stale));
        assert_eq!(fs.change_sequence(), before);
    }

    #[test]
    fn rename_pairs_real_names_and_preserves_replaced_open_inode_lifetime() {
        let mut fs = FileSystem::new();
        fs.mkdir(path("/a")).unwrap();
        fs.mkdir(path("/b")).unwrap();
        fs.write(path("/a/key"), b"source", false).unwrap();
        fs.write(path("/b/key"), b"target", false).unwrap();
        let source = fs.identity(path("/a/key")).unwrap();
        let target = fs.identity(path("/b/key")).unwrap();
        let from_parent = fs.identity(path("/a")).unwrap();
        let to_parent = fs.identity(path("/b")).unwrap();
        let source_handle = fs.pin(path("/a/key")).unwrap();
        let target_handle = fs.pin(path("/b/key")).unwrap();
        let before = fs.change_sequence();
        fs.rename_file(path("/a/key"), path("/b/key"), false)
            .unwrap();
        let mut records = fs.changes_after(before);
        let from = records.next().expect("missing rename origin");
        let to = records.next().expect("missing rename destination");
        assert_eq!((from.action, to.action), (Action::MoveFrom, Action::MoveTo));
        assert_ne!(from.cookie, 0);
        assert_eq!(from.cookie, to.cookie);
        assert_eq!((from.inode, to.inode), (source, source));
        assert_eq!((from.parent, to.parent), (from_parent, to_parent));
        assert_eq!((from.path, to.path), (path("/a/key"), path("/b/key")));
        let unlinked = records
            .next()
            .expect("missing overwritten inode observation");
        assert_eq!(unlinked.action, Action::Unlink);
        assert_eq!(unlinked.inode, target);
        assert!(!unlinked.linked);
        let moved = records.next().expect("missing inode move");
        assert_eq!(
            (moved.action, moved.inode, moved.cookie),
            (Action::MoveSelf, source, 0)
        );
        assert!(records.next().is_none());
        drop(records);
        let before = fs.change_sequence();
        fs.write_at(source_handle, 0, b"new").unwrap();
        fs.unpin(target_handle).unwrap();
        let mut records = fs.changes_after(before);
        let written = records.next().unwrap();
        assert_eq!(
            (written.action, written.inode, written.parent),
            (Action::Modify, source, to_parent)
        );
        let deleted = records.next().unwrap();
        assert_eq!(
            (deleted.action, deleted.inode),
            (Action::DeleteSelf, target)
        );
        assert!(records.next().is_none());
        drop(records);
        let before = fs.change_sequence();
        fs.rename_file(path("/b/key"), path("/b/key"), false)
            .unwrap();
        assert_eq!(fs.change_sequence(), before);
        fs.unpin(source_handle).unwrap();
    }

    #[test]
    fn weak_identity_liveness_tracks_orphans_and_not_reused_paths_or_slots() {
        let mut fs = FileSystem::new();
        fs.write(path("/file"), b"old", false).unwrap();
        let old = fs.identity(path("/file")).unwrap();
        let handle = fs.pin(path("/file")).unwrap();
        assert!(fs.identity_alive(old));
        fs.remove(path("/file"), false).unwrap();
        assert!(fs.identity_alive(old));
        fs.write(path("/file"), b"new", false).unwrap();
        let new = fs.identity(path("/file")).unwrap();
        assert_ne!(old, new);
        assert!(fs.identity_alive(old) && fs.identity_alive(new));
        fs.unpin(handle).unwrap();
        assert!(!fs.identity_alive(old));
        assert!(fs.identity_alive(new));
        assert!(fs.identity_alive(1));
        assert!(!fs.identity_alive(0));
    }

    #[test]
    fn snapshot_keeps_journal_transient_and_restores_stable_parent_identity() {
        let mut fs = FileSystem::new();
        fs.mkdir(path("/config")).unwrap();
        fs.write(path("/config/key"), b"value", false).unwrap();
        let parent = fs.identity(path("/config")).unwrap();
        let inode = fs.identity(path("/config/key")).unwrap();
        let mut before = [0; 1024];
        let size = fs.write_snapshot(&mut before).unwrap();
        let handle = fs.pin(path("/config/key")).unwrap();
        fs.notify_open(Some(handle)).unwrap();
        fs.read_at(handle, 0, &mut [0; 8]).unwrap();
        fs.notify_close(Some(handle), false).unwrap();
        fs.unpin(handle).unwrap();
        let mut after = [0; 1024];
        assert_eq!(fs.write_snapshot(&mut after), Ok(size));
        assert_eq!(&before[..size], &after[..size]);
        let mut recovered = FileSystem::new();
        recovered.restore_snapshot(&before[..size]).unwrap();
        assert_eq!(recovered.change_sequence(), 0);
        assert!(!recovered.changes_lost(0));
        assert!(recovered.changes_after(0).next().is_none());
        let handle = recovered.pin(path("/config/key")).unwrap();
        recovered.write_at(handle, 0, b"new").unwrap();
        let record = recovered.changes_after(0).next().unwrap();
        assert_eq!(record.action, Action::Modify);
        assert_eq!(record.inode, inode);
        assert_eq!(record.parent, parent);
        recovered.unpin(handle).unwrap();
    }

    #[test]
    fn bounded_history_reports_lag_without_hiding_retained_changes() {
        let mut fs = FileSystem::new();
        fs.write(path("/file"), b"", false).unwrap();
        assert_eq!(fs.change_sequence(), 1);
        for i in 0..CAPACITY {
            fs.set_mode(path("/file"), if i % 2 == 0 { 0o600 } else { 0o640 })
                .unwrap();
        }
        assert!(fs.changes_lost(0));
        assert!(!fs.changes_lost(1));
        assert!(fs.changes_lost(u64::MAX));
        assert_eq!(fs.changes_after(1).count(), CAPACITY);
        assert_eq!(fs.changes_after(1).next().unwrap().sequence, 2);
        assert_eq!(
            fs.changes_after(1).last().unwrap().sequence,
            CAPACITY as u64 + 1
        );
        assert!(
            fs.changes_after(1)
                .all(|record| record.action == Action::Attrib)
        );
        let latest = fs.change_sequence();
        assert!(fs.changes_after(latest).next().is_none());
        fs.set_mode(path("/file"), 0o666).unwrap();
        assert!(!fs.changes_lost(latest));
        assert_eq!(fs.changes_after(latest).count(), 1);
    }

    #[test]
    fn rejected_mutations_and_noop_operations_publish_no_changes() {
        let mut fs = FileSystem::new();
        fs.mkdir(path("/d")).unwrap();
        fs.write(path("/d/file"), b"value", false).unwrap();
        fs.write(path("/target"), b"old", false).unwrap();
        let handle = fs.pin(path("/d/file")).unwrap();
        let before = fs.change_sequence();
        assert_eq!(fs.mkdir(path("/d")), Err(Error::Exists));
        assert_eq!(
            fs.write(path("/d/file"), &[0; super::super::FILE_BYTES + 1], false),
            Err(Error::TooLarge)
        );
        assert_eq!(
            fs.rename_file(path("/d/file"), path("/target"), true),
            Err(Error::Exists)
        );
        assert_eq!(fs.remove(path("/d"), true), Err(Error::NotEmpty));
        assert_eq!(fs.remove(path("/missing"), false), Err(Error::NotFound));
        assert_eq!(fs.read(path("/d/file"), &mut [0; 2]), Err(Error::TooLarge));
        assert_eq!(
            fs.write_at(handle, super::super::FILE_BYTES, b"x"),
            Err(Error::TooLarge)
        );
        assert_eq!(fs.write_at(handle, 0, &[]), Ok(0));
        fs.rename_file(path("/d/file"), path("/d/file"), false)
            .unwrap();
        fs.write(path("/d/file"), &[], true).unwrap();
        fs.unpin(handle).unwrap();
        assert_eq!(fs.set_inode_mode(handle, 0o600), Err(Error::Stale));
        assert_eq!(fs.change_sequence(), before);
        assert!(fs.changes_after(before).next().is_none());
    }
}
