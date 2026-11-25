//! SEC-F: path/capability validation and a non-forgetting durability receipt.
//! Media ordering and actual FLUSH completion are owned by the native LogFS.
use super::Error;

pub const MAX_PATH: usize = 512;
pub const MAX_COMPONENT: usize = 63;
pub const MAX_WRITE: usize = 64 * 1024;

/// Validate one absolute, component-anchored path before looking up any inode.
/// This accepts root "/" but rejects "."/"..", duplicate slashes, NUL,
/// invalid UTF-8, excessive lengths and trailing separators.
pub fn validate_absolute_path(path: &[u8]) -> Result<(), Error> {
    if path.is_empty() || path.len() > MAX_PATH || path[0] != b'/' {
        return Err(Error::Invalid);
    }
    core::str::from_utf8(path).map_err(|_| Error::Invalid)?;
    if path == b"/" {
        return Ok(());
    }
    let tail = &path[1..];
    for component in tail.split(|b| *b == b'/') {
        if component.is_empty()
            || component.len() > MAX_COMPONENT
            || component == b"."
            || component == b".."
            || component.contains(&0)
        {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

pub const READ: u8 = 1;
pub const WRITE: u8 = 2;
pub const DIRECTORY: u8 = 4;
pub const DELETE: u8 = 8;
pub const SYSTEM_STORE: u8 = 16;

/// Unforgeable only at its native capability table boundary; a model or a
/// network message must never be treated as a constructor for FileCapability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileCapability {
    owner: u64,
    inode: u16,
    generation: u64,
    permissions: u8,
}
impl FileCapability {
    #[allow(dead_code)] // Constructed by the native authority adapter once integrated.
    pub(crate) const fn from_registry(
        owner: u64,
        inode: u16,
        generation: u64,
        permissions: u8,
    ) -> Self {
        Self {
            owner,
            inode,
            generation,
            permissions,
        }
    }
    pub fn permits(
        self,
        owner: u64,
        inode: u16,
        generation: u64,
        requested: u8,
    ) -> Result<(), Error> {
        if owner == 0 || self.owner != owner {
            return Err(Error::Unauthorized);
        }
        if self.inode != inode || self.generation != generation || generation == 0 {
            return Err(Error::Stale);
        }
        if requested == 0 || requested & !self.permissions != 0 {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    /// BootEpoch and other protected-system records cannot be reached by
    /// ordinary file capabilities, including through a fabricated path.
    /// A caller supplies *trusted native registry* identity and generation;
    /// no protected inode encoding is invented here (DEC-01 is not frozen).
    /// A matching SYSTEM_STORE bit on an unrelated normal inode is insufficient.
    pub fn protected_store(
        self,
        owner: u64,
        protected_inode: u16,
        protected_generation: u64,
    ) -> Result<(), Error> {
        if self.owner != owner || owner == 0 || self.permissions & SYSTEM_STORE == 0 {
            return Err(Error::Unauthorized);
        }
        if self.inode != protected_inode
            || self.generation == 0
            || protected_generation == 0
            || self.generation != protected_generation
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Reserved,
    RedoFlushed,
    CommitFlushed,
    Visible,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Receipt {
    request_id: u64,
    payload_hash: [u8; 32],
    stage: Stage,
}
/// UNKNOWN retains its original key and cannot be resubmitted as a fresh
/// operation. COMMIT/FLUSH is evidence from LogFS, never inferred here.
pub struct DurableReceipts<const N: usize> {
    rows: [Option<Receipt>; N],
}
impl<const N: usize> Default for DurableReceipts<N> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize> DurableReceipts<N> {
    pub const fn new() -> Self {
        Self { rows: [None; N] }
    }
    pub fn submit(&mut self, id: u64, hash: [u8; 32]) -> Result<Stage, Error> {
        if id == 0 {
            return Err(Error::Invalid);
        }
        if let Some(row) = self.rows.iter().flatten().find(|r| r.request_id == id) {
            return if row.payload_hash == hash {
                Ok(row.stage)
            } else {
                Err(Error::Conflict)
            };
        }
        let pos = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.rows[pos] = Some(Receipt {
            request_id: id,
            payload_hash: hash,
            stage: Stage::Reserved,
        });
        Ok(Stage::Reserved)
    }
    fn row(&mut self, id: u64) -> Result<&mut Receipt, Error> {
        self.rows
            .iter_mut()
            .flatten()
            .find(|r| r.request_id == id)
            .ok_or(Error::Stale)
    }
    pub fn advance(&mut self, id: u64, from: Stage, to: Stage) -> Result<(), Error> {
        if !matches!(
            (from, to),
            (Stage::Reserved, Stage::RedoFlushed)
                | (Stage::RedoFlushed, Stage::CommitFlushed)
                | (Stage::CommitFlushed, Stage::Visible)
        ) {
            return Err(Error::Invalid);
        }
        let row = self.row(id)?;
        if row.stage != from {
            return Err(Error::Stale);
        }
        row.stage = to;
        Ok(())
    }
    pub fn uncertain(&mut self, id: u64) -> Result<(), Error> {
        let row = self.row(id)?;
        if row.stage != Stage::Visible {
            row.stage = Stage::Unknown;
        }
        Ok(())
    }
    pub fn state(&mut self, id: u64) -> Result<Stage, Error> {
        Ok(self.row(id)?.stage)
    }
    pub fn acknowledge_fsync(&mut self, id: u64) -> Result<(), Error> {
        if self.row(id)?.stage != Stage::Visible {
            return Err(Error::Unknown);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cap() -> FileCapability {
        FileCapability::from_registry(7, 2, 3, READ | WRITE | DIRECTORY)
    }
    #[test]
    fn sec_f01_rejects_escape_and_invalid_paths() {
        for path in [
            b"relative".as_slice(),
            b"/a/../b",
            b"/./b",
            b"/a//b",
            b"/a/",
            b"/a\0b",
        ] {
            assert_eq!(validate_absolute_path(path), Err(Error::Invalid));
        }
        assert_eq!(validate_absolute_path(b"/valid/path"), Ok(()));
    }
    #[test]
    fn native_path_guard_rejects_duplicate_slashes_nul_and_invalid_utf8() {
        assert_eq!(validate_absolute_path(b"/a//b"), Err(Error::Invalid));
        assert_eq!(validate_absolute_path(b"/dir/"), Err(Error::Invalid));
        assert_eq!(validate_absolute_path(b"/a\0b"), Err(Error::Invalid));
        assert_eq!(validate_absolute_path(&[b'/', 0xff]), Err(Error::Invalid));
        assert_eq!(validate_absolute_path(b"/a/b"), Ok(()));
    }
    #[test]
    fn sec_f02_capabilities_do_not_cross_owner_or_rights() {
        assert_eq!(cap().permits(8, 2, 3, READ), Err(Error::Unauthorized));
        assert_eq!(cap().permits(7, 2, 3, DELETE), Err(Error::Unauthorized));
        assert_eq!(cap().permits(7, 2, 3, READ), Ok(()));
    }
    #[test]
    fn sec_f03_stale_inode_generation_rejected() {
        assert_eq!(cap().permits(7, 2, 4, READ), Err(Error::Stale));
    }
    #[test]
    fn sec_f04_component_and_write_bounds() {
        let mut path = [b'a'; 65];
        path[0] = b'/';
        assert_eq!(validate_absolute_path(&path), Err(Error::Invalid));
        assert_eq!(MAX_WRITE, 65536);
    }
    #[test]
    fn sec_f05_commit_order_cannot_be_skipped() {
        let mut t = DurableReceipts::<1>::new();
        t.submit(1, [2; 32]).unwrap();
        assert_eq!(
            t.advance(1, Stage::Reserved, Stage::CommitFlushed),
            Err(Error::Invalid)
        );
        assert_eq!(t.acknowledge_fsync(1), Err(Error::Unknown));
        t.advance(1, Stage::Reserved, Stage::RedoFlushed).unwrap();
        t.advance(1, Stage::RedoFlushed, Stage::CommitFlushed)
            .unwrap();
        t.advance(1, Stage::CommitFlushed, Stage::Visible).unwrap();
        assert_eq!(t.acknowledge_fsync(1), Ok(()));
    }
    #[test]
    fn sec_f06_lost_ack_preserves_id_and_rejects_new_body() {
        let mut t = DurableReceipts::<1>::new();
        t.submit(1, [2; 32]).unwrap();
        t.uncertain(1).unwrap();
        assert_eq!(t.submit(1, [2; 32]), Ok(Stage::Unknown));
        assert_eq!(t.submit(1, [3; 32]), Err(Error::Conflict));
    }
    #[test]
    fn sec_f07_unknown_transaction_keeps_capacity() {
        let mut t = DurableReceipts::<1>::new();
        t.submit(1, [2; 32]).unwrap();
        t.uncertain(1).unwrap();
        assert_eq!(t.submit(2, [4; 32]), Err(Error::Capacity));
    }
    #[test]
    fn sec_f08_boot_epoch_store_is_not_ordinary_file() {
        assert_eq!(cap().protected_store(7, 0, 1), Err(Error::Unauthorized));
        let system = FileCapability::from_registry(7, 0, 1, SYSTEM_STORE);
        assert_eq!(system.protected_store(7, 0, 1), Ok(()));
        assert_eq!(system.protected_store(8, 0, 1), Err(Error::Unauthorized));
    }
    #[test]
    fn v019_sec_f08_trusted_system_registry_scope_and_generation_required() {
        let malicious = FileCapability::from_registry(7, 2, 3, SYSTEM_STORE);
        assert_eq!(malicious.protected_store(7, 0, 1), Err(Error::Stale));
        let stale = FileCapability::from_registry(7, 0, 0, SYSTEM_STORE);
        assert_eq!(stale.protected_store(7, 0, 1), Err(Error::Stale));
    }
}
