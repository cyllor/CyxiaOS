//! Versioned RAMFS serialization. Only linked files/directories survive reboot;
//! open handles, caches, runtime counters and learned model state do not.
use super::{Error, FILE_BYTES, FileSystem, Kind, NODES, Node, PATH_BYTES, Path};

const HEADER: usize = 32;
const RECORD: usize = 16 + PATH_BYTES;
pub const MAX_BYTES: usize = HEADER + NODES * (RECORD + FILE_BYTES);
const MAGIC: &[u8; 8] = b"CYXRAM01";

#[derive(Clone, Copy)]
struct Entry {
    path: Path,
    kind: Kind,
    mode: u16,
    serial: u64,
    data: usize,
    len: usize,
}
impl Entry {
    const EMPTY: Self = Self {
        path: Path::ROOT,
        kind: Kind::File,
        mode: 0,
        serial: 0,
        data: 0,
        len: 0,
    };
}

impl FileSystem {
    /// CPU0 must exclude mutations for this bounded copy. No grant is created
    /// here: the storage service admits and owns its staging memory separately.
    pub fn write_snapshot(&self, output: &mut [u8]) -> Result<usize, Error> {
        // A serial at MAX cannot provide the public inode serial+1 identity.
        // Never commit a payload that this schema cannot restore after reboot.
        if self
            .nodes
            .iter()
            .any(|n| n.used && n.linked && n.serial == u64::MAX)
        {
            return Err(Error::Exhausted);
        }
        let length = HEADER
            + self
                .nodes
                .iter()
                .filter(|n| n.used && n.linked)
                .map(|n| RECORD + n.len)
                .sum::<usize>();
        if output.len() < length {
            return Err(Error::TooLarge);
        }
        let count = self.nodes.iter().filter(|n| n.used && n.linked).count();
        output[..length].fill(0);
        output[..8].copy_from_slice(MAGIC);
        output[8..12].copy_from_slice(&1u32.to_le_bytes());
        output[12..16].copy_from_slice(&(count as u32).to_le_bytes());
        output[16..24].copy_from_slice(&self.revision.to_le_bytes());
        let mut at = HEADER;
        for n in self.nodes.iter().filter(|n| n.used && n.linked) {
            output[at] = if n.kind == Kind::Directory { 2 } else { 1 };
            output[at + 1] = n.path.len as u8;
            output[at + 2..at + 4].copy_from_slice(&n.mode.to_le_bytes());
            output[at + 4..at + 12].copy_from_slice(&n.serial.to_le_bytes());
            output[at + 12..at + 16].copy_from_slice(&(n.len as u32).to_le_bytes());
            output[at + 16..at + 16 + n.path.len].copy_from_slice(n.path.as_str().as_bytes());
            output[at + RECORD..at + RECORD + n.len].copy_from_slice(&n.data[..n.len]);
            at += RECORD + n.len;
        }
        Ok(length)
    }

    /// Restore only into a fresh filesystem before processes can open handles.
    /// All records, topology and identities are validated before publication.
    /// Recovery replays already committed bytes as BOOTSTRAP, not a new write
    /// proposal that an AI model could alter or silently discard.
    pub fn restore_snapshot(&mut self, input: &[u8]) -> Result<(), Error> {
        if self.nodes.iter().any(|n| n.used) {
            return Err(Error::Exists);
        }
        if input.len() < HEADER
            || input.len() > MAX_BYTES
            || &input[..8] != MAGIC
            || input[8..12] != 1u32.to_le_bytes()
            || input[24..32].iter().any(|b| *b != 0)
        {
            return Err(Error::InvalidPath);
        }
        let count = u32::from_le_bytes(input[12..16].try_into().unwrap()) as usize;
        let revision = u64::from_le_bytes(input[16..24].try_into().unwrap());
        if count > NODES || revision == 0 {
            return Err(Error::InvalidPath);
        }
        let mut entries = [Entry::EMPTY; NODES];
        let mut at = HEADER;
        for i in 0..count {
            let record = input.get(at..at + RECORD).ok_or(Error::InvalidPath)?;
            let kind = match record[0] {
                1 => Kind::File,
                2 => Kind::Directory,
                _ => return Err(Error::InvalidPath),
            };
            let path_len = record[1] as usize;
            let mode = u16::from_le_bytes(record[2..4].try_into().unwrap());
            let serial = u64::from_le_bytes(record[4..12].try_into().unwrap());
            let len = u32::from_le_bytes(record[12..16].try_into().unwrap()) as usize;
            if !(2..PATH_BYTES).contains(&path_len)
                || mode & !0o7777 != 0
                || serial == 0
                || serial == u64::MAX
                || serial > revision
                || len > FILE_BYTES
                || (kind == Kind::Directory && len != 0)
                || record[16 + path_len..RECORD].iter().any(|b| *b != 0)
            {
                return Err(Error::InvalidPath);
            }
            let text =
                core::str::from_utf8(&record[16..16 + path_len]).map_err(|_| Error::InvalidPath)?;
            let path = Path::resolve(Path::ROOT, text)?;
            if path.as_str() != text
                || entries[..i]
                    .iter()
                    .any(|e| e.path == path || e.serial == serial)
            {
                return Err(Error::InvalidPath);
            }
            let data = at + RECORD;
            input.get(data..data + len).ok_or(Error::InvalidPath)?;
            entries[i] = Entry {
                path,
                kind,
                mode,
                serial,
                data,
                len,
            };
            at = data + len;
        }
        if at != input.len() {
            return Err(Error::InvalidPath);
        }
        for e in &entries[..count] {
            if e.path.parent() != Path::ROOT
                && !entries[..count]
                    .iter()
                    .any(|p| p.path == e.path.parent() && p.kind == Kind::Directory)
            {
                return Err(Error::NotDirectory);
            }
        }
        for (node, e) in self.nodes.iter_mut().zip(&entries[..count]) {
            *node = Node {
                path: e.path,
                kind: e.kind,
                used: true,
                linked: true,
                serial: e.serial,
                mode: e.mode,
                len: e.len,
                ..Node::EMPTY
            };
            node.data[..e.len].copy_from_slice(&input[e.data..e.data + e.len]);
        }
        self.revision = revision;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn path(s: &str) -> Path {
        Path::resolve(Path::ROOT, s).unwrap()
    }
    #[test]
    fn reboot_preserves_contents_modes_identity_and_excludes_unlinked_handles() {
        let mut fs = FileSystem::new();
        fs.mkdir(path("/用户")).unwrap();
        fs.write(path("/用户/a file"), &[0x7e; FILE_BYTES], false)
            .unwrap();
        fs.set_mode(path("/用户/a file"), 0o640).unwrap();
        fs.write(path("/removed"), b"not durable", false).unwrap();
        let h = fs.pin(path("/removed")).unwrap();
        fs.remove(path("/removed"), false).unwrap();
        let id = fs.identity(path("/用户/a file")).unwrap();
        let mut bytes = [0; MAX_BYTES];
        let n = fs.write_snapshot(&mut bytes).unwrap();
        let mut recovered = FileSystem::new();
        recovered.restore_snapshot(&bytes[..n]).unwrap();
        assert_eq!(recovered.status().nodes, 2);
        assert_eq!(recovered.identity(path("/用户/a file")), Ok(id));
        assert_eq!(recovered.stat(path("/用户/a file")).unwrap().mode, 0o640);
        let mut data = [0; FILE_BYTES];
        assert_eq!(
            recovered.read(path("/用户/a file"), &mut data),
            Ok(FILE_BYTES)
        );
        assert_eq!(data, [0x7e; FILE_BYTES]);
        assert_eq!(recovered.inode_len(h), Err(Error::Stale));
        assert_eq!(recovered.restore_snapshot(&bytes[..n]), Err(Error::Exists));
    }
    #[test]
    fn invalid_snapshot_is_rejected_before_any_file_is_published() {
        let mut fs = FileSystem::new();
        fs.mkdir(path("/d")).unwrap();
        fs.write(path("/d/f"), b"hello", false).unwrap();
        let mut bytes = [0; MAX_BYTES];
        let n = fs.write_snapshot(&mut bytes).unwrap();
        for cut in [0, HEADER - 1, HEADER, n - 1] {
            let mut target = FileSystem::new();
            assert!(target.restore_snapshot(&bytes[..cut]).is_err());
            assert_eq!(target.status().nodes, 0);
        }
        // Change directory kind into file while retaining its child.
        bytes[HEADER] = 1;
        let mut target = FileSystem::new();
        assert_eq!(
            target.restore_snapshot(&bytes[..n]),
            Err(Error::NotDirectory)
        );
        assert_eq!(target.status().nodes, 0);
    }

    #[test]
    fn exhausted_inode_identity_cannot_be_committed_as_a_snapshot() {
        let mut fs = FileSystem::new();
        fs.revision = u64::MAX - 1;
        fs.write(path("/last"), b"x", false).unwrap();
        let mut bytes = [0xa5; 256];
        assert_eq!(fs.write_snapshot(&mut bytes), Err(Error::Exhausted));
        assert_eq!(bytes, [0xa5; 256]);
    }
}
