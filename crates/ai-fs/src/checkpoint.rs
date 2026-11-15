//! Versioned RAMFS serialization. Only linked inodes survive reboot;
//! open handles, caches, runtime counters and learned model state do not.
use super::{Error, FILE_BYTES, FileSystem, Kind, NODES, Node, PATH_BYTES, Path, RETAINED_BYTES};

const HEADER: usize = 32;
const RECORD: usize = 16 + PATH_BYTES;
pub const MAX_BYTES: usize = HEADER + NODES * RECORD + RETAINED_BYTES;
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
        if output.len() < length || length > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let count = self.nodes.iter().filter(|n| n.used && n.linked).count();
        // Preserve the original encoding for ordinary file-only snapshots.
        // Version 2 adds kind 3, whose payload is the exact link target bytes.
        let version = if self
            .nodes
            .iter()
            .any(|n| n.used && n.linked && n.kind == Kind::Symlink)
        {
            2u32
        } else {
            1u32
        };
        output[..length].fill(0);
        output[..8].copy_from_slice(MAGIC);
        output[8..12].copy_from_slice(&version.to_le_bytes());
        output[12..16].copy_from_slice(&(count as u32).to_le_bytes());
        output[16..24].copy_from_slice(&self.revision.to_le_bytes());
        let mut at = HEADER;
        for n in self.nodes.iter().filter(|n| n.used && n.linked) {
            output[at] = match n.kind {
                Kind::File => 1,
                Kind::Directory => 2,
                Kind::Symlink => 3,
            };
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
            || input[24..32].iter().any(|b| *b != 0)
        {
            return Err(Error::InvalidPath);
        }
        let version = u32::from_le_bytes(input[8..12].try_into().unwrap());
        if !matches!(version, 1 | 2) {
            return Err(Error::InvalidPath);
        }
        let count = u32::from_le_bytes(input[12..16].try_into().unwrap()) as usize;
        let revision = u64::from_le_bytes(input[16..24].try_into().unwrap());
        if count > NODES || revision == 0 {
            return Err(Error::InvalidPath);
        }
        let mut entries = [Entry::EMPTY; NODES];
        let mut at = HEADER;
        let mut retained = 0usize;
        for i in 0..count {
            let record = input.get(at..at + RECORD).ok_or(Error::InvalidPath)?;
            let kind = match record[0] {
                1 => Kind::File,
                2 => Kind::Directory,
                3 if version == 2 => Kind::Symlink,
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
            let payload = input.get(data..data + len).ok_or(Error::InvalidPath)?;
            retained = retained.checked_add(len).ok_or(Error::InvalidPath)?;
            if retained > RETAINED_BYTES {
                return Err(Error::InvalidPath);
            }
            if kind == Kind::Symlink {
                let target = core::str::from_utf8(payload).map_err(|_| Error::InvalidPath)?;
                Self::validate_link_target(target).map_err(|_| Error::InvalidPath)?;
            }
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
                parent: if e.path.parent() == Path::ROOT {
                    1
                } else {
                    entries[..count]
                        .iter()
                        .find(|parent| parent.path == e.path.parent())
                        .expect("validated snapshot parent")
                        .serial
                        + 1
                },
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
        self.changes = super::events::Journal::new();
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

    #[test]
    fn original_v1_bytes_restore_and_ordinary_snapshots_keep_v1_encoding() {
        // Construct the original wire schema independently of the writer.
        let mut legacy = [0; HEADER + RECORD + 3];
        legacy[..8].copy_from_slice(MAGIC);
        legacy[8..12].copy_from_slice(&1u32.to_le_bytes());
        legacy[12..16].copy_from_slice(&1u32.to_le_bytes());
        legacy[16..24].copy_from_slice(&9u64.to_le_bytes());
        legacy[HEADER] = 1;
        legacy[HEADER + 1] = 4;
        legacy[HEADER + 2..HEADER + 4].copy_from_slice(&0o640u16.to_le_bytes());
        legacy[HEADER + 4..HEADER + 12].copy_from_slice(&7u64.to_le_bytes());
        legacy[HEADER + 12..HEADER + 16].copy_from_slice(&3u32.to_le_bytes());
        legacy[HEADER + 16..HEADER + 20].copy_from_slice(b"/old");
        legacy[HEADER + RECORD..].copy_from_slice(b"v1\n");
        let mut fs = FileSystem::new();
        fs.restore_snapshot(&legacy).unwrap();
        assert_eq!(fs.identity(path("/old")), Ok(8));
        assert_eq!(fs.stat(path("/old")).unwrap().mode, 0o640);
        assert_eq!(fs.status().revision, 9);
        let mut data = [0; 3];
        assert_eq!(fs.read(path("/old"), &mut data), Ok(3));
        assert_eq!(&data, b"v1\n");
        let mut written = [0xa5; HEADER + RECORD + 3];
        assert_eq!(fs.write_snapshot(&mut written), Ok(legacy.len()));
        assert_eq!(written, legacy);
    }

    #[test]
    fn v2_roundtrip_restores_links_as_links_and_v1_returns_after_last_link_is_removed() {
        let mut fs = FileSystem::new();
        fs.mkdir(path("/config")).unwrap();
        fs.write(path("/target"), b"contents", false).unwrap();
        fs.symlink(path("/config/current"), "/target//../用户")
            .unwrap();
        fs.symlink(path("/dangling"), "../missing").unwrap();
        let identity = fs.identity(path("/config/current")).unwrap();
        let retained = fs.status().bytes;
        let mut bytes = [0; 1024];
        let n = fs.write_snapshot(&mut bytes).unwrap();
        assert_eq!(&bytes[8..12], &2u32.to_le_bytes());
        let mut recovered = FileSystem::new();
        recovered.restore_snapshot(&bytes[..n]).unwrap();
        assert_eq!(recovered.status().bytes, retained);
        assert_eq!(
            recovered.stat(path("/config/current")).unwrap().kind,
            Kind::Symlink
        );
        assert_eq!(recovered.identity(path("/config/current")), Ok(identity));
        assert_eq!(
            recovered.pin(path("/config/current")),
            Err(Error::InvalidPath)
        );
        let mut target = [0; PATH_BYTES];
        let len = recovered
            .readlink(path("/config/current"), &mut target)
            .unwrap();
        assert_eq!(&target[..len], "/target//../用户".as_bytes());
        let len = recovered.readlink(path("/dangling"), &mut target).unwrap();
        assert_eq!(&target[..len], b"../missing");
        assert_eq!(recovered.change_sequence(), 0);
        recovered.remove(path("/config/current"), false).unwrap();
        recovered.remove(path("/dangling"), false).unwrap();
        recovered.write_snapshot(&mut bytes).unwrap();
        assert_eq!(&bytes[8..12], &1u32.to_le_bytes());
    }

    fn assert_invalid_snapshot_is_atomic(bytes: &[u8]) {
        let mut fs = FileSystem::new();
        assert_eq!(fs.restore_snapshot(bytes), Err(Error::InvalidPath));
        assert_eq!(fs.status().nodes, 0);
        assert_eq!(fs.status().bytes, 0);
        assert_eq!(fs.status().revision, 1);
        assert_eq!(fs.change_sequence(), 0);
    }

    #[test]
    fn malformed_link_snapshots_reject_before_publishing_any_record() {
        let mut fs = FileSystem::new();
        fs.mkdir(path("/d")).unwrap();
        fs.symlink(path("/d/link"), "/target").unwrap();
        let mut original = [0; 1024];
        let size = fs.write_snapshot(&mut original).unwrap();
        let link_record = HEADER + RECORD;
        let payload = link_record + RECORD;
        for version in [0u32, 1, 3, u32::MAX] {
            let mut bytes = original;
            bytes[8..12].copy_from_slice(&version.to_le_bytes());
            assert_invalid_snapshot_is_atomic(&bytes[..size]);
        }
        for invalid_byte in [0u8, 0xff] {
            let mut bytes = original;
            bytes[payload] = invalid_byte;
            assert_invalid_snapshot_is_atomic(&bytes[..size]);
        }
        let mut empty = original;
        empty[link_record + 12..link_record + 16].copy_from_slice(&0u32.to_le_bytes());
        assert_invalid_snapshot_is_atomic(&empty[..payload]);
        let mut too_long = original;
        too_long[link_record + 12..link_record + 16]
            .copy_from_slice(&((PATH_BYTES + 1) as u32).to_le_bytes());
        too_long[payload..payload + PATH_BYTES + 1].fill(b'x');
        assert_invalid_snapshot_is_atomic(&too_long[..payload + PATH_BYTES + 1]);
        // Unknown kind is invalid even in v2.
        let mut unknown = original;
        unknown[link_record] = 4;
        assert_invalid_snapshot_is_atomic(&unknown[..size]);
    }

    #[cfg(feature = "full-os")]
    #[test]
    fn snapshot_aggregate_bound_fits_existing_slot_and_rejects_oversized_payload() {
        assert_eq!(MAX_BYTES, 276512);
        assert!(MAX_BYTES <= 392704);
        // Every record and file is individually valid. The sum alone is too
        // large, while the wire image still fits MAX_BYTES and the disk slot.
        let count = RETAINED_BYTES / FILE_BYTES + 1;
        let size = HEADER + count * (RECORD + FILE_BYTES);
        assert!(size < MAX_BYTES);
        let mut bytes = [0; MAX_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&(count as u32).to_le_bytes());
        bytes[16..24].copy_from_slice(&(count as u64).to_le_bytes());
        for i in 0..count {
            let at = HEADER + i * (RECORD + FILE_BYTES);
            bytes[at] = 1;
            bytes[at + 1] = 3;
            bytes[at + 2..at + 4].copy_from_slice(&0o600u16.to_le_bytes());
            bytes[at + 4..at + 12].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            bytes[at + 12..at + 16].copy_from_slice(&(FILE_BYTES as u32).to_le_bytes());
            bytes[at + 16..at + 19].copy_from_slice(&[
                b'/',
                b'a' + (i / 26) as u8,
                b'a' + (i % 26) as u8,
            ]);
        }
        assert_invalid_snapshot_is_atomic(&bytes[..size]);
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert_invalid_snapshot_is_atomic(&bytes[..size]);
    }
}
