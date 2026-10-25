//! Fixed little-endian file service frame shared verbatim by EL0 and EL1.
pub const SVC: u16 = 0x45;
pub const DISPATCH: u64 = 0x40;
pub const MAGIC: u64 = 0x435946494c453031;
pub const VERSION: u16 = 1;
pub const FRAME_BYTES: usize = 640;
pub const PATH_BYTES: usize = 512;
pub const MAX_IO: usize = 65536;
pub const DIRENT_BYTES: usize = 128;
pub const CREATE: u16 = 1;
pub const OPEN: u16 = 2;
pub const READ: u16 = 3;
pub const WRITE: u16 = 4;
pub const FSYNC: u16 = 5;
pub const CLOSE: u16 = 6;
pub const MKDIR: u16 = 7;
pub const READDIR: u16 = 8;
pub const UNLINK: u16 = 9;
pub const STAT: u16 = 10;
pub const GET_STAT_CAP: u16 = 11;
pub const MODE_READ: u16 = 1;
pub const MODE_WRITE: u16 = 2;
pub const MODE_READ_WRITE: u16 = 3;
pub const MODE_DIRECTORY: u16 = 4;
pub const RIGHT_READ: u16 = 1;
pub const RIGHT_WRITE: u16 = 2;
pub const RIGHT_CREATE: u16 = 4;
pub const RIGHT_DELETE: u16 = 8;
pub const ALL_RIGHTS: u16 = 15;
pub const OFF_MAGIC: usize = 0;
pub const OFF_VERSION: usize = 8;
pub const OFF_LENGTH: usize = 10;
pub const OFF_OPERATION: usize = 12;
pub const OFF_MODE: usize = 14;
pub const OFF_REQUEST: usize = 16;
pub const OFF_AUTH_ID: usize = 24;
pub const OFF_AUTH_GENERATION: usize = 32;
pub const OFF_HANDLE_ID: usize = 40;
pub const OFF_HANDLE_GENERATION: usize = 48;
pub const OFF_OFFSET: usize = 56;
pub const OFF_DATA: usize = 64;
pub const OFF_DATA_LENGTH: usize = 72;
pub const OFF_PATH_LENGTH: usize = 76;
pub const OFF_FLAGS: usize = 78;
pub const OFF_RESULT: usize = 80;
pub const OFF_COUNT: usize = 88;
pub const OFF_OBJECT_ID: usize = 96;
pub const OFF_OBJECT_GENERATION: usize = 104;
pub const OFF_WRITE_SEQ: usize = 112;
pub const OFF_DURABLE_SEQ: usize = 120;
pub const OFF_PATH: usize = 128;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capability {
    pub id: u64,
    pub generation: u64,
}
#[derive(Clone, Copy)]
pub struct Frame {
    pub bytes: [u8; FRAME_BYTES],
}
impl Frame {
    pub fn new(operation: u16, request: u64, authority: Capability) -> Self {
        let mut f = Self {
            bytes: [0; FRAME_BYTES],
        };
        f.set_u64(OFF_MAGIC, MAGIC);
        f.set_u16(OFF_VERSION, VERSION);
        f.set_u16(OFF_LENGTH, FRAME_BYTES as u16);
        f.set_u16(OFF_OPERATION, operation);
        f.set_u64(OFF_REQUEST, request);
        f.set_u64(OFF_AUTH_ID, authority.id);
        f.set_u64(OFF_AUTH_GENERATION, authority.generation);
        f
    }
    pub fn u16(&self, at: usize) -> u16 {
        u16::from_le_bytes(self.bytes[at..at + 2].try_into().unwrap())
    }
    pub fn u32(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.bytes[at..at + 4].try_into().unwrap())
    }
    pub fn u64(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.bytes[at..at + 8].try_into().unwrap())
    }
    pub fn set_u16(&mut self, at: usize, value: u16) {
        self.bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    pub fn set_u32(&mut self, at: usize, value: u32) {
        self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    pub fn set_u64(&mut self, at: usize, value: u64) {
        self.bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    pub fn set_path(&mut self, path: &str) -> bool {
        if path.len() > PATH_BYTES {
            return false;
        }
        self.bytes[OFF_PATH..].fill(0);
        self.bytes[OFF_PATH..OFF_PATH + path.len()].copy_from_slice(path.as_bytes());
        self.set_u16(OFF_PATH_LENGTH, path.len() as u16);
        true
    }
    pub fn result(&self) -> i64 {
        self.u64(OFF_RESULT) as i64
    }
}
