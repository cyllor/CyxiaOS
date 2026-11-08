//! Provision only a NEW A09 input volume. File bytes are inputs, not evidence.
use cyxia_prototype::{
    domains::filesystem::{FileSystem, OpenMode},
    journal::{self, BlockDevice, Journal},
    storage::{BLOCK_SIZE, TOTAL_BLOCKS},
};
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
};
struct Disk(std::fs::File);
impl BlockDevice for Disk {
    type Error = std::io::Error;
    fn block_count(&self) -> u32 {
        TOTAL_BLOCKS
    }
    fn read_block(&mut self, b: u32, out: &mut [u8; BLOCK_SIZE]) -> std::io::Result<()> {
        self.0
            .seek(SeekFrom::Start(u64::from(b) * BLOCK_SIZE as u64))?;
        self.0.read_exact(out)
    }
    fn write_block(&mut self, b: u32, input: &[u8; BLOCK_SIZE]) -> std::io::Result<()> {
        self.0
            .seek(SeekFrom::Start(u64::from(b) * BLOCK_SIZE as u64))?;
        self.0.write_all(input)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.sync_all()
    }
}
fn word(nonce: [u64; 2], page: u64, index: u64) -> u64 {
    nonce[0]
        ^ nonce[1].rotate_left(17)
        ^ page.wrapping_mul(0xc2b2ae3d27d4eb4f)
        ^ index.wrapping_mul(0x165667b19e3779f9)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 3 || args[2].len() != 32 || !args[2].bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("usage: prototype-memory-disk NEW_IMAGE RUN_NONCE_HEX".into());
    }
    let mut uuid = [0u8; 16];
    for (i, b) in uuid.iter_mut().enumerate() {
        *b = u8::from_str_radix(&args[2][i * 2..i * 2 + 2], 16)?;
    }
    if uuid == [0; 16] {
        return Err("nonzero run nonce required".into());
    }
    let nonce = [
        u64::from_le_bytes(uuid[..8].try_into()?),
        u64::from_le_bytes(uuid[8..].try_into()?),
    ];
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&args[1])?;
    file.set_len(u64::from(TOTAL_BLOCKS) * BLOCK_SIZE as u64)?;
    let mut d = Disk(file);
    let mut scratch = [0; 8192];
    journal::format(&mut d, uuid, &mut scratch).map_err(|e| format!("format: {e:?}"))?;
    let mut j = Journal::new();
    j.mount(&mut d, &mut scratch)
        .map_err(|e| format!("mount: {e:?}"))?;
    cyxia_prototype::boot::BootSession::new()
        .allocate(&mut j, &mut d, &mut scratch, &mut [[0; 4096]; 4])
        .map_err(|e| format!("fixture boot metadata: {e:?}"))?;
    let mut f = FileSystem::<64>::new();
    f.mount(&mut j, &mut d, &mut scratch)
        .map_err(|e| format!("files: {e:?}"))?;
    f.mkdir("/a09", &mut j, &mut d, &mut scratch)
        .map_err(|e| format!("mkdir: {e:?}"))?;
    let mut bytes = [0u8; 65536];
    let mut global = 0u64;
    for (name, pages) in [
        ("/a09/blob-a", 2048u64),
        ("/a09/blob-b", 2048),
        ("/a09/blob-c", 1),
    ] {
        f.create(name, &mut j, &mut d, &mut scratch)
            .map_err(|e| format!("create: {e:?}"))?;
        let h = f
            .open(name, OpenMode::ReadWrite, &mut j, &mut d, &mut scratch)
            .map_err(|e| format!("open: {e:?}"))?;
        let mut offset = 0;
        while offset < pages {
            let batch = (pages - offset).min(16) as usize;
            for p in 0..batch {
                for k in 0..512 {
                    bytes[p * 4096 + k * 8..p * 4096 + k * 8 + 8]
                        .copy_from_slice(&word(nonce, global + p as u64, k as u64).to_le_bytes());
                }
            }
            let n = f
                .write(
                    h,
                    offset * 4096,
                    &bytes[..batch * 4096],
                    &mut j,
                    &mut d,
                    &mut scratch,
                )
                .map_err(|e| format!("write: {e:?}"))?;
            if n != batch * 4096 {
                return Err("short fixture write".into());
            }
            f.fsync(h, &mut j, &mut d, &mut scratch)
                .map_err(|e| format!("fsync: {e:?}"))?;
            global += batch as u64;
            offset += batch as u64;
        }
        f.close(h).map_err(|e| format!("close: {e:?}"))?;
    }
    d.flush()?;
    println!(
        "A09_INPUT fixture_pages=4097 file_limit_pages=2048 log_epoch={} nonce={}",
        j.superblock().log_epoch,
        args[2]
    );
    Ok(())
}
