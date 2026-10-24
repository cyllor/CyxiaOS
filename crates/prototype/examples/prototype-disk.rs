//! Provision a NEW exact-size image. Never repair/reformat an existing image.
use cyxia_prototype::{
    journal::{self, BlockDevice},
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
    fn read_block(&mut self, block: u32, output: &mut [u8; BLOCK_SIZE]) -> std::io::Result<()> {
        self.0
            .seek(SeekFrom::Start(u64::from(block) * BLOCK_SIZE as u64))?;
        self.0.read_exact(output)
    }
    fn write_block(&mut self, block: u32, bytes: &[u8; BLOCK_SIZE]) -> std::io::Result<()> {
        self.0
            .seek(SeekFrom::Start(u64::from(block) * BLOCK_SIZE as u64))?;
        self.0.write_all(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.sync_all()
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || args[2].len() != 32 || !args[2].bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("usage: prototype-disk NEW_IMAGE UUID_32_HEX".into());
    }
    let mut uuid = [0; 16];
    for (index, byte) in uuid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&args[2][index * 2..index * 2 + 2], 16)?;
    }
    if uuid == [0; 16] {
        return Err("nonzero UUID required".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&args[1])?;
    file.set_len(u64::from(TOTAL_BLOCKS) * BLOCK_SIZE as u64)?;
    let mut disk = Disk(file);
    journal::format(&mut disk, uuid, &mut [0; 8192])
        .map_err(|error| format!("format failed: {error:?}"))?;
    println!("formatted new 512 MiB image; no BootEpoch allocated");
    Ok(())
}
