use crate::weights;
pub const MEMORY_ID: u64 = 0x2001;
pub const CPU_ID: u64 = 0x3001;
pub const DEVICE_ID: u64 = 0x4001;
fn score(w: [i32; 4], x: [i32; 4]) -> i32 {
    w.into_iter().zip(x).map(|(a, b)| a * b).sum()
}
pub fn memory(free: usize, count: usize) -> bool {
    score(weights::MEMORY, [1, free as i32, count as i32, 0]) >= 0
}
pub fn cpu(age: u64, priority: u8, remaining: u32) -> i32 {
    score(
        weights::CPU,
        [
            1,
            age.min(32) as i32,
            priority as i32,
            remaining.div_ceil(256).min(16) as i32,
        ],
    )
}
pub fn quantum(ready: usize, remaining: u32) -> u32 {
    if score(
        weights::QUANTUM,
        [1, ready as i32, remaining.div_ceil(256).min(16) as i32, 0],
    ) >= 0
    {
        256
    } else {
        32
    }
}
pub fn device(age: u64, priority: u8, retries: u8) -> i32 {
    score(
        weights::DEVICE,
        [
            1,
            age.min(32) as i32,
            priority as i32,
            retries.min(4) as i32,
        ],
    )
}
