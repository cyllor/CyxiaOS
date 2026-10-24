//! Fixed engineering-fixture ABI; no authority or production policy messages.
pub const INPUT_VA: u64 = 0xa0000;
pub const OUTPUT_VA: u64 = 0xa1000;
pub const MODEL_VA: u64 = 0x90000;
pub const STACK_TOP: u64 = 0xb9000;
pub const INPUT_WORDS: usize = 72;
pub const OUTPUT_WORDS: usize = 64;
pub const INPUT_MAGIC: u64 = 0x435958494e503133;
pub const OUTPUT_MAGIC: u64 = 0x4359584f55543133;
pub const SUBMIT: u64 = 0x531;
pub const CASES: usize = 8;
pub const MODELS: usize = 6;
