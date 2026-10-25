//! Freestanding deterministic initialization shared by package construction
//! and a bootstrap ABI. These bytes carry no trained/validated provenance.
//! Keep this module free of crate dependencies so a tiny no_std ELF ABI can
//! include the same source instead of maintaining a second model generator.
pub const SEED_MODEL_BYTES: usize = 2772;
pub const UNTRAINED_SEED0_BYTES: [u8; SEED_MODEL_BYTES] = untrained_seed_bytes(0);

pub const fn untrained_seed_bytes(seed: u64) -> [u8; SEED_MODEL_BYTES] {
    let mut bytes = [0; SEED_MODEL_BYTES];
    let inputs = [
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 41, 42, 56, 58,
    ];
    let mut row = 0;
    while row < inputs.len() {
        bytes[row * 64 + inputs[row]] = 64;
        bytes[2048 + row * 32 + row] = 64;
        bytes[2560 + row] = if row == 12 {
            64
        } else if row == 13 {
            16
        } else {
            1
        };
        row += 1;
    }
    bytes[14 * 64 + 57] = 16;
    bytes[15 * 64 + 59] = 16;
    bytes[2560] = (1 + (seed & 3)) as u8;
    bytes
}
