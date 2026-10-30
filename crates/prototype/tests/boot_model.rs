//! Component vector checks; these never substitute for the actual EL0 self-test.
use cyxia_prototype::{boot_model, learning::seed::UNTRAINED_SEED0_BYTES};
use sha2::{Digest, Sha256};

#[test]
fn exact_boot_seed_passes_full_layer_vectors_and_hash() {
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(UNTRAINED_SEED0_BYTES)),
        boot_model::PARAMETER_HASH
    );
    assert!(boot_model::check(&UNTRAINED_SEED0_BYTES));
}
#[test]
fn wrong_shape_or_corrupt_output_bias_never_passes() {
    assert!(!boot_model::check(&[]));
    let mut bytes = UNTRAINED_SEED0_BYTES;
    bytes[2768] ^= 1;
    assert!(!boot_model::check(&bytes));
}
#[test]
fn each_active_layer_is_exercised() {
    for offset in [16, 2048, 2560] {
        let mut bytes = UNTRAINED_SEED0_BYTES;
        bytes[offset] ^= 0x40;
        assert!(!boot_model::check(&bytes), "layer mutation at {offset}");
    }
}
