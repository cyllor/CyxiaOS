//! Exact equivalence with the schema's wide integer expression, including
//! the boundary where the production encoder switches arithmetic width.
use cyxia_prototype::{
    domains::Error,
    features::{COMMON_LIMITS, DOMAIN_LIMITS, TARGET_LIMITS, normalize},
};

fn wide(value: u64, upper: u64) -> (i16, bool) {
    let value_in_range = u128::from(value.min(upper));
    let upper_wide = u128::from(upper);
    (((512 * value_in_range + upper_wide) / (2 * upper_wide)) as i16, value > upper)
}

#[test]
fn every_schema_limit_preserves_all_rounding_boundaries_and_saturation() {
    for upper in COMMON_LIMITS.into_iter().chain(DOMAIN_LIMITS.into_iter().flatten()).chain(TARGET_LIMITS) {
        for step in 0..=512u64 {
            let midpoint = step * upper / 512;
            for value in [midpoint.saturating_sub(1), midpoint, midpoint + 1, upper, upper + 1, u64::MAX] {
                assert_eq!(normalize(value, upper), Ok(wide(value, upper)), "value={value}, upper={upper}");
            }
        }
    }
}

#[test]
fn width_boundary_and_large_random_inputs_preserve_the_wide_formula() {
    let limit = u64::MAX / 513;
    for upper in [1, 512, limit - 1, limit, limit + 1, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
        for value in [0, 1, upper / 2, upper - 1, upper, upper.saturating_add(1), u64::MAX] {
            assert_eq!(normalize(value, upper), Ok(wide(value, upper)), "value={value}, upper={upper}");
        }
    }
    let mut state = 0x8422_2325_cbf2_9ce4u64;
    for _ in 0..10_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let value = state;
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let upper = state.max(1);
        assert_eq!(normalize(value, upper), Ok(wide(value, upper)));
    }
    assert_eq!(normalize(0, 0), Err(Error::Schema));
    assert_eq!(normalize(u64::MAX, 0), Err(Error::Schema));
}
