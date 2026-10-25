use cyxia_prototype::learning::softfloat::{F64, FloatError};

fn soft(x: f64) -> F64 {
    F64::from_bits_checked(x.to_bits()).unwrap()
}
fn equal(actual: Result<F64, FloatError>, expected: f64, context: (u64, u64, u8)) {
    if expected.is_finite() {
        assert_eq!(
            actual.map(F64::to_bits),
            Ok(expected.to_bits()),
            "{context:x?}"
        );
    } else {
        assert_eq!(actual, Err(FloatError::Overflow), "{context:x?}");
    }
}
#[test]
fn binary64_operations_match_independent_hardware_at_rounding_and_range_edges() {
    let bits = [
        0,
        1 << 63,
        1,
        2,
        3,
        0x000f_ffff_ffff_ffff,
        0x0010_0000_0000_0000,
        0x0010_0000_0000_0001,
        0x3ca0_0000_0000_0000,
        0x3cb0_0000_0000_0000,
        0x3fe0_0000_0000_0000,
        0x3ff0_0000_0000_0000,
        0x3ff0_0000_0000_0001,
        0x4000_0000_0000_0000,
        0x433f_ffff_ffff_ffff,
        0x4340_0000_0000_0000,
        0x7fdf_ffff_ffff_ffff,
        0x7fef_ffff_ffff_ffff,
    ];
    for &x in &bits {
        for &y in &bits {
            for sign in [0, 1 << 63] {
                let (x, y) = (x ^ sign, y);
                let (a, b) = (
                    F64::from_bits_checked(x).unwrap(),
                    F64::from_bits_checked(y).unwrap(),
                );
                let (a_ref, b_ref) = (f64::from_bits(x), f64::from_bits(y));
                equal(a.add(b), a_ref + b_ref, (x, y, 0));
                equal(a.sub(b), a_ref - b_ref, (x, y, 1));
                equal(a.mul(b), a_ref * b_ref, (x, y, 2));
                if b_ref != 0.0 {
                    equal(a.div(b), a_ref / b_ref, (x, y, 3));
                } else {
                    assert_eq!(a.div(b), Err(FloatError::DivisionByZero));
                }
            }
        }
    }
}

#[test]
fn binary64_operations_match_hardware_for_deterministic_finite_bit_patterns() {
    let mut seed = 0x4359584c4541524eu64;
    let mut next = || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        if (seed >> 52) & 0x7ff == 0x7ff {
            seed ^ (1 << 52)
        } else {
            seed
        }
    };
    for _ in 0..40_000 {
        let (x, y) = (next(), next());
        let (a, b) = (
            F64::from_bits_checked(x).unwrap(),
            F64::from_bits_checked(y).unwrap(),
        );
        let (a_ref, b_ref) = (f64::from_bits(x), f64::from_bits(y));
        equal(a.add(b), a_ref + b_ref, (x, y, 0));
        equal(a.sub(b), a_ref - b_ref, (x, y, 1));
        equal(a.mul(b), a_ref * b_ref, (x, y, 2));
        if b_ref != 0.0 {
            equal(a.div(b), a_ref / b_ref, (x, y, 3));
        }
    }
}

#[test]
fn integer_conversion_clipping_and_nonfinite_rejection_are_explicit() {
    for i in [
        0u64,
        1,
        255,
        256,
        (1 << 53) - 1,
        1 << 53,
        (1 << 53) + 1,
        u64::MAX,
    ] {
        assert_eq!(F64::from_u64(i).to_bits(), (i as f64).to_bits());
    }
    for i in [i64::MIN, -32769, -32768, -257, -1, 0, 1, 32767, i64::MAX] {
        assert_eq!(F64::from_i64(i).to_bits(), (i as f64).to_bits());
    }
    for x in [
        -65535.25, -256.5, -1.5, -0.5, -0.0, 0.0, 0.5, 1.5, 256.5, 65535.25,
    ] {
        assert_eq!(soft(x).floor().unwrap().to_bits(), x.floor().to_bits());
        assert_eq!(soft(x).to_i64_trunc(), Ok(x as i64));
        assert_eq!(
            soft(x).clamp(soft(-1.0), soft(1.0)).unwrap().to_bits(),
            x.clamp(-1.0, 1.0).to_bits()
        );
    }
    assert_eq!(soft(f64::MAX).to_i64_trunc(), Err(FloatError::Range));
    assert_eq!(soft(-1.0).to_u64_trunc(), Err(FloatError::Range));
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            F64::from_bits_checked(value.to_bits()),
            Err(FloatError::NonFinite)
        );
    }
}

fn bits(value: u64) -> F64 {
    F64::from_bits_checked(value).unwrap()
}

#[test]
fn fixed_golden_vectors_pin_ties_signed_zero_underflow_and_overflow() {
    // Expected encodings are fixed constants, independent of the hardware
    // reference used by the differential tests. op = add/sub/mul/div.
    const S: u64 = 1 << 63;
    const ONE: u64 = 0x3ff0_0000_0000_0000;
    const HALF: u64 = 0x3fe0_0000_0000_0000;
    const TWO: u64 = 0x4000_0000_0000_0000;
    const HALF_ULP: u64 = 0x3ca0_0000_0000_0000;
    const QUARTER_ULP: u64 = 0x3c90_0000_0000_0000;
    const NORMAL: u64 = 0x0010_0000_0000_0000;
    const MAX: u64 = 0x7fef_ffff_ffff_ffff;
    let vectors: &[(u8, u64, u64, Result<u64, FloatError>)] = &[
        (0, 0, S, Ok(0)),
        (0, S, S, Ok(S)),
        (1, S, 0, Ok(S)),
        (1, S, S, Ok(0)),
        (1, ONE, ONE, Ok(0)),
        (1, S | ONE, S | ONE, Ok(0)),
        (2, 0, S | ONE, Ok(S)),
        (3, S, S | ONE, Ok(0)),
        (0, ONE, HALF_ULP, Ok(ONE)),
        (0, ONE, HALF_ULP - 1, Ok(ONE)),
        (0, ONE, HALF_ULP + 1, Ok(ONE + 1)),
        (0, ONE + 1, HALF_ULP, Ok(ONE + 2)),
        (0, S | ONE, S | HALF_ULP, Ok(S | ONE)),
        (1, ONE, QUARTER_ULP, Ok(ONE)),
        (1, ONE - 1, QUARTER_ULP, Ok(ONE - 2)),
        (1, ONE, HALF_ULP, Ok(ONE - 1)),
        (1, ONE + 1, ONE, Ok(0x3cb0_0000_0000_0000)),
        (1, NORMAL, NORMAL - 1, Ok(1)),
        (0, NORMAL - 1, 1, Ok(NORMAL)),
        (2, 1, HALF, Ok(0)),
        (2, S | 1, HALF, Ok(S)),
        (2, 3, HALF, Ok(2)),
        (2, 5, HALF, Ok(2)),
        (2, S | 3, HALF, Ok(S | 2)),
        (2, 1, HALF + 1, Ok(1)),
        (2, 1, HALF - 1, Ok(0)),
        (2, NORMAL, ONE - 1, Ok(NORMAL)),
        (2, NORMAL, ONE - 2, Ok(NORMAL - 1)),
        (2, NORMAL + 1, ONE - 1, Ok(NORMAL)),
        (2, NORMAL - 1, ONE + 1, Ok(NORMAL)),
        (2, NORMAL, HALF, Ok(0x0008_0000_0000_0000)),
        (2, ONE + 1, ONE + 1, Ok(ONE + 2)),
        (2, ONE + 1, ONE - 2, Ok(ONE)),
        (3, ONE, 0x4008_0000_0000_0000, Ok(0x3fd5_5555_5555_5555)),
        (3, TWO, 0x4008_0000_0000_0000, Ok(0x3fe5_5555_5555_5555)),
        (3, ONE, 0x4024_0000_0000_0000, Ok(0x3fb9_9999_9999_999a)),
        (3, 1, TWO, Ok(0)),
        (3, 3, TWO, Ok(2)),
        (3, 5, TWO, Ok(2)),
        (3, S | 1, TWO, Ok(S)),
        (3, NORMAL, TWO, Ok(0x0008_0000_0000_0000)),
        (0, MAX, ((970 + 1023) << 52) - 1, Ok(MAX)),
        (0, MAX, (970 + 1023) << 52, Err(FloatError::Overflow)),
        (
            0,
            S | MAX,
            S | ((970 + 1023) << 52),
            Err(FloatError::Overflow),
        ),
        (2, MAX, ONE + 1, Err(FloatError::Overflow)),
        (3, MAX, HALF, Err(FloatError::Overflow)),
        (3, ONE, 0, Err(FloatError::DivisionByZero)),
        (3, ONE, S, Err(FloatError::DivisionByZero)),
        (3, 0, 0, Err(FloatError::DivisionByZero)),
    ];
    for &(op, x, y, expected) in vectors {
        let (a, b) = (bits(x), bits(y));
        let actual = match op {
            0 => a.add(b),
            1 => a.sub(b),
            2 => a.mul(b),
            3 => a.div(b),
            _ => unreachable!(),
        };
        assert_eq!(
            actual.map(F64::to_bits),
            expected,
            "op={op} x={x:016x} y={y:016x}"
        );
    }
    // Each primitive rounds separately. Fusing the multiply with the subtract
    // would produce -2^-104 here, violating the specified left fold.
    assert_eq!(
        bits(ONE + 1).mul(bits(ONE - 2)).unwrap().sub(F64::ONE),
        Ok(F64::ZERO)
    );
}

#[test]
fn cancellation_and_guard_bits_match_at_every_normal_exponent() {
    const FRACTION: u64 = (1 << 52) - 1;
    let tails = [
        0,
        1,
        2,
        3,
        0x0008_0000_0000_0000,
        FRACTION - 2,
        FRACTION - 1,
        FRACTION,
    ];
    for exponent in 1..=2046u64 {
        for &tail in &tails {
            let x = (exponent << 52) | tail;
            for distance in [0, 1, 2, 3, 4, 52, 53, 54, 55, 63, 64, 127, 128] {
                let Some(other_exponent) = exponent.checked_sub(distance) else {
                    continue;
                };
                for &other_tail in &[tail, FRACTION ^ tail] {
                    let y = (other_exponent << 52) | other_tail;
                    let (a, b) = (bits(x), bits(y));
                    let (ar, br) = (f64::from_bits(x), f64::from_bits(y));
                    equal(a.add(b), ar + br, (x, y, 0));
                    equal(a.sub(b), ar - br, (x, y, 1));
                    equal(a.neg().add(b), -ar + br, (x, y, 2));
                }
            }
        }
    }
}

#[test]
fn gradual_underflow_rounds_once_around_zero_and_the_normal_boundary() {
    let factors = [
        0x3fdf_ffff_ffff_ffff,
        0x3fe0_0000_0000_0000,
        0x3fe0_0000_0000_0001,
        0x3fef_ffff_ffff_ffff,
        0x3ff0_0000_0000_0000,
        0x3ff0_0000_0000_0001,
        0x4000_0000_0000_0000,
        0x4008_0000_0000_0000,
    ];
    for x in (0..2048u64).chain(0x000f_ffff_ffff_f800..0x0010_0000_0000_0800) {
        for y in factors {
            let (a, b) = (bits(x), bits(y));
            let (ar, br) = (f64::from_bits(x), f64::from_bits(y));
            equal(a.mul(b), ar * br, (x, y, 0));
            equal(a.div(b), ar / br, (x, y, 1));
            equal(a.neg().mul(b), -ar * br, (x, y, 2));
            equal(a.neg().div(b), -ar / br, (x, y, 3));
        }
    }
}

#[test]
fn comparison_floor_and_integer_conversion_cover_full_finite_range() {
    let mut state = 0x26f4_487a_72cb_928du64;
    for _ in 0..20_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        assert_eq!(F64::from_u64(state).to_bits(), (state as f64).to_bits());
        assert_eq!(
            F64::from_i64(state as i64).to_bits(),
            (state as i64 as f64).to_bits()
        );
        let raw = if (state >> 52) & 0x7ff == 0x7ff {
            state ^ (1 << 52)
        } else {
            state
        };
        let a = bits(raw);
        let reference = f64::from_bits(raw);
        assert_eq!(a.abs().to_bits(), reference.abs().to_bits());
        assert_eq!(a.neg().to_bits(), (-reference).to_bits());
        assert_eq!(
            a.floor().map(F64::to_bits),
            Ok(reference.floor().to_bits()),
            "{raw:016x}"
        );
        for bound in [f64::NEG_INFINITY.next_up(), -1.0, -0.0, 0.0, 1.0, f64::MAX] {
            assert_eq!(
                a.compare(soft(bound)),
                reference.partial_cmp(&bound).unwrap()
            );
        }
        let truncated = reference.trunc();
        let signed = if truncated >= -9223372036854775808.0 && truncated < 9223372036854775808.0 {
            Ok(truncated as i64)
        } else {
            Err(FloatError::Range)
        };
        let unsigned = if truncated >= 0.0 && truncated < 18446744073709551616.0 {
            Ok(truncated as u64)
        } else {
            Err(FloatError::Range)
        };
        assert_eq!(a.to_i64_trunc(), signed, "{raw:016x}");
        assert_eq!(a.to_u64_trunc(), unsigned, "{raw:016x}");
    }
    assert_eq!(bits(0).compare(bits(1 << 63)), core::cmp::Ordering::Equal);
    assert_eq!(bits(1 << 63).floor().unwrap().to_bits(), 1 << 63);
    assert_eq!(bits(0xbfe0_0000_0000_0000).to_u64_trunc(), Ok(0));
    assert_eq!(bits(0xc3e0_0000_0000_0000).to_i64_trunc(), Ok(i64::MIN));
    assert_eq!(
        bits(0xc3e0_0000_0000_0001).to_i64_trunc(),
        Err(FloatError::Range)
    );
    assert_eq!(
        bits(0x43e0_0000_0000_0000).to_i64_trunc(),
        Err(FloatError::Range)
    );
    assert_eq!(
        bits(0x43ef_ffff_ffff_ffff).to_u64_trunc(),
        Ok(u64::MAX - 2047)
    );
    assert_eq!(
        bits(0x43f0_0000_0000_0000).to_u64_trunc(),
        Err(FloatError::Range)
    );
    assert_eq!(F64::ZERO.clamp(F64::ONE, F64::ZERO), Err(FloatError::Range));
    for raw in [
        0x7ff0_0000_0000_0000,
        0xfff0_0000_0000_0000,
        0x7ff0_0000_0000_0001,
        0x7ff8_0000_0000_0000,
        0xffff_ffff_ffff_ffff,
    ] {
        assert_eq!(F64::from_bits_checked(raw), Err(FloatError::NonFinite));
    }
}
