use cyxia_prototype::learning::{
    Error,
    manifest::UntrainedSeed,
    softfloat::F64,
    train::{Parameters, quantize_bias, quantize_weight},
    validate::{integer_reference, operator_selftest},
};
use cyxia_prototype::model::{MODEL_BYTES, Model};

fn ratio(n: i64, d: u64) -> F64 {
    F64::from_i64(n).div(F64::from_u64(d)).unwrap()
}

#[test]
fn four_normative_sgd_projection_quantization_and_integer_output_goldens() {
    // Operator fixtures only. These are not replay samples or trained models.
    let vectors = [
        (256, 127, -768, 127, 64, -767, 256, 127, -767, -259),
        (256, -128, 1024, -2, 1, 1023, 256, -128, 1023, 511),
        (16640, -128, 32767, -511, 256, 32767, 256, -128, 32767, -513),
        (16640, 127, -32768, 507, 256, -128, 1, 127, -32768, 252),
    ];
    for (hidden, seed_w, seed_b, wn, wd, bn, bd, wq, bq, expected) in vectors {
        let mut weights = [0i8; 16];
        weights[0] = seed_w;
        let parameters = Parameters::from_quantized(weights, seed_b).unwrap();
        let mut h = [0i16; 16];
        h[0] = hidden;
        let step = parameters.step(&h, F64::ZERO).unwrap();
        assert_eq!(step.next.weights()[0], ratio(wn, wd));
        assert_eq!(step.next.bias(), ratio(bn, bd));
        let (weights, bias) = step.next.quantized().unwrap();
        assert_eq!((weights[0], bias), (wq, bq));
        let mut model = [0u8; MODEL_BYTES];
        model[0] = 64;
        model[2048] = 64;
        model[2560] = weights[0] as u8;
        model[2768..].copy_from_slice(&bias.to_le_bytes());
        let mut input = [0i16; 64];
        input[0] = hidden;
        assert_eq!(Model::parse(&model).unwrap().score(&input), expected);
        assert_eq!(integer_reference(&model, &input).output, expected);
    }
}

#[test]
fn quantization_is_half_away_and_bad_seed_is_never_silently_projected() {
    for sign in [-1, 1] {
        assert_eq!(quantize_weight(ratio(sign, 128)).unwrap(), sign as i8);
        assert_eq!(quantize_bias(ratio(sign, 512)).unwrap(), sign as i32);
    }
    let seed = UntrainedSeed::new(7);
    for bias in [32768i32, -32769] {
        let mut bytes = *seed.bytes();
        bytes[2768..].copy_from_slice(&bias.to_le_bytes());
        let original = bytes;
        assert_eq!(Parameters::from_model(&bytes), Err(Error::Model));
        assert_eq!(bytes, original);
    }
    // Full int32 biases in the frozen layers remain legal.
    let mut bytes = *seed.bytes();
    bytes[2576..2580].copy_from_slice(&i32::MAX.to_le_bytes());
    assert!(Parameters::from_model(&bytes).is_ok());
    assert!(F64::from_bits_checked(f64::NAN.to_bits()).is_err());
    assert!(F64::from_bits_checked(f64::INFINITY.to_bits()).is_err());
}

#[test]
fn gradients_share_one_preupdate_error_and_every_step_stays_bounded() {
    let parameters = Parameters::from_quantized([0; 16], 256).unwrap();
    let mut hidden = [0; 16];
    hidden[0] = 128;
    hidden[1] = 64;
    let step = parameters.step(&hidden, F64::ZERO).unwrap();
    assert_eq!(step.prediction, F64::ONE);
    assert_eq!(step.clipped_gradients[0], ratio(1, 2));
    assert_eq!(step.clipped_gradients[1], ratio(1, 4));
    assert_eq!(step.next.weights()[0], ratio(-1, 512));
    assert_eq!(step.next.weights()[1], ratio(-1, 1024));
    assert_eq!(step.next.bias(), ratio(255, 256));
    let mut parameters = parameters;
    for turn in 0..1024 {
        let reward = if turn % 2 == 0 {
            ratio(1, 2)
        } else {
            ratio(-1, 4)
        };
        let next = parameters.step(&[32767; 16], reward).unwrap().next;
        for (a, b) in parameters.weights().iter().zip(next.weights()) {
            assert!(!a.sub(*b).unwrap().abs().compare(ratio(1, 256)).is_gt());
        }
        assert!(
            !parameters
                .bias()
                .sub(next.bias())
                .unwrap()
                .abs()
                .compare(ratio(1, 256))
                .is_gt()
        );
        parameters = next;
    }
    assert_eq!(parameters.step(&[-1; 16], F64::ZERO), Err(Error::Evidence));
    // A finite but enormous label overflows the raw e*h gradient. Clipping
    // must not hide the non-finite intermediate or modify the old parameters.
    let prior = parameters;
    let enormous = F64::from_bits_checked(0x7fef_ffff_ffff_ffff).unwrap();
    assert_eq!(parameters.step(&[32767; 16], enormous), Err(Error::Numeric));
    assert_eq!(parameters, prior);
}

#[test]
fn full_integer_reference_matches_independent_extreme_models_and_fixed_operators() {
    operator_selftest().unwrap();
    let mut seed = 0x3fa2_b17c_46e9_2231u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..64 {
        let mut bytes = [0; MODEL_BYTES];
        for b in &mut bytes {
            *b = next() as u8;
        }
        // Mix very large int32 biases with moderate ones; check all layers.
        for i in (0..49).step_by(2) {
            bytes[2576 + 4 * i..2580 + 4 * i]
                .copy_from_slice(&((next() as i32) % 1024).to_le_bytes());
        }
        let mut input = [0i16; 64];
        for v in &mut input {
            *v = next() as i16;
        }
        assert_eq!(
            Model::parse(&bytes).unwrap().trace(&input),
            integer_reference(&bytes, &input)
        );
    }
}
