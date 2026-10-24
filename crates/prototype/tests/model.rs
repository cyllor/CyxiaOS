use cyxia_prototype::model::{Error, Model};

const BYTES: usize = 2772;

#[test]
fn parser_rejects_every_non_exact_package_length() {
    for actual in [0, 1, 2576, 2771, 2773, 4096] {
        let bytes = vec![0; actual];
        assert!(matches!(
            Model::parse(&bytes),
            Err(Error::InvalidModelLength { actual: found }) if found == actual
        ));
    }
    assert!(Model::parse(&[0; BYTES]).is_ok());
}

// Fixtures below are synthetic engineering vectors, not a trained model package.
fn bias(bytes: &mut [u8; BYTES], index: usize, value: i32) {
    bytes[2576 + 4 * index..2580 + 4 * index].copy_from_slice(&value.to_le_bytes());
}

fn path_model() -> [u8; BYTES] {
    let mut bytes = [0; BYTES];
    bytes[0] = 64;
    bytes[2048] = 64;
    bytes[2560] = 64;
    bytes
}

#[test]
fn hand_calculated_network_uses_row_major_weights_and_layer_ordered_biases() {
    let mut bytes = [0; BYTES];
    bytes[0] = 32;
    bytes[1] = (-16_i8) as u8;
    bytes[63] = 1;
    bytes[64] = (-64_i8) as u8;
    bytes[31 * 64 + 1] = (-64_i8) as u8;
    bias(&mut bytes, 0, 3);
    bias(&mut bytes, 1, 1);
    bias(&mut bytes, 31, -2);
    bytes[2048] = 32;
    bytes[2049] = 64;
    bytes[2048 + 31] = (-16_i8) as u8;
    bytes[2048 + 15 * 32] = (-16_i8) as u8;
    bytes[2048 + 15 * 32 + 31] = 64;
    bias(&mut bytes, 32, -1);
    bias(&mut bytes, 33, -1);
    bias(&mut bytes, 47, 2);
    bytes[2560] = (-32_i8) as u8;
    bytes[2561] = (-128_i8) as u8;
    bytes[2575] = 16;
    bias(&mut bytes, 48, -3);
    let model = Model::parse(&bytes).unwrap();
    let mut input = [0; 64];
    input[0] = 256;
    input[1] = -128;
    input[63] = 64;
    // h1[0,1,31] = [164,0,126]; h2[0,1,15] = [50,0,87].
    // Output accumulator = -32*50 + 16*87 - 64*3 = -400 -> -6.
    assert_eq!(model.score(&input), -6);
    // For zero input: h1 = [3,1,0], h2 = [2,0,1], z = -240 -> -4.
    assert_eq!(model.score(&[0; 64]), -4);
}

#[test]
fn output_rounds_both_signs_at_half_away_from_zero() {
    for (weight, cases) in [
        (1_i8, [(31, 0), (32, 1), (33, 1), (95, 1), (96, 2)]),
        (-1_i8, [(31, 0), (32, -1), (33, -1), (95, -1), (96, -2)]),
    ] {
        let mut bytes = path_model();
        bytes[2560] = weight as u8;
        let model = Model::parse(&bytes).unwrap();
        for (raw_input, expected) in cases {
            let mut input = [0; 64];
            input[0] = raw_input;
            assert_eq!(model.score(&input), expected, "w={weight}, x={raw_input}");
        }
    }
}

#[test]
fn each_hidden_layer_saturates_before_the_following_layer() {
    for (w1, w2) in [(127, 1), (64, 127)] {
        let mut bytes = path_model();
        bytes[0] = w1;
        bytes[2048] = w2;
        bytes[2560] = if w1 == 127 { 64 } else { 1 };
        let mut input = [0; 64];
        input[0] = i16::MAX;
        // 32767*127/64 rounds to 65022, then clamps to 32767;
        // the adjacent weight 1 divides that clamped value to 512.
        assert_eq!(Model::parse(&bytes).unwrap().score(&input), 512);
    }
}

#[test]
fn output_saturates_and_biases_decode_as_unaligned_little_endian() {
    for (raw_bias, expected) in [
        (0x0102, 258),
        (-0x0102, -258),
        (i32::MAX, i16::MAX),
        (i32::MIN, i16::MIN),
    ] {
        let mut unaligned = [0; BYTES + 1];
        unaligned[1 + 2768..1 + 2772].copy_from_slice(&raw_bias.to_le_bytes());
        let model = Model::parse(&unaligned[1..]).unwrap();
        assert_eq!(model.score(&[0; 64]), expected);
    }
}

#[test]
fn maximum_weight_input_and_bias_accumulation_stays_in_range() {
    let mut bytes = [0; BYTES];
    bytes[..2048].fill((-128_i8) as u8);
    bytes[2048..2560].fill(127);
    bytes[2560..2576].fill(1);
    for index in 0..48 {
        bias(&mut bytes, index, i32::MAX);
    }
    // Each h1 accumulator is 137438953408 + 268435456 = 137707388864.
    // All hidden activations saturate to 32767; output = 16*32767/64 ->8192.
    assert_eq!(Model::parse(&bytes).unwrap().score(&[i16::MIN; 64]), 8192);
    for index in 0..48 {
        bias(&mut bytes, index, i32::MIN);
    }
    bias(&mut bytes, 48, 9);
    // Even maximum positive dot products cannot overcome these negative biases.
    assert_eq!(Model::parse(&bytes).unwrap().score(&[i16::MIN; 64]), 9);
}

#[test]
fn selection_rejects_empty_or_more_than_32_candidates() {
    let bytes = path_model();
    let model = Model::parse(&bytes).unwrap();
    assert_eq!(model.select(&[]), Err(Error::EmptyCandidates));
    assert_eq!(
        model.select(&[[0; 64]; 33]),
        Err(Error::TooManyCandidates { actual: 33 })
    );
}

#[test]
fn selection_accepts_one_and_32_and_scores_the_last_candidate() {
    let bytes = path_model();
    let model = Model::parse(&bytes).unwrap();
    assert_eq!(model.select(&[[0; 64]; 1]), Ok(0));
    let mut candidates = [[0; 64]; 32];
    candidates[31][0] = 1;
    assert_eq!(model.select(&candidates), Ok(31));
}

#[test]
fn selection_uses_first_maximum_even_for_all_negative_scores() {
    let mut bytes = path_model();
    bytes[2560] = (-64_i8) as u8;
    let model = Model::parse(&bytes).unwrap();
    let mut candidates = [[0; 64]; 4];
    for (candidate, input) in candidates.iter_mut().zip([300, 100, 100, 200]) {
        candidate[0] = input;
    }
    assert_eq!(model.select(&candidates), Ok(1));
    assert_eq!(model.select(&[candidates[0]; 32]), Ok(0));
}

#[test]
fn trace_exposes_actual_hidden_activations_on_the_score_path() {
    let mut bytes = path_model();
    bytes[0] = 127;
    bytes[2048] = 1;
    bytes[2560] = (-1_i8) as u8;
    let model = Model::parse(&bytes).unwrap();
    let mut input = [0; 64];
    input[0] = i16::MAX;
    let trace = model.trace(&input);
    assert_eq!(trace.hidden1[0], 32767);
    assert_eq!(trace.hidden2[0], 512);
    assert_eq!(trace.output, -8);
    assert_eq!(trace.output, model.score(&input));
    assert!(trace.hidden1[1..].iter().all(|v| *v == 0));
    assert!(trace.hidden2[1..].iter().all(|v| *v == 0));
}
