//! Same-runner host microbenchmark, not native control-core timing evidence.
use cyxia_prototype::model::{INPUT_FEATURES, MAX_CANDIDATES, MODEL_BYTES, Model};
use std::{hint::black_box, time::Instant};

const ROUNDS: usize = 512;
const SAMPLES: usize = 7;

fn full(model: &Model<'_>, inputs: &[[i16; INPUT_FEATURES]]) -> [i16; MAX_CANDIDATES] {
    let mut scores = [0; MAX_CANDIDATES];
    for (score, input) in scores.iter_mut().zip(inputs) {
        *score = model.score(input);
    }
    scores
}

fn shared(model: &Model<'_>, inputs: &[[i16; INPUT_FEATURES]]) -> [i16; MAX_CANDIDATES] {
    let prefix = model.prepare_prefix(&inputs[0]);
    let mut scores = [0; MAX_CANDIDATES];
    for (score, input) in scores.iter_mut().zip(inputs) {
        *score = prefix.score(input);
    }
    scores
}

fn measure(mut run: impl FnMut() -> [i16; MAX_CANDIDATES]) -> u128 {
    let start = Instant::now();
    for _ in 0..ROUNDS {
        black_box(run());
    }
    start.elapsed().as_nanos()
}

fn main() {
    let mut parameters = [0u8; MODEL_BYTES];
    for (i, weight) in parameters[..2576].iter_mut().enumerate() {
        *weight = ((i * 73 % 17) as i8 - 8) as u8;
    }
    for (i, bytes) in parameters[2576..].chunks_exact_mut(4).enumerate() {
        bytes.copy_from_slice(&(i as i32 - 24).to_le_bytes());
    }
    let model = Model::parse(&parameters).unwrap();
    let inputs: [[i16; INPUT_FEATURES]; MAX_CANDIDATES] = core::array::from_fn(|candidate| {
        core::array::from_fn(|i| {
            let offset = if i < 40 { 0 } else { candidate * 13 };
            ((i * 17 + offset) % 513) as i16 - 256
        })
    });
    println!("scope=host_mlp_microbenchmark rounds={ROUNDS} samples={SAMPLES}");
    for count in [3, 4, MAX_CANDIDATES] {
        let candidates = &inputs[..count];
        assert_eq!(full(&model, candidates), shared(&model, candidates));
        for _ in 0..64 {
            black_box(full(black_box(&model), black_box(candidates)));
            black_box(shared(black_box(&model), black_box(candidates)));
        }
        let mut baseline = [0u128; SAMPLES];
        let mut optimized = [0u128; SAMPLES];
        for sample in 0..SAMPLES {
            let a = || full(black_box(&model), black_box(candidates));
            let b = || shared(black_box(&model), black_box(candidates));
            if sample % 2 == 0 {
                baseline[sample] = measure(a);
                optimized[sample] = measure(b);
            } else {
                optimized[sample] = measure(b);
                baseline[sample] = measure(a);
            }
            println!(
                "sample,count={count},index={sample},full_ns={},shared_ns={}",
                baseline[sample], optimized[sample]
            );
        }
        baseline.sort_unstable();
        optimized.sort_unstable();
        println!(
            "median,count={count},full_batch_ns={},shared_batch_ns={}",
            baseline[SAMPLES / 2] / ROUNDS as u128,
            optimized[SAMPLES / 2] / ROUNDS as u128
        );
    }
}
