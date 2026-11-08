//! Synthetic protected-owner fixtures only. These do not constitute native
//! replay data, a qualified Learned package, or an Active promotion.
#[path = "support/learning.rs"]
mod support;
use cyxia_prototype::{
    learning::{
        data::FrozenData,
        manifest::UntrainedSeed,
        reward::{self, CpuClass, CpuInterval, RewardWorkspace, Trial},
        softfloat::F64,
        train::{self, Parameters, Trainer},
    },
    model::Model,
};

fn ratio(n: i64, d: u64) -> F64 {
    F64::from_i64(n).div(F64::from_u64(d)).unwrap()
}

fn rounded_step_crosses_binary64_boundary(weight: bool) {
    let mut weights = [0; 16];
    let mut first = [0; 16];
    let mut second = [0; 16];
    let bias = if weight {
        weights[0] = -8;
        weights[1] = 64;
        first[0] = 256;
        second[0] = 256;
        second[1] = 1024;
        0
    } else {
        weights[0] = 64;
        second[0] = 1024;
        -32
    };
    let original = Parameters::from_quantized(weights, bias).unwrap();
    let prior = original.step(&first, ratio(1, 3)).unwrap().next;
    let value = if weight {
        prior.weights()[0]
    } else {
        prior.bias()
    };
    assert_eq!(value.to_bits(), 0xbfbf_8aaa_aaaa_aaab);
    // Independent native IEEE operations agree with the required software RNE
    // update. Subtracting its rounded endpoints is NOT the original delta.
    let expected = f64::from_bits(value.to_bits()) - 1.0 / 256.0;
    assert_eq!(expected.to_bits(), 0xbfc0_4555_5555_5556);
    assert!((expected - f64::from_bits(value.to_bits())).abs() > 1.0 / 256.0);
    let step = prior.step(&second, ratio(1, 10)).unwrap();
    let (gradient, updated) = if weight {
        (step.clipped_gradients[0], step.next.weights()[0])
    } else {
        (step.clipped_gradients[16], step.next.bias())
    };
    assert_eq!(gradient, F64::ONE);
    assert_eq!(updated.to_bits(), expected.to_bits());
}

#[test]
fn clipped_bias_delta_is_checked_before_rounding_the_updated_parameter() {
    rounded_step_crosses_binary64_boundary(false);
}

#[test]
fn clipped_weight_delta_is_checked_before_rounding_the_updated_parameter() {
    rounded_step_crosses_binary64_boundary(true);
}

fn native_step(weights: &mut [f64; 16], bias: &mut f64, hidden: &[i16; 16], reward: f64) {
    let mut prediction = 0.0;
    for j in 0..16 {
        let product = weights[j] * (f64::from(hidden[j]) / 256.0);
        prediction += product;
    }
    prediction += *bias;
    let error = prediction - reward;
    let gradients = hidden.map(|h| (error * (f64::from(h) / 256.0)).clamp(-1.0, 1.0));
    for j in 0..16 {
        let delta = (1.0 / 256.0) * gradients[j];
        weights[j] = (weights[j] - delta).clamp(-2.0, 127.0 / 64.0);
    }
    let delta = (1.0 / 256.0) * error.clamp(-1.0, 1.0);
    *bias = (*bias - delta).clamp(-128.0, 32767.0 / 256.0);
}

#[test]
fn projected_updates_match_independent_ieee_bits_at_both_signed_limits() {
    for (weight, bias) in [(0, 0), (127, 32767), (-128, -32768), (1, -32), (-8, 32)] {
        let mut actual = Parameters::from_quantized([weight; 16], bias).unwrap();
        let mut expected_weights = [f64::from(weight) / 64.0; 16];
        let mut expected_bias = f64::from(bias) / 256.0;
        for turn in 0..256 {
            let hidden = core::array::from_fn(|j| {
                if turn % 3 == 0 {
                    0
                } else {
                    ((turn * 193 + j * 17) % 32768) as i16
                }
            });
            let reward: f64 = [0.0, -0.0, 1.0 / 3.0, -1.0 / 3.0, 0.1, -0.1][turn % 6];
            native_step(&mut expected_weights, &mut expected_bias, &hidden, reward);
            actual = actual
                .step(&hidden, F64::from_bits_checked(reward.to_bits()).unwrap())
                .unwrap()
                .next;
            for (got, expected) in actual.weights().iter().zip(expected_weights) {
                assert_eq!(
                    got.to_bits(),
                    expected.to_bits(),
                    "weight {weight}, bias {bias}, turn {turn}"
                );
            }
            assert_eq!(actual.bias().to_bits(), expected_bias.to_bits());
        }
    }
}

#[test]
fn accepted_cpu_cost_rewards_complete_one_pass_and_match_ieee_quantization() {
    let mut training = Vec::new();
    let mut validation = Vec::new();
    let mut id = 1;
    for family in support::FAMILIES {
        for group in 0..12 {
            let sample = support::with_trials(
                family,
                if group < 8 { 1 } else { 2 },
                id,
                Default::default(),
                |candidate, baseline| {
                    let mut cpu = candidate.cpu.to_vec();
                    cpu.push(CpuInterval {
                        node: candidate.local_node,
                        core: 0,
                        start_ns: candidate.observation_ns + 500_000_000,
                        end_ns: candidate.observation_ns + 5_500_000_000,
                        class: CpuClass::ExecutorWork,
                    });
                    let same_qos = Trial {
                        cpu: &cpu,
                        requests: baseline.requests,
                        ..*candidate
                    };
                    let sample = reward::pair(
                        &same_qos,
                        baseline,
                        &support::TestAuthority,
                        &mut RewardWorkspace::new(),
                    )?;
                    assert!(sample.reward().delta_latency.is_zero());
                    assert!(sample.reward().delta_throughput.is_zero());
                    assert_eq!(sample.reward().candidate_cpu.union_ns, 5_000_003_000);
                    assert!(f64::from_bits(sample.reward().raw_cost.to_bits()) < 1.0);
                    assert!(f64::from_bits(sample.reward().value.to_bits()) < -0.1);
                    Ok(sample)
                },
            )
            .unwrap();
            if group < 8 {
                training.push(sample);
            } else {
                validation.push(sample);
            }
            id += 1;
        }
    }
    let data = FrozenData::freeze(&training, &validation, 1, support::schemas()).unwrap();
    assert_eq!(data.manifest().training_per_family, [8; 18]);
    assert_eq!(data.manifest().validation_per_family, [4; 18]);
    let seed = UntrainedSeed::new(0);
    let original = Model::parse(seed.bytes()).unwrap();
    let mut weights =
        core::array::from_fn(|j| f64::from(seed.bytes()[train::LAST_WEIGHTS + j] as i8) / 64.0);
    let mut bias = 0.0;
    let mut trainer = Trainer::start(seed.bytes(), &data).unwrap();
    for sample in data.training() {
        native_step(
            &mut weights,
            &mut bias,
            &original.trace(sample.input()).hidden2,
            f64::from_bits(sample.reward().value.to_bits()),
        );
        assert!(trainer.step_next().unwrap());
    }
    assert!(!trainer.step_next().unwrap());
    assert_eq!(trainer.completed_steps(), 144);
    let trained = trainer.finish().unwrap();
    assert!(train::frozen_equal(seed.bytes(), trained.bytes()));
    for (j, value) in weights.into_iter().enumerate() {
        let encoded =
            (value.signum() * (value.abs() * 64.0 + 0.5).floor()).clamp(-128.0, 127.0) as i8;
        assert_eq!(trained.bytes()[train::LAST_WEIGHTS + j] as i8, encoded);
    }
    let encoded_bias = (bias.signum() * (bias.abs() * 256.0 + 0.5).floor()) as i32;
    assert_eq!(
        i32::from_le_bytes(trained.bytes()[train::LAST_BIAS..].try_into().unwrap()),
        encoded_bias
    );
    assert_eq!(trained.record().steps, 144);
    assert_eq!(trained.record().data, data.manifest());
}
