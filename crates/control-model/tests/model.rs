use cyxia_control_model::{abi::*, model};
fn input(high: bool) -> Input {
    let mut f = [0; 64];
    f[..4].copy_from_slice(if high {
        &[30000, 30000, 28000, 2000]
    } else {
        &[1000, 1000, 1000, 2000]
    });
    for i in 0..4 {
        for (j, m) in [15, 2, 2, 1].into_iter().enumerate() {
            f[8 + i * 7 + j] = if m & (1 << i) != 0 { 32767 } else { 0 };
        }
        f[8 + i * 7 + 4] = if i == 2 { 28000 } else { 8000 };
        f[8 + i * 7 + 5] = 20000;
    }
    Input {
        boot: 1,
        controller: 1,
        model_epoch: 1,
        resources: 1,
        cores: 1,
        sequence: 1,
        window: 1,
        sample_start: 2,
        sampled_at: 3,
        issued: 5,
        expires: 100,
        online: 15,
        control: 2,
        protected_control: 2,
        protected_business: 1,
        features: f,
    }
}
#[test]
fn q15_and_exact_epochs_roundtrip() {
    let mut p = input(true);
    p.boot = u64::MAX;
    assert_eq!(Input::decode(p.encode()), Ok(p));
}
#[test]
fn trained_head_chooses_growth() {
    let r = model::infer(&input(true)).unwrap();
    assert_eq!(r.action, 1);
    assert_eq!(r.desired, 6);
}
#[test]
fn trained_head_chooses_shrink() {
    let mut p = input(false);
    p.control = 6;
    p.features[8 + 2 * 7 + 1] = 32767;
    let r = model::infer(&p).unwrap();
    assert_eq!(r.action, 2);
    assert_eq!(r.desired, 2);
}
#[test]
fn rank_uses_features_not_cpu_number() {
    let mut p = input(true);
    p.features[8 + 2 * 7 + 4] = 1000;
    p.features[8 + 3 * 7 + 4] = 31000;
    assert_eq!(model::infer(&p).unwrap().desired, 10);
}
#[test]
fn invalid_schema_and_model_rejected() {
    for i in [1, 26, 16, 20] {
        let mut w = input(true).encode();
        w[i] ^= 1;
        assert!(Input::decode(w).is_err());
    }
}
#[test]
fn inconsistent_masks_rejected() {
    let mut p = input(true);
    p.features[8 + 7 + 1] = 0;
    assert_eq!(model::infer(&p), Err(Error::Invalid));
}
#[test]
fn offline_core_cannot_have_hidden_features() {
    let mut p = input(true);
    p.features[8 + 6 * 7 + 4] = 1;
    assert!(p.validate().is_err());
}
#[test]
fn reserved_features_and_bad_quantization_rejected() {
    for at in [4, 14, 63] {
        let mut p = input(true);
        p.features[at] = 1;
        assert!(p.validate().is_err());
    }
    let mut p = input(true);
    p.features[0] = -1;
    assert!(p.validate().is_err());
}
#[test]
fn output_rejects_unknown_bits_and_preserves_signed_logits() {
    let o = model::infer(&input(true)).unwrap();
    assert_eq!(Output::decode(o.encode()), Ok(o));
    for at in [1, 22, 12, 23] {
        let mut w = o.encode();
        w[at] ^= 1;
        assert!(Output::decode(w).is_err());
    }
    let mut w = o.encode();
    w[16] = 65536;
    assert!(Output::decode(w).is_err());
}
#[test]
fn malformed_model_and_no_available_candidate_fail_safely() {
    assert_eq!(model::infer_with(&input(true), b"bad"), Err(Error::Model));
    let mut p = input(true);
    p.protected_business = 13;
    for i in [0, 2, 3] {
        p.features[8 + i * 7 + 3] = 32767;
    }
    assert_eq!(model::infer(&p).unwrap().desired, 2);
}
#[test]
fn extreme_features_never_overflow() {
    for high in [0, 1, 32766, 32767] {
        let mut p = input(true);
        p.features[..4].fill(high);
        let r = model::infer(&p).unwrap();
        assert_eq!(r.desired & !15, 0);
        assert_eq!(r.desired & 2, 2);
        assert_eq!(r.desired & 1, 0);
    }
}
