use cyxia_control_model::{
    abi::{self, Input},
    model,
};
use cyxia_kernel_core::control_plane::{cores::*, exchange::Exchange, image, service::*, *};
fn actor() -> Identity {
    Identity {
        id: 1,
        generation: 1,
    }
}
fn epochs() -> Epochs {
    Epochs {
        boot: 1,
        controller: 1,
        model: 1,
        resources: 1,
        cores: 1,
    }
}
fn config() -> Config {
    Config {
        grow_windows: 2,
        shrink_windows: 4,
        high: 24576,
        low: 8192,
        minimum_benefit: 16384,
        dwell_ticks: 2,
        request_ticks: 20,
        window_ticks: 1,
    }
}
fn snapshot() -> Snapshot {
    Snapshot {
        generation: 1,
        control: 2,
        business: 13,
        online: 15,
        transition: 0,
        quarantined: 0,
        phase: Phase::Stable,
    }
}
fn input() -> Input {
    let mut f = [0; 64];
    f[..4].copy_from_slice(&[30000, 30000, 28000, 2000]);
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
        issued: 3,
        expires: 23,
        online: 15,
        control: 2,
        protected_control: 2,
        protected_business: 1,
        features: f,
    }
}
fn port() -> Port {
    Port::new(actor(), epochs(), config(), 0).unwrap()
}
#[test]
fn grow_requires_two_fresh_windows() {
    let mut p = port();
    for seq in 1..=2 {
        let i = p
            .issue(
                Input {
                    window: seq,
                    sample_start: (seq - 1) * 3,
                    sampled_at: seq * 3,
                    ..input()
                },
                seq * 3,
            )
            .unwrap();
        let d = p
            .accept(
                actor(),
                1,
                model::infer(&i).unwrap().encode(),
                snapshot(),
                seq * 3 + 1,
            )
            .unwrap();
        assert_eq!(matches!(d, Decision::Scale(_)), seq == 2);
    }
}
#[test]
fn single_snapshot_cannot_be_replayed_for_hysteresis() {
    let mut p = port();
    let i = p.issue(input(), 3).unwrap();
    let o = model::infer(&i).unwrap().encode();
    assert_eq!(p.accept(actor(), 1, o, snapshot(), 4), Ok(Decision::Hold));
    assert_eq!(
        p.accept(actor(), 1, o, snapshot(), 5),
        Err(abi::Error::Stale)
    );
}
#[test]
fn unauthenticated_actor_does_not_consume_reply() {
    let mut p = port();
    let i = p.issue(input(), 3).unwrap();
    let o = model::infer(&i).unwrap().encode();
    assert_eq!(
        p.accept(
            Identity {
                id: 2,
                generation: 1
            },
            1,
            o,
            snapshot(),
            4
        ),
        Err(abi::Error::Denied)
    );
    assert!(p.accept(actor(), 1, o, snapshot(), 4).is_ok());
}
#[test]
fn business_cpu_cannot_publish() {
    let mut p = port();
    let i = p.issue(input(), 3).unwrap();
    assert_eq!(
        p.accept(
            actor(),
            2,
            model::infer(&i).unwrap().encode(),
            snapshot(),
            4
        ),
        Err(abi::Error::Denied)
    );
}
#[test]
fn wrong_schema_does_not_turn_into_authority() {
    let mut p = port();
    let i = p.issue(input(), 3).unwrap();
    let mut o = model::infer(&i).unwrap().encode();
    o[12] ^= 1;
    assert_eq!(
        p.accept(actor(), 1, o, snapshot(), 4),
        Err(abi::Error::Schema)
    );
}
#[test]
fn expired_response_cannot_extend_absolute_deadline() {
    let mut p = port();
    let i = p.issue(input(), 3).unwrap();
    assert_eq!(
        p.accept(
            actor(),
            1,
            model::infer(&i).unwrap().encode(),
            snapshot(),
            23
        ),
        Err(abi::Error::Expired)
    );
    assert!(
        p.issue(
            Input {
                window: 2,
                sample_start: 3,
                sampled_at: 24,
                ..input()
            },
            24
        )
        .is_ok()
    );
}
#[test]
fn pending_requests_cannot_overwrite() {
    let mut p = port();
    p.issue(input(), 3).unwrap();
    assert_eq!(p.issue(input(), 4), Err(abi::Error::Busy));
    assert_eq!(p.expire(22), Ok(false));
    assert_eq!(p.expire(23), Ok(true));
}
#[test]
fn core_change_while_inference_is_stale() {
    let mut p = port();
    let i = p.issue(input(), 3).unwrap();
    let mut s = snapshot();
    s.generation = 2;
    assert_eq!(
        p.accept(actor(), 1, model::infer(&i).unwrap().encode(), s, 4),
        Err(abi::Error::Stale)
    );
}
#[test]
fn illegal_mask_rejected_before_core_owner_changes() {
    for mask in [0, 1, 3, 15, 255, 16, 14] {
        let mut p = port();
        let i = p.issue(input(), 3).unwrap();
        let mut o = model::infer(&i).unwrap();
        o.desired = mask;
        assert!(
            p.accept(actor(), 1, o.encode(), snapshot(), 4).is_err(),
            "mask={mask}"
        );
    }
}
#[test]
fn dwell_is_checked_even_after_many_windows() {
    let mut c = config();
    c.dwell_ticks = 100;
    let mut p = Port::new(actor(), epochs(), c, 0).unwrap();
    for now in [3, 6, 9] {
        let i = p
            .issue(
                Input {
                    window: now / 3,
                    sample_start: now - 3,
                    sampled_at: now,
                    ..input()
                },
                now,
            )
            .unwrap();
        assert_eq!(
            p.accept(
                actor(),
                1,
                model::infer(&i).unwrap().encode(),
                snapshot(),
                now + 1
            ),
            Ok(Decision::Hold)
        );
    }
}
#[test]
fn shrink_requires_four_low_windows() {
    let mut p = port();
    for now in [3, 6, 9, 12] {
        let mut i = input();
        i.features[..4].copy_from_slice(&[1000, 1000, 1000, 2000]);
        i.control = 6;
        i.features[23] = 32767;
        i.window = now / 3;
        i.sample_start = now - 3;
        i.sampled_at = now;
        let i = p.issue(i, now).unwrap();
        let s = Snapshot {
            control: 6,
            business: 9,
            ..snapshot()
        };
        let d = p
            .accept(actor(), 1, model::infer(&i).unwrap().encode(), s, now + 1)
            .unwrap();
        assert_eq!(matches!(d, Decision::Scale(_)), now == 12);
    }
}
#[test]
fn restart_rejects_old_reply_and_carries_sequence() {
    let mut p = port();
    let i = p.issue(input(), 3).unwrap();
    let out = model::infer(&i).unwrap().encode();
    let e = Epochs {
        controller: 2,
        ..epochs()
    };
    let actor = Identity {
        id: 1,
        generation: 2,
    };
    p.restart(actor, e, 4).unwrap();
    let i = p
        .issue(
            Input {
                controller: 2,
                window: 2,
                sample_start: 3,
                sampled_at: 5,
                ..input()
            },
            5,
        )
        .unwrap();
    assert_eq!(i.sequence, 2);
    assert_eq!(
        p.accept(actor, 1, out, snapshot(), 6),
        Err(abi::Error::Stale)
    );
}
#[test]
fn clock_regression_latches_closed() {
    let mut p = port();
    p.issue(input(), 3).unwrap();
    assert_eq!(p.expire(2), Err(abi::Error::Clock));
    assert_eq!(p.issue(input(), 4), Err(abi::Error::Clock));
}
#[test]
fn invalid_config_refused() {
    let mut c = config();
    c.grow_windows = 1;
    assert!(Port::new(actor(), epochs(), c, 0).is_err());
}
#[test]
fn exchange_rejects_overwrite_and_returns_exact_words() {
    let q = Exchange::<2, 2>::new();
    q.submit([1, 2]).unwrap();
    assert_eq!(q.submit([3, 4]), Err(Error::Busy));
    let w = q.take().unwrap();
    assert_eq!(w.input, [1, 2]);
    assert!(q.take().is_none());
    assert!(q.receive().is_none());
    w.complete([7, 9]);
    assert_eq!(q.receive(), Some([7, 9]));
    assert!(q.idle());
}
#[test]
fn cancelled_worker_returns_invalid_reply_not_stale_data() {
    let q = Exchange::<1, 2>::new();
    q.submit([1]).unwrap();
    drop(q.take());
    assert_eq!(q.receive(), Some([0; 2]));
}
#[test]
fn exchange_multithreaded_messages_are_not_torn() {
    let q = Exchange::<2, 2>::new();
    std::thread::scope(|s| {
        s.spawn(|| {
            for _ in 0..2000 {
                let w = loop {
                    if let Some(w) = q.take() {
                        break w;
                    }
                    std::thread::yield_now();
                };
                assert_eq!(w.input[1], !w.input[0]);
                let v = w.input[0];
                w.complete([v, !v]);
            }
        });
        for n in 0..2000 {
            q.submit([n, !n]).unwrap();
            let result = loop {
                if let Some(r) = q.receive() {
                    break r;
                }
                std::thread::yield_now();
            };
            assert_eq!(result, [n, !n]);
        }
    });
}
fn elf() -> Vec<u8> {
    let mut b = vec![0u8; 8192];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&183u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..32].copy_from_slice(&image::BASE.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&1u16.to_le_bytes());
    b[64..68].copy_from_slice(&1u32.to_le_bytes());
    b[68..72].copy_from_slice(&5u32.to_le_bytes());
    b[72..80].copy_from_slice(&4096u64.to_le_bytes());
    b[80..88].copy_from_slice(&image::BASE.to_le_bytes());
    b[96..104].copy_from_slice(&16u64.to_le_bytes());
    b[104..112].copy_from_slice(&16u64.to_le_bytes());
    b[112..120].copy_from_slice(&4096u64.to_le_bytes());
    b
}
#[test]
fn strict_elf_accepts_rx_and_rejects_all_truncations() {
    let b = elf();
    assert!(image::Image::parse(&b).is_ok());
    for len in 0..4112 {
        assert!(image::Image::parse(&b[..len]).is_err());
    }
}
#[test]
fn strict_elf_rejects_wx_dynamic_and_alias() {
    for (at, val) in [(68, 7), (64, 2), (18, 62)] {
        let mut b = elf();
        b[at] = val;
        assert!(image::Image::parse(&b).is_err());
    }
    let mut b = elf();
    b[56] = 2;
    let header = b[64..120].to_vec();
    b[120..176].copy_from_slice(&header);
    assert!(image::Image::parse(&b).is_err());
}
#[test]
fn strict_elf_rejects_overflow_and_unmapped_entry() {
    let mut b = elf();
    b[24..32].copy_from_slice(&0xdeadbeefu64.to_le_bytes());
    assert!(image::Image::parse(&b).is_err());
    let mut b = elf();
    b[104..112].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(image::Image::parse(&b).is_err());
}
#[test]
fn repeated_or_overlapping_sample_cannot_count_as_another_window() {
    let mut p = port();
    let req = p.issue(input(), 3).unwrap();
    p.accept(
        actor(),
        1,
        model::infer(&req).unwrap().encode(),
        snapshot(),
        4,
    )
    .unwrap();
    assert_eq!(p.issue(input(), 5), Err(abi::Error::Stale));
    assert_eq!(
        p.issue(
            Input {
                window: 2,
                sample_start: 2,
                sampled_at: 5,
                ..input()
            },
            5
        ),
        Err(abi::Error::Stale)
    );
}
#[test]
fn skipped_window_breaks_hysteresis() {
    let mut p = port();
    let req = p.issue(input(), 3).unwrap();
    p.accept(
        actor(),
        1,
        model::infer(&req).unwrap().encode(),
        snapshot(),
        4,
    )
    .unwrap();
    let req = p
        .issue(
            Input {
                window: 3,
                sample_start: 3,
                sampled_at: 6,
                ..input()
            },
            6,
        )
        .unwrap();
    assert_eq!(
        p.accept(
            actor(),
            1,
            model::infer(&req).unwrap().encode(),
            snapshot(),
            7
        ),
        Ok(Decision::Hold)
    );
}
#[test]
fn old_snapshot_does_not_get_a_new_deadline_on_issue() {
    let mut p = port();
    let req = p.issue(input(), 20).unwrap();
    assert_eq!(req.expires, 23);
    assert_eq!(
        p.accept(
            actor(),
            1,
            model::infer(&req).unwrap().encode(),
            snapshot(),
            23
        ),
        Err(abi::Error::Expired)
    );
}
#[test]
fn future_or_too_short_samples_are_refused() {
    let mut p = port();
    assert_eq!(p.issue(input(), 2), Err(abi::Error::Invalid));
    assert_eq!(
        p.issue(
            Input {
                sample_start: 3,
                sampled_at: 3,
                ..input()
            },
            3
        ),
        Err(abi::Error::Invalid)
    );
}
#[test]
fn every_epoch_and_sample_window_is_bound_in_response() {
    for field in [7, 19, 20, 21] {
        let mut p = port();
        let i = p.issue(input(), 3).unwrap();
        let mut reply = model::infer(&i).unwrap().encode();
        reply[field] += 1;
        assert_eq!(
            p.accept(actor(), 1, reply, snapshot(), 4),
            Err(abi::Error::Stale)
        );
    }
}
#[test]
fn resource_change_invalidates_pending_response() {
    let mut p = port();
    let i = p.issue(input(), 3).unwrap();
    p.invalidate(
        Epochs {
            resources: 2,
            ..epochs()
        },
        4,
    )
    .unwrap();
    assert_eq!(
        p.accept(
            actor(),
            1,
            model::infer(&i).unwrap().encode(),
            snapshot(),
            5
        ),
        Err(abi::Error::Stale)
    );
}
