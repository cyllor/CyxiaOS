//! Production caller/collector transition seams with explicit host clocks.
//! These fixtures create no native capture, accepted label or release receipt.
#[path = "../../../kernel/src/runtime/learning/learning_replay/close_sources.rs"]
mod close_sources;
use core::cell::Cell;
use cyxia_prototype::{
    domains::ObjectKey,
    learning::{
        Error, Family,
        capture::{Capture, Config, FrozenRequest, RunKey, Source},
        reward::{CpuClass, OBSERVATION_NS},
    },
};
const OBS: u64 = 96_311_054_992;
const EARLY: u64 = 98_572_916_000;
const END: u64 = OBS + OBSERVATION_NS;
fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
fn config() -> Config {
    Config {
        key: RunKey {
            boot_epoch: 1,
            trial_id: 1,
            generation: 1,
        },
        family: Family {
            domain: 13,
            kind: 1,
        },
        node: [1; 32],
        first_ns: OBS,
        frozen_scope_hash: [7; 32],
        observation_ns: OBS,
    }
}
fn sources() -> [Source; 4] {
    [
        CpuClass::Policy,
        CpuClass::ExecutorAction,
        CpuClass::ExecutorWork,
        CpuClass::Optional,
    ]
    .map(|class| Source {
        owner: key(class as u64 + 1),
        class,
        allowed_cores: 1,
    })
}
fn fixture(cfg: Config) -> Capture<8, 100> {
    let mut c = Capture::empty();
    let requests: [FrozenRequest; 100] = core::array::from_fn(|i| FrozenRequest {
        id: i as u64 + 1,
        owner: key(20),
        arrived_ns: cfg.observation_ns + i as u64,
    });
    c.start(cfg, &sources(), &requests).unwrap();
    c
}
#[test]
fn actual_early_close_counterexample_waits_without_touching_collector_or_cursor() {
    let cfg = config();
    let source = sources()[2];
    let mut original = fixture(cfg);
    let token = original.source(source.owner, source.class).unwrap();
    assert_eq!(original.close_source(token, EARLY), Err(Error::Evidence));
    let mut c = fixture(cfg);
    let token = c.source(source.owner, source.class).unwrap();
    let before = c.status();
    let calls = Cell::new(0);
    let mut cursor = 2;
    let progressed =
        close_sources::close_if_due(&c.config().unwrap(), cfg.key, source.class, EARLY, || {
            calls.set(calls.get() + 1);
            c.close_source(token, EARLY)
        })
        .unwrap();
    if progressed {
        cursor += 1;
    }
    assert!(!progressed);
    assert_eq!(calls.get(), 0);
    assert_eq!(cursor, 2);
    assert_eq!(c.status(), before);
    assert_eq!(c.config(), Some(cfg));
    assert_eq!(
        c.start(cfg, &sources(), &[]),
        Err(Error::Unknown),
        "capture is still owed, not retired"
    );
    assert_eq!(c.status().closed_sources, 0);
    assert_eq!(c.status().sealed, None);
}
#[test]
fn every_class_preserves_its_original_before_equal_and_after_boundary() {
    for source in sources() {
        for delta in [-1i64, 0, 1] {
            let mut cfg = config();
            cfg.first_ns -= 1_000_000_000;
            let mut c = fixture(cfg);
            let token = c.source(source.owner, source.class).unwrap();
            let due = match source.class {
                CpuClass::Policy | CpuClass::ExecutorAction => cfg.first_ns,
                CpuClass::ExecutorWork | CpuClass::Optional => END,
            };
            let at = due.checked_add_signed(delta).unwrap();
            let calls = Cell::new(0);
            let result = close_sources::close_if_due(
                &c.config().unwrap(),
                cfg.key,
                source.class,
                at,
                || {
                    calls.set(calls.get() + 1);
                    c.close_source(token, at)
                },
            )
            .unwrap();
            assert_eq!(result, delta >= 0, "{:?} {delta}", source.class);
            assert_eq!(calls.get(), usize::from(delta >= 0));
            assert_eq!(c.status().closed_sources, usize::from(delta >= 0));
        }
    }
}
#[test]
fn mismatched_run_and_checked_overflow_never_call_close() {
    let cfg = config();
    let calls = Cell::new(0);
    let mut other = cfg.key;
    other.generation += 1;
    assert_eq!(
        close_sources::close_if_due(&cfg, other, CpuClass::ExecutorWork, END, || {
            calls.set(calls.get() + 1);
            Ok(())
        }),
        Err(Error::Stale)
    );
    for class in [CpuClass::ExecutorWork, CpuClass::Optional] {
        let mut invalid = cfg;
        invalid.observation_ns = u64::MAX - OBSERVATION_NS + 1;
        assert_eq!(
            close_sources::close_if_due(&invalid, cfg.key, class, u64::MAX, || {
                calls.set(calls.get() + 1);
                Ok(())
            }),
            Err(Error::Numeric)
        );
        let mut c = Capture::<8, 100>::empty();
        assert_eq!(c.start(invalid, &sources(), &[]), Err(Error::Numeric));
    }
    assert_eq!(calls.get(), 0);
}
#[test]
fn due_callback_preserves_actual_open_span_and_stale_token_rejections() {
    let cfg = config();
    let source = sources()[0];
    let mut c = fixture(cfg);
    let token = c.source(source.owner, source.class).unwrap();
    let span = c.begin(token, 0, OBS).unwrap();
    assert_eq!(
        close_sources::close_if_due(&c.config().unwrap(), cfg.key, source.class, END, || c
            .close_source(token, END)),
        Err(Error::Unknown)
    );
    assert_eq!(c.status().open, 1);
    assert_eq!(c.status().closed_sources, 0);
    c.end(span, 0, OBS + 1).unwrap();
    let foreign = fixture(cfg);
    let wrong = foreign.source(source.owner, source.class).unwrap();
    assert_eq!(
        close_sources::close_if_due(&c.config().unwrap(), cfg.key, source.class, END, || c
            .close_source(wrong, END)),
        Err(Error::Stale)
    );
    assert_eq!(c.status().closed_sources, 0);
    assert_eq!(
        close_sources::close_if_due(&c.config().unwrap(), cfg.key, source.class, END, || c
            .close_source(token, END)),
        Ok(true)
    );
    assert_eq!(c.status().closed_sources, 1);
}
#[test]
fn excluded_unactivated_wait_adds_no_event_or_issuance_and_still_owes_real_close() {
    let cfg = config();
    let mut waited = fixture(cfg);
    let mut direct = fixture(cfg);
    waited.taint(Error::DataIncomplete);
    direct.taint(Error::DataIncomplete);
    let source = sources()[2];
    let token = waited.source(source.owner, source.class).unwrap();
    assert_eq!(
        close_sources::close_if_due(
            &waited.config().unwrap(),
            cfg.key,
            source.class,
            EARLY,
            || waited.close_source(token, EARLY)
        ),
        Ok(false)
    );
    assert_eq!(waited.status().issued, 0);
    assert_eq!(waited.status().requests, 100);
    assert_eq!(waited.status().sealed, None);
    for c in [&mut waited, &mut direct] {
        for source in sources() {
            let token = c.source(source.owner, source.class).unwrap();
            assert_eq!(
                close_sources::close_if_due(
                    &c.config().unwrap(),
                    cfg.key,
                    source.class,
                    END,
                    || c.close_source(token, END)
                ),
                Ok(true)
            );
        }
    }
    let a = waited.seal_incomplete(END + 1).unwrap();
    let b = direct.seal_incomplete(END + 1).unwrap();
    assert_eq!(a.event_hash, b.event_hash);
    assert_eq!(a.exclusion, Some(Error::DataIncomplete));
    assert_eq!(waited.status().closed_sources, 4);
    assert_eq!(waited.status().issued, 0);
}
