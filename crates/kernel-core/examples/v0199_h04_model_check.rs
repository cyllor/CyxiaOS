//! Emit finite traces from the current advice ledger and deterministic plan owners.
//! A separate program checks these observations against the H04 state model.
use cyxia_kernel_core::control_plane::{
    Epochs, Error, Identity,
    advice_disposition_v1::DISPOSITION_BYTES,
    advice_envelope_v1::{ADVICE_BYTES, TrustedAdviceScope},
    advice_ledger_v0199::{AdviceKey, AdviceResult, EvidenceLedger},
    apply_report_v1::{ExecutorBindingV1, ReportOrigin, TrustedApplyScope},
    decision_record_v3::DECISION_BYTES,
    desired_plan_v0199::DesiredBank,
    registered_gate_v3::{FrozenAction, RegisteredDecisionGate, TrustedRegistrationScope},
    rule_profile_v2::Profile,
};
use sha2::{Digest, Sha256};
use std::{
    fmt::Debug,
    io::{self, BufWriter, Write},
};

const BOOT: u64 = 2;
const CONTROLLER_EPOCH: u64 = 3;
const ADVISOR: u64 = 3;
const FIRST_SEQUENCE: u64 = 2;
const TARGET: Identity = Identity {
    id: 17,
    generation: 6,
};
const OPERATIONS: Identity = role(6);
const CONTROLLER: Identity = role(2);
const PUBLISHER: Identity = role(8);
const SUPERVISOR: Identity = role(11);
const ADMISSION: &[&str] = &[
    "fresh",
    "exact",
    "conflict",
    "reordered",
    "short",
    "stale_boot",
    "stale_advisor",
    "stale_model",
    "stale_resources",
    "stale_cores",
    "stale_target",
    "stale_snapshot",
    "stale_sender",
];

const fn role(id: u64) -> Identity {
    Identity { id, generation: 2 }
}
const fn previous(actor: Identity) -> Identity {
    Identity {
        id: actor.id,
        generation: actor.generation - 1,
    }
}
fn put<const N: usize>(wire: &mut [u8], at: usize, v: [u8; N]) {
    wire[at..at + N].copy_from_slice(&v);
}
fn hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
fn status<T: Debug>(result: Result<T, Error>) -> String {
    match result {
        Ok(value) => format!("{value:?}"),
        Err(error) => format!("err_{error:?}"),
    }
}

fn scope(now_ns: u64, refreshed: bool) -> TrustedAdviceScope<'static> {
    let next = u64::from(refreshed);
    TrustedAdviceScope {
        epochs: Epochs {
            boot: BOOT,
            controller: CONTROLLER_EPOCH,
            model: 7 + next,
            resources: 3 + next,
            cores: 4 + next,
        },
        advisor_epoch: ADVISOR,
        snapshot_seq: 4 + next,
        domain: 1,
        target: Identity {
            generation: TARGET.generation + next,
            ..TARGET
        },
        sampled_ns: if refreshed { 400 } else { 100 },
        now_ns,
        action_kind: 1,
        candidates: &[2, 4],
        model_hash: [3 + next as u8; 32],
        candidate_set_hash: [4 + next as u8; 32],
    }
}
fn advice(seq: u64, s: &TrustedAdviceScope<'_>) -> [u8; ADVICE_BYTES] {
    let mut wire = [0; ADVICE_BYTES];
    put(&mut wire, 0, 0x43594131u32.to_le_bytes());
    put(&mut wire, 4, 1u16.to_le_bytes());
    put(&mut wire, 6, (ADVICE_BYTES as u16).to_le_bytes());
    for (at, value) in [
        (8, s.advisor_epoch),
        (16, seq),
        (24, s.snapshot_seq),
        (32, s.target.id),
        (40, s.target.generation),
        (48, s.epochs.resources),
        (56, s.epochs.cores),
        (64, s.sampled_ns + 100),
        (72, s.epochs.model),
    ] {
        put(&mut wire, at, value.to_le_bytes());
    }
    put(&mut wire, 80, s.domain.to_le_bytes());
    put(&mut wire, 82, s.action_kind.to_le_bytes());
    put(&mut wire, 86, (s.candidates.len() as u16).to_le_bytes());
    put(&mut wire, 88, s.model_hash);
    put(&mut wire, 120, s.candidate_set_hash);
    wire
}
fn attempt(
    ledger: &mut EvidenceLedger,
    fill: u64,
    now: u64,
    kind: &str,
) -> Result<AdviceResult, Error> {
    let mut trusted = scope(now, false);
    let seq = match kind {
        "exact" | "conflict" => FIRST_SEQUENCE,
        "reordered" => FIRST_SEQUENCE - 1,
        _ => 2 * fill + 2,
    };
    let mut wire = advice(seq, &trusted);
    let mut sender = OPERATIONS;
    match kind {
        "conflict" => put(&mut wire, 84, 1u16.to_le_bytes()),
        "stale_boot" => trusted.epochs.boot -= 1,
        "stale_advisor" => put(&mut wire, 8, (ADVISOR - 1).to_le_bytes()),
        "stale_model" => put(&mut wire, 72, 6u64.to_le_bytes()),
        "stale_resources" => put(&mut wire, 48, 2u64.to_le_bytes()),
        "stale_cores" => put(&mut wire, 56, 3u64.to_le_bytes()),
        "stale_target" => put(&mut wire, 40, (TARGET.generation - 1).to_le_bytes()),
        "stale_snapshot" => put(&mut wire, 24, 3u64.to_le_bytes()),
        "stale_sender" => sender = previous(sender),
        _ => {}
    }
    let extent = if kind == "short" {
        ADVICE_BYTES - 1
    } else {
        ADVICE_BYTES
    };
    ledger.record(sender, &wire[..extent], &trusted)
}

fn disposition(head: &[u8; ADVICE_BYTES], now: u64, expires: bool) -> [u8; DISPOSITION_BYTES] {
    let mut wire = [0; DISPOSITION_BYTES];
    put(&mut wire, 0, 0x43594144u32.to_le_bytes());
    put(&mut wire, 4, 1u16.to_le_bytes());
    put(&mut wire, 6, (DISPOSITION_BYTES as u16).to_le_bytes());
    for (at, value) in [
        (8, BOOT),
        (16, ADVISOR),
        (24, FIRST_SEQUENCE),
        (32, 4),
        (56, TARGET.id),
        (64, TARGET.generation),
        (72, 7),
        (80, now),
    ] {
        put(&mut wire, at, value.to_le_bytes());
    }
    let (state, reason) = if expires { (4u16, 4u16) } else { (5, 6) };
    for (at, value) in [
        (88, 1u16),
        (90, 1),
        (92, state),
        (94, reason),
        (100, u16::MAX),
        (104, u16::MAX),
        (106, u16::MAX),
    ] {
        put(&mut wire, at, value.to_le_bytes());
    }
    put(&mut wire, 112, [4; 32]);
    put(&mut wire, 144, hash(head));
    wire
}

struct DeterministicPlan {
    rules: [u8; 80],
    plan: [u8; 212],
    record: [u8; DECISION_BYTES],
    binding: ExecutorBindingV1,
}
impl DeterministicPlan {
    fn new() -> Self {
        let mut rules = [0; 80];
        put(&mut rules, 0, 0x43595255u32.to_le_bytes());
        for (at, value) in [
            (4, 2u16),
            (6, 32),
            (36, 1),
            (38, 1),
            (52, 2),
            (64, 2),
            (72, 4),
            (74, 1),
        ] {
            put(&mut rules, at, value.to_le_bytes());
        }
        for (at, value) in [(16, 1u32), (20, 80), (32, 1), (56, 48)] {
            put(&mut rules, at, value.to_le_bytes());
        }
        put(&mut rules, 8, 7u64.to_le_bytes());
        put(&mut rules, 40, TARGET.id.to_le_bytes());
        let mut plan = [0; 212];
        for (at, value) in [(0, 0x43594c31u32), (8, 212), (64, 0x43595031), (76, 4)] {
            put(&mut plan, at, value.to_le_bytes());
        }
        for (at, value) in [
            (4, 2u16),
            (6, 64),
            (12, 1),
            (68, 2),
            (70, 144),
            (72, 1),
            (74, 1),
            (210, 2),
        ] {
            put(&mut plan, at, value.to_le_bytes());
        }
        for (at, value) in [
            (16, 1u64),
            (40, CONTROLLER_EPOCH),
            (48, 4),
            (56, 10_000_000_100),
            (80, CONTROLLER_EPOCH),
            (88, 8),
            (96, 4),
            (104, TARGET.id),
            (112, TARGET.generation),
            (120, 3),
            (128, 4),
            (136, 600),
        ] {
            put(&mut plan, at, value.to_le_bytes());
        }
        put(&mut plan, 176, [4; 32]);
        let mut record = [0; DECISION_BYTES];
        for (at, value) in [(0, 0x43594431u32), (88, 1), (108, 2), (152, 3)] {
            put(&mut record, at, value.to_le_bytes());
        }
        for (at, value) in [(4, 3u16), (6, 256), (94, 1), (96, 1), (104, u16::MAX)] {
            put(&mut record, at, value.to_le_bytes());
        }
        for (at, value) in [
            (8, BOOT),
            (16, CONTROLLER_EPOCH),
            (24, 8),
            (32, 1),
            (40, 4),
            (48, TARGET.id),
            (56, TARGET.generation),
            (64, 3),
            (72, 4),
            (80, 7),
            (144, 600),
        ] {
            put(&mut record, at, value.to_le_bytes());
        }
        put(&mut record, 160, hash(&rules));
        put(&mut record, 192, hash(&plan));
        put(&mut record, 224, [4; 32]);
        Self {
            rules,
            plan,
            record,
            binding: ExecutorBindingV1 {
                domain: 1,
                role: 1,
                active: true,
                target: TARGET,
                executor_generation: 2,
                holder: Identity {
                    id: 0,
                    generation: 0,
                },
                endpoint_cap_id: 0,
            },
        }
    }

    fn publish(
        &self,
        gate: &mut RegisteredDecisionGate<'_>,
        bank: &mut DesiredBank,
        now_ns: u64,
    ) -> (String, String, usize) {
        let profile = Profile::parse(&self.rules).unwrap();
        let actions = [FrozenAction {
            domain_id: 1,
            target: TARGET,
            candidate_set_hash: [4; 32],
            static_ordinals: &[2, 4],
            candidate_payloads: &[&[2, 0], &[4, 0]],
            raw_fields: [None; 7],
            action_payload: &[2, 0],
        }];
        let records = [self.record];
        let ctx = TrustedRegistrationScope {
            boot_epoch: BOOT,
            controller_epoch: CONTROLLER_EPOCH,
            rules_generation: 7,
            rules_hash: hash(&self.rules),
            base_plan_version: 0,
            ledger_generation: 3,
            core_generation: 4,
            snapshot_seq: 4,
            sampled_ns: 100,
            now_ns,
        };
        let registration = status(
            gate.register_rule_only(CONTROLLER, &self.plan, &records, &profile, &actions, ctx),
        );
        let mut called = 0;
        let publication = status(gate.publish_once(
            PUBLISHER,
            &self.plan,
            &records,
            &profile,
            &actions,
            ctx,
            || {
                called += 1;
                bank.publish_registered(PUBLISHER, 0, &self.plan, ctx, |_| Ok(()))
                    .map(|_| ())
            },
        ));
        (registration, publication, called)
    }

    fn claim(
        &self,
        gate: &mut RegisteredDecisionGate<'_>,
        bank: &mut DesiredBank,
    ) -> (String, String, usize) {
        let mut called = 0;
        let mut run = || {
            gate.claim_apply_work(
                &self.plan,
                0,
                TrustedApplyScope {
                    boot_epoch: BOOT,
                    plan_version: 1,
                    now_ns: 411,
                },
                self.binding,
                ReportOrigin::Kernel,
                |work| {
                    called += 1;
                    bank.accept(work, ReportOrigin::Kernel, 411, |_| Ok(()))
                },
            )
            .map_or_else(|e| format!("err_{e:?}"), |frame| hex(&hash(frame.bytes())))
        };
        let first = run();
        let retry = run();
        (first, retry, called)
    }
}

struct Case<'a> {
    fill: u64,
    now: u64,
    admission: &'a str,
    terminal: &'a str,
    archive: &'a str,
    plan_order: &'a str,
}
fn run_case(out: &mut impl Write, case: Case<'_>, plan: &DeterministicPlan) -> io::Result<()> {
    let Case {
        fill,
        now,
        admission,
        terminal,
        archive,
        plan_order,
    } = case;
    let mut gate = RegisteredDecisionGate::new_with_terminal_owner(
        CONTROLLER,
        PUBLISHER,
        SUPERVISOR,
        BOOT,
        CONTROLLER_EPOCH,
    )
    .unwrap();
    let mut bank = DesiredBank::empty();
    bank.bind_boot(BOOT, CONTROLLER_EPOCH, PUBLISHER, || Ok(()))
        .unwrap();
    bank.register_target(plan.binding, |_| Ok(())).unwrap();
    let early_publication =
        (plan_order == "before").then(|| plan.publish(&mut gate, &mut bank, 145));

    let mut ledger =
        EvidenceLedger::new(OPERATIONS, CONTROLLER, SUPERVISOR, BOOT, ADVISOR).unwrap();
    let initial = scope(150, false);
    for i in 1..=fill {
        assert_eq!(
            ledger.record(OPERATIONS, &advice(2 * i, &initial), &initial),
            Ok(AdviceResult::Recorded)
        );
    }
    let admitted = status(attempt(&mut ledger, fill, now, admission));
    let after_admit = ledger.pending();
    let version_at_pressure = bank.version();
    let (registered, published, publish_calls) =
        early_publication.unwrap_or_else(|| plan.publish(&mut gate, &mut bank, now));
    let head = advice(FIRST_SEQUENCE, &initial);
    let disp = disposition(&head, now, terminal != "observe");
    let finished = if terminal == "skip" {
        String::from("skip")
    } else {
        let owner = match terminal {
            "observe" => CONTROLLER,
            "stale_supervisor" => previous(SUPERVISOR),
            _ => SUPERVISOR,
        };
        status(ledger.finalize(owner, &disp, None, now))
    };
    let key = AdviceKey {
        boot_epoch: BOOT,
        advisor_epoch: ADVISOR,
        advice_seq: FIRST_SEQUENCE,
    };
    let mut archive_calls = 0;
    let mut custody = String::from("-");
    let owner = if archive == "stale_supervisor" {
        previous(SUPERVISOR)
    } else {
        SUPERVISOR
    };
    let release = ledger.consume_verified(owner, key, |ev, a, d| {
        archive_calls += 1;
        let mut hasher = Sha256::new();
        hasher.update(a);
        hasher.update(d);
        custody = format!("{}:{}", ev.state, hex(&hasher.finalize()));
        if ev.key != key || ev.advice_hash != hash(a) || ev.disposition_hash != hash(d) {
            return Err(Error::Invalid);
        }
        if archive == "refused" {
            Err(Error::NotReady)
        } else {
            Ok(())
        }
    });
    let released = release.map_or_else(|e| format!("err_{e:?}"), |_| String::from("Released"));
    let after_archive = ledger.pending();
    let replay = status(ledger.record(OPERATIONS, &head, &scope(now + 1, false)));
    let refreshed = scope(410, true);
    let replacement =
        status(ledger.record(OPERATIONS, &advice(2 * fill + 3, &refreshed), &refreshed));
    let replay_refreshed = status(ledger.record(OPERATIONS, &head, &refreshed));
    let mut old = advice(2 * fill + 4, &initial);
    put(&mut old, 64, 450u64.to_le_bytes()); // valid time, older target and scope
    let stale_refreshed = status(ledger.record(OPERATIONS, &old, &refreshed));
    let (work, work_retry, work_calls) = plan.claim(&mut gate, &mut bank);
    writeln!(
        out,
        "{fill}\t{now}\t{admission}\t{terminal}\t{archive}\t{plan_order}\t{admitted}\t{after_admit}\t{version_at_pressure}\t{registered}\t{published}\t{publish_calls}\t{finished}\t{released}\t{archive_calls}\t{custody}\t{after_archive}\t{replay}\t{replacement}\t{replay_refreshed}\t{stale_refreshed}\t{}\t{}\t{work}\t{work_retry}\t{work_calls}",
        ledger.pending(),
        bank.version(),
    )
}

fn main() -> io::Result<()> {
    let mut out = BufWriter::new(io::stdout().lock());
    writeln!(
        out,
        "fill\tnow\tadmission\tterminal\tarchive\tplan_order\tadmitted\tafter_admit\tversion_at_pressure\tregistered\tpublished\tpublish_calls\tfinished\treleased\tarchive_calls\tcustody\tafter_archive\treplay\treplacement\treplay_refreshed\tstale_refreshed\tfinal_pending\tfinal_version\twork_sha256\twork_retry\twork_calls",
    )?;
    let plan = DeterministicPlan::new();
    for fill in [1, 63, 64] {
        for now in [199, 200] {
            for &admission in ADMISSION {
                for terminal in ["skip", "observe", "expire", "stale_supervisor"] {
                    for archive in ["archived", "refused", "stale_supervisor"] {
                        for plan_order in ["before", "peak"] {
                            run_case(
                                &mut out,
                                Case {
                                    fill,
                                    now,
                                    admission,
                                    terminal,
                                    archive,
                                    plan_order,
                                },
                                &plan,
                            )?;
                        }
                    }
                }
            }
        }
    }
    out.flush()
}
