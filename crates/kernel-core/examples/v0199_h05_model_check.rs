//! Host-only execution of the current ABI3 decision/publication components.
//! The independent H05 checker interprets the raw transitions emitted here.
use cyxia_control_model::native_v0199::SnapshotReplyV3;
use cyxia_kernel_core::control_plane::{
    Epochs, Error, Identity,
    action_schema_v2::ActionV2,
    advice_disposition_v1::DISPOSITION_BYTES,
    advice_envelope_v1::{ADVICE_BYTES, TrustedAdviceScope},
    advice_ledger_v0199::EvidenceLedger,
    apply_report_v1::ExecutorBindingV1,
    candidate_registry_v0199::{CatalogEntry, FrozenCandidates},
    decision_record_v3::DECISION_BYTES,
    desired_plan_v0199::DesiredBank,
    plan_wire_v2::PlanV2,
    registered_gate_v3::{AssistedScope, RegisteredDecisionGate, TrustedRegistrationScope},
    rule_profile_v2::{Candidates, Profile, RuleMatch},
    svc_bridge_v3::{FrozenNativePlan, SvcV3Bridge, VerifiedNativeCaller},
};
use sha2::{Digest, Sha256};
use std::{
    fmt::Debug,
    io::{self, BufWriter, Write},
};

const CONTROLLER: Identity = actor(2);
const OPERATIONS: Identity = actor(6);
const PUBLISHER: Identity = actor(8);
const SUPERVISOR: Identity = actor(11);
const TARGET: Identity = actor(17);
const REGISTER_CAP: u64 = 50;
const PUBLISH_CAP: u64 = 41;
const SAMPLED: u64 = 100;
const REGISTERED: u64 = 150;
const ADVICE_END: u64 = 200;
const DECISION_END: u64 = 300;
const MODEL: [u8; 32] = [3; 32];
const MODES: [&str; 5] = [
    "rule",
    "shadow_rule",
    "shadow_proposal",
    "assisted",
    "model_closed",
];
const STEPS: [&str; 5] = [
    "skip",
    "publish",
    "advice_end",
    "decision_end",
    "operations",
];

const fn actor(id: u64) -> Identity {
    Identity { id, generation: 1 }
}
fn put<const N: usize>(bytes: &mut [u8], at: usize, word: [u8; N]) {
    bytes[at..at + N].copy_from_slice(&word);
}
fn hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
fn result<T: Debug>(result: Result<T, Error>) -> String {
    match result {
        Ok(v) => format!("{v:?}"),
        Err(e) => format!("err_{e:?}"),
    }
}
fn sensitive(domain: u16) -> bool {
    matches!(domain, 6 | 11 | 12 | 14)
}

fn candidate_set(domain: u16) -> FrozenCandidates {
    let values = ActionV2::values(domain).unwrap();
    let catalog: Vec<_> = values
        .iter()
        .enumerate()
        .map(|(i, &value)| CatalogEntry {
            ordinal: 7 + 3 * i as u16,
            value,
        })
        .collect();
    FrozenCandidates::capture(
        SnapshotReplyV3 {
            snapshot_seq: 3,
            boot_epoch: 1,
            ledger_generation: 5,
            core_generation: 6,
            target_id: TARGET.id,
            target_generation: TARGET.generation,
            sampled_ns: SAMPLED,
            domain,
            fields: [None; 12],
        },
        &catalog,
        hash(b"CYX/H05/MODEL-CHECK/FIXTURE-CATALOG"),
        values[0],
        None,
        Some(true),
        false,
        |c, h| {
            if c == catalog && h == hash(b"CYX/H05/MODEL-CHECK/FIXTURE-CATALOG") {
                Ok(())
            } else {
                Err(Error::Denied)
            }
        },
        |_| Ok(true),
    )
    .unwrap()
}

fn rules(domain: u16, ordinals: &[u16], mask: usize, reverse: bool) -> Vec<u8> {
    let mut chosen: Vec<_> = ordinals
        .iter()
        .enumerate()
        .filter(|(i, _)| mask & (1 << i) != 0)
        .map(|(_, ordinal)| *ordinal)
        .collect();
    if reverse {
        chosen.reverse();
    }
    let len = 64 + 8 * chosen.len();
    let mut wire = vec![0; len];
    put(&mut wire, 0, 0x43595255u32.to_le_bytes());
    put(&mut wire, 4, 2u16.to_le_bytes());
    put(&mut wire, 6, 32u16.to_le_bytes());
    put(&mut wire, 8, 7u64.to_le_bytes());
    put(&mut wire, 16, 1u32.to_le_bytes());
    put(&mut wire, 20, (len as u32).to_le_bytes());
    put(&mut wire, 32, 1u32.to_le_bytes());
    put(&mut wire, 36, domain.to_le_bytes());
    put(&mut wire, 38, 1u16.to_le_bytes());
    put(&mut wire, 40, TARGET.id.to_le_bytes());
    put(&mut wire, 48, u16::from(!sensitive(domain)).to_le_bytes());
    put(&mut wire, 52, (chosen.len() as u16).to_le_bytes());
    put(&mut wire, 56, (len as u32 - 32).to_le_bytes());
    for (rank, ordinal) in chosen.into_iter().enumerate() {
        put(&mut wire, 64 + rank * 8, ordinal.to_le_bytes());
        put(&mut wire, 66 + rank * 8, (rank as u16).to_le_bytes());
    }
    wire
}

fn context(rule_hash: [u8; 32], now_ns: u64) -> TrustedRegistrationScope {
    TrustedRegistrationScope {
        boot_epoch: 1,
        controller_epoch: 2,
        rules_generation: 7,
        rules_hash: rule_hash,
        base_plan_version: 0,
        ledger_generation: 5,
        core_generation: 6,
        snapshot_seq: 3,
        sampled_ns: SAMPLED,
        now_ns,
    }
}

fn advice_scope(c: &FrozenCandidates, now_ns: u64) -> TrustedAdviceScope<'_> {
    TrustedAdviceScope {
        epochs: Epochs {
            boot: 1,
            controller: 2,
            model: 9,
            resources: 5,
            cores: 6,
        },
        advisor_epoch: 1,
        snapshot_seq: 3,
        domain: c.snapshot().domain,
        target: TARGET,
        sampled_ns: SAMPLED,
        now_ns,
        action_kind: 1,
        candidates: c.ordinals(),
        model_hash: MODEL,
        candidate_set_hash: c.digest(),
    }
}

fn advice_wire(c: &FrozenCandidates, recommended: u16) -> [u8; ADVICE_BYTES] {
    let mut wire = [0; ADVICE_BYTES];
    put(&mut wire, 0, 0x43594131u32.to_le_bytes());
    put(&mut wire, 4, 1u16.to_le_bytes());
    put(&mut wire, 6, (ADVICE_BYTES as u16).to_le_bytes());
    for (at, value) in [
        (8, 1u64),
        (16, 1),
        (24, 3),
        (32, TARGET.id),
        (40, TARGET.generation),
        (48, 5),
        (56, 6),
        (64, ADVICE_END),
        (72, 9),
    ] {
        put(&mut wire, at, value.to_le_bytes());
    }
    for (at, value) in [
        (80, c.snapshot().domain),
        (82, 1),
        (84, recommended),
        (86, c.ordinals().len() as u16),
    ] {
        put(&mut wire, at, value.to_le_bytes());
    }
    put(&mut wire, 88, MODEL);
    put(&mut wire, 120, c.digest());
    wire
}

struct Attempt {
    domain: u16,
    selected: u16,
    scope: RuleMatch,
    assisted: bool,
    shadow_rule: bool,
    candidate_hash: [u8; 32],
    rule_hash: [u8; 32],
}

impl Attempt {
    fn plan(&self, payload: &[u8]) -> Vec<u8> {
        let extent = 210 + payload.len();
        let mut wire = vec![0; extent];
        put(&mut wire, 0, 0x43594c31u32.to_le_bytes());
        put(&mut wire, 4, 2u16.to_le_bytes());
        put(&mut wire, 6, 64u16.to_le_bytes());
        put(&mut wire, 8, (extent as u32).to_le_bytes());
        put(&mut wire, 12, 1u16.to_le_bytes());
        put(&mut wire, 14, u16::from(self.assisted).to_le_bytes());
        let model = if self.assisted { 9u64 } else { 0u64 };
        let lease = if self.domain == 14 {
            0
        } else {
            SAMPLED + 10_000_000_000
        };
        for (at, value) in [
            (16, 1u64),
            (32, model),
            (40, 2),
            (48, 3),
            (56, lease),
            (80, 2),
            (88, 4),
            (96, 3),
            (104, TARGET.id),
            (112, TARGET.generation),
            (120, 5),
            (128, 6),
            (136, DECISION_END),
        ] {
            put(&mut wire, at, value.to_le_bytes());
        }
        put(&mut wire, 64, 0x43595031u32.to_le_bytes());
        put(&mut wire, 68, 2u16.to_le_bytes());
        put(&mut wire, 70, 144u16.to_le_bytes());
        put(&mut wire, 72, self.domain.to_le_bytes());
        put(&mut wire, 74, 1u16.to_le_bytes());
        put(&mut wire, 76, ((payload.len() + 2) as u32).to_le_bytes());
        if self.assisted {
            put(&mut wire, 144, MODEL);
        }
        put(&mut wire, 176, self.candidate_hash);
        put(&mut wire, 208, self.selected.to_le_bytes());
        wire[210..].copy_from_slice(payload);
        wire
    }

    fn claimed_mask(&self) -> u32 {
        // Supply a structurally valid alleged set even for an excluded
        // candidate. The implementation must recompute the trusted set.
        self.scope.allowed_mask | (1 << self.selected)
    }

    fn record(&self, plan: &[u8], index: u16) -> [u8; DECISION_BYTES] {
        let mut wire = [0; DECISION_BYTES];
        put(&mut wire, 0, 0x43594431u32.to_le_bytes());
        put(&mut wire, 4, 3u16.to_le_bytes());
        put(&mut wire, 6, (DECISION_BYTES as u16).to_le_bytes());
        for (at, value) in [
            (8, 1u64),
            (16, 2),
            (24, 4),
            (32, 1),
            (40, 3),
            (48, TARGET.id),
            (56, TARGET.generation),
            (64, 5),
            (72, 6),
            (80, 7),
            (144, DECISION_END),
        ] {
            put(&mut wire, at, value.to_le_bytes());
        }
        put(&mut wire, 88, self.scope.rule_id.to_le_bytes());
        put(&mut wire, 94, self.domain.to_le_bytes());
        put(&mut wire, 96, 1u16.to_le_bytes());
        put(&mut wire, 102, self.selected.to_le_bytes());
        put(&mut wire, 152, self.claimed_mask().to_le_bytes());
        put(&mut wire, 156, self.scope.fallback_index.to_le_bytes());
        if self.assisted {
            wire[98..102].copy_from_slice(&[2, 1, 1, 1]);
            put(&mut wire, 104, index.to_le_bytes());
            put(&mut wire, 108, 8u32.to_le_bytes());
            put(&mut wire, 112, 1u64.to_le_bytes());
            put(&mut wire, 120, 1u64.to_le_bytes());
            put(&mut wire, 128, 9u64.to_le_bytes());
            put(&mut wire, 158, 1u16.to_le_bytes());
        } else {
            wire[98] = u8::from(self.shadow_rule);
            put(&mut wire, 104, u16::MAX.to_le_bytes());
            put(&mut wire, 108, 2u32.to_le_bytes());
            put(&mut wire, 158, self.scope.choice_policy.to_le_bytes());
        }
        put(&mut wire, 160, self.rule_hash);
        put(&mut wire, 192, hash(plan));
        put(&mut wire, 224, self.candidate_hash);
        wire
    }

    fn disposition(&self, advice: &[u8], record: &[u8], index: u16) -> [u8; DISPOSITION_BYTES] {
        let mut wire = [0; DISPOSITION_BYTES];
        put(&mut wire, 0, 0x43594144u32.to_le_bytes());
        put(&mut wire, 4, 1u16.to_le_bytes());
        put(&mut wire, 6, (DISPOSITION_BYTES as u16).to_le_bytes());
        for (at, value) in [
            (8, 1u64),
            (16, 1),
            (24, 1),
            (32, 3),
            (40, 2),
            (48, 4),
            (56, TARGET.id),
            (64, TARGET.generation),
            (72, 9),
            (80, REGISTERED),
        ] {
            put(&mut wire, at, value.to_le_bytes());
        }
        for (at, value) in [
            (88, self.domain),
            (90, 1),
            (92, 1),
            (100, self.scope.fallback_index),
            (102, index),
            (104, self.selected),
            (106, 1),
        ] {
            put(&mut wire, at, value.to_le_bytes());
        }
        put(&mut wire, 96, self.claimed_mask().to_le_bytes());
        put(&mut wire, 112, self.candidate_hash);
        put(&mut wire, 144, hash(advice));
        put(&mut wire, 176, hash(record));
        put(&mut wire, 208, self.rule_hash);
        wire
    }
}

#[allow(clippy::too_many_arguments)]
fn explore(
    out: &mut impl Write,
    candidates: &FrozenCandidates,
    profile: &Profile<'_>,
    rule: RuleMatch,
    mask: usize,
    reverse: bool,
    mode: &str,
    index: u16,
    step: &str,
) -> io::Result<()> {
    let domain = candidates.snapshot().domain;
    let count = candidates.ordinals().len() as u16;
    let assisted = !matches!(mode, "rule" | "shadow_rule");
    let selected = if assisted {
        index.min(count - 1)
    } else {
        rule.fallback_index
    };
    let view = candidates.view();
    let local = view.selected(selected).unwrap();
    let attempt = Attempt {
        domain,
        selected,
        scope: rule,
        assisted,
        shadow_rule: mode == "shadow_rule",
        rule_hash: hash(profile.canonical_bytes()),
        candidate_hash: candidates.digest(),
    };
    let plan = attempt.plan(local.action_payload);
    let record = attempt.record(&plan, index);
    let advice = advice_wire(candidates, index);
    let disposition = attempt.disposition(&advice, &record, index);
    let records = [record];
    let actions = [local];
    let mut bank = DesiredBank::empty();
    bank.bind_boot(1, 2, PUBLISHER, || Ok(())).unwrap();
    let (role, holder, endpoint_cap_id) = if domain == 4 {
        (12, actor(12), 130)
    } else {
        (
            1,
            Identity {
                id: 0,
                generation: 0,
            },
            0,
        )
    };
    bank.register_target(
        ExecutorBindingV1 {
            domain,
            role,
            active: true,
            target: TARGET,
            executor_generation: 1,
            holder,
            endpoint_cap_id,
        },
        |_| Ok(()),
    )
    .unwrap();
    let mut ledger = EvidenceLedger::new(OPERATIONS, CONTROLLER, SUPERVISOR, 1, 1).unwrap();
    let mut gate =
        RegisteredDecisionGate::new_with_terminal_owner(CONTROLLER, PUBLISHER, SUPERVISOR, 1, 2)
            .unwrap();
    let mut bridge = SvcV3Bridge {
        gate: &mut gate,
        decision_endpoint_cap: REGISTER_CAP,
        publisher_cap: PUBLISH_CAP,
    };
    let ad_scope = advice_scope(candidates, REGISTERED);
    let reg_scope = AssistedScope {
        advice: &ad_scope,
        assisted_mode: mode != "shadow_proposal",
        offline_model_authorized: mode != "model_closed",
    };
    let recorded = if mode == "rule" {
        String::from("skip")
    } else {
        result(ledger.record(OPERATIONS, &advice, &ad_scope))
    };
    let after_advice = bank.version();

    let caller = VerifiedNativeCaller {
        identity: CONTROLLER,
        package_abi: 3,
        endpoint_cap: REGISTER_CAP,
        cpu: 0,
    };
    let frozen = FrozenNativePlan {
        bytes: &plan,
        sidecars: &records,
        rules: profile,
        actions: &actions,
        context: context(attempt.rule_hash, REGISTERED),
    };
    let reg_args = |len| [REGISTER_CAP, 0x1000, len, 0, 0x2000, 8];
    let registered = if assisted {
        let copied = [record.as_slice(), disposition.as_slice()].concat();
        result(bridge.register_assisted_one(
            caller,
            reg_args(copied.len() as u64),
            &copied,
            &frozen,
            &reg_scope,
            &mut ledger,
        ))
    } else {
        result(bridge.register_rule_only(caller, reg_args(record.len() as u64), &record, &frozen))
    };
    let after_register = bank.version();
    let retained = bridge
        .gate
        .read_decision(PUBLISHER, 1, 2, 4)
        .map_or_else(|e| format!("err_{e:?}"), |raw| hex(&hash(&raw)));

    let now = match step {
        "advice_end" => ADVICE_END,
        "decision_end" => DECISION_END,
        _ => REGISTERED + 1,
    };
    let pub_scope = advice_scope(candidates, now);
    let pub_assisted = AssistedScope {
        advice: &pub_scope,
        ..reg_scope
    };
    let publication = FrozenNativePlan {
        context: context(attempt.rule_hash, now),
        ..frozen
    };
    let publisher = VerifiedNativeCaller {
        identity: if step == "operations" {
            OPERATIONS
        } else {
            PUBLISHER
        },
        endpoint_cap: if step == "operations" {
            60
        } else {
            PUBLISH_CAP
        },
        ..caller
    };
    let publish_args = [0x1000, plan.len() as u64, 0x2000, 1, 0, 0];
    let mut accepted = 0;
    let mut publish = || {
        let native = || {
            accepted += 1;
            bank.publish_registered(PUBLISHER, 0, &plan, publication.context, |_| Ok(()))
                .map(|_| ())
        };
        if assisted {
            result(bridge.publish_assisted_one(
                publisher,
                publish_args,
                &plan,
                &records,
                &publication,
                &pub_assisted,
                native,
            ))
        } else {
            result(bridge.publish_plan(
                publisher,
                publish_args,
                &plan,
                &records,
                &publication,
                native,
            ))
        }
    };
    let published = if step == "skip" {
        String::from("skip")
    } else {
        publish()
    };
    let replayed = if step == "skip" {
        String::from("skip")
    } else {
        publish()
    };
    let mut committed = String::from("-");
    let mut published_count = 0;
    if bank.version() > 0 {
        let plan_hash = hash(&plan);
        let verified = bank.verify_committed_publication(
            &PlanV2::decode(&plan).unwrap(),
            plan_hash,
            bank.version(),
            |stages| {
                published_count = stages.iter().flatten().count();
                let stage = stages.first().and_then(|p| *p).ok_or(Error::Denied)?;
                let mut bytes = [0; 6];
                let len = stage.value.encode(domain, &mut bytes)?;
                committed = hex(&bytes[..len]);
                if stage.plan_digest != plan_hash
                    || stage.index != 0
                    || stage.version != bank.version()
                    || stage.key.boot_epoch != 1
                    || stage.key.controller_epoch != 2
                    || stage.key.plan_seq != 1
                    || stage.binding.target != TARGET
                {
                    return Err(Error::Denied);
                }
                Ok(())
            },
        );
        if let Err(e) = verified {
            committed = format!("err_{e:?}");
        }
    }
    writeln!(
        out,
        "{domain}\t{}\t{mask}\t{mode}\t{index}\t{step}\t{recorded}\t{after_advice}\t{registered}\t{after_register}\t{retained}\t{published}\t{replayed}\t{}\t{accepted}\t{}\t{published_count}\t{committed}\t{}\t{}\t{}\t{}\t{}",
        u8::from(reverse),
        bank.version(),
        bridge.gate.published_count(),
        hex(&attempt.candidate_hash),
        hex(&attempt.rule_hash),
        hex(&hash(&plan)),
        hex(&hash(&record)),
        if mode == "rule" {
            String::from("-")
        } else {
            hex(&hash(&advice))
        },
    )
}

fn main() -> io::Result<()> {
    let mut out = BufWriter::new(io::stdout().lock());
    writeln!(
        out,
        "domain\treverse\tmask\tmode\tindex\tstep\tadvice\tafter_advice\tregister\tafter_register\tretained\tpublish\treplay\tversion\taccept_calls\tgate_published\tbank_published\tpayload\tcandidates_sha256\trules_sha256\tplan_sha256\tdecision_sha256\tadvice_sha256"
    )?;
    for domain in 1..=15 {
        let candidates = candidate_set(domain);
        let ordinals = candidates.ordinals();
        for reverse in [false, true] {
            for mask in 1..(1 << ordinals.len()) {
                let wire = rules(domain, ordinals, mask, reverse);
                let profile = Profile::parse(&wire).unwrap();
                let rule = profile
                    .match_candidates(
                        domain,
                        TARGET.id,
                        candidates.rule_fields(),
                        Candidates {
                            static_ordinals: ordinals,
                        },
                    )
                    .unwrap()
                    .unwrap();
                for mode in MODES {
                    let first = if mode == "rule" { ordinals.len() } else { 0 };
                    for index in first..=ordinals.len() {
                        for step in STEPS {
                            explore(
                                &mut out,
                                &candidates,
                                &profile,
                                rule,
                                mask,
                                reverse,
                                mode,
                                index as u16,
                                step,
                            )?;
                        }
                    }
                }
            }
        }
    }
    out.flush()
}
