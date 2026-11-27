//! Canonical single-action RULE_ONLY encoding shared by the native effect fixtures.
//! Callers still authenticate the observation and register against their real owner.
use cyxia_kernel_core::control_plane::{
    registered_gate_v3::TrustedRegistrationScope, rule_profile_v2::RuleMatch,
    snapshot_store_v3::Target,
};
use sha2::{Digest, Sha256};

fn put<const N: usize>(bytes: &mut [u8], at: usize, value: [u8; N]) {
    bytes[at..at + N].copy_from_slice(&value);
}

pub(super) fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(super) fn rule(
    target: Target,
    generation: u64,
    field: u16,
    minimum: u64,
    ordinal: u16,
) -> [u8; 88] {
    let mut out = [0; 88];
    put(&mut out, 0, 0x43595255u32.to_le_bytes());
    put(&mut out, 4, 2u16.to_le_bytes());
    put(&mut out, 6, 32u16.to_le_bytes());
    put(&mut out, 8, generation.to_le_bytes());
    put(&mut out, 16, 1u32.to_le_bytes());
    put(&mut out, 20, 88u32.to_le_bytes());
    put(&mut out, 32, 1u32.to_le_bytes());
    put(&mut out, 36, target.domain.to_le_bytes());
    put(&mut out, 38, 1u16.to_le_bytes());
    put(&mut out, 40, target.object.id.to_le_bytes());
    put(&mut out, 50, 1u16.to_le_bytes());
    put(&mut out, 52, 1u16.to_le_bytes());
    put(&mut out, 56, 56u32.to_le_bytes());
    put(&mut out, 64, field.to_le_bytes());
    out[66] = 3;
    put(&mut out, 72, minimum.to_le_bytes());
    put(&mut out, 80, ordinal.to_le_bytes());
    out
}

pub(super) fn encode_decision<const N: usize>(
    target: Target,
    sequence: u64,
    ctx: TrustedRegistrationScope,
    rule: RuleMatch,
    candidate_hash: [u8; 32],
    payload: &[u8],
) -> ([u8; N], [u8; 256]) {
    assert_eq!(N, 210 + payload.len());
    let expiry = ctx.sampled_ns + 100_000_000;
    let mut plan = [0; N];
    put(&mut plan, 0, 0x43594c31u32.to_le_bytes());
    put(&mut plan, 4, 2u16.to_le_bytes());
    put(&mut plan, 6, 64u16.to_le_bytes());
    put(&mut plan, 8, u32::try_from(N).unwrap().to_le_bytes());
    put(&mut plan, 12, 1u16.to_le_bytes());
    put(&mut plan, 64, 0x43595031u32.to_le_bytes());
    put(&mut plan, 68, 2u16.to_le_bytes());
    put(&mut plan, 70, 144u16.to_le_bytes());
    put(&mut plan, 72, target.domain.to_le_bytes());
    put(&mut plan, 74, 1u16.to_le_bytes());
    put(
        &mut plan,
        76,
        u32::try_from(2 + payload.len()).unwrap().to_le_bytes(),
    );
    for (at, value) in [
        (16, sequence),
        (24, ctx.base_plan_version),
        (40, ctx.controller_epoch),
        (48, ctx.snapshot_seq),
        (56, ctx.sampled_ns + 10_000_000_000),
        (80, ctx.controller_epoch),
        (88, sequence),
        (96, ctx.snapshot_seq),
        (104, target.object.id),
        (112, target.object.generation),
        (120, ctx.ledger_generation),
        (128, ctx.core_generation),
        (136, expiry),
    ] {
        put(&mut plan, at, value.to_le_bytes());
    }
    put(&mut plan, 176, candidate_hash);
    put(&mut plan, 208, rule.fallback_index.to_le_bytes());
    plan[210..].copy_from_slice(payload);
    let mut record = [0; 256];
    put(&mut record, 0, 0x43594431u32.to_le_bytes());
    put(&mut record, 4, 3u16.to_le_bytes());
    put(&mut record, 6, 256u16.to_le_bytes());
    for (at, value) in [
        (8, ctx.boot_epoch),
        (16, ctx.controller_epoch),
        (24, sequence),
        (32, sequence),
        (40, ctx.snapshot_seq),
        (48, target.object.id),
        (56, target.object.generation),
        (64, ctx.ledger_generation),
        (72, ctx.core_generation),
        (80, ctx.rules_generation),
        (144, expiry),
    ] {
        put(&mut record, at, value.to_le_bytes());
    }
    put(&mut record, 88, rule.rule_id.to_le_bytes());
    put(&mut record, 94, target.domain.to_le_bytes());
    put(&mut record, 96, 1u16.to_le_bytes());
    put(&mut record, 102, rule.fallback_index.to_le_bytes());
    put(&mut record, 104, u16::MAX.to_le_bytes());
    put(&mut record, 108, 3u32.to_le_bytes());
    put(&mut record, 152, rule.allowed_mask.to_le_bytes());
    put(&mut record, 156, rule.fallback_index.to_le_bytes());
    put(&mut record, 158, rule.choice_policy.to_le_bytes());
    put(&mut record, 160, ctx.rules_hash);
    put(&mut record, 192, sha(&plan));
    put(&mut record, 224, candidate_hash);
    (plan, record)
}
