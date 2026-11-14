//! Bounded outbound serialization of an initialized actual AcceptedSample.
//! No parser, setter, or EvidenceAuthority; callers retain acceptance custody.
use super::Split;
use cyxia_prototype::learning::reward::{AcceptedSample, VerifiedReplay};
pub const WITNESS_BYTES: usize = 1024;
// 32 magic + ids16 + canonical64 + family16 + group72 + schemas160 + split/slot16
// + input128 + performance128 + costs112 + binary64 40 + evidence32 = 816.
const USED_WITNESS: usize = 816;
const _: () = assert!(USED_WITNESS <= WITNESS_BYTES);
pub struct Witness(pub(super) [u8; WITNESS_BYTES]);
fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
impl Witness {
    pub fn from_stored(
        sample: &AcceptedSample,
        candidate: &VerifiedReplay,
        baseline: &VerifiedReplay,
        split: Split,
        slot: usize,
    ) -> Self {
        let mut out = Self([0; WITNESS_BYTES]);
        out.0[..16].copy_from_slice(b"CYXIA_SAMPLE_16\0");
        let mut at = 32;
        for value in [baseline.trial_id(), candidate.trial_id()] {
            put(&mut out.0, at, value);
            at += 8;
        }
        for digest in [baseline.evidence_hash(), candidate.evidence_hash()] {
            out.0[at..at + 32].copy_from_slice(&digest);
            at += 32;
        }
        let family = sample.family();
        for value in [
            family.domain as u64,
            family.kind as u64,
            sample.group().seed,
        ] {
            put(&mut out.0, at, value);
            at += 8;
        }
        for hash in [sample.group().workload, sample.group().initial_image] {
            out.0[at..at + 32].copy_from_slice(&hash);
            at += 32;
        }
        let schemas = sample.schemas();
        for schema in [
            schemas.feature,
            schemas.action,
            schemas.reward,
            schemas.learning,
        ] {
            put(&mut out.0, at, schema.version as u64);
            at += 8;
            out.0[at..at + 32].copy_from_slice(&schema.hash);
            at += 32;
        }
        for value in [u64::from(split == Split::Validation), slot as u64] {
            put(&mut out.0, at, value);
            at += 8;
        }
        for value in sample.input() {
            out.0[at..at + 2].copy_from_slice(&value.to_le_bytes());
            at += 2;
        }
        let reward = sample.reward();
        for p in [reward.candidate, reward.baseline] {
            for value in [
                p.emitted,
                p.completed,
                p.rejected,
                p.timed_out,
                p.pending,
                p.penalty_p99_ns,
                u64::from(p.actual_completed_p99_ns.is_some()),
                p.actual_completed_p99_ns.unwrap_or(0),
            ] {
                put(&mut out.0, at, value);
                at += 8;
            }
        }
        for c in [reward.candidate_cpu, reward.baseline_cpu] {
            for value in [
                c.union_ns,
                c.policy_ns,
                c.executor_ns,
                c.optional_ns,
                c.raw_tagged_ns[0],
                c.raw_tagged_ns[1],
                c.raw_tagged_ns[2],
            ] {
                put(&mut out.0, at, value);
                at += 8;
            }
        }
        for value in [
            reward.raw_cost,
            reward.clipped_cost,
            reward.delta_throughput,
            reward.delta_latency,
            reward.value,
        ] {
            put(&mut out.0, at, value.to_bits());
            at += 8;
        }
        out.0[at..at + 32].copy_from_slice(&sample.evidence_hash());
        at += 32;
        debug_assert_eq!(at, USED_WITNESS);
        out
    }
}
