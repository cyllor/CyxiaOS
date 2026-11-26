//! Protected candidate registration for one current target/family.
//! This is an internal frozen object, not a new user wire format. Static
//! ordinals are taken from the authenticated ActionSchema catalog, never
//! assigned by a model or inferred from the candidate array index.
use super::{Error, Identity, action_schema_v2::ActionV2, registered_gate_v3::FrozenAction};
use cyxia_control_model::native_v0199::SnapshotReplyV3;
use sha2::{Digest, Sha256};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogEntry {
    pub ordinal: u16,
    pub value: ActionV2,
}
#[derive(Clone, Copy)]
struct Payload {
    bytes: [u8; 6],
    len: u8,
}
const EMPTY: Payload = Payload {
    bytes: [0; 6],
    len: 0,
};
impl Payload {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}
pub struct FrozenCandidates {
    snapshot: SnapshotReplyV3,
    ordinals: [u16; 32],
    payloads: [Payload; 32],
    len: usize,
    raw_fields: [Option<u64>; 7],
    digest: [u8; 32],
}
pub struct View<'a> {
    set: &'a FrozenCandidates,
    refs: [&'a [u8]; 32],
}
impl<'a> View<'a> {
    pub fn selected(&self, index: u16) -> Result<FrozenAction<'_>, Error> {
        let s = self.set;
        let payload = *self.refs[..s.len]
            .get(usize::from(index))
            .ok_or(Error::Denied)?;
        Ok(FrozenAction {
            domain_id: s.snapshot.domain,
            target: Identity {
                id: s.snapshot.target_id,
                generation: s.snapshot.target_generation,
            },
            candidate_set_hash: s.digest,
            static_ordinals: &s.ordinals[..s.len],
            candidate_payloads: &self.refs[..s.len],
            raw_fields: s.raw_fields,
            action_payload: payload,
        })
    }
}
impl FrozenCandidates {
    /// Each static value is considered exactly once, in the authenticated
    /// numeric/tier order required by main §6.1 and §8. A signed catalog
    /// may bind static ordinals but cannot reorder the canonical tiers.
    /// A hard-gate error aborts the whole capture, rather
    /// than pretending that an unavailable owner rejected that candidate.
    /// Ordinary admission forbids trial-only values.
    #[allow(clippy::too_many_arguments)]
    pub fn capture(
        snapshot: SnapshotReplyV3,
        catalog: &[CatalogEntry],
        catalog_digest: [u8; 32],
        current: ActionV2,
        used: Option<u64>,
        healthy: Option<bool>,
        trial: bool,
        verify_catalog: impl FnOnce(&[CatalogEntry], [u8; 32]) -> Result<(), Error>,
        mut hard_legal: impl FnMut(ActionV2) -> Result<bool, Error>,
    ) -> Result<Self, Error> {
        let wire = snapshot.encode().map_err(|_| Error::Invalid)?;
        let all = ActionV2::values(snapshot.domain)?;
        if catalog_digest == [0; 32]
            || catalog.len() != all.len()
            || catalog.len() > 32
            || !all.contains(&current)
        {
            return Err(Error::Invalid);
        }
        for (i, r) in catalog.iter().enumerate() {
            if r.ordinal == u16::MAX
                || r.value != all[i]
                || catalog[..i]
                    .iter()
                    .any(|old| old.ordinal == r.ordinal || old.value == r.value)
            {
                return Err(Error::Denied);
            }
        }
        verify_catalog(catalog, catalog_digest)?;
        let mut out = Self {
            snapshot,
            ordinals: [u16::MAX; 32],
            payloads: [EMPTY; 32],
            len: 0,
            raw_fields: [None; 7],
            digest: [0; 32],
        };
        out.raw_fields[..4].copy_from_slice(&snapshot.fields[8..12]);
        out.raw_fields[4] = catalog
            .iter()
            .find(|r| r.value == current)
            .map(|r| u64::from(r.ordinal));
        out.raw_fields[5] = used;
        out.raw_fields[6] = healthy.map(u64::from);
        for r in catalog {
            if !trial && r.value.requires_trial() {
                continue;
            }
            if !hard_legal(r.value)? {
                continue;
            }
            let mut bytes = [0; 6];
            let len = r.value.encode(snapshot.domain, &mut bytes)?;
            out.ordinals[out.len] = r.ordinal;
            out.payloads[out.len] = Payload {
                bytes,
                len: len as u8,
            };
            out.len += 1;
        }
        if out.len == 0 {
            return Err(Error::NotReady);
        }
        // Internal immutable object hash binds exact observation, catalog,
        // rule fields and legal ordered list. G1 must independently freeze
        // any external canonical hash/schema artifact before deployment.
        let mut h = Sha256::new();
        h.update(b"CYX/REGISTERED-CANDIDATES/v0199");
        h.update(catalog_digest);
        h.update(wire);
        h.update([u8::from(trial)]);
        for v in out.raw_fields {
            h.update([u8::from(v.is_some())]);
            h.update(v.unwrap_or(0).to_le_bytes());
        }
        h.update((out.len as u16).to_le_bytes());
        for (i, p) in out.payloads[..out.len].iter().enumerate() {
            h.update(out.ordinals[i].to_le_bytes());
            h.update([p.len]);
            h.update(p.as_slice());
        }
        out.digest = h.finalize().into();
        Ok(out)
    }
    pub fn snapshot(&self) -> SnapshotReplyV3 {
        self.snapshot
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn ordinals(&self) -> &[u16] {
        &self.ordinals[..self.len]
    }
    pub fn rule_fields(&self) -> [Option<u64>; 7] {
        self.raw_fields
    }
    pub fn view(&self) -> View<'_> {
        View {
            set: self,
            refs: core::array::from_fn(|i| self.payloads[i].as_slice()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot() -> SnapshotReplyV3 {
        SnapshotReplyV3 {
            snapshot_seq: 1,
            boot_epoch: 1,
            ledger_generation: 2,
            core_generation: 3,
            target_id: 15,
            target_generation: 1,
            sampled_ns: 10,
            domain: 15,
            fields: [
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(20),
                Some(0),
                Some(1),
                Some(1),
            ],
        }
    }
    #[test]
    fn stable_actual_payloads_and_raw_rule_fields_bind_scope() {
        let values = ActionV2::values(15).unwrap();
        let c: [CatalogEntry; 4] = core::array::from_fn(|i| CatalogEntry {
            ordinal: 10 + i as u16,
            value: values[i],
        });
        let s = FrozenCandidates::capture(
            snapshot(),
            &c,
            [1; 32],
            values[1],
            Some(20),
            Some(true),
            false,
            |_, _| Ok(()),
            |v| Ok(v != values[0]),
        )
        .unwrap();
        assert_eq!(s.ordinals(), &[11, 12, 13]);
        assert_eq!(
            s.rule_fields(),
            [
                Some(20),
                Some(0),
                Some(1),
                Some(1),
                Some(11),
                Some(20),
                Some(1)
            ]
        );
        let view = s.view();
        let f = view.selected(1).unwrap();
        assert_eq!(f.action_payload, &[32, 0]);
        assert!(view.selected(3).is_err());
        let mut reordered = c;
        reordered.swap(0, 3);
        assert!(matches!(
            FrozenCandidates::capture(
                snapshot(),
                &reordered,
                [1; 32],
                values[1],
                None,
                None,
                false,
                |_, _| panic!("noncanonical tier order"),
                |_| panic!()
            ),
            Err(Error::Denied)
        ));
        let mut invalid = c;
        invalid[1] = c[0];
        assert!(matches!(
            FrozenCandidates::capture(
                snapshot(),
                &invalid,
                [1; 32],
                values[1],
                None,
                None,
                false,
                |_, _| panic!(),
                |_| panic!()
            ),
            Err(Error::Denied)
        ));
        assert!(matches!(
            FrozenCandidates::capture(
                snapshot(),
                &c,
                [1; 32],
                values[1],
                None,
                None,
                false,
                |_, _| Ok(()),
                |_| Err(Error::NotReady)
            ),
            Err(Error::NotReady)
        ));
    }
    #[test]
    fn entire_local_static_inventory_roundtrips() {
        for domain in 1..=15 {
            let values = ActionV2::values(domain).unwrap();
            assert!((3..=4).contains(&values.len()));
            for v in values {
                let mut b = [0; 6];
                let n = v.encode(domain, &mut b).unwrap();
                assert_eq!(ActionV2::decode(domain, 1, &b[..n]), Ok(*v));
            }
        }
        assert!(ActionV2::values(16).is_err());
    }
}
