//! Immutable, allocation-free RuleProfile v2 parser (V0.19.9, main §6.1).
//!
//! It validates a frozen offline rule catalog and computes its candidate
//! intersection. Neither a legal value nor a model suggestion is an execution
//! grant: a separate deterministic controller must still check authoritative
//! ledgers, capabilities, stability, current epochs and any TrialPermit.
use super::Error;

pub const RULE_MAGIC: u32 = 0x4359_5255;
pub const RULE_VERSION: u16 = 2;
pub const HEADER: usize = 32;
pub const ENTRY: usize = 32;
pub const PREDICATE: usize = 16;
pub const VALUE: usize = 8;
pub const MAX_BYTES: usize = 64 * 1024;

fn get16(b: &[u8], at: usize) -> Result<u16, Error> {
    let x = b.get(at..at + 2).ok_or(Error::Invalid)?;
    Ok(u16::from_le_bytes([x[0], x[1]]))
}
fn get32(b: &[u8], at: usize) -> Result<u32, Error> {
    let x = b.get(at..at + 4).ok_or(Error::Invalid)?;
    Ok(u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
}
fn get64(b: &[u8], at: usize) -> Result<u64, Error> {
    let x = b.get(at..at + 8).ok_or(Error::Invalid)?;
    Ok(u64::from_le_bytes([x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]]))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleMatch {
    pub rule_id: u32,
    pub choice_policy: u16,
    pub allowed_mask: u32,
    pub fallback_index: u16,
}

/// Must be formed from a trusted local candidate table; indexes are the table
/// order, and ordinals are ActionSchema static values, NOT model-supplied bytes.
pub struct Candidates<'a> {
    pub static_ordinals: &'a [u16],
}

#[derive(Clone, Copy)]
pub struct Profile<'a> {
    bytes: &'a [u8],
    pub generation: u64,
    pub rule_count: u32,
}
impl<'a> Profile<'a> {
    /// Exact canonical bytes; the EL1 owner hashes these, never a model claim.
    pub fn canonical_bytes(&self) -> &'a [u8] { self.bytes }

    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER || bytes.len() > MAX_BYTES
            || get32(bytes, 0)? != RULE_MAGIC
            || get16(bytes, 4)? != RULE_VERSION
            || usize::from(get16(bytes, 6)?) != HEADER
            || get64(bytes, 8)? == 0
            || get32(bytes, 20)? as usize != bytes.len()
            || get64(bytes, 24)? != 0
        {
            return Err(Error::Invalid);
        }
        let count = get32(bytes, 16)?;
        if count == 0 { return Err(Error::Invalid); }
        let mut at = HEADER;
        let mut previous_id = 0u32;
        for _ in 0..count {
            let hdr = bytes.get(at..at.checked_add(ENTRY).ok_or(Error::Invalid)?)
                .ok_or(Error::Invalid)?;
            let id = get32(hdr, 0)?;
            let domain = get16(hdr, 4)?;
            let kind = get16(hdr, 6)?;
            let _target = get64(hdr, 8)?;
            let policy = get16(hdr, 16)?;
            let predicates = usize::from(get16(hdr, 18)?);
            let values = usize::from(get16(hdr, 20)?);
            let len = usize::try_from(get32(hdr, 24)?).map_err(|_| Error::Invalid)?;
            let expected = ENTRY + PREDICATE * predicates + VALUE * values;
            if id <= previous_id || domain == 0 || domain > 15
                || kind != 1 || policy > 2
                || (policy == 1 && matches!(domain, 6 | 11 | 12 | 14))
                || predicates > 8 || values == 0 || values > 32
                || get16(hdr, 22)? != 0 || get32(hdr, 28)? != 0
                || len != expected
            {
                return Err(Error::Invalid);
            }
            let frame = bytes.get(at..at.checked_add(len).ok_or(Error::Invalid)?)
                .ok_or(Error::Invalid)?;
            for p in 0..predicates {
                let start = ENTRY + p * PREDICATE;
                let field = get16(frame, start)?;
                let cmp = frame[start + 2];
                if !(1..=7).contains(&field) || !(1..=3).contains(&cmp)
                    || frame[start + 3..start + 8].iter().any(|b| *b != 0)
                {
                    return Err(Error::Invalid);
                }
            }
            let mut ranks = 0u32;
            // ActionSchema ordinals are per-family static u16 identifiers,
            // NOT indexes into this 32-element candidate array. In particular
            // a valid ordinal 32 or higher must not be rejected as an index.
            let mut seen_ordinals = [u16::MAX; 32];
            for i in 0..values {
                let start = ENTRY + predicates * PREDICATE + i * VALUE;
                let ordinal = get16(frame, start)?;
                let rank = u32::from(get16(frame, start + 2)?);
                if ordinal == u16::MAX || rank >= values as u32
                    || get32(frame, start + 4)? != 0
                    || ranks & (1 << rank) != 0
                    || seen_ordinals[..i].contains(&ordinal)
                {
                    return Err(Error::Invalid);
                }
                ranks |= 1 << rank;
                seen_ordinals[i] = ordinal;
            }
            previous_id = id;
            at += len;
        }
        if at != bytes.len() { return Err(Error::Invalid); }
        Ok(Self { bytes, generation: get64(bytes, 8)?, rule_count: count })
    }

    /// Independent template catalog check. The rule ID names an exact
    /// trial-only rule; every template ordinal must occur in its list.
    /// Repeated ordinals in the template are intentional cycle entries.
    pub fn validate_trial_template(&self,rule:u32,domain:u16,target:u64,order:&[u16])->Result<(),Error>{
        if rule==0||!(1..=15).contains(&domain)||order.is_empty()||order.len()>32{return Err(Error::Invalid);}
        let mut at=HEADER;
        for _ in 0..self.rule_count{
            let hdr=&self.bytes[at..at+ENTRY];
            let predicates=usize::from(get16(hdr,18)?);
            let values=usize::from(get16(hdr,20)?);
            let len=get32(hdr,24)? as usize;
            let frame=&self.bytes[at..at+len];at+=len;
            if get32(hdr,0)?!=rule{continue;}
            if get16(hdr,4)?!=domain||get16(hdr,16)?!=2
                ||(get64(hdr,8)?!=target&&get64(hdr,8)?!=u64::MAX){return Err(Error::Denied);}
            for &ordinal in order{
                if ordinal==u16::MAX||!(0..values).any(|i|
                    get16(frame,ENTRY+predicates*PREDICATE+i*VALUE)==Ok(ordinal)){
                    return Err(Error::Denied);
                }
            }
            return Ok(());
        }
        Err(Error::Denied)
    }
    /// Trial matching does not authorize a permit; caller already owns the
    /// protected next ordinal from that permit. Recompute raw predicates
    /// and its one-bit current candidate intersection.
    pub(super) fn match_trial(&self,rule:u32,domain:u16,target:u64,ordinal:u16,
        raw_fields:[Option<u64>;7],candidates:Candidates<'_>)->Result<RuleMatch,Error>{
        self.validate_trial_template(rule,domain,target,&[ordinal])?;
        if candidates.static_ordinals.is_empty()||candidates.static_ordinals.len()>32{return Err(Error::Invalid);}
        for (i,&v) in candidates.static_ordinals.iter().enumerate(){
            if v==u16::MAX||candidates.static_ordinals[..i].contains(&v){return Err(Error::Invalid);}
        }
        let index=candidates.static_ordinals.iter().position(|&v|v==ordinal).ok_or(Error::Denied)?;
        let mut at=HEADER;
        for _ in 0..self.rule_count{
            let hdr=&self.bytes[at..at+ENTRY];
            let predicates=usize::from(get16(hdr,18)?);
            let len=get32(hdr,24)? as usize;
            let frame=&self.bytes[at..at+len];at+=len;
            if get32(hdr,0)?!=rule{continue;}
            for i in 0..predicates{
                let off=ENTRY+i*PREDICATE;let field=usize::from(get16(frame,off)?)-1;
                let value=get64(frame,off+8)?;
                if !raw_fields[field].is_some_and(|v|match frame[off+2]{
                    1=>v==value,2=>v<=value,3=>v>=value,_=>false,
                }){return Err(Error::Denied);}
            }
            return Ok(RuleMatch{rule_id:rule,choice_policy:2,allowed_mask:1u32<<index,fallback_index:index as u16});
        }
        Err(Error::Denied)
    }

    /// Ordered first matching rule; invalid/unavailable predicates do not match.
    /// A missing candidate intersection returns None and MUST force SAFE_EXEC
    /// for that target, never a fabricated fallback.
    pub fn match_candidates(
        &self,
        domain: u16,
        target: u64,
        raw_fields: [Option<u64>; 7],
        candidates: Candidates<'_>,
    ) -> Result<Option<RuleMatch>, Error> {
        if domain == 0 || domain > 15
            || candidates.static_ordinals.is_empty()
            || candidates.static_ordinals.len() > 32
        {
            return Err(Error::Invalid);
        }
        for (index, &ordinal) in candidates.static_ordinals.iter().enumerate() {
            if ordinal == u16::MAX
                || candidates.static_ordinals[..index].contains(&ordinal)
            {
                return Err(Error::Invalid);
            }
        }
        let mut at = HEADER;
        for _ in 0..self.rule_count {
            let hdr = &self.bytes[at..at + ENTRY];
            let predicates = usize::from(get16(hdr, 18)?);
            let values = usize::from(get16(hdr, 20)?);
            let len = get32(hdr, 24)? as usize;
            let frame = &self.bytes[at..at + len];
            at += len;
            if get16(hdr, 4)? != domain
                || (get64(hdr, 8)? != u64::MAX && get64(hdr, 8)? != target)
            {
                continue;
            }
            let matches = (0..predicates).all(|i| {
                let off = ENTRY + i * PREDICATE;
                let field = get16(frame, off).ok().unwrap_or(0);
                let value = get64(frame, off + 8).ok().unwrap_or(0);
                raw_fields.get(usize::from(field).saturating_sub(1))
                    .and_then(|v| *v)
                    .is_some_and(|v| match frame[off + 2] {
                        1 => v == value,
                        2 => v <= value,
                        3 => v >= value,
                        _ => false,
                    })
            });
            if !matches { continue; }
            // An explicit offline TrialPermit is mandatory for choice_policy=2.
            // This read-only ordinary-rule API has no TrialPermit input, hence
            // it MUST NOT return a trial candidate or silently treat one as
            // ordinary permission. A verified-trial entry point is separate.
            if get16(hdr, 16)? == 2 { continue; }
            let mut allowed_mask = 0u32;
            let mut fallback_index = 0xffffu16;
            let mut best_rank = u16::MAX;
            for i in 0..values {
                let off = ENTRY + predicates * PREDICATE + i * VALUE;
                let ordinal = get16(frame, off)?;
                let rank = get16(frame, off + 2)?;
                if let Some(index) = candidates.static_ordinals.iter().position(|&v| v == ordinal) {
                    allowed_mask |= 1u32 << index;
                    if rank < best_rank {
                        best_rank = rank;
                        fallback_index = index as u16;
                    }
                }
            }
            if allowed_mask == 0 { return Ok(None); }
            return Ok(Some(RuleMatch {
                rule_id: get32(hdr, 0)?,
                choice_policy: get16(hdr, 16)?,
                allowed_mask,
                fallback_index,
            }));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> [u8; 96] {
        // One v2 D01 assisted rule: field 1 GE 7; ordinals 1 and 3,
        // rank 0 belongs to ordinal 3 (candidate index 1).
        let mut b = [0u8; 96];
        b[0..4].copy_from_slice(&RULE_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&RULE_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(HEADER as u16).to_le_bytes());
        b[8..16].copy_from_slice(&1u64.to_le_bytes());
        b[16..20].copy_from_slice(&1u32.to_le_bytes());
        b[20..24].copy_from_slice(&96u32.to_le_bytes());
        b[32..36].copy_from_slice(&5u32.to_le_bytes());
        b[36..38].copy_from_slice(&1u16.to_le_bytes());
        b[38..40].copy_from_slice(&1u16.to_le_bytes());
        b[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        b[48..50].copy_from_slice(&1u16.to_le_bytes());
        b[50..52].copy_from_slice(&1u16.to_le_bytes());
        b[52..54].copy_from_slice(&2u16.to_le_bytes());
        b[56..60].copy_from_slice(&64u32.to_le_bytes());
        b[64..66].copy_from_slice(&1u16.to_le_bytes());
        b[66] = 3; // GE
        b[72..80].copy_from_slice(&7u64.to_le_bytes());
        b[80..82].copy_from_slice(&1u16.to_le_bytes());
        b[82..84].copy_from_slice(&1u16.to_le_bytes());
        b[88..90].copy_from_slice(&3u16.to_le_bytes());
        b // second rank is zero, completing the canonical rank permutation.
    }
    #[test]
    fn profile_intersects_current_candidates_without_granting_execution() {
        let b = sample();
        let profile = Profile::parse(&b).unwrap();
        let rule = profile.match_candidates(
            1, 44, [Some(7), None, None, None, None, None, None],
            Candidates { static_ordinals: &[1, 3] },
        ).unwrap().unwrap();
        assert_eq!(rule.rule_id, 5);
        assert_eq!(rule.choice_policy, 1);
        assert_eq!(rule.allowed_mask, 0b11);
        assert_eq!(rule.fallback_index, 1);
        assert!(profile.match_candidates(1, 44, [Some(6); 7],
            Candidates { static_ordinals: &[1, 3] }).unwrap().is_none());
        assert!(profile.match_candidates(1, 44, [Some(7); 7],
            Candidates { static_ordinals: &[2] }).unwrap().is_none());
    }
    #[test]
    fn static_ordinals_are_not_candidate_indices_and_target_zero_is_exact() {
        let mut b = sample();
        b[40..48].copy_from_slice(&0u64.to_le_bytes());
        b[80..82].copy_from_slice(&1024u16.to_le_bytes());
        b[88..90].copy_from_slice(&32768u16.to_le_bytes());
        let profile = Profile::parse(&b).unwrap();
        let outcome = profile.match_candidates(
            1, 0, [Some(7); 7],
            Candidates { static_ordinals: &[1024, 32768] }
        ).unwrap().unwrap();
        assert_eq!(outcome.allowed_mask, 0b11);
        assert_eq!(outcome.fallback_index, 1);
        assert!(profile.match_candidates(
            1, 1, [Some(7); 7],
            Candidates { static_ordinals: &[1024, 32768] }
        ).unwrap().is_none());
        assert!(profile.match_candidates(
            1, 0, [Some(7); 7],
            Candidates { static_ordinals: &[1024, 1024] }
        ).is_err());
        b[88..90].copy_from_slice(&1024u16.to_le_bytes());
        assert!(Profile::parse(&b).is_err());
        b[88..90].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(Profile::parse(&b).is_err());
    }

    #[test]
    fn trial_rule_never_grants_an_ordinary_candidate_without_a_permit() {
        let mut b = sample();
        b[48..50].copy_from_slice(&2u16.to_le_bytes());
        let p = Profile::parse(&b).unwrap();
        assert!(p.match_candidates(
            1, 22, [Some(7); 7],
            Candidates { static_ordinals: &[1, 3] }
        ).unwrap().is_none());
    }
    #[test]
    fn reject_old_version_wrong_length_unsafe_mode_and_reserved_bytes() {
        let b = sample();
        for (at, val) in [(4, 1), (20, 0), (38, 2), (36, 12), (63, 1), (82, 0), (90, 1)] {
            let mut changed = b.clone();
            changed[at] = val;
            assert!(Profile::parse(&changed).is_err(), "offset {at}");
        }
        assert!(Profile::parse(&b[..95]).is_err());
        let mut bad = b;
        bad[36..38].copy_from_slice(&6u16.to_le_bytes());
        assert!(Profile::parse(&bad).is_err()); // D06 cannot be model-selected
    }
}
