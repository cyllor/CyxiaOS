//! Deterministic replay effects that are deliberately outside the AI action
//! space. In particular D16's baseline stops issuing new QUOTEs; it does not
//! turn a positive OfferCpu tier into a fabricated zero-capacity model choice.
use super::Error;
use crate::{domains::Action, policy_wire};

pub fn validate(action: Action) -> Result<(), Error> {
    if action == Action::OfferCpu(0) { Ok(()) }
    else { action.validate().map_err(|_| Error::Evidence) }
}
pub fn encode(action: Action, out: &mut [u8]) -> Result<usize, Error> {
    validate(action)?;
    if action == Action::OfferCpu(0) {
        out.get_mut(..4).ok_or(Error::Capacity)?.fill(0); Ok(4)
    } else { policy_wire::encode_payload(action, 0, out).map_err(|_| Error::Evidence) }
}
pub fn decode(domain: u16, kind: u16, bytes: &[u8]) -> Result<Action, Error> {
    if (domain, kind) == (16, 1) && bytes == [0; 4] { return Ok(Action::OfferCpu(0)); }
    let (action, index) = policy_wire::decode_payload(domain, kind, bytes).map_err(|_| Error::Evidence)?;
    if index != 0 { return Err(Error::Evidence); }
    Ok(action)
}
