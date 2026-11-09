//! One existing prepaid turn: visit normal work before optional read-only work.
use cyxia_prototype::domains::Error;

#[inline(always)]
pub(crate) fn normal_then_optional<S, I>(
    state: &mut S,
    input: &mut I,
    ordinary: bool,
    facts: impl Fn(&S) -> (bool, bool),
    normal: impl FnOnce(&mut S, &mut I) -> Result<bool, Error>,
    optional: impl FnOnce(&mut S, &mut I) -> Result<bool, Error>,
) -> Result<bool, Error> {
    if ordinary && facts(state).0 {
        return Ok(false);
    }
    match normal(state, input) {
        Ok(false) => (),
        result => return result,
    }
    let (job, preparation) = facts(state);
    if ordinary && (job || preparation) {
        return Ok(false);
    }
    // A completed EMPTY/inapplicable mandatory visit used no model invocation.
    // Other families retain their own rotation and due times. This existing
    // prepaid turn may spend its remaining unchanged envelope on one read-only
    // job; the caller retains its original CPU/wall start and real credit.
    optional(state, input)
}
