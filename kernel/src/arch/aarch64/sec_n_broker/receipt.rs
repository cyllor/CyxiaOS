//! Fixed-width guest admission receipt on SVC 0x43. Only CPU0 stages a stream.

pub(super) const WIRE_BYTES: usize = 12;

/// Return the kernel-observed connection identity once for the staged stream.
/// The only guest-controlled values here are the twelve bytes of the receipt.
pub(super) fn validate(
    wire: &[u8; WIRE_BYTES],
    connected: bool,
    epoch: u64,
    polled_epoch: u64,
    source: u32,
    recorded: bool,
) -> Option<(u64, u32)> {
    if recorded || !connected || epoch == 0 || epoch != polled_epoch || source == 0 {
        return None;
    }
    (wire[..8] == epoch.to_le_bytes() && wire[8..] == source.to_le_bytes())
        .then_some((epoch, source))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: u32 = 0x0a00_0202;
    const WIRE: [u8; WIRE_BYTES] = [1, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 10];

    #[test]
    fn grant_matches_the_polled_connection_only_once() {
        let first = validate(&WIRE, true, 1, 1, SOURCE, false);
        assert_eq!(first, Some((1, SOURCE)));
        assert_eq!(validate(&WIRE, true, 1, 1, SOURCE, first.is_some()), None);
    }

    #[test]
    fn stale_unpolled_disconnected_and_wrong_source_receipts_are_rejected() {
        assert_eq!(validate(&WIRE, true, 2, 2, SOURCE, false), None);
        assert_eq!(validate(&WIRE, true, 1, 0, SOURCE, false), None);
        assert_eq!(validate(&WIRE, false, 1, 1, SOURCE, false), None);
        assert_eq!(validate(&WIRE, true, 1, 1, SOURCE + 1, false), None);
        assert_eq!(validate(&[0; WIRE_BYTES], true, 0, 0, 0, false), None);
    }
}
