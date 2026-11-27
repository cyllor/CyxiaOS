//! Frozen SecurityProfile v3 structure from V0.19.9 §安0.8.
//! Generation and the canonical RuleProfile digest are the only variables.
use super::Error;
use crate::security::network::tls_deadline::{
    TLS_ACTIVE_IDLE_SECONDS, TLS_HANDSHAKE_MS, TLS_RECORD_IDLE_MS, TLS_SESSION_SECONDS,
};

pub(super) const BYTES: usize = 256;
const FIXED: [u8; BYTES] = fixed_profile();

const fn field<const N: usize>(wire: &mut [u8; BYTES], offset: usize, value: [u8; N]) {
    let mut at = 0;
    while at < N {
        wire[offset + at] = value[at];
        at += 1;
    }
}

const fn fixed_profile() -> [u8; BYTES] {
    let mut wire = [0; BYTES];
    field(&mut wire, 0, 0x4359_5350u32.to_le_bytes());
    field(&mut wire, 4, 3u16.to_le_bytes());
    field(&mut wire, 6, (BYTES as u16).to_le_bytes());
    field(&mut wire, 48, 0xfu64.to_le_bytes());

    // Groups, threads, capabilities, endpoints and mapping quotas.
    field(&mut wire, 56, [16, 8, 64, 64]);
    field(&mut wire, 60, 256u16.to_le_bytes());
    field(&mut wire, 62, 64u16.to_le_bytes());
    field(&mut wire, 64, [8, 32]);
    field(&mut wire, 66, 128u16.to_le_bytes());
    field(&mut wire, 68, 8192u32.to_le_bytes());

    // File, directory, FSYNC and staging quotas.
    field(&mut wire, 72, [16, 16, 64, 32]);
    field(&mut wire, 76, 2048u16.to_le_bytes());
    field(&mut wire, 78, 4096u16.to_le_bytes());
    field(&mut wire, 80, [32, 16]);
    field(&mut wire, 82, 256u16.to_le_bytes());
    field(&mut wire, 84, [8, 32, 8, 8, 8, 1, 8]);

    // Connection limits, ARP, MTU and TCP deadlines.
    field(&mut wire, 91, [16, 4, 4, 32, 8]);
    field(&mut wire, 96, 1000u16.to_le_bytes());
    field(&mut wire, 98, 60u16.to_le_bytes());
    field(&mut wire, 100, 1500u16.to_le_bytes());
    field(&mut wire, 102, 1526u16.to_le_bytes());
    field(&mut wire, 104, 16384u16.to_le_bytes());
    field(&mut wire, 106, 16384u16.to_le_bytes());
    field(&mut wire, 108, [8, 8, 16]);
    field(&mut wire, 111, 30u16.to_le_bytes());
    field(&mut wire, 113, 200u16.to_le_bytes());
    field(&mut wire, 115, 3000u16.to_le_bytes());
    field(&mut wire, 117, [5]);

    // TLS time and buffer limits, SYN cookies and challenge ACK budgets.
    field(&mut wire, 118, TLS_HANDSHAKE_MS.to_le_bytes());
    field(&mut wire, 120, TLS_RECORD_IDLE_MS.to_le_bytes());
    field(&mut wire, 122, 16645u16.to_le_bytes());
    field(&mut wire, 124, TLS_SESSION_SECONDS.to_le_bytes());
    field(&mut wire, 126, 1000u16.to_le_bytes());
    field(&mut wire, 128, 1000u16.to_le_bytes());
    field(&mut wire, 130, [32, 16]);
    field(&mut wire, 132, 16u16.to_le_bytes());
    field(&mut wire, 134, [4, 30, 5, 3, 24, 1]);
    field(&mut wire, 140, 8u16.to_le_bytes());
    field(&mut wire, 142, 24u16.to_le_bytes());

    // D12 admission, DRBG, timers, IRQ and audit quotas.
    field(&mut wire, 144, [16, 4, 8, 4, 32]);
    field(&mut wire, 149, 4096u16.to_le_bytes());
    field(&mut wire, 151, 65536u32.to_le_bytes());
    field(&mut wire, 155, 600u16.to_le_bytes());
    field(&mut wire, 157, [32, 16]);
    field(&mut wire, 159, 256u16.to_le_bytes());
    field(&mut wire, 161, 1000u16.to_le_bytes());
    field(&mut wire, 163, [3]);
    field(&mut wire, 164, 100u16.to_le_bytes());
    field(&mut wire, 166, 1000u16.to_le_bytes());
    field(&mut wire, 168, 1000u16.to_le_bytes());
    field(&mut wire, 170, [3, 8, 8]);

    // Admission bounds, operation deadlines, stacks, and TLS key usage.
    field(&mut wire, 173, [16, 32, 4, 1, 5]);
    field(&mut wire, 178, 500u16.to_le_bytes());
    field(&mut wire, 180, 1000u16.to_le_bytes());
    field(&mut wire, 182, 250u16.to_le_bytes());
    field(&mut wire, 184, 100u16.to_le_bytes());
    field(&mut wire, 186, 100u16.to_le_bytes());
    field(&mut wire, 188, 5u16.to_le_bytes());
    field(&mut wire, 190, 50u16.to_le_bytes());
    field(&mut wire, 192, [4]);
    field(&mut wire, 193, TLS_ACTIVE_IDLE_SECONDS.to_le_bytes());
    field(&mut wire, 195, [8, 17, 64, 32, 16, 16, 8, 4, 5, 2, 120]);
    field(&mut wire, 206, 1_048_576u32.to_le_bytes());
    field(&mut wire, 210, 17_179_869_184u64.to_le_bytes());
    field(&mut wire, 218, [1]);
    field(&mut wire, 219, 45u16.to_le_bytes());
    wire
}

pub(super) fn generation(wire: &[u8; BYTES], rules_hash: &[u8; 32]) -> Result<u64, Error> {
    let generation = u64::from_le_bytes(wire[8..16].try_into().unwrap());
    if generation == 0 || wire[..8] != FIXED[..8] || wire[48..] != FIXED[48..] {
        return Err(Error::Invalid);
    }
    if &wire[16..48] != rules_hash {
        return Err(Error::Conflict);
    }
    Ok(generation)
}

#[cfg(test)]
pub(super) fn fixture(generation: u64, rules_hash: [u8; 32]) -> [u8; BYTES] {
    let mut wire = FIXED;
    field(&mut wire, 8, generation.to_le_bytes());
    field(&mut wire, 16, rules_hash);
    wire
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_generation_and_canonical_rules_digest_may_vary() {
        let rules = [0x3c; 32];
        let good = fixture(7, rules);
        assert_eq!(generation(&good, &rules), Ok(7));
        assert_eq!(generation(&fixture(0, rules), &rules), Err(Error::Invalid));
        assert_eq!(generation(&good, &[0x4b; 32]), Err(Error::Conflict));
        for offset in (0..8).chain(48..BYTES) {
            let mut changed = good;
            changed[offset] ^= 1;
            assert_eq!(
                generation(&changed, &rules),
                Err(Error::Invalid),
                "{offset}"
            );
        }
    }
}
