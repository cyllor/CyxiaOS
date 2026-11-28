//! Scalar SHA-256 for the freestanding role probes.
//! No allocator, hardware privilege or external crypto service.
#[allow(dead_code)]
pub(super) fn record_digest(record: &[u8; 128]) -> [u8; 32] {
    let mut preimage = [0; 108];
    preimage[..12].copy_from_slice(b"CYX/AUDIT/v2");
    preimage[12..].copy_from_slice(&record[..96]);
    sha256(&preimage)
}

pub(super) fn sha256(bytes: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let padded_len = (bytes.len() + 9).next_multiple_of(64);
    for offset in (0..padded_len).step_by(64) {
        let mut block = [0; 64];
        let available = bytes.len().saturating_sub(offset).min(64);
        if available != 0 {
            block[..available].copy_from_slice(&bytes[offset..offset + available]);
        }
        if offset <= bytes.len() && available < 64 {
            block[available] = 0x80;
        }
        if offset + 64 == padded_len {
            block[56..].copy_from_slice(&((bytes.len() as u64) * 8).to_be_bytes());
        }
        let mut w = [0u32; 64];
        for (dst, src) in w.iter_mut().zip(block.chunks_exact(4)) {
            *dst = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
        }
        for i in 16..64 {
            let x = w[i - 15];
            let y = w[i - 2];
            let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
            let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for (&k, w) in K.iter().zip(w) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add((e & f) ^ (!e & g))
                .wrapping_add(k)
                .wrapping_add(w);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let t2 = s0.wrapping_add((a & b) ^ (a & c) ^ (b & c));
            [a, b, c, d, e, f, g, h] = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
        }
        for (dst, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *dst = dst.wrapping_add(v);
        }
    }
    let mut out = [0; 32];
    for (dst, v) in out.chunks_exact_mut(4).zip(state) {
        dst.copy_from_slice(&v.to_be_bytes());
    }
    out
}
