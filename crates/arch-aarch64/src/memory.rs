//! Bounded access to exclusively owned private RAM; no mapping authority.

/// Clear and independently read back a retired private RAM page in bounded
/// pieces. The native owner must stop the old context, revoke its mappings
/// and complete TLBI before calling; this does not establish DMA quiescence.
/// No unfinished page may be published while `checkpoint` yields the owner.
///
/// Each checkpoint follows at most 256 bytes of stores AND readback. Aligned
/// volatile words avoid thousands of byte-load loop iterations per page and
/// prevent the compiler from replacing the check with knowledge of the stores.
/// Every byte, including an unaligned prefix/tail, is still checked. Native
/// accounting charges all work under the original reservation. A failed
/// readback returns false; the caller must keep the page unpublished.
pub fn scrub_retired_page(page: &mut [u8; 4096], mut checkpoint: impl FnMut()) -> bool {
    for piece in page.chunks_exact_mut(256) {
        // SAFETY: u8 and u64 admit every bit pattern. align_to_mut returns
        // disjoint, correctly aligned spans within this exclusive RAM slice.
        let (prefix, words, tail) = unsafe { piece.align_to_mut::<u64>() };
        for byte in prefix.iter_mut().chain(tail.iter_mut()) {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        for word in words.iter_mut() {
            unsafe { core::ptr::write_volatile(word, 0) };
        }
        if prefix
            .iter()
            .chain(tail.iter())
            .any(|byte| unsafe { core::ptr::read_volatile(byte) != 0 })
            || words
                .iter()
                .any(|word| unsafe { core::ptr::read_volatile(word) != 0 })
        {
            return false;
        }
        checkpoint();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_scrub_covers_unaligned_page_and_preserves_adjacent_bytes() {
        for start in 0..8 {
            let mut backing = [0xa5; 4096 + 16];
            let mut checkpoints = 0;
            let page = (&mut backing[start..start + 4096]).try_into().unwrap();
            assert!(scrub_retired_page(page, || checkpoints += 1));
            assert!(backing[..start].iter().all(|&b| b == 0xa5));
            assert!(backing[start..start + 4096].iter().all(|&b| b == 0));
            assert!(backing[start + 4096..].iter().all(|&b| b == 0xa5));
            // A 4 KiB page cannot hide more than 256 bytes of clear/readback
            // between native accounting opportunities.
            assert_eq!(checkpoints, 16);
        }
    }
}
