use super::{PAGE_COUNT, UNMAPPED};

const LEAF_PAGES: usize = 64;
const BLOCKS: usize = PAGE_COUNT / LEAF_PAGES;
const LEAVES: usize = BLOCKS.next_power_of_two();
const _: () = assert!(PAGE_COUNT.is_multiple_of(LEAF_PAGES));

#[derive(Clone, Copy)]
struct Span {
    pages: u16,
    prefix: u16,
    suffix: u16,
    longest: u16,
}

impl Span {
    const fn free(pages: u16) -> Self {
        Self {
            pages,
            prefix: pages,
            suffix: pages,
            longest: pages,
        }
    }

    fn from_slots(block: &[u16]) -> Self {
        let prefix = block.iter().take_while(|&&slot| slot == UNMAPPED).count() as u16;
        let mut suffix = prefix;
        let mut longest = prefix;
        for &slot in &block[usize::from(prefix)..] {
            suffix = if slot == UNMAPPED { suffix + 1 } else { 0 };
            longest = longest.max(suffix);
        }
        Self {
            pages: block.len() as u16,
            prefix,
            suffix,
            longest,
        }
    }

    fn join(left: Self, right: Self) -> Self {
        let prefix = if left.prefix == left.pages {
            left.pages + right.prefix
        } else {
            left.prefix
        };
        let suffix = if right.suffix == right.pages {
            right.pages + left.suffix
        } else {
            right.suffix
        };
        Self {
            pages: left.pages + right.pages,
            prefix,
            suffix,
            longest: left
                .longest
                .max(right.longest)
                .max(left.suffix + right.prefix),
        }
    }
}

/// Summaries of the authoritative virtual slots. Only blocks touched by a
/// committed allocation or unmap and their ancestors need to be recomputed.
pub(super) struct FreeRanges {
    spans: [Span; 2 * LEAVES],
}

impl FreeRanges {
    pub(super) const fn new() -> Self {
        let mut spans = [Span::free(0); 2 * LEAVES];
        let mut node = LEAVES;
        while node < LEAVES + BLOCKS {
            spans[node] = Span::free(LEAF_PAGES as u16);
            node += 1;
        }
        node = LEAVES - 1;
        while node != 0 {
            spans[node] = Span::free(spans[2 * node].pages + spans[2 * node + 1].pages);
            node -= 1;
        }
        Self { spans }
    }

    pub(super) fn longest(&self) -> usize {
        usize::from(self.spans[1].longest)
    }

    pub(super) fn first_fit(&self, slots: &[u16; PAGE_COUNT], pages: usize) -> Option<usize> {
        if pages > self.longest() {
            return None;
        }
        let mut node = 1;
        let mut start = 0;
        while node < LEAVES {
            let left = self.spans[2 * node];
            let right = self.spans[2 * node + 1];
            // A run wholly in the left child precedes either other candidate.
            // Otherwise, a run crossing the boundary precedes the right child.
            if pages <= usize::from(left.longest) {
                node *= 2;
            } else if pages <= usize::from(left.suffix + right.prefix) {
                return Some(start + usize::from(left.pages - left.suffix));
            } else {
                node = 2 * node + 1;
                start += usize::from(left.pages);
            }
        }
        let mut run = 0;
        for (offset, &slot) in slots[start..start + LEAF_PAGES].iter().enumerate() {
            run = if slot == UNMAPPED { run + 1 } else { 0 };
            if run == pages {
                return Some(start + offset + 1 - pages);
            }
        }
        None
    }

    pub(super) fn refresh(&mut self, slots: &[u16; PAGE_COUNT], start: usize, pages: usize) {
        let mut first = LEAVES + start / LEAF_PAGES;
        let mut last = LEAVES + (start + pages - 1) / LEAF_PAGES;
        for node in first..=last {
            let at = (node - LEAVES) * LEAF_PAGES;
            self.spans[node] = Span::from_slots(&slots[at..at + LEAF_PAGES]);
        }
        while first > 1 {
            first /= 2;
            last /= 2;
            for node in first..=last {
                self.spans[node] = Span::join(self.spans[2 * node], self.spans[2 * node + 1]);
            }
        }
    }
}
