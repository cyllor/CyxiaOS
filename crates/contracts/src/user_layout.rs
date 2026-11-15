//! Versioned user-image and anonymous-memory windows. Selecting a layout does
//! not allocate RAM or authorize a grant; the kernel must back every mapped page.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageProfile {
    Legacy,
    FullOsV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageLayout {
    pub image_base: u64,
    pub image_end: u64,
    pub stack_base: u64,
    pub stack_pages: usize,
    pub exec_pool_pages: usize,
    pub heap_base: u64,
    pub heap_pages: usize,
}

impl ImageProfile {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::FullOsV1 => "full-os-v1",
        }
    }

    pub const fn layout(self) -> ImageLayout {
        match self {
            Self::Legacy => ImageLayout {
                image_base: 0x0100_0000,
                image_end: 0x0200_0000,
                stack_base: 0x0300_0000,
                stack_pages: 64,
                exec_pool_pages: 4096,
                heap_base: 0x0400_0000,
                heap_pages: 4096,
            },
            Self::FullOsV1 => ImageLayout {
                image_base: 0x0100_0000,
                image_end: 0x0500_0000,
                stack_base: 0x0a00_0000,
                stack_pages: 512,
                exec_pool_pages: 16384,
                heap_base: 0x0800_0000,
                heap_pages: 4096,
            },
        }
    }
}

impl ImageLayout {
    pub const fn image_pages(self) -> usize {
        ((self.image_end - self.image_base) / 4096) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_os_image_heap_stack_and_existing_shared_window_do_not_alias() {
        let layout = ImageProfile::FullOsV1.layout();
        let regions = [
            (layout.image_base, layout.image_end),
            (layout.stack_base, layout.stack_base + layout.stack_pages as u64 * 4096),
            (layout.heap_base, layout.heap_base + layout.heap_pages as u64 * 4096),
            (0x0600_0000, 0x0700_0000),
        ];
        for (i, &(start, end)) in regions.iter().enumerate() {
            assert!(start < end && start % 0x200000 == 0 && end % 4096 == 0);
            for &(other_start, other_end) in &regions[i + 1..] {
                assert!(end <= other_start || start >= other_end);
            }
        }
        // Actual cosmic-comp LOAD span from the independently parsed target ELF.
        assert!(layout.image_base <= 16_777_216 && layout.image_end >= 51_788_596);
        assert!(8548 + layout.stack_pages < layout.exec_pool_pages);
        assert!(layout.exec_pool_pages < u16::MAX as usize);
        // 128 actual page-table frames must cover even all these leaf tables,
        // plus separate ancestor tables for the low user and high kernel halves.
        let leaf_tables = layout.image_pages() / 512 + layout.heap_pages / 512 + 8 + 1;
        assert!(leaf_tables + 8 < 128);
    }

    #[test]
    fn legacy_profile_retains_historical_image_and_stack_contract() {
        let layout = ImageProfile::Legacy.layout();
        assert_eq!((layout.image_base, layout.image_end), (0x01000000, 0x02000000));
        assert_eq!((layout.stack_base, layout.stack_pages), (0x03000000, 64));
        assert_eq!(layout.exec_pool_pages, 4096);
    }
}
