//! Target instruction-set identity shared by kernel and application loaders.
//! Choosing an ABI validates machine code; it never translates that code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageAbi {
    Aarch64,
    X86_64,
}

impl ImageAbi {
    pub const fn machine(self) -> u16 {
        match self {
            Self::Aarch64 => 183,
            Self::X86_64 => 62,
        }
    }
    pub const fn entry_alignment(self) -> u64 {
        match self {
            Self::Aarch64 => 4,
            Self::X86_64 => 1,
        }
    }
}
