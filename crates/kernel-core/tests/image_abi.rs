use cyxia_kernel_core::control_plane::{image, image_abi::ImageAbi, service_image};

fn elf(machine: u16, base: u64, entry: u64) -> Vec<u8> {
    let mut bytes = vec![0; 8192];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (at, value) in [(16, 2u16), (18, machine), (52, 64), (54, 56), (56, 1)] {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&entry.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
    for (at, value) in [(72, 4096u64), (80, base), (96, 16), (104, 16), (112, 4096)] {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[test]
fn x86_control_accepts_byte_aligned_code_but_rejects_cross_isa() {
    let bytes = elf(62, image::BASE, image::BASE + 1);
    assert_eq!(
        image::Image::parse_for(&bytes, ImageAbi::X86_64)
            .unwrap()
            .entry,
        0x80001
    );
    assert!(image::Image::parse_for(&bytes, ImageAbi::Aarch64).is_err());
    assert!(image::Image::parse(&bytes).is_err());
    let arm = elf(183, image::BASE, image::BASE);
    assert!(image::Image::parse_for(&arm, ImageAbi::X86_64).is_err());
    assert!(image::Image::parse(&arm).is_ok());
}

#[test]
fn x86_service_accepts_byte_aligned_code_but_rejects_cross_isa() {
    let bytes = elf(62, service_image::BASE, service_image::BASE + 1);
    assert_eq!(
        service_image::Image::parse_for(&bytes, ImageAbi::X86_64)
            .unwrap()
            .entry,
        0x01000001
    );
    assert!(service_image::Image::parse_for(&bytes, ImageAbi::Aarch64).is_err());
    assert!(service_image::Image::parse(&bytes).is_err());
    let arm = elf(183, service_image::BASE, service_image::BASE);
    assert!(service_image::Image::parse_for(&arm, ImageAbi::X86_64).is_err());
    assert!(service_image::Image::parse(&arm).is_ok());
}

#[test]
fn arm_entry_alignment_stays_strict_for_both_loaders() {
    assert!(
        image::Image::parse_for(&elf(183, image::BASE, image::BASE + 1), ImageAbi::Aarch64)
            .is_err()
    );
    assert!(
        service_image::Image::parse_for(
            &elf(183, service_image::BASE, service_image::BASE + 1),
            ImageAbi::Aarch64
        )
        .is_err()
    );
}

#[test]
fn x86_still_rejects_wx_dynamic_overlap_and_unbacked_entry() {
    for base in [image::BASE, service_image::BASE] {
        let rejects = |bytes: &[u8]| {
            if base == image::BASE {
                image::Image::parse_for(bytes, ImageAbi::X86_64).is_err()
            } else {
                service_image::Image::parse_for(bytes, ImageAbi::X86_64).is_err()
            }
        };
        for (at, value) in [(68, 7u32), (64, 3)] {
            let mut bytes = elf(62, base, base + 1);
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert!(rejects(&bytes));
        }
        let mut bytes = elf(62, base, base + 1);
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
        let header: Vec<_> = bytes[64..120].to_vec();
        bytes[120..176].copy_from_slice(&header);
        assert!(rejects(&bytes));
        assert!(rejects(&elf(62, base, base + 16)));
        assert!(rejects(&elf(0, base, base)));
    }
}

#[test]
fn x86_retains_loader_windows_size_caps_and_segment_alignment() {
    for (base, limit, cap, control) in [
        (image::BASE, image::BASE + 32 * 4096, 512 * 1024, true),
        (
            service_image::BASE,
            service_image::LIMIT,
            8 * 1024 * 1024,
            false,
        ),
    ] {
        let rejects = |bytes: &[u8]| {
            if control {
                image::Image::parse_for(bytes, ImageAbi::X86_64).is_err()
            } else {
                service_image::Image::parse_for(bytes, ImageAbi::X86_64).is_err()
            }
        };
        assert!(rejects(&elf(62, limit, limit)));
        let mut bytes = elf(62, base, base + 1);
        bytes[112..120].copy_from_slice(&1u64.to_le_bytes());
        assert!(rejects(&bytes));
        let mut bytes = elf(62, base, base + 1);
        bytes[104..112].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(rejects(&bytes));
        let mut bytes = elf(62, base, base + 1);
        bytes.resize(cap + 1, 0);
        assert!(rejects(&bytes));
    }
}
