use cyxia_kernel_core::control_plane::service_image::{BASE, Image, LIMIT};
fn elf() -> Vec<u8> {
    let mut b = vec![0; 16384];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&183u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..32].copy_from_slice(&BASE.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&3u16.to_le_bytes());
    for (i, flags) in [5u32, 4, 6].into_iter().enumerate() {
        let p = 64 + i * 56;
        b[p..p + 4].copy_from_slice(&1u32.to_le_bytes());
        b[p + 4..p + 8].copy_from_slice(&flags.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&((i as u64 + 1) * 4096).to_le_bytes());
        b[p + 16..p + 24].copy_from_slice(&(BASE + i as u64 * 4096).to_le_bytes());
        b[p + 32..p + 40].copy_from_slice(&16u64.to_le_bytes());
        b[p + 40..p + 48].copy_from_slice(&(if i == 2 { 8192u64 } else { 4096 }).to_le_bytes());
        b[p + 48..p + 56].copy_from_slice(&4096u64.to_le_bytes());
    }
    b
}
#[test]
fn isolated_service_accepts_rx_ro_rw_and_zero_bss() {
    let b = elf();
    let i = Image::parse(&b).unwrap();
    assert_eq!(i.entry, 0x01000000);
    assert_eq!(i.count, 3);
    assert!(i.segments[0].executable);
    assert!(!i.segments[0].writable);
    assert!(i.segments[2].writable);
    assert_eq!(i.segments[2].memory_size, 8192);
}
#[test]
fn rejects_wx_overlap_outside_private_window_and_noncode_entry() {
    let mut b = elf();
    b[68..72].copy_from_slice(&7u32.to_le_bytes());
    assert!(Image::parse(&b).is_err());
    let mut b = elf();
    b[136..144].copy_from_slice(&BASE.to_le_bytes());
    assert!(Image::parse(&b).is_err());
    let mut b = elf();
    b[192..200].copy_from_slice(&(LIMIT - 4096).to_le_bytes());
    assert!(Image::parse(&b).is_err());
    let mut b = elf();
    b[24..32].copy_from_slice(&(BASE + 8192).to_le_bytes());
    assert!(Image::parse(&b).is_err());
}
#[test]
fn rejects_dynamic_interpreter_truncation_overflow_and_bad_alignment() {
    let mut b = elf();
    b[64..68].copy_from_slice(&3u32.to_le_bytes());
    assert!(Image::parse(&b).is_err());
    assert!(Image::parse(&elf()[..100]).is_err());
    let mut b = elf();
    b[208..216].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(Image::parse(&b).is_err());
    let mut b = elf();
    b[112..120].copy_from_slice(&65536u64.to_le_bytes());
    assert!(Image::parse(&b).is_err());
}

#[test]
fn same_boot_reset_restores_only_writable_segments_and_zeroes_their_bss() {
    let mut b = elf();
    for (index, value) in (0u8..16).enumerate() {
        b[12288 + index] = value.wrapping_mul(7).wrapping_add(3);
    }
    let image = Image::parse(&b).unwrap();
    let mut private = vec![0xa5; (LIMIT - BASE) as usize];
    image.reset_writable(&mut private).unwrap();

    assert_eq!(&private[..8192], &[0xa5; 8192]);
    assert_eq!(&private[8192..8208], &b[12288..12304]);
    assert!(private[8208..16384].iter().all(|byte| *byte == 0));
    assert_eq!(private[16384], 0xa5);
}

#[test]
fn same_boot_reset_rejects_a_backing_window_that_cannot_hold_the_image() {
    let b = elf();
    let image = Image::parse(&b).unwrap();
    let mut short = vec![0; 12287];
    assert!(image.reset_writable(&mut short).is_err());
}

#[test]
fn same_boot_reset_clears_the_mapped_tail_past_memsz() {
    let mut b = elf();
    let rw = 64 + 2 * 56;
    b[rw + 40..rw + 48].copy_from_slice(&5000u64.to_le_bytes());
    let image = Image::parse(&b).unwrap();
    let mut private = vec![0xa5; (LIMIT - BASE) as usize];
    image.reset_writable(&mut private).unwrap();

    assert!(private[8208..16384].iter().all(|byte| *byte == 0));
}

#[test]
fn restart_can_reset_one_writable_page_per_paid_turn() {
    let b = elf();
    let image = Image::parse(&b).unwrap();
    let mut private = vec![0xa5; (LIMIT - BASE) as usize];
    assert_eq!(image.writable_pages(), 2);

    image.reset_writable_page(&mut private, 0).unwrap();
    assert_eq!(&private[8192..8208], &b[12288..12304]);
    assert!(private[8208..12288].iter().all(|byte| *byte == 0));
    assert!(private[12288..16384].iter().all(|byte| *byte == 0xa5));

    image.reset_writable_page(&mut private, 1).unwrap();
    assert!(private[12288..16384].iter().all(|byte| *byte == 0));
    assert!(image.reset_writable_page(&mut private, 2).is_err());
}
