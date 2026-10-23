extern crate std;
use super::*;
use std::{vec, vec::Vec};

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
#[allow(clippy::too_many_arguments)] // Mirrors the independent ELF program-header fields.
fn header(
    bytes: &mut [u8],
    n: usize,
    kind: u32,
    flags: u32,
    off: u64,
    va: u64,
    file: u64,
    mem: u64,
) {
    let p = 64 + n * 56;
    put32(bytes, p, kind);
    put32(bytes, p + 4, flags);
    put64(bytes, p + 8, off);
    put64(bytes, p + 16, va);
    put64(bytes, p + 32, file);
    put64(bytes, p + 40, mem);
    put64(bytes, p + 48, PAGE_SIZE);
}
fn image() -> Vec<u8> {
    let mut bytes = vec![0; 8192];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut bytes, 16, 2);
    put16(&mut bytes, 18, 183);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, IMAGE_BASE + 1024);
    put64(&mut bytes, 32, 64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    put16(&mut bytes, 56, 2);
    header(&mut bytes, 0, 1, 5, 0, IMAGE_BASE, 2048, 2048);
    header(&mut bytes, 1, 1, 6, 4096, IMAGE_BASE + 4096, 32, 8192);
    bytes
}
fn config() -> StackConfig {
    StackConfig {
        phdr: IMAGE_BASE + 64,
        phnum: 2,
        entry: IMAGE_BASE + 1024,
        uid: 12,
        euid: 13,
        gid: 14,
        egid: 15,
        secure: true,
        random: [0xa5; 16],
    }
}

#[test]
fn load_plan_maps_text_data_and_zero_fill_without_copying() {
    let bytes = image();
    let plan = parse(&bytes).unwrap();
    assert_eq!(plan.entry, IMAGE_BASE + 1024);
    assert_eq!(plan.phdr_address, IMAGE_BASE + 64);
    assert_eq!(plan.phnum, 2);
    let loads = plan.loads().collect::<Vec<_>>();
    assert_eq!(loads.len(), 2);
    assert_eq!(loads[1].data.len(), 32);
    assert_eq!(loads[1].memory_size, 8192);
    let pages = plan.pages().collect::<Vec<_>>();
    assert_eq!(pages.len(), 3);
    assert!(pages[0].permissions.execute && !pages[0].permissions.write);
    assert!(pages[2].permissions.write && !pages[2].permissions.execute);
}

#[test]
fn unwind_header_is_metadata_but_must_describe_real_file_bytes() {
    let mut bytes = image();
    put16(&mut bytes, 56, 3);
    header(
        &mut bytes,
        2,
        0x6474_e550,
        4,
        1024,
        IMAGE_BASE + 1024,
        16,
        16,
    );
    put64(&mut bytes, 64 + 2 * 56 + 48, 4);
    assert!(parse(&bytes).is_ok());
    put64(&mut bytes, 64 + 2 * 56 + 8, 1028);
    assert!(parse(&bytes).is_err());
}

#[test]
fn zero_file_tls_may_use_unmapped_tbss_padding() {
    let mut bytes = image();
    put16(&mut bytes, 56, 3);
    header(&mut bytes, 2, 7, 4, 2048, IMAGE_BASE + 2048, 0, 384);
    put64(&mut bytes, 64 + 2 * 56 + 48, 8);
    let plan = parse(&bytes).unwrap();
    assert_eq!(plan.tls().unwrap().memory_size, 384);
    assert!(plan.tls().unwrap().data.is_empty());
    put64(&mut bytes, 64 + 2 * 56 + 16, IMAGE_END);
    assert!(parse(&bytes).is_err());
}

#[test]
fn truncated_and_overflowing_tables_are_rejected() {
    let bytes = image();
    for end in 0..176 {
        assert!(parse(&bytes[..end]).is_err());
    }
    for offset in [u64::MAX, u64::MAX - 55] {
        let mut bad = image();
        put64(&mut bad, 32, offset);
        assert!(parse(&bad).is_err());
    }
    let mut bad = image();
    put16(&mut bad, 56, 65);
    assert!(parse(&bad).is_err());
}

#[test]
fn load_overflow_file_truncation_and_alignment_are_rejected() {
    for (offset, va, file, mem) in [
        (4096, u64::MAX - 4095, 16, 8192),
        (u64::MAX - 4095, IMAGE_BASE + 4096, 32, 4096),
        (4096, IMAGE_END - 4096, 16, 8192),
        (4096, IMAGE_BASE + 4096, 5000, 8192),
        (4096, IMAGE_BASE + 4096, 32, 16),
        (4097, IMAGE_BASE + 4096, 16, 4096),
    ] {
        let mut bad = image();
        header(&mut bad, 1, 1, 6, offset, va, file, mem);
        assert!(parse(&bad).is_err());
    }
}

#[test]
fn wx_and_shared_pages_are_rejected_even_for_disjoint_byte_ranges() {
    let mut bad = image();
    put32(&mut bad, 64 + 4, 7);
    assert!(matches!(parse(&bad), Err(Error::Permissions)));
    header(&mut bad, 0, 1, 5, 0, IMAGE_BASE, 2048, 2048);
    header(&mut bad, 1, 1, 4, 3072, IMAGE_BASE + 3072, 16, 16);
    assert!(matches!(parse(&bad), Err(Error::Overlap)));
}

#[test]
fn entry_must_be_aligned_and_four_file_backed_executable_bytes() {
    for entry in [
        IMAGE_BASE + 1025,
        IMAGE_BASE + 2048,
        IMAGE_BASE + 4096,
        IMAGE_BASE - 4,
    ] {
        let mut bad = image();
        put64(&mut bad, 24, entry);
        assert!(matches!(parse(&bad), Err(Error::Entry)));
    }
    let mut bad = image();
    put64(&mut bad, 64 + 32, 1026);
    assert!(matches!(parse(&bad), Err(Error::Entry)));
}

#[test]
fn interpreter_dynamic_unknown_and_executable_stack_are_rejected() {
    for (kind, flags) in [
        (3, 4),
        (2, 6),
        (0x7000_0000, 4),
        (0x6474_e553, 4),
        (0x6474_e551, 7),
    ] {
        let mut bad = image();
        put16(&mut bad, 56, 3);
        header(&mut bad, 2, kind, flags, 0, 0, 0, 0);
        assert!(parse(&bad).is_err());
    }
}

#[test]
fn phdr_nx_stack_relro_and_tls_template_are_preserved() {
    let mut bytes = image();
    put16(&mut bytes, 56, 6);
    header(&mut bytes, 2, 6, 4, 64, IMAGE_BASE + 64, 6 * 56, 6 * 56);
    put64(&mut bytes, 64 + 2 * 56 + 48, 8);
    header(&mut bytes, 3, 0x6474_e551, 6, 0, 0, 0, 32768);
    header(
        &mut bytes,
        4,
        0x6474_e552,
        4,
        4096,
        IMAGE_BASE + 4096,
        16,
        16,
    );
    header(&mut bytes, 5, 7, 4, 4096, IMAGE_BASE + 4096, 16, 48);
    put64(&mut bytes, 64 + 5 * 56 + 48, 16);
    let plan = parse(&bytes).unwrap();
    assert_eq!(plan.stack_size_hint, 32768);
    assert_eq!(plan.relro.unwrap().address, IMAGE_BASE + 4096);
    let tls = plan.tls().unwrap();
    assert_eq!(tls.alignment, 16);
    assert_eq!(tls.memory_size, 48);
    assert_eq!(tls.data, &bytes[4096..4112]);
}

#[test]
fn forged_phdr_and_tls_outside_load_are_rejected() {
    let mut bad = image();
    put16(&mut bad, 56, 3);
    header(&mut bad, 2, 6, 4, 64, IMAGE_BASE + 128, 168, 168);
    put64(&mut bad, 64 + 2 * 56 + 48, 8);
    assert!(parse(&bad).is_err());
    header(&mut bad, 2, 7, 4, 4096, IMAGE_BASE + 16384, 16, 16);
    assert!(matches!(parse(&bad), Err(Error::Tls)));
}

#[test]
fn sixteen_loads_fit_but_seventeenth_exceeds_fixed_metadata() {
    for count in [16usize, 17] {
        let mut bytes = image();
        bytes.resize(count * 4096, 0);
        put16(&mut bytes, 56, count as u16);
        for i in 0..count {
            header(
                &mut bytes,
                i,
                1,
                if i == 0 { 5 } else { 6 },
                (i * 4096) as u64,
                IMAGE_BASE + (i * 4096) as u64,
                if i == 0 { 2048 } else { 16 },
                4096,
            );
        }
        if count == 16 {
            assert_eq!(parse(&bytes).unwrap().loads().count(), 16);
        } else {
            assert!(matches!(parse(&bytes), Err(Error::Limit)));
        }
    }
}

#[test]
fn truthful_phdr_requires_header_bytes_inside_a_load() {
    let mut bad = image();
    header(&mut bad, 0, 1, 5, 4096, IMAGE_BASE, 2048, 2048);
    assert!(matches!(parse(&bad), Err(Error::Headers)));
    let mut bad = image();
    put64(&mut bad, 64 + 32, 80);
    put64(&mut bad, 24, IMAGE_BASE + 72);
    assert!(matches!(parse(&bad), Err(Error::Headers)));
}

#[test]
fn note_bounds_are_checked_and_gnu_feature_requirements_are_not_ignored() {
    let mut bytes = image();
    put16(&mut bytes, 56, 3);
    header(&mut bytes, 2, 4, 4, 5000, 0, 20, 20);
    put32(&mut bytes, 5000, 4);
    put32(&mut bytes, 5004, 4);
    put32(&mut bytes, 5008, 3);
    bytes[5012..5016].copy_from_slice(b"GNU\0");
    assert!(parse(&bytes).is_ok());
    put32(&mut bytes, 5008, 5);
    assert!(matches!(parse(&bytes), Err(Error::Unsupported)));
    put32(&mut bytes, 5008, 3);
    put32(&mut bytes, 5004, u32::MAX);
    assert!(matches!(parse(&bytes), Err(Error::Bounds)));
}

#[test]
fn duplicate_or_forged_tls_templates_are_rejected() {
    let mut bad = image();
    put16(&mut bad, 56, 4);
    for i in 2..4 {
        header(&mut bad, i, 7, 4, 4096, IMAGE_BASE + 4096, 16, 48);
    }
    assert!(matches!(parse(&bad), Err(Error::Tls)));
    put16(&mut bad, 56, 3);
    put64(&mut bad, 64 + 2 * 56 + 8, 4112);
    put64(&mut bad, 64 + 2 * 56 + 48, 16);
    assert!(matches!(parse(&bad), Err(Error::Tls)));
}

#[test]
fn build_stack_has_real_pointers_auxv_entropy_and_alignment() {
    let mut memory = [0x55; 32768];
    let base = 0x0300_0000;
    let result = build_stack(
        &mut memory,
        base,
        &[b"/bin/app", b"two words"],
        &[b"A=B"],
        &config(),
    )
    .unwrap();
    let read = |address: u64| -> u64 {
        let i = (address - base) as usize;
        u64::from_le_bytes(memory[i..i + 8].try_into().unwrap())
    };
    assert_eq!(result.sp % 16, 0);
    assert_eq!(read(result.sp), 2);
    assert_eq!(read(result.argv), result.execfn);
    assert_eq!(read(result.argv + 16), 0);
    assert_eq!(read(result.envp + 8), 0);
    let exec = (result.execfn - base) as usize;
    assert_eq!(&memory[exec..exec + 9], b"/bin/app\0");
    let argument = (read(result.argv + 8) - base) as usize;
    assert_eq!(&memory[argument..argument + 10], b"two words\0");
    let environment = (read(result.envp) - base) as usize;
    assert_eq!(&memory[environment..environment + 4], b"A=B\0");
    assert!(
        memory[..(result.sp - base) as usize]
            .iter()
            .all(|byte| *byte == 0x55)
    );
    let random = (result.random - base) as usize;
    assert_eq!(&memory[random..random + 16], &[0xa5; 16]);
    let mut aux = Vec::new();
    let mut address = result.auxiliary;
    loop {
        let tag = read(address);
        let value = read(address + 8);
        aux.push((tag, value));
        address += 16;
        if tag == 0 {
            break;
        }
    }
    for expected in [
        (3, IMAGE_BASE + 64),
        (4, 56),
        (5, 2),
        (6, 4096),
        (9, IMAGE_BASE + 1024),
        (11, 12),
        (12, 13),
        (13, 14),
        (14, 15),
        (23, 1),
        (25, result.random),
        (31, result.execfn),
        (0, 0),
    ] {
        assert!(aux.contains(&expected));
    }
}

#[test]
fn stack_validation_is_failure_atomic_for_budget_nul_bounds_and_empty_argv() {
    let long = [b'a'; MAX_STRING_BYTES];
    for argv in [
        &[][..],
        &[b"".as_slice()][..],
        &[b"bad\0arg".as_slice()][..],
        &[long.as_slice()][..],
    ] {
        let mut memory = [0x5a; 1024];
        assert!(build_stack(&mut memory, 0x0300_0000, argv, &[], &config()).is_err());
        assert_eq!(memory, [0x5a; 1024]);
    }
    for (base, size) in [(u64::MAX - 15, 64), (0x0300_0001, 1024), (0x0300_0000, 32)] {
        let mut memory = vec![0x5a; size];
        assert!(build_stack(&mut memory, base, &[b"app"], &[], &config()).is_err());
        assert!(memory.iter().all(|b| *b == 0x5a));
    }
}

#[test]
fn stack_argument_environment_and_string_limits_are_exact() {
    let mut memory = [0x55; 32768];
    let base = 0x0300_0000;
    let many = [b"x".as_slice(); MAX_ARGUMENTS + 1];
    assert!(build_stack(&mut memory, base, &many, &[], &config()).is_err());
    assert_eq!(memory, [0x55; 32768]);
    let environment = [b"X=Y".as_slice(); MAX_ENVIRONMENT + 1];
    assert!(build_stack(&mut memory, base, &[b"app"], &environment, &config()).is_err());
    assert_eq!(memory, [0x55; 32768]);
    let exact = [b'x'; MAX_STRING_BYTES - 1];
    let result = build_stack(&mut memory, base, &[&exact], &[], &config()).unwrap();
    assert_eq!(result.argc, 1);
    assert_eq!(memory.last(), Some(&0));
    assert_eq!(result.sp % 16, 0);
}

#[test]
fn hostile_header_field_mutations_return_errors_without_panics() {
    let original = image();
    for at in (16..176).step_by(8) {
        for value in [0u64, 1, u64::MAX, u64::MAX - 4095, 0x8000_0000_0000_0000] {
            let mut bytes = original.clone();
            put64(&mut bytes, at, value);
            assert!(std::panic::catch_unwind(|| parse(&bytes)).is_ok());
        }
    }
}

#[test]
fn executable_identity_is_separate_from_caller_chosen_argv_zero() {
    let mut memory = [0x55; 4096];
    let base = 0x0300_0000;
    let stack = build_stack_with_execfn(
        &mut memory,
        base,
        &[b"\xffdisplay", b"arg"],
        &[b"A=B"],
        &config(),
        b"/bin/actual",
    )
    .unwrap();
    let at = (stack.argv - base) as usize;
    let argv0 = u64::from_le_bytes(memory[at..at + 8].try_into().unwrap()) - base;
    assert_eq!(
        &memory[argv0 as usize..argv0 as usize + 9],
        b"\xffdisplay\0"
    );
    let execfn = (stack.execfn - base) as usize;
    assert_eq!(&memory[execfn..execfn + 12], b"/bin/actual\0");
    assert_ne!(stack.execfn, base + argv0);
    let before = memory;
    assert!(
        build_stack_with_execfn(&mut memory, base, &[b"name"], &[], &config(), b"bad\0path")
            .is_err()
    );
    assert_eq!(memory, before);
}
