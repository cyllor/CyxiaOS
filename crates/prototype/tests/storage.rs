use cyxia_prototype::storage::{
    BLOCK_SIZE, DATA_START, DirectoryEntry, Error, Extent, Inode, InodeKind, LogPayload,
    MAX_FILE_SIZE, Record, Superblock, crc32c, select_superblock,
};

fn superblock(generation: u64, checkpoint_lsn: u64, log_epoch: u64) -> Superblock {
    Superblock {
        fs_uuid: [0x23; 16],
        generation,
        checkpoint_lsn,
        log_epoch,
    }
}

fn encode_superblock(value: Superblock) -> [u8; BLOCK_SIZE] {
    let mut bytes = [0xaa; BLOCK_SIZE];
    value.encode(&mut bytes).unwrap();
    bytes
}

fn checksum_at(bytes: &mut [u8], offset: usize) {
    bytes[offset..offset + 4].fill(0);
    let crc = crc32c(bytes);
    bytes[offset..offset + 4].copy_from_slice(&crc.to_le_bytes());
}

fn file() -> Inode {
    let mut extents = [Extent::EMPTY; 16];
    extents[0] = Extent {
        logical_start: 0,
        physical_start: DATA_START,
        block_count: 2,
    };
    extents[1] = Extent {
        logical_start: 2,
        physical_start: DATA_START + 8,
        block_count: 1,
    };
    Inode {
        kind: InodeKind::File,
        generation: 2,
        size: 8193,
        durable_write_seq: 19,
        parent_inode: 0,
        parent_generation: 1,
        extent_count: 2,
        extents,
    }
}

fn root() -> Inode {
    Inode {
        kind: InodeKind::Directory,
        generation: 1,
        size: 0,
        durable_write_seq: 0,
        parent_inode: 0,
        parent_generation: 1,
        extent_count: 0,
        extents: [Extent::EMPTY; 16],
    }
}

fn header_crc(bytes: &mut [u8]) {
    checksum_at(&mut bytes[..64], 56);
}

#[test]
fn castagnoli_crc_matches_published_golden_and_empty_input() {
    assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    assert_eq!(crc32c(b""), 0);
}

#[test]
fn superblock_has_exact_little_endian_layout_and_zero_tail() {
    let value = superblock(7, 0x0102_0304_0506_0708, 9);
    let bytes = encode_superblock(value);
    assert_eq!(
        &bytes[..16],
        &[0x53, 0x46, 0x59, 0x43, 1, 0, 80, 0, 0, 16, 0, 0, 0, 0, 2, 0]
    );
    assert_eq!(&bytes[16..32], &[0x23; 16]);
    assert_eq!(&bytes[32..40], &7_u64.to_le_bytes());
    assert_eq!(&bytes[40..48], &[8, 7, 6, 5, 4, 3, 2, 1]);
    assert_eq!(&bytes[48..56], &9_u64.to_le_bytes());
    assert_eq!(
        &bytes[56..76],
        &[
            2, 16, 0, 0, 6, 16, 0, 0, 22, 16, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0
        ]
    );
    assert!(bytes[80..].iter().all(|&b| b == 0));
    assert_eq!(Superblock::decode(&bytes).unwrap(), value);
}

#[test]
fn superblock_rejects_mutation_even_with_recomputed_crc() {
    let bytes = encode_superblock(superblock(1, 0, 1));
    for offset in [0, 4, 6, 8, 12, 56, 60, 64, 68, 72, 80, 4095] {
        let mut bad = bytes;
        bad[offset] ^= 1;
        checksum_at(&mut bad, 76);
        assert!(
            Superblock::decode(&bad).is_err(),
            "accepted unsupported byte {offset}"
        );
    }
    let mut bad = bytes;
    bad[40] ^= 1;
    assert_eq!(Superblock::decode(&bad), Err(Error::Checksum));
    for range in [16..32, 32..40, 48..56] {
        let mut bad = bytes;
        bad[range].fill(0);
        checksum_at(&mut bad, 76);
        assert!(Superblock::decode(&bad).is_err());
    }
}

#[test]
fn superblock_selection_rejects_split_identity_and_regressing_tuples() {
    let old = encode_superblock(superblock(3, 20, 7));
    let new = encode_superblock(superblock(4, 20, 8));
    assert_eq!(select_superblock(&old, &new).unwrap(), superblock(4, 20, 8));
    assert_eq!(select_superblock(&new, &old).unwrap(), superblock(4, 20, 8));
    assert_eq!(select_superblock(&new, &new).unwrap(), superblock(4, 20, 8));
    for bad in [
        superblock(4, 21, 8),
        superblock(5, 19, 9),
        superblock(5, 30, 8),
    ] {
        assert_eq!(
            select_superblock(&new, &encode_superblock(bad)),
            Err(Error::Conflict)
        );
    }
    let mut other = superblock(5, 30, 9);
    other.fs_uuid[0] ^= 1;
    assert_eq!(
        select_superblock(&new, &encode_superblock(other)),
        Err(Error::Conflict)
    );
    let mut corrupt = new;
    corrupt[76] ^= 1;
    assert_eq!(
        select_superblock(&old, &corrupt).unwrap(),
        superblock(3, 20, 7)
    );
    assert!(select_superblock(&corrupt, &corrupt).is_err());
}

#[test]
fn inode_roundtrip_has_exact_extents_and_free_slot_encoding() {
    let mut bytes = [0xaa; 256];
    file().encode(1, &mut bytes).unwrap();
    assert_eq!(&bytes[0..8], &[0x4e, 0x49, 0x59, 0x43, 1, 0, 0, 0]);
    assert_eq!(&bytes[24..32], &19_u64.to_le_bytes());
    assert_eq!(&bytes[32..40], &[2, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&bytes[48..60], &[0, 0, 0, 0, 22, 16, 0, 0, 2, 0, 0, 0]);
    assert!(bytes[72..252].iter().all(|&b| b == 0));
    assert_eq!(Inode::decode(1, &bytes).unwrap(), file());
    let free = Inode {
        kind: InodeKind::Free,
        generation: 5,
        ..root()
    };
    let free = Inode {
        parent_generation: 0,
        ..free
    };
    free.encode(9, &mut bytes).unwrap();
    assert!(bytes[16..252].iter().all(|&b| b == 0));
    assert_eq!(Inode::decode(9, &bytes).unwrap(), free);
    root().encode(0, &mut bytes).unwrap();
    assert_eq!(Inode::decode(0, &bytes).unwrap(), root());
}

#[test]
fn inode_rejects_bad_extent_coverage_overlap_bounds_and_unused_fields() {
    let original = file();
    let mut cases = Vec::new();
    let mut x = original;
    x.extents[1].logical_start = 3;
    cases.push(x);
    let mut x = original;
    x.extents[1].physical_start = DATA_START + 1;
    cases.push(x);
    let mut x = original;
    x.extents[0].physical_start = DATA_START - 1;
    cases.push(x);
    let mut x = original;
    x.extents[1].physical_start = 131072;
    cases.push(x);
    let mut x = original;
    x.extents[1].block_count = u32::MAX;
    cases.push(x);
    let mut x = original;
    x.extents[2].block_count = 1;
    cases.push(x);
    let mut x = original;
    x.extent_count = 17;
    cases.push(x);
    let mut x = original;
    x.extent_count = 1;
    cases.push(x);
    let mut x = original;
    x.size = MAX_FILE_SIZE + 1;
    cases.push(x);
    let mut x = original;
    x.generation = 0;
    cases.push(x);
    let mut x = original;
    x.parent_generation = 0;
    cases.push(x);
    let mut x = original;
    x.parent_inode = 256;
    cases.push(x);
    for invalid in cases {
        let mut bytes = [0xaa; 256];
        assert!(
            invalid.encode(1, &mut bytes).is_err(),
            "accepted {invalid:?}"
        );
        assert!(bytes.iter().all(|&b| b == 0xaa));
    }
    let mut bytes = [0; 256];
    original.encode(1, &mut bytes).unwrap();
    for offset in [4, 6, 34, 240, 251] {
        let mut bad = bytes;
        bad[offset] = 0xff;
        checksum_at(&mut bad, 252);
        assert!(Inode::decode(1, &bad).is_err());
    }
    bytes[252] ^= 1;
    assert_eq!(Inode::decode(1, &bytes), Err(Error::Checksum));
}

#[test]
fn inode_root_directory_size_and_slot_bounds_are_checked() {
    let mut bytes = [0; 256];
    assert!(file().encode(0, &mut bytes).is_err());
    assert!(root().encode(256, &mut bytes).is_err());
    let mut invalid = root();
    invalid.generation = 2;
    assert!(invalid.encode(0, &mut bytes).is_err());
    let mut invalid = root();
    invalid.size = 1;
    assert!(invalid.encode(0, &mut bytes).is_err());
    let mut dir = file();
    dir.kind = InodeKind::Directory;
    dir.size = 32769;
    assert!(dir.encode(1, &mut bytes).is_err());
    let mut invalid = root();
    invalid.kind = InodeKind::Free;
    invalid.parent_generation = 0;
    assert!(invalid.encode(0, &mut bytes).is_err());
}

#[test]
fn directory_has_utf8_byte_names_empty_sentinel_and_strict_padding() {
    let entry = DirectoryEntry {
        inode_id: 17,
        inode_generation: 9,
        name: "文档",
    };
    let mut bytes = [0xaa; 128];
    entry.encode(&mut bytes).unwrap();
    assert_eq!(
        &bytes[..16],
        &[17, 0, 0, 0, 6, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(&bytes[16..22], "文档".as_bytes());
    assert!(bytes[22..124].iter().all(|&b| b == 0));
    assert_eq!(DirectoryEntry::decode(&bytes).unwrap(), entry);
    for offset in [6, 22, 79, 123] {
        let mut bad = bytes;
        bad[offset] = 1;
        checksum_at(&mut bad, 124);
        assert!(DirectoryEntry::decode(&bad).is_err());
    }
    let mut invalid_utf8 = bytes;
    invalid_utf8[16] = 0xff;
    checksum_at(&mut invalid_utf8, 124);
    assert!(DirectoryEntry::decode(&invalid_utf8).is_err());
    DirectoryEntry::EMPTY.encode(&mut bytes).unwrap();
    assert_eq!(&bytes[..4], &[0xff; 4]);
    assert!(bytes[4..124].iter().all(|&b| b == 0));
    assert_eq!(
        DirectoryEntry::decode(&bytes).unwrap(),
        DirectoryEntry::EMPTY
    );
    bytes[8] = 1;
    checksum_at(&mut bytes, 124);
    assert!(DirectoryEntry::decode(&bytes).is_err());
}

#[test]
fn directory_rejects_ambiguous_names_and_invalid_references() {
    for name in [
        "",
        ".",
        "..",
        "a/b",
        "a\0b",
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl",
    ] {
        let mut bytes = [0xaa; 128];
        assert!(
            DirectoryEntry {
                inode_id: 2,
                inode_generation: 1,
                name
            }
            .encode(&mut bytes)
            .is_err()
        );
        assert!(bytes.iter().all(|&b| b == 0xaa));
    }
    for (inode_id, inode_generation) in [(256, 1), (1, 0), (u32::MAX, 1)] {
        assert!(
            DirectoryEntry {
                inode_id,
                inode_generation,
                name: "valid"
            }
            .encode(&mut [0; 128])
            .is_err()
        );
    }
    let name = "a".repeat(63);
    let mut bytes = [0; 128];
    DirectoryEntry {
        inode_id: 255,
        inode_generation: u64::MAX,
        name: &name,
    }
    .encode(&mut bytes)
    .unwrap();
    assert_eq!(DirectoryEntry::decode(&bytes).unwrap().name, name);
}

#[test]
fn begin_redo_commit_layout_and_borrowed_after_image_are_exact() {
    let begin = Record {
        txid: 7,
        lsn: 10,
        log_epoch: 3,
        payload: LogPayload::Begin { redo_count: 1 },
    };
    let mut bytes = [0xaa; 4096];
    begin.encode(&mut bytes).unwrap();
    assert_eq!(
        &bytes[..12],
        &[0x47, 0x4c, 0x59, 0x43, 1, 0, 1, 0, 80, 0, 0, 0]
    );
    assert_eq!(&bytes[16..24], &7_u64.to_le_bytes());
    assert!(bytes[40..56].iter().all(|&b| b == 0));
    assert_eq!(
        &bytes[64..80],
        &[1, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0]
    );
    assert!(bytes[80..].iter().all(|&b| b == 0));
    assert_eq!(Record::decode(&bytes).unwrap(), begin);
    let image = [0xab; 4096];
    let redo = Record {
        txid: 7,
        lsn: 11,
        log_epoch: 3,
        payload: LogPayload::Redo {
            home_block: 4098,
            index: 0,
            count: 1,
            after_image: &image,
        },
    };
    let mut bytes = [0xaa; 8192];
    redo.encode(&mut bytes).unwrap();
    assert_eq!(&bytes[6..12], &[2, 0, 64, 16, 0, 0]);
    assert_eq!(&bytes[40..48], &4098_u64.to_le_bytes());
    assert_eq!(&bytes[48..56], &[0, 0, 0, 0, 1, 0, 0, 0]);
    assert_eq!(&bytes[64..4160], &image);
    assert!(bytes[4160..].iter().all(|&b| b == 0));
    let decoded = Record::decode(&bytes).unwrap();
    assert_eq!(decoded, redo);
    if let LogPayload::Redo { after_image, .. } = decoded.payload {
        assert_eq!(after_image.as_ptr(), bytes[64..].as_ptr());
    } else {
        panic!("wrong record kind");
    }
    let commit = Record {
        txid: 7,
        lsn: 12,
        log_epoch: 3,
        payload: LogPayload::Commit {
            begin_lsn: 10,
            last_redo_lsn: 11,
            redo_count: 1,
            ordered_digest: [0x5e; 32],
        },
    };
    let mut bytes = [0xaa; 4096];
    commit.encode(&mut bytes).unwrap();
    assert_eq!(&bytes[6..12], &[3, 0, 128, 0, 0, 0]);
    assert_eq!(&bytes[64..72], &7_u64.to_le_bytes());
    assert_eq!(&bytes[72..80], &10_u64.to_le_bytes());
    assert_eq!(&bytes[80..88], &11_u64.to_le_bytes());
    assert_eq!(&bytes[88..96], &[1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&bytes[96..128], &[0x5e; 32]);
    assert_eq!(Record::decode(&bytes).unwrap(), commit);
}

#[test]
fn log_rejects_header_payload_crc_reserved_padding_and_inconsistent_payload() {
    let begin = Record {
        txid: 7,
        lsn: 10,
        log_epoch: 3,
        payload: LogPayload::Begin { redo_count: 1 },
    };
    let mut bytes = [0; 4096];
    begin.encode(&mut bytes).unwrap();
    for offset in [0, 4, 6, 8, 40, 48, 52, 60, 80, 4095] {
        let mut bad = bytes;
        bad[offset] ^= 0x80;
        header_crc(&mut bad);
        assert!(
            Record::decode(&bad).is_err(),
            "accepted field offset {offset}"
        );
    }
    let mut bad = bytes;
    bad[24] ^= 1;
    assert_eq!(Record::decode(&bad), Err(Error::Checksum));
    let mut bad = bytes;
    bad[64] ^= 1;
    assert_eq!(Record::decode(&bad), Err(Error::Checksum));
    for offset in [68, 72] {
        let mut bad = bytes;
        bad[offset] ^= 1;
        let crc = crc32c(&bad[64..80]);
        bad[12..16].copy_from_slice(&crc.to_le_bytes());
        header_crc(&mut bad);
        assert!(Record::decode(&bad).is_err());
    }
    let mut bad = bytes;
    bad[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    header_crc(&mut bad);
    assert!(Record::decode(&bad).is_err());
    let commit = Record {
        txid: 7,
        lsn: 12,
        log_epoch: 3,
        payload: LogPayload::Commit {
            begin_lsn: 10,
            last_redo_lsn: 11,
            redo_count: 1,
            ordered_digest: [0; 32],
        },
    };
    commit.encode(&mut bytes).unwrap();
    for offset in [64, 72, 80, 88, 92] {
        let mut bad = bytes;
        bad[offset] ^= 1;
        let crc = crc32c(&bad[64..128]);
        bad[12..16].copy_from_slice(&crc.to_le_bytes());
        header_crc(&mut bad);
        assert!(
            Record::decode(&bad).is_err(),
            "accepted commit offset {offset}"
        );
    }
}

#[test]
fn log_checks_count_home_index_epoch_and_lsn_overflow_without_mutation() {
    let image = [0; 4096];
    let base = Record {
        txid: 7,
        lsn: 10,
        log_epoch: 3,
        payload: LogPayload::Begin { redo_count: 1 },
    };
    let cases = [
        Record { txid: 0, ..base },
        Record { lsn: 0, ..base },
        Record {
            log_epoch: 0,
            ..base
        },
        Record {
            lsn: u64::MAX,
            ..base
        },
        Record {
            payload: LogPayload::Begin { redo_count: 129 },
            ..base
        },
        Record {
            payload: LogPayload::Commit {
                begin_lsn: u64::MAX,
                last_redo_lsn: u64::MAX,
                redo_count: 1,
                ordered_digest: [0; 32],
            },
            ..base
        },
    ];
    for invalid in cases {
        let mut out = [0xaa; 4096];
        assert!(invalid.encode(&mut out).is_err());
        assert!(out.iter().all(|&b| b == 0xaa));
    }
    for (home_block, index, count) in [
        (4097, 0, 1),
        (131072, 0, 1),
        (4098, 1, 1),
        (4098, 0, 0),
        (4098, 0, 129),
    ] {
        let mut out = [0xaa; 8192];
        let invalid = Record {
            payload: LogPayload::Redo {
                home_block,
                index,
                count,
                after_image: &image,
            },
            ..base
        };
        assert!(invalid.encode(&mut out).is_err());
        assert!(out.iter().all(|&b| b == 0xaa));
    }
    let invalid = Record {
        payload: LogPayload::Redo {
            home_block: 4098,
            index: 0,
            count: 1,
            after_image: &image[..4095],
        },
        ..base
    };
    assert!(invalid.encode(&mut [0; 8192]).is_err());
    let empty_begin = Record {
        payload: LogPayload::Begin { redo_count: 0 },
        ..base
    };
    let mut out = [0; 4096];
    assert!(empty_begin.encode(&mut out).is_err());
    let max_begin = Record {
        payload: LogPayload::Begin { redo_count: 128 },
        ..base
    };
    max_begin.encode(&mut out).unwrap();
    assert_eq!(Record::decode(&out).unwrap(), max_begin);
}

#[test]
fn every_decoder_rejects_wrong_lengths_without_panicking() {
    let bytes = [0; 8193];
    for length in 0..=bytes.len() {
        let slice = &bytes[..length];
        assert!(Superblock::decode(slice).is_err());
        assert!(Inode::decode(1, slice).is_err());
        assert!(DirectoryEntry::decode(slice).is_err());
        assert!(Record::decode(slice).is_err());
    }
    let sb = encode_superblock(superblock(1, 0, 1));
    for length in 0..sb.len() {
        assert!(Superblock::decode(&sb[..length]).is_err());
    }
    assert!(superblock(1, 0, 1).encode(&mut [0; 4095]).is_err());
    assert!(file().encode(1, &mut [0; 255]).is_err());
    assert!(DirectoryEntry::EMPTY.encode(&mut [0; 127]).is_err());
    let record = Record {
        txid: 1,
        lsn: 1,
        log_epoch: 1,
        payload: LogPayload::Begin { redo_count: 1 },
    };
    assert!(record.encode(&mut [0; 8192]).is_err());
}

#[test]
fn maximum_file_extent_directory_and_record_bounds_remain_encodable() {
    let mut maximum = file();
    maximum.size = MAX_FILE_SIZE;
    maximum.extent_count = 16;
    for (index, extent) in maximum.extents.iter_mut().enumerate() {
        *extent = Extent {
            logical_start: index as u32 * 128,
            physical_start: DATA_START + index as u32 * 256,
            block_count: 128,
        };
    }
    let mut bytes = [0; 256];
    maximum.encode(255, &mut bytes).unwrap();
    assert_eq!(Inode::decode(255, &bytes).unwrap(), maximum);
    let mut last_block = file();
    last_block.size = 4096;
    last_block.extent_count = 1;
    last_block.extents = [Extent::EMPTY; 16];
    last_block.extents[0] = Extent {
        logical_start: 0,
        physical_start: 131071,
        block_count: 1,
    };
    last_block.encode(1, &mut bytes).unwrap();
    assert_eq!(Inode::decode(1, &bytes).unwrap(), last_block);
    let mut maximum_dir = root();
    maximum_dir.size = 32768;
    maximum_dir.extent_count = 1;
    maximum_dir.extents[0] = Extent {
        logical_start: 0,
        physical_start: DATA_START,
        block_count: 8,
    };
    maximum_dir.encode(0, &mut bytes).unwrap();
    assert_eq!(Inode::decode(0, &bytes).unwrap(), maximum_dir);

    let image = [0; 4096];
    let redo = Record {
        txid: u64::MAX,
        lsn: 129,
        log_epoch: u64::MAX,
        payload: LogPayload::Redo {
            home_block: 131071,
            index: 127,
            count: 128,
            after_image: &image,
        },
    };
    let mut bytes = [0; 8192];
    redo.encode(&mut bytes).unwrap();
    assert_eq!(Record::decode(&bytes).unwrap(), redo);
    let commit = Record {
        txid: u64::MAX,
        lsn: u64::MAX,
        log_epoch: u64::MAX,
        payload: LogPayload::Commit {
            begin_lsn: u64::MAX - 129,
            last_redo_lsn: u64::MAX - 1,
            redo_count: 128,
            ordered_digest: [0; 32],
        },
    };
    let mut bytes = [0; 4096];
    commit.encode(&mut bytes).unwrap();
    assert_eq!(Record::decode(&bytes).unwrap(), commit);
}

#[test]
fn crc_valid_inode_mutations_either_reject_or_roundtrip_without_ignored_fields() {
    let mut original = [0; 256];
    file().encode(1, &mut original).unwrap();
    for offset in 0..252 {
        let mut mutated = original;
        mutated[offset] ^= 0x80;
        checksum_at(&mut mutated, 252);
        if let Ok(decoded) = Inode::decode(1, &mutated) {
            let mut encoded = [0; 256];
            decoded.encode(1, &mut encoded).unwrap();
            assert_eq!(encoded, mutated, "silently dropped field at {offset}");
        }
    }
}

#[test]
fn redo_rejects_recomputed_crc_for_local_metadata_and_nonzero_padding() {
    let image = [0x51; 4096];
    let redo = Record {
        txid: 1,
        lsn: 3,
        log_epoch: 1,
        payload: LogPayload::Redo {
            home_block: 4098,
            index: 1,
            count: 2,
            after_image: &image,
        },
    };
    let mut original = [0; 8192];
    redo.encode(&mut original).unwrap();
    for (offset, value) in [
        (40, 4097_u64),
        (40, 131072),
        (40, u64::MAX),
        (24, 1),
        (24, u64::MAX),
        (16, 0),
        (32, 0),
    ] {
        let mut mutated = original;
        mutated[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        header_crc(&mut mutated);
        assert!(
            Record::decode(&mutated).is_err(),
            "accepted field {offset} = {value}"
        );
    }
    for (offset, value) in [(48, 2_u32), (48, u32::MAX), (52, 0), (52, 129)] {
        let mut mutated = original;
        mutated[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        header_crc(&mut mutated);
        assert!(Record::decode(&mutated).is_err());
    }
    for offset in [4160, 8191] {
        let mut mutated = original;
        mutated[offset] = 1;
        assert_eq!(Record::decode(&mutated), Err(Error::Reserved));
    }
    assert!(Record::decode(&original[..4096]).is_err());
    original[4095] ^= 1;
    assert_eq!(Record::decode(&original), Err(Error::Checksum));
}
