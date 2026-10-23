use super::*;
fn p(s: &str) -> Path {
    Path::resolve(Path::ROOT, s).unwrap()
}
#[test]
fn paths_are_canonical_and_bounded() {
    assert_eq!(p("//a/./b/../c/"), p("/a/c"));
    assert_eq!(p("/../../"), Path::ROOT);
    assert_eq!(Path::resolve(p("/a/b"), "../x"), Ok(p("/a/x")));
    assert_eq!(
        Path::resolve(Path::ROOT, "/bad\0name"),
        Err(Error::InvalidPath)
    );
    let long = [b'a'; 96];
    assert_eq!(
        Path::resolve(Path::ROOT, core::str::from_utf8(&long).unwrap()),
        Err(Error::TooLong)
    );
}
#[test]
fn crud_types_and_directory_integrity() {
    let mut fs = FileSystem::new();
    let mut out = [0; 1024];
    assert_eq!(fs.write(p("/d/f"), b"x", false), Err(Error::NotFound));
    fs.mkdir(p("/d")).unwrap();
    fs.write(p("/d/f"), b"hello", false).unwrap();
    fs.write(p("/d/f"), b" world", true).unwrap();
    assert_eq!(fs.read(p("/d/f"), &mut out), Ok(11));
    assert_eq!(&out[..11], b"hello world");
    assert_eq!(fs.remove(p("/d"), true), Err(Error::NotEmpty));
    assert_eq!(fs.remove(p("/d"), false), Err(Error::IsDirectory));
    assert_eq!(fs.write(p("/d"), b"x", false), Err(Error::IsDirectory));
    assert_eq!(fs.read(Path::ROOT, &mut out), Err(Error::IsDirectory));
    fs.remove(p("/d/f"), false).unwrap();
    fs.remove(p("/d"), true).unwrap();
    assert_eq!(fs.status().nodes, 0);
}
#[test]
fn boot_assets_keep_their_directory_nonempty_for_every_fs_caller() {
    let mut fs = FileSystem::new();
    assert_eq!(
        fs.register_boot_file(p("/missing/font.ttf")),
        Err(Error::NotFound)
    );
    assert_eq!(fs.status().nodes, 0);
    fs.mkdir(p("/fonts")).unwrap();
    fs.mkdir(p("/fonts/truetype")).unwrap();
    fs.mkdir(p("/empty")).unwrap();
    let decisions = fs.status().decisions;
    let nodes = fs.status().nodes;
    let revision = fs.status().revision;
    fs.register_boot_file(p("/fonts/truetype/font.ttf"))
        .unwrap();
    fs.register_boot_file(p("/fonts/truetype/font.ttf"))
        .unwrap();
    assert_eq!(fs.status().decisions, decisions);
    assert_eq!(fs.status().nodes, nodes);
    assert_eq!(fs.status().revision, revision);
    assert_eq!(fs.remove(p("/fonts/truetype"), true), Err(Error::NotEmpty));
    assert_eq!(fs.remove(p("/fonts"), true), Err(Error::NotEmpty));
    assert_eq!(
        fs.write(p("/fonts/truetype"), b"replace", false),
        Err(Error::IsDirectory)
    );
    fs.remove(p("/empty"), true).unwrap();
    assert_eq!(fs.stat(p("/fonts/truetype")).unwrap().kind, Kind::Directory);
}
#[test]
fn oversized_write_is_atomic_and_short_overwrite_zeroes_tail() {
    let mut fs = FileSystem::new();
    let mut out = [0; FILE_BYTES];
    fs.write(p("/f"), &[7; FILE_BYTES], false).unwrap();
    let rev = fs.status().revision;
    assert_eq!(fs.write(p("/f"), b"!", true), Err(Error::TooLarge));
    assert_eq!(fs.status().revision, rev);
    assert_eq!(fs.read(p("/f"), &mut out), Ok(FILE_BYTES));
    assert_eq!(out, [7; FILE_BYTES]);
    fs.write(p("/f"), b"a", false).unwrap();
    assert_eq!(fs.read(p("/f"), &mut out), Ok(1));
    assert_eq!(out[0], b'a');
    assert!(fs.nodes[0].data[1..].iter().all(|b| *b == 0));
}
#[test]
fn cache_write_remove_and_reuse_never_return_old_data() {
    let mut fs = FileSystem::new();
    let mut out = [0; 1024];
    fs.write(p("/a"), b"old", false).unwrap();
    fs.read(p("/a"), &mut out).unwrap();
    fs.read(p("/a"), &mut out).unwrap();
    assert_eq!(fs.status().hits, 1);
    fs.write(p("/a"), b"new", false).unwrap();
    fs.read(p("/a"), &mut out).unwrap();
    assert_eq!(&out[..3], b"new");
    fs.remove(p("/a"), false).unwrap();
    fs.write(p("/b"), b"safe", false).unwrap();
    fs.read(p("/b"), &mut out).unwrap();
    assert_eq!(&out[..4], b"safe");
}
#[test]
fn invalid_and_stale_ai_plans_cannot_change_cache() {
    let mut fs = FileSystem::new();
    fs.write(p("/f"), b"x", false).unwrap();
    let old = fs.proposal();
    fs.mkdir(p("/d")).unwrap();
    assert_eq!(fs.commit_cache(old), Err(Error::InvalidDecision));
    for ids in [
        [Some(NODES), None, None, None],
        [Some(0), Some(0), None, None],
        [Some(1), None, None, None],
    ] {
        let mut proposal = fs.proposal();
        proposal.ids = ids;
        assert_eq!(fs.commit_cache(proposal), Err(Error::InvalidDecision));
        assert!(fs.cache.iter().all(|c| c.id.is_none()));
    }
    let mut proposal = fs.proposal();
    proposal.model += 1;
    assert_eq!(fs.commit_cache(proposal), Err(Error::InvalidDecision));
}
#[test]
fn capacity_and_ai_refusal_preserve_existing_files() {
    let mut fs = FileSystem::new();
    for i in 0..NODES {
        let name = [b'/', b'a' + (i / 26) as u8, b'a' + (i % 26) as u8];
        fs.write(p(core::str::from_utf8(&name).unwrap()), b"", false)
            .unwrap();
    }
    assert_eq!(fs.write(p("/extra"), b"", false), Err(Error::Full));
    let rev = fs.status().revision;
    assert_eq!(fs.write(p("/aa"), b"grow", false), Err(Error::AiDenied));
    assert_eq!(fs.status().revision, rev);
    assert_eq!(fs.stat(p("/aa")).unwrap().len, 0);
    fs.remove(p("/bf"), false).unwrap();
    fs.write(p("/aa"), b"grow", false).unwrap();
}
#[test]
fn learning_needs_data_and_never_implicitly_activates() {
    let mut fs = FileSystem::new();
    assert_eq!(fs.train(), Err(Error::NeedSamples));
    assert_eq!(fs.status().model.train_requests, 1);
    assert_eq!(fs.status().model.insufficient_samples, 1);
    assert_eq!(fs.apply(), Err(Error::NoCandidate));
    fs.write(p("/hot"), b"unchanged", false).unwrap();
    fs.write(p("/cold"), b"cold", false).unwrap();
    let initial = fs.status().model.weights;
    let mut out = [0; 1024];
    // Fixed fixture seed 140: acceptance-path test, not a performance benchmark.
    let trace = [
        0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0,
        1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0,
        0, 1, 0, 1,
    ];
    for choice in trace {
        fs.read(if choice == 0 { p("/hot") } else { p("/cold") }, &mut out)
            .unwrap();
    }
    fs.train()
        .expect("held-out and canary validation should pass for this fixture");
    let validation = fs.status().model.validation.unwrap();
    assert!(validation.candidate_holdout_correct >= validation.active_holdout_correct);
    assert!(validation.candidate_canary_correct >= validation.active_canary_correct);
    assert_eq!(fs.status().model.publications, 0);
    assert_eq!(fs.status().model.weights, initial);
    assert_eq!(fs.status().model.version, 1);
    fs.apply().unwrap();
    assert_eq!(fs.status().model.version, 2);
    assert_eq!(fs.status().model.publications, 1);
    assert!(fs.status().model.validation.is_none());
    assert_ne!(fs.status().model.weights, initial);
    assert_eq!(fs.status().model.samples, 0);
    assert_eq!(fs.read(p("/hot"), &mut out), Ok(9));
    assert_eq!(&out[..9], b"unchanged");
    fs.rollback().unwrap();
    assert_eq!(fs.status().model.weights, initial);
    assert_eq!(fs.status().model.version, 3);
    assert_eq!(fs.status().model.rollbacks, 1);
    assert_eq!(fs.rollback(), Err(Error::NoCandidate));
}
#[test]
fn fixed_service_budget_and_counter_exhaustion() {
    assert!(core::mem::size_of::<FileSystem>() < 320 * 1024);
    let mut fs = FileSystem::new();
    fs.revision = u64::MAX;
    assert_eq!(fs.write(p("/f"), b"data", false), Err(Error::Exhausted));
    assert_eq!(fs.status().nodes, 0);
}

#[test]
fn validation_windows_are_whole_read_events_at_full_capacity() {
    let mut fs = FileSystem::new();
    for i in 0..NODES {
        let name = [b'/', b'a' + (i / 26) as u8, b'a' + (i % 26) as u8];
        fs.write(p(core::str::from_utf8(&name).unwrap()), b"", false)
            .unwrap();
    }
    let mut out = [0; 1024];
    for _ in 0..32 {
        fs.read(p("/aa"), &mut out).unwrap();
    }
    assert_eq!(fs.status().model.samples, 62); // 31 complete transitions, never 32 rows per read.
    assert_eq!(fs.train(), Err(Error::NeedSamples));
    fs.read(p("/aa"), &mut out).unwrap();
    assert_eq!(fs.status().model.samples, 64);
}

#[test]
fn cache_policy_selects_only_four_copies_and_keeps_all_backing_files() {
    let mut fs = FileSystem::new();
    let mut out = [0; 1024];
    for name in ["/a", "/b", "/c", "/d", "/e", "/f"] {
        fs.write(p(name), name.as_bytes(), false).unwrap();
    }
    for _ in 0..20 {
        fs.read(p("/f"), &mut out).unwrap();
    }
    assert!(fs.stat(p("/f")).unwrap().cached);
    assert_eq!(fs.entries().filter(|e| e.cached).count(), 4);
    assert_eq!(fs.status().nodes, 6);
    for name in ["/a", "/b", "/c", "/d", "/e", "/f"] {
        assert_eq!(fs.read(p(name), &mut out), Ok(2));
        assert_eq!(&out[..2], name.as_bytes());
    }
}

#[test]
fn posix_reads_share_learning_and_only_cache_competition_counts_as_ai() {
    let mut fs = FileSystem::new();
    fs.write(p("/hot"), b"preserved", false).unwrap();
    let inode = fs.pin(p("/hot")).unwrap();
    let mut out = [0; 16];
    for _ in 0..33 {
        assert_eq!(fs.read_at(inode, 0, &mut out), Ok(9));
        assert_eq!(&out[..9], b"preserved");
    }
    let status = fs.status();
    assert_eq!(status.policy.admission_proposals, 1);
    assert_eq!(status.policy.admission_allowed, 1);
    assert_eq!(status.policy.cache_proposals, 0);
    assert_eq!(status.policy.cache_selected, 0);
    assert_eq!(status.policy.cache_mechanisms, 33);
    assert_eq!(status.last_source, DecisionSource::Mechanism);
    assert_eq!(status.model.samples, 64);
    for name in ["/a", "/b", "/c", "/d"] {
        fs.write(p(name), b"cold", false).unwrap();
    }
    fs.read_at(inode, 0, &mut out).unwrap();
    assert_eq!(fs.status().policy.cache_proposals, 1);
    assert_eq!(fs.status().policy.cache_selected, 1);
    assert_eq!(fs.status().last_source, DecisionSource::AiDirect);
    assert_eq!(&out[..9], b"preserved");
    fs.unpin(inode).unwrap();
}

#[test]
fn cache_observations_stay_in_declared_training_domain() {
    let mut fs = FileSystem::new();
    fs.write(p("/empty"), b"", false).unwrap();
    fs.write(p("/large"), &[b'x'; FILE_BYTES], false).unwrap();
    let (features, valid) = fs.features();
    for (x, present) in features.iter().zip(valid) {
        if present {
            assert!((1..=4).contains(&x[3]));
        }
    }
}

#[test]
fn unicode_space_names_and_atomic_rename_keep_open_inodes() {
    let mut fs = FileSystem::new();
    let source = p("/新建 文本.txt");
    let target = p("/final file.txt");
    fs.write(source, b"new", false).unwrap();
    fs.write(target, b"old", false).unwrap();
    let source_handle = fs.pin(source).unwrap();
    let old_handle = fs.pin(target).unwrap();
    let source_identity = fs.identity(source).unwrap();
    let revision = fs.status().revision;
    assert_eq!(fs.rename_file(source, target, true), Err(Error::Exists));
    assert_eq!(fs.status().revision, revision);
    fs.rename_file(source, target, false).unwrap();
    assert_eq!(fs.stat(source).err(), Some(Error::NotFound));
    assert_eq!(fs.identity(target), Ok(source_identity));
    let mut out = [0; 3];
    assert_eq!(fs.read_at(old_handle, 0, &mut out), Ok(3));
    assert_eq!(&out, b"old");
    assert_eq!(fs.read_at(source_handle, 0, &mut out), Ok(3));
    assert_eq!(&out, b"new");
    fs.unpin(old_handle).unwrap();
    assert_eq!(fs.status().nodes, 1);
    fs.unpin(source_handle).unwrap();
    let revision = fs.status().revision;
    fs.rename_file(target, target, false).unwrap();
    assert_eq!(fs.status().revision, revision);
    fs.mkdir(p("/folder")).unwrap();
    assert_eq!(
        fs.rename_file(target, p("/folder"), false),
        Err(Error::IsDirectory)
    );
    assert_eq!(
        fs.rename_file(p("/folder"), p("/other"), false),
        Err(Error::IsDirectory)
    );
    fs.revision = u64::MAX;
    assert_eq!(fs.rename_file(target, source, false), Err(Error::Exhausted));
    assert_eq!(fs.identity(target), Ok(source_identity));
}
