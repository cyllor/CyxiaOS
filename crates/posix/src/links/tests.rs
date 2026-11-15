extern crate std;
use super::*;

fn path(name: &str) -> Path {
    Path::resolve(Path::ROOT, name).unwrap()
}

#[test]
fn relative_absolute_and_intermediate_links_expand_before_parent_components() {
    let mut fs = FileSystem::new();
    fs.mkdir(path("/a")).unwrap();
    fs.mkdir(path("/a/b")).unwrap();
    fs.write(path("/a/name"), b"parent", false).unwrap();
    fs.write(path("/a/b/file"), b"child", false).unwrap();
    fs.symlink(path("/alias"), "a/b").unwrap();
    fs.symlink(path("/a/relative"), "b/../name").unwrap();
    fs.symlink(path("/absolute"), "/a/relative").unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();

    assert_eq!(p.resolved_path(&fs, "/alias/../name"), Ok(path("/a/name")));
    assert_eq!(p.resolved_path(&fs, "/absolute"), Ok(path("/a/name")));
    assert_eq!(
        p.path_at_with_follow(&fs, -100, "/alias/file", false),
        Ok(path("/a/b/file"))
    );
    assert_eq!(
        p.resolved_path_with_follow(&fs, "/absolute", false),
        Ok(path("/absolute"))
    );
    assert_eq!(
        p.resolved_path_with_follow(&fs, "/alias/", false),
        Ok(path("/a/b"))
    );
    assert_eq!(p.resolved_path(&fs, "/absolute/"), Err(Errno::Notdir));
    assert_eq!(
        p.resolved_path(&fs, "/absolute/../name"),
        Err(Errno::Notdir)
    );
    p.chdir(&fs, "/alias").unwrap();
    assert_eq!(p.resolved_path(&fs, "../relative"), Ok(path("/a/name")));
    let mut cwd = [0; 32];
    assert_eq!(p.getcwd(&mut cwd), Ok(5));
    assert_eq!(&cwd[..5], b"/a/b\0");
}

#[test]
fn link_limit_counts_expansions_and_does_not_block_nofollow_inspection() {
    let mut fs = FileSystem::new();
    fs.write(path("/target"), b"value", false).unwrap();
    for index in 0..41 {
        let name = std::format!("/link{index}");
        let target = if index == 40 {
            std::string::String::from("target")
        } else {
            std::format!("link{}", index + 1)
        };
        fs.symlink(path(&name), &target).unwrap();
    }
    fs.symlink(path("/self"), "self").unwrap();
    fs.symlink(path("/cycle-a"), "cycle-b").unwrap();
    fs.symlink(path("/cycle-b"), "cycle-a").unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();

    assert_eq!(p.resolved_path(&fs, "/link1"), Ok(path("/target")));
    assert_eq!(p.resolved_path(&fs, "/link0"), Err(Errno::Loop));
    assert_eq!(p.stat(&fs, "/self"), Err(Errno::Loop));
    assert_eq!(p.stat(&fs, "/cycle-a"), Err(Errno::Loop));
    assert_eq!(
        p.resolved_path_with_follow(&fs, "/self", false),
        Ok(path("/self"))
    );
    assert_eq!(p.open(&mut fs, "/self", O_NOFOLLOW, 0), Err(Errno::Loop));
    let mut text = [0; 16];
    assert_eq!(p.readlink_at(&fs, -100, "/self", &mut text), Ok(4));
    assert_eq!(&text[..4], b"self");
    p.unlink(&mut fs, "/self").unwrap();
    assert_eq!(fs.stat(path("/self")).err(), Some(Error::NotFound));
}

#[test]
fn expansion_keeps_utf8_path_bounds_and_null_device_traversal() {
    let mut fs = FileSystem::new();
    fs.mkdir(path("/dev")).unwrap();
    fs.write(path("/é space"), b"utf8", false).unwrap();
    fs.symlink(path("/unicode"), "é space").unwrap();
    fs.symlink(path("/null"), "/dev/null").unwrap();
    let long = [b'x'; PATH_BYTES - 2];
    fs.symlink(path("/long"), core::str::from_utf8(&long).unwrap())
        .unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();

    assert_eq!(p.resolved_path(&fs, "/unicode"), Ok(path("/é space")));
    assert_eq!(p.resolved_path(&fs, "/long/x"), Err(Errno::Nametoolong));
    assert_eq!(p.stat(&fs, "/null"), Ok(NULL_DEVICE_INFO));
    assert_eq!(
        p.readlink_at(&fs, -100, "/dev/null", &mut [0; 16]),
        Err(Errno::Inval)
    );
    assert_eq!(p.resolved_path(&fs, "/null/child"), Err(Errno::Notdir));
    assert_eq!(p.open(&mut fs, "/null", O_NOFOLLOW, 0), Err(Errno::Loop));
    let fd = p.open(&mut fs, "/null", O_RDONLY, 0).unwrap();
    assert_eq!(p.fstat(&fs, fd), Ok(NULL_DEVICE_INFO));
    p.close_all(&mut fs).unwrap();
}

#[test]
fn directory_fd_relative_targets_preserve_authority_and_check_actual_traversal() {
    let mut fs = FileSystem::new();
    fs.mkdir(path("/a")).unwrap();
    fs.mkdir(path("/a/b")).unwrap();
    fs.write(path("/a/b/target"), b"data", false).unwrap();
    fs.write(path("/a/secret"), b"hidden", false).unwrap();
    fs.symlink(path("/a/b/local"), "target").unwrap();
    fs.symlink(path("/a/b/absolute"), "/a/b/target").unwrap();
    fs.symlink(path("/a/b/up"), "../secret").unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();
    let dir = p.open(&mut fs, "/a/b", O_DIRECTORY, 0).unwrap();
    p.chmod(&mut fs, "/a", 0).unwrap();

    assert_eq!(p.path_at(&fs, dir, "local"), Ok(path("/a/b/target")));
    assert_eq!(p.path_at(&fs, dir, "absolute"), Err(Errno::Access));
    assert_eq!(p.path_at(&fs, dir, "up"), Err(Errno::Access));
    assert_eq!(p.stat(&fs, "/a/b/local"), Err(Errno::Access));
    p.symlink_at(&mut fs, "target", dir, "created").unwrap();
    let mut target = [0; 16];
    assert_eq!(p.readlink_at(&fs, dir, "created", &mut target), Ok(6));
    let resolved = p.path_at(&fs, dir, "created").unwrap();
    let file = p.open_resolved(&mut fs, resolved, O_RDONLY, 0).unwrap();
    assert_eq!(p.stat_resolved(&fs, resolved), p.fstat(&fs, file));
    p.fchmod(&mut fs, dir, 0o500).unwrap();
    assert_eq!(
        p.symlink_at(&mut fs, "target", dir, "denied"),
        Err(Errno::Access)
    );
    assert_eq!(fs.stat(path("/a/b/denied")).err(), Some(Error::NotFound));
    p.fchmod(&mut fs, dir, 0o400).unwrap();
    assert_eq!(p.path_at(&fs, dir, "local"), Err(Errno::Access));
    assert_eq!(
        p.readlink_at(&fs, dir, "local", &mut target),
        Err(Errno::Access)
    );
    p.close_all(&mut fs).unwrap();
}

#[test]
fn nofollow_and_exclusive_open_preserve_links_and_dangling_create_uses_target() {
    let mut fs = FileSystem::new();
    fs.write(path("/target"), b"keep", false).unwrap();
    fs.symlink(path("/existing"), "target").unwrap();
    fs.symlink(path("/dangling"), "created").unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();

    assert_eq!(
        p.open(&mut fs, "/existing", O_NOFOLLOW | O_TRUNC | O_WRONLY, 0),
        Err(Errno::Loop)
    );
    for name in ["/existing", "/dangling"] {
        assert_eq!(
            p.open(&mut fs, name, O_CREAT | O_EXCL | O_RDWR, 0o600),
            Err(Errno::Exist)
        );
        assert_eq!(fs.stat(path(name)).unwrap().kind, Kind::Symlink);
    }
    assert_eq!(
        p.open(&mut fs, "/dangling", O_CREAT | O_NOFOLLOW | O_RDWR, 0o600),
        Err(Errno::Loop)
    );
    assert_eq!(fs.stat(path("/target")).unwrap().len, 4);
    assert_eq!(fs.stat(path("/created")).err(), Some(Error::NotFound));
    assert_eq!(p.open(&mut fs, "/dangling", O_RDONLY, 0), Err(Errno::Noent));
    let fd = p
        .open(&mut fs, "/dangling", O_CREAT | O_RDWR, 0o600)
        .unwrap();
    assert_eq!(p.stat(&fs, "/dangling"), p.fstat(&fs, fd));
    assert_eq!(fs.stat(path("/created")).unwrap().mode, 0o600);
    assert_eq!(fs.stat(path("/dangling")).unwrap().kind, Kind::Symlink);
    p.close_all(&mut fs).unwrap();

    fs.mkdir(path("/locked")).unwrap();
    fs.symlink(path("/denied"), "locked/new").unwrap();
    fs.set_mode(path("/locked"), 0o500).unwrap();
    assert_eq!(
        p.open(&mut fs, "/denied", O_CREAT | O_RDWR, 0o600),
        Err(Errno::Access)
    );
    assert_eq!(fs.stat(path("/locked/new")).err(), Some(Error::NotFound));
}

#[test]
fn unlink_rename_and_directory_operations_preserve_link_targets() {
    let mut fs = FileSystem::new();
    fs.write(path("/target"), b"keep", false).unwrap();
    fs.write(path("/victim"), b"also keep", false).unwrap();
    fs.mkdir(path("/directory")).unwrap();
    fs.symlink(path("/from"), "target").unwrap();
    fs.symlink(path("/to"), "victim").unwrap();
    fs.symlink(path("/dirlink"), "directory").unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();

    let from = p.path_at_with_follow(&fs, -100, "/from", false).unwrap();
    let to = p.path_at_with_follow(&fs, -100, "/to", false).unwrap();
    assert_eq!(
        p.rename_file_resolved(&mut fs, from, to, true),
        Err(Errno::Exist)
    );
    p.rename_file_resolved(&mut fs, from, to, false).unwrap();
    let mut target = [0; 16];
    assert_eq!(p.readlink_at(&fs, -100, "/to", &mut target), Ok(6));
    assert_eq!(&target[..6], b"target");
    p.unlink(&mut fs, "/to").unwrap();
    assert_eq!(fs.stat(path("/target")).unwrap().len, 4);
    assert_eq!(fs.stat(path("/victim")).unwrap().len, 9);
    assert_eq!(p.mkdir(&mut fs, "/dirlink/", 0o700), Err(Errno::Exist));
    assert_eq!(p.rmdir(&mut fs, "/dirlink/"), Err(Errno::Notdir));
    assert_eq!(fs.stat(path("/directory")).unwrap().kind, Kind::Directory);
    p.unlink(&mut fs, "/dirlink").unwrap();
    assert_eq!(fs.stat(path("/directory")).unwrap().kind, Kind::Directory);
}

#[test]
fn link_metadata_readlink_and_directory_entry_types_are_observable() {
    let mut fs = FileSystem::new();
    fs.write(path("/target"), b"content", false).unwrap();
    fs.symlink(path("/link"), "target").unwrap();
    let objects = OpenDescriptions::new();
    let mut p = Process::new(&objects, 1).unwrap();

    let link = p.resolved_path_with_follow(&fs, "/link", false).unwrap();
    let info = p.stat_resolved(&fs, link).unwrap();
    assert_eq!(info.mode & 0o170000, 0o120000);
    assert_eq!(info.size, 6);
    assert_ne!(info.inode, p.stat(&fs, "/link").unwrap().inode);
    let mut text = [0xa5; 16];
    assert_eq!(p.readlink_at(&fs, -100, "/link", &mut text[..3]), Ok(3));
    assert_eq!(&text[..4], b"tar\xa5");
    assert_eq!(
        p.readlink_at(&fs, -100, "/link", &mut []),
        Err(Errno::Inval)
    );
    assert_eq!(
        p.readlink_at(&fs, -100, "/target", &mut text),
        Err(Errno::Inval)
    );
    assert_eq!(
        p.readlink_at(&fs, -100, "/absent", &mut text),
        Err(Errno::Noent)
    );
    let dir = p.open(&mut fs, "/", O_DIRECTORY, 0).unwrap();
    let mut entries = [0; 256];
    let count = p.getdents(&mut fs, dir, &[], &mut entries).unwrap();
    let mut at = 0;
    let mut found = false;
    while at < count {
        let size = u16::from_le_bytes(entries[at + 16..at + 18].try_into().unwrap()) as usize;
        if &entries[at + 19..at + 24] == b"link\0" {
            assert_eq!(entries[at + 18], 10);
            assert_eq!(
                u64::from_le_bytes(entries[at..at + 8].try_into().unwrap()),
                info.inode
            );
            found = true;
        }
        at += size;
    }
    assert!(found);
    p.close_all(&mut fs).unwrap();
}

#[test]
fn empty_symlink_target_is_rejected_without_creating_a_node() {
    let mut fs = FileSystem::new();
    let objects = OpenDescriptions::new();
    let p = Process::new(&objects, 1).unwrap();
    assert_eq!(p.symlink_at(&mut fs, "", -100, "/empty"), Err(Errno::Noent));
    assert_eq!(fs.stat(path("/empty")).err(), Some(Error::NotFound));
}
