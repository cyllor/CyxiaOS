use super::*;
struct Output;
impl Console for Output {
    fn write(&mut self, b: &[u8]) -> Result<usize, Errno> {
        Ok(b.len().min(3))
    }
}
fn p(s: &str) -> Path {
    Path::resolve(Path::ROOT, s).unwrap()
}
#[test]
fn pipe_descriptors_are_atomic_and_share_endpoint_lifetimes() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    let [read, write] = process
        .install_pipe([256, 257], O_NONBLOCK | O_CLOEXEC)
        .unwrap();
    assert_eq!(process.flags(read), Ok(O_RDONLY | O_NONBLOCK));
    assert_eq!(process.flags(write), Ok(O_WRONLY | O_NONBLOCK));
    assert_eq!(process.socket(read), Ok(None));
    assert_eq!(process.pipe(read), Ok(Some(256)));
    assert_eq!(process.fstat(&fs, read).unwrap().mode, 0o10600);
    assert_eq!(
        process.fstat(&fs, read).unwrap().inode,
        process.fstat(&fs, write).unwrap().inode
    );
    assert_eq!(process.lseek(&fs, read, 0, 0), Err(Errno::Spipe));
    let alias = process.dup(write).unwrap();
    assert_eq!(process.close_on_exec(write), Ok(true));
    assert_eq!(process.close_on_exec(alias), Ok(false));
    assert_eq!(process.last_reference(write), Ok(false));
    process.set_flags(alias, O_WRONLY).unwrap();
    assert_eq!(process.flags(write), Ok(O_WRONLY));
    process.close(&mut fs, write).unwrap();
    assert_eq!(process.pipe(alias), Ok(Some(257)));
    assert_eq!(process.last_reference(alias), Ok(true));
    while process.fds.iter().filter(|v| v.is_none()).count() > 1 {
        process.dup(read).unwrap();
    }
    assert_eq!(process.install_pipe([512, 513], 0), Err(Errno::Mfile));
    assert_eq!(process.fds.iter().filter(|v| v.is_none()).count(), 1);
    assert_eq!(
        process.install_pipe([512, 513], O_APPEND),
        Err(Errno::Inval)
    );
    process.close_all(&mut fs).unwrap();
    assert_eq!(objects.snapshot().live, 0);
}
#[test]
fn event_counter_atomic_overflow_dup_and_semaphore() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    let fd = process.eventfd(0, O_NONBLOCK | O_CLOEXEC).unwrap();
    let other = process.dup(fd).unwrap();
    assert_eq!(process.close_on_exec(fd), Ok(true));
    assert_eq!(process.close_on_exec(other), Ok(false));
    let mut bytes = [0; 16];
    assert_eq!(process.read(&mut fs, fd, &mut bytes), Err(Errno::Again));
    assert_eq!(process.local_readiness(fd), Ok((false, true)));
    assert_eq!(
        process.write(&mut fs, &mut Output, fd, &(u64::MAX - 1).to_le_bytes()),
        Ok(8)
    );
    assert_eq!(process.local_readiness(other), Ok((true, false)));
    assert_eq!(
        process.write(&mut fs, &mut Output, other, &1u64.to_le_bytes()),
        Err(Errno::Again)
    );
    assert_eq!(
        process.write(&mut fs, &mut Output, fd, &u64::MAX.to_le_bytes()),
        Err(Errno::Inval)
    );
    assert_eq!(
        process.read(&mut fs, fd, &mut bytes[..7]),
        Err(Errno::Inval)
    );
    process.close(&mut fs, fd).unwrap();
    assert_eq!(process.read(&mut fs, other, &mut bytes), Ok(8));
    assert_eq!(
        u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        u64::MAX - 1
    );
    assert_eq!(process.local_readiness(other), Ok((false, true)));
    assert_eq!(process.lseek(&fs, other, 0, 0), Err(Errno::Spipe));
    let sem = process.eventfd(2, 1 | O_NONBLOCK).unwrap();
    for _ in 0..2 {
        assert_eq!(process.read(&mut fs, sem, &mut bytes), Ok(8));
        assert_eq!(u64::from_le_bytes(bytes[..8].try_into().unwrap()), 1);
    }
    assert_eq!(process.read(&mut fs, sem, &mut bytes), Err(Errno::Again));
    assert_eq!(
        process.write(&mut fs, &mut Output, sem, b""),
        Err(Errno::Inval)
    );
    assert_eq!(process.eventfd(0, 2), Err(Errno::Inval));
    process.close_all(&mut fs).unwrap();
    assert_eq!(process.eventfd(0, 0), Ok(0));
}
#[test]
fn directory_cookies_permissions_assets_and_unlink_identity() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    process.mkdir(&mut fs, "/dir", 0o700).unwrap();
    let file = process
        .open(&mut fs, "/dir/file", O_CREAT | O_RDWR, 0o600)
        .unwrap();
    process.close(&mut fs, file).unwrap();
    let dir = process
        .open(&mut fs, "/dir", O_RDONLY | O_DIRECTORY, 0)
        .unwrap();
    let alias = process.dup(dir).unwrap();
    assert_eq!(process.fstat(&fs, dir).unwrap().mode & 0o170000, 0o40000);
    let assets: &[(&str, &[u8])] = &[("/dir/font.ttf", b"font"), ("/elsewhere", b"x")];
    let mut buffer = [0u8; 128];
    assert_eq!(
        process.getdents(&fs, dir, assets, &mut buffer[..1]),
        Err(Errno::Inval)
    );
    assert_eq!(
        process.getdents(&fs, dir, assets, &mut buffer[..24]),
        Ok(24)
    );
    assert_eq!(&buffer[19..21], b".\0");
    assert_eq!(
        process.getdents(&fs, alias, assets, &mut buffer[..24]),
        Ok(24)
    );
    assert_eq!(&buffer[19..22], b"..\0");
    let n = process.getdents(&fs, alias, assets, &mut buffer).unwrap();
    assert_eq!(n, 56);
    assert_eq!(&buffer[19..24], b"file\0");
    assert_eq!(&buffer[43..52], b"font.ttf\0");
    assert_eq!(process.getdents(&fs, dir, assets, &mut buffer), Ok(0));
    assert_eq!(process.path_at(&fs, dir, "file"), Ok(p("/dir/file")));
    process.lseek(&fs, alias, 0, 0).unwrap();
    assert_eq!(
        process.getdents(&fs, dir, assets, &mut buffer[..24]),
        Ok(24)
    );
    assert_eq!(process.read(&mut fs, dir, &mut buffer), Err(Errno::Isdir));
    assert_eq!(
        process.open(&mut fs, "/dir/file", O_DIRECTORY, 0),
        Err(Errno::Notdir)
    );
    let identity = process.fstat(&fs, dir).unwrap().inode;
    process.unlink(&mut fs, "/dir/file").unwrap();
    process.rmdir(&mut fs, "/dir").unwrap();
    process.mkdir(&mut fs, "/dir", 0o700).unwrap();
    assert_ne!(process.stat(&fs, "/dir").unwrap().inode, identity);
    assert_eq!(process.fstat(&fs, dir).unwrap().inode, identity);
    assert_eq!(process.fstat(&fs, dir).unwrap().links, 0);
    assert_eq!(
        process.getdents(&fs, dir, assets, &mut buffer),
        Err(Errno::Noent)
    );
    assert_eq!(process.path_at(&fs, dir, "file"), Err(Errno::Noent));
    process.chmod(&mut fs, "/dir", 0o100).unwrap();
    assert_eq!(
        process.open(&mut fs, "/dir", O_DIRECTORY, 0),
        Err(Errno::Access)
    );
    process.close_all(&mut fs).unwrap();
}
#[test]
fn directory_fd_lookup_does_not_recheck_ancestors_but_checks_its_own_permissions() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    process.mkdir(&mut fs, "/a", 0o700).unwrap();
    process.mkdir(&mut fs, "/a/b", 0o700).unwrap();
    let file = process
        .open(&mut fs, "/a/b/file", O_CREAT | O_RDWR, 0o600)
        .unwrap();
    process.close(&mut fs, file).unwrap();
    let dir = process
        .open(&mut fs, "/a/b", O_RDONLY | O_DIRECTORY, 0)
        .unwrap();
    process.chmod(&mut fs, "/a", 0).unwrap();
    assert_eq!(process.stat(&fs, "/a/b/file"), Err(Errno::Access));
    let path = process.path_at(&fs, dir, "file").unwrap();
    let file = process.open_resolved(&mut fs, path, O_RDONLY, 0).unwrap();
    assert_eq!(
        process.stat_resolved(&fs, path).unwrap(),
        process.fstat(&fs, file).unwrap()
    );
    process.close(&mut fs, file).unwrap();
    let path = process.path_at(&fs, dir, "created").unwrap();
    let file = process
        .open_resolved(&mut fs, path, O_CREAT | O_RDWR, 0o600)
        .unwrap();
    process.close(&mut fs, file).unwrap();
    process.fchmod(&mut fs, dir, 0o400).unwrap();
    assert_eq!(process.path_at(&fs, dir, "file"), Err(Errno::Access));
    process.fchmod(&mut fs, dir, 0o500).unwrap();
    let path = process.path_at(&fs, dir, "denied").unwrap();
    assert_eq!(
        process.open_resolved(&mut fs, path, O_CREAT | O_RDWR, 0o600),
        Err(Errno::Access)
    );
    assert_eq!(fs.stat(path).err(), Some(Error::NotFound));
    process.close_all(&mut fs).unwrap();
}
#[test]
fn empty_path_stats_cwd_and_open_handles_without_search_permission() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    process.mkdir(&mut fs, "/cwd", 0o700).unwrap();
    process.chdir(&fs, "/cwd").unwrap();
    let dir = process
        .open(&mut fs, ".", O_RDONLY | O_DIRECTORY, 0)
        .unwrap();
    let file = process
        .open(&mut fs, "file", O_CREAT | O_RDWR, 0o600)
        .unwrap();
    process.fchmod(&mut fs, dir, 0).unwrap();
    assert_eq!(process.stat(&fs, "."), Err(Errno::Access));
    assert_eq!(
        process.stat_empty_at(&fs, -100).unwrap().inode,
        process.fstat(&fs, dir).unwrap().inode
    );
    assert_eq!(process.stat_empty_at(&fs, file), process.fstat(&fs, file));
    assert_eq!(process.stat_empty_at(&fs, -1), Err(Errno::Badf));
    process.close_all(&mut fs).unwrap();
}
#[test]
fn posix_rmdir_cannot_remove_directories_containing_boot_assets() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    process.mkdir(&mut fs, "/fonts", 0o700).unwrap();
    fs.register_boot_file(p("/fonts/font.ttf")).unwrap();
    assert_eq!(process.rmdir(&mut fs, "/fonts"), Err(Errno::Notempty));
    assert_eq!(
        process.open(&mut fs, "/fonts", O_TRUNC | O_WRONLY, 0),
        Err(Errno::Isdir)
    );
    assert_eq!(fs.stat(p("/fonts")).unwrap().kind, Kind::Directory);
}
#[test]
fn independent_open_offsets_and_shared_dup_offsets() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut a = Process::new(&objects, 1).unwrap();
    let mut b = [0; 8];
    let f = a.open(&mut fs, "/f", O_CREAT | O_RDWR, 0o600).unwrap();
    a.write(&mut fs, &mut Output, f, b"abcdef").unwrap();
    a.lseek(&fs, f, 0, 0).unwrap();
    let d = a.dup(f).unwrap();
    let other = a.open(&mut fs, "/f", O_RDONLY, 0).unwrap();
    assert_eq!(a.read(&mut fs, d, &mut b[..2]), Ok(2));
    assert_eq!(&b[..2], b"ab");
    assert_eq!(a.read(&mut fs, f, &mut b[..2]), Ok(2));
    assert_eq!(&b[..2], b"cd");
    assert_eq!(a.read(&mut fs, other, &mut b[..2]), Ok(2));
    assert_eq!(&b[..2], b"ab");
    assert_eq!(a.dup2(&mut fs, 99, d), Err(Errno::Badf));
    assert_eq!(a.read(&mut fs, d, &mut b), Ok(2));
    assert_eq!(&b[..2], b"ef");
    assert_eq!(a.dup2(&mut fs, f, f), Ok((f, None)));
    a.close_all(&mut fs).unwrap();
}
#[test]
fn unlink_keeps_description_until_last_close_and_does_not_alias_recreated_path() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut a = Process::new(&objects, 1).unwrap();
    let mut b = [0; 8];
    let f = a.open(&mut fs, "/f", O_CREAT | O_RDWR, 0o600).unwrap();
    a.write(&mut fs, &mut Output, f, b"old").unwrap();
    let d = a.dup(f).unwrap();
    a.unlink(&mut fs, "/f").unwrap();
    assert_eq!(a.open(&mut fs, "/f", O_RDONLY, 0), Err(Errno::Noent));
    let new = a.open(&mut fs, "/f", O_CREAT | O_RDWR, 0o600).unwrap();
    a.write(&mut fs, &mut Output, new, b"new").unwrap();
    a.lseek(&fs, d, 0, 0).unwrap();
    a.close(&mut fs, f).unwrap();
    assert_eq!(a.read(&mut fs, d, &mut b), Ok(3));
    assert_eq!(&b[..3], b"old");
    assert_eq!(fs.status().nodes, 2);
    a.close(&mut fs, d).unwrap();
    assert_eq!(fs.status().nodes, 1);
    a.close_all(&mut fs).unwrap();
}
#[test]
fn positional_writes_preserve_suffix_append_ignores_seek_and_holes_are_zero() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut a = Process::new(&objects, 1).unwrap();
    let mut b = [0; 32];
    let f = a.open(&mut fs, "/f", O_CREAT | O_RDWR, 0o600).unwrap();
    a.write(&mut fs, &mut Output, f, b"abcdef").unwrap();
    a.lseek(&fs, f, 2, 0).unwrap();
    a.write(&mut fs, &mut Output, f, b"XY").unwrap();
    a.lseek(&fs, f, 10, 0).unwrap();
    a.write(&mut fs, &mut Output, f, b"Z").unwrap();
    let d = a.open(&mut fs, "/f", O_APPEND | O_WRONLY, 0).unwrap();
    a.lseek(&fs, d, 0, 0).unwrap();
    a.write(&mut fs, &mut Output, d, b"!").unwrap();
    a.lseek(&fs, f, 0, 0).unwrap();
    assert_eq!(a.read(&mut fs, f, &mut b), Ok(12));
    assert_eq!(&b[..12], b"abXYef\0\0\0\0Z!");
    assert_eq!(a.read(&mut fs, f, &mut b), Ok(0));
}
#[test]
fn flags_permissions_and_descriptor_capacity_precede_mutation() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut a = Process::new(&objects, 1).unwrap();
    let f = a.open(&mut fs, "/f", O_CREAT | O_RDWR, 0o600).unwrap();
    a.write(&mut fs, &mut Output, f, b"keep").unwrap();
    assert_eq!(
        a.open(&mut fs, "/f", O_CREAT | O_EXCL, 0o600),
        Err(Errno::Exist)
    );
    assert_eq!(a.open(&mut fs, "/f", O_TRUNC, 0), Err(Errno::Inval));
    assert_eq!(a.open(&mut fs, "/f", 1 << 30, 0), Err(Errno::Inval));
    for _ in 4..OPEN_MAX {
        a.dup(f).unwrap();
    }
    assert_eq!(
        a.open(&mut fs, "/f", O_TRUNC | O_WRONLY, 0),
        Err(Errno::Mfile)
    );
    assert_eq!(fs.stat(p("/f")).unwrap().len, 4);
    assert_eq!(
        a.open(&mut fs, "/not-created", O_CREAT | O_RDWR, 0o600),
        Err(Errno::Mfile)
    );
    assert!(fs.stat(p("/not-created")).is_err());
    a.close_all(&mut fs).unwrap();
}
#[test]
fn owner_mode_and_umask_and_component_walk() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut a = Process::new(&objects, 1).unwrap();
    let mut buf = [0; 32];
    assert_eq!(a.umask(0o077), 0o022);
    a.mkdir(&mut fs, "/dir/", 0o777).unwrap();
    assert_eq!(fs.stat(p("/dir")).unwrap().mode, 0o700);
    a.chdir(&fs, "/dir").unwrap();
    assert_eq!(a.getcwd(&mut buf), Ok(5));
    assert_eq!(&buf[..5], b"/dir\0");
    let f = a.open(&mut fs, "f", O_CREAT | O_RDWR, 0o400).unwrap();
    a.close(&mut fs, f).unwrap();
    assert_eq!(a.open(&mut fs, "f", O_WRONLY, 0), Err(Errno::Access));
    assert_eq!(
        a.open(&mut fs, "f/../x", O_CREAT | O_WRONLY, 0o600),
        Err(Errno::Notdir)
    );
    assert_eq!(
        a.open(&mut fs, "missing/../f", O_RDONLY, 0),
        Err(Errno::Noent)
    );
    assert_eq!(a.open(&mut fs, "f/", O_RDONLY, 0), Err(Errno::Notdir));
    assert_eq!(a.open(&mut fs, "", O_RDONLY, 0), Err(Errno::Noent));
    a.mkdir(&mut fs, "/locked", 0).unwrap();
    assert_eq!(
        a.open(&mut fs, "/locked/x", O_CREAT | O_RDWR, 0o600),
        Err(Errno::Access)
    );
}
#[test]
fn short_io_bounds_errors_and_no_offset_advance_on_failure() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut a = Process::new(&objects, 1).unwrap();
    let mut buf = [0; 10];
    assert_eq!(a.write(&mut fs, &mut Output, 1, b"hello"), Ok(3));
    assert_eq!(a.read(&mut fs, 1, &mut buf), Err(Errno::Badf));
    assert_eq!(a.lseek(&fs, 1, 0, 0), Err(Errno::Spipe));
    let f = a.open(&mut fs, "/f", O_CREAT | O_RDWR, 0o600).unwrap();
    a.lseek(&fs, f, (cyxia_ai_fs::FILE_BYTES - 4) as i64, 0)
        .unwrap();
    assert_eq!(a.write(&mut fs, &mut Output, f, b"12345678"), Ok(4));
    assert_eq!(a.write(&mut fs, &mut Output, f, b"!"), Err(Errno::Fbig));
    assert_eq!(a.lseek(&fs, f, 0, 1), Ok(cyxia_ai_fs::FILE_BYTES as u64));
    assert_eq!(
        a.lseek(&fs, f, -(cyxia_ai_fs::FILE_BYTES as i64 + 1), 1),
        Err(Errno::Inval)
    );
    assert_eq!(a.lseek(&fs, f, i64::MAX, 1), Err(Errno::Overflow));
    assert_eq!(a.lseek(&fs, f, 0, 1), Ok(cyxia_ai_fs::FILE_BYTES as u64));
}
#[test]
fn ai_denial_does_not_advance_offset_or_mutate_bytes() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut a = Process::new(&objects, 1).unwrap();
    let f = a.open(&mut fs, "/f", O_CREAT | O_RDWR, 0o600).unwrap();
    for i in 0..(cyxia_ai_fs::NODES - 1) as u8 {
        let name = [b'/', b'a' + i / 26, b'a' + i % 26];
        fs.write(p(core::str::from_utf8(&name).unwrap()), b"", false)
            .unwrap();
    }
    assert_eq!(a.write(&mut fs, &mut Output, f, b"x"), Err(Errno::Nospc));
    assert_eq!(a.lseek(&fs, f, 0, 1), Ok(0));
    assert_eq!(fs.stat(p("/f")).unwrap().len, 0);
}
#[test]
fn user_copy_rejects_kernel_code_guard_overflow_and_cross_boundary() {
    use usermem::*;
    let mut m = Arena::new();
    assert_eq!(m.write(BASE, b"x"), Err(Errno::Fault));
    assert_eq!(m.read(u64::MAX, 2), Err(Errno::Fault));
    assert_eq!(m.read(0xffffffc040200000, 1), Err(Errno::Fault));
    assert_eq!(m.read(BASE + 0x6000, 1), Err(Errno::Fault));
    assert_eq!(m.read(BASE + 0x5fff, 2), Err(Errno::Fault));
    assert_eq!(m.write(STACK_TOP - 1, b"xx"), Err(Errno::Fault));
    m.write(STACK_TOP - 2, b"x\0").unwrap();
    let mut b = [0; 4];
    assert_eq!(m.cstring(STACK_TOP - 2, &mut b), Ok(1));
    m.clear();
    assert_eq!(m.read(STACK_TOP - 2, 2), Ok(&[0, 0][..]));
}
fn elf() -> [u8; 8192] {
    let mut b = [0; 8192];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    for (i, v) in [(16, 2u16), (18, 183), (52, 64), (54, 56), (56, 2)] {
        b[i..i + 2].copy_from_slice(&v.to_le_bytes());
    }
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    for (i, v) in [(24, usermem::BASE), (32, 64)] {
        b[i..i + 8].copy_from_slice(&v.to_le_bytes());
    }
    for (p, flags, va, off, files) in [
        (64, 5u32, usermem::BASE, 4096u64, 4u64),
        (120, 6, usermem::BASE + 0x4000, 8192, 0),
    ] {
        b[p..p + 4].copy_from_slice(&1u32.to_le_bytes());
        b[p + 4..p + 8].copy_from_slice(&flags.to_le_bytes());
        for (i, v) in [
            (p + 8, off),
            (p + 16, va),
            (p + 32, files),
            (p + 40, 4096),
            (p + 48, 4096),
        ] {
            b[i..i + 8].copy_from_slice(&v.to_le_bytes());
        }
    }
    b[4096..4100].copy_from_slice(&[1, 2, 3, 4]);
    b
}
#[test]
fn elf_loader_validates_before_mutating_and_rejects_wx_interpreter_and_overflows() {
    let good = elf();
    let mut m = usermem::Arena::new();
    assert_eq!(image::load(&good, &mut m), Ok(usermem::BASE));
    assert_eq!(m.read(usermem::BASE, 4), Ok(&[1, 2, 3, 4][..]));
    for (i, bytes) in [
        (68, &7u32.to_le_bytes()[..]),
        (64, &3u32.to_le_bytes()[..]),
        (64 + 32, &u64::MAX.to_le_bytes()[..]),
        (32, &u64::MAX.to_le_bytes()[..]),
        (24, &(usermem::BASE + 0x4000).to_le_bytes()[..]),
    ] {
        let mut bad = good;
        bad[i..i + bytes.len()].copy_from_slice(bytes);
        assert_eq!(image::load(&bad, &mut m), Err(Errno::Inval));
        assert_eq!(m.read(usermem::BASE, 4), Ok(&[1, 2, 3, 4][..]));
    }
    for len in 0..176 {
        assert_eq!(image::load(&good[..len], &mut m), Err(Errno::Inval));
    }
}

#[test]
fn rmdir_dot_is_not_collapsed_into_a_removable_directory() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    process.mkdir(&mut fs, "/empty", 0o700).unwrap();
    assert_eq!(process.rmdir(&mut fs, "/empty/."), Err(Errno::Inval));
    assert_eq!(process.rmdir(&mut fs, "/empty/.///"), Err(Errno::Inval));
    assert!(fs.stat(p("/empty")).is_ok());
    assert_eq!(process.mkdir(&mut fs, "/", 0o700), Err(Errno::Exist));
}

#[test]
fn unified_socket_descriptors_share_status_but_not_close_on_exec() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    let fd = process
        .install_socket(0x101, O_NONBLOCK | O_CLOEXEC)
        .unwrap();
    let file = process
        .open(&mut fs, "/mixed", O_CREAT | O_RDWR, 0o600)
        .unwrap();
    assert_ne!(fd, file);
    let duplicate = process.dup(fd).unwrap();
    assert_eq!(process.socket(duplicate), Ok(Some(0x101)));
    assert_eq!(process.close_on_exec(fd), Ok(true));
    assert_eq!(process.close_on_exec(duplicate), Ok(false));
    assert_eq!(process.last_reference(fd), Ok(false));
    process.set_flags(duplicate, O_RDWR).unwrap();
    assert_eq!(process.flags(fd), Ok(O_RDWR));
    process.close(&mut fs, duplicate).unwrap();
    assert_eq!(process.last_reference(fd), Ok(true));
    process.close(&mut fs, fd).unwrap();
    assert_eq!(process.socket(fd), Err(Errno::Badf));
    assert_eq!(process.socket(file), Ok(None));
}

#[test]
fn readonly_boot_assets_use_real_offsets_stat_and_shared_open_descriptions() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    static ASSET: [u8; 12052] = [0xa5; 12052];
    assert_eq!(
        process.open_readonly(65536, &ASSET, O_RDWR),
        Err(Errno::Access)
    );
    let fd = process.open_readonly(65536, &ASSET, O_CLOEXEC).unwrap();
    let duplicate = process.dup(fd).unwrap();
    assert_eq!(process.fstat(&fs, fd).unwrap().size, 12052);
    assert_eq!(process.fstat(&fs, fd).unwrap().mode, 0o100444);
    process.lseek(&fs, fd, -2, 2).unwrap();
    let mut bytes = [0; 8];
    assert_eq!(process.read(&mut fs, duplicate, &mut bytes), Ok(2));
    assert_eq!(&bytes[..2], &[0xa5; 2]);
    assert_eq!(process.read(&mut fs, fd, &mut bytes), Ok(0));
    process.close_all(&mut fs).unwrap();
}

#[test]
fn fstat_of_unlinked_file_preserves_identity_until_last_close() {
    let mut fs = FileSystem::new();
    let objects = crate::OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    let fd = process
        .open(&mut fs, "/orphan-stat", O_CREAT | O_RDWR, 0o600)
        .unwrap();
    let before = process.fstat(&fs, fd).unwrap();
    assert_eq!(
        process.stat(&fs, "/orphan-stat").unwrap().inode,
        before.inode
    );
    process.unlink(&mut fs, "/orphan-stat").unwrap();
    let after = process.fstat(&fs, fd).unwrap();
    assert_eq!(after.inode, before.inode);
    assert_eq!(after.links, 0);
    assert_eq!(process.stat(&fs, "/orphan-stat"), Err(Errno::Noent));
    process.close(&mut fs, fd).unwrap();
}
