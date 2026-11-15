use cyxia_ai_fs::{FileSystem, Path};
use cyxia_posix::{
    Console, Errno, O_APPEND, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW,
    O_NONBLOCK, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, OPEN_MAX, OpenDescriptions, Process,
};

struct NoConsole;
impl Console for NoConsole {
    fn write(&mut self, _: &[u8]) -> Result<usize, Errno> {
        panic!("null writes must not reach the console")
    }
}

#[test]
fn null_returns_eof_discards_writes_and_enforces_access_modes() {
    let objects = OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    let mut fs = FileSystem::new();
    for mode in [O_RDONLY, O_WRONLY, O_RDWR] {
        let fd = process.open_null(mode).unwrap();
        let mut bytes = [0xa5; 17];
        assert_eq!(
            process.read(&mut fs, fd, &mut bytes),
            if mode == O_WRONLY { Err(Errno::Badf) } else { Ok(0) },
        );
        assert_eq!(bytes, [0xa5; 17]);
        assert_eq!(
            process.write(&mut fs, &mut NoConsole, fd, &[0x5a; 257]),
            if mode == O_RDONLY { Err(Errno::Badf) } else { Ok(257) },
        );
        let info = process.fstat(&fs, fd).unwrap();
        assert_eq!(info.mode, 0o20666);
        assert_eq!(info.size, 0);
        assert_eq!(info.links, 1);
        assert_eq!(process.close(&mut fs, fd), Ok(None));
    }
    process.close_all(&mut fs).unwrap();
    assert_eq!(objects.snapshot().live, 0);
}

#[test]
fn null_creation_flags_do_not_create_storage_and_dup_keeps_shared_status() {
    let objects = OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    let mut fs = FileSystem::new();
    let fd = process
        .open_null(O_RDWR | O_CREAT | O_TRUNC | O_APPEND | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        .unwrap();
    assert_eq!(process.flags(fd), Ok(O_RDWR | O_APPEND | O_NONBLOCK | O_NOFOLLOW));
    assert!(process.close_on_exec(fd).unwrap());
    let alias = process.dup(fd).unwrap();
    assert!(!process.close_on_exec(alias).unwrap());
    process.set_flags(alias, O_RDWR).unwrap();
    assert_eq!(process.flags(fd).unwrap() & (O_APPEND | O_NONBLOCK), 0);
    assert!(process.close_on_exec(fd).unwrap());
    process.close(&mut fs, fd).unwrap();
    assert_eq!(process.write(&mut fs, &mut NoConsole, alias, b"discard"), Ok(7));
    assert_eq!(process.read(&mut fs, alias, &mut [0; 1]), Ok(0));
    process.close_all(&mut fs).unwrap();
    assert_eq!(objects.snapshot().live, 0);
}

#[test]
fn null_rejects_invalid_flags_before_allocating_a_description() {
    let objects = OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    let before = objects.snapshot();
    for (flags, error) in [
        (3, Errno::Inval),
        (1 << 31, Errno::Inval),
        (O_DIRECTORY, Errno::Notdir),
        (O_RDWR | O_DIRECTORY, Errno::Notdir),
        (O_CREAT | O_EXCL, Errno::Exist),
    ] {
        assert_eq!(process.open_null(flags), Err(error));
        assert_eq!(objects.snapshot(), before);
    }
    let mut fs = FileSystem::new();
    // Truncation has no content to remove from this character device, even
    // when opened read-only. O_EXCL alone does not request exclusive creation.
    for flags in [O_RDONLY | O_TRUNC, O_RDONLY | O_EXCL] {
        let fd = process.open_null(flags).unwrap();
        assert_eq!(process.flags(fd), Ok(O_RDONLY));
        process.close(&mut fs, fd).unwrap();
    }
    process.close_all(&mut fs).unwrap();
}

#[test]
fn null_descriptor_exhaustion_does_not_leak_or_replace_live_handles() {
    let objects = OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    for expected in 3..OPEN_MAX {
        assert_eq!(process.open_null(O_RDWR), Ok(expected as i32));
    }
    let before = objects.snapshot();
    assert_eq!(process.open_null(O_RDWR), Err(Errno::Mfile));
    assert_eq!(objects.snapshot(), before);
    let mut fs = FileSystem::new();
    assert_eq!(process.read(&mut fs, 3, &mut [0; 1]), Ok(0));
    assert_eq!(process.write(&mut fs, &mut NoConsole, 3, b"still-live"), Ok(10));
    process.close_all(&mut fs).unwrap();
    assert_eq!(objects.snapshot().live, 0);
}

fn device_parent(process: &mut Process<'_>, fs: &mut FileSystem) {
    process.mkdir(fs, "/dev", 0o755).unwrap();
    fs.register_boot_file(Path::resolve(Path::ROOT, "/dev/null").unwrap()).unwrap();
}

#[test]
fn null_path_open_and_stat_are_shared_with_native_process_operations() {
    let objects = OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    let mut fs = FileSystem::new();
    device_parent(&mut process, &mut fs);
    for path in ["/dev/null", "/dev//null", "/dev/./null"] {
        assert_eq!(process.stat(&fs, path), Ok(cyxia_posix::NULL_DEVICE_INFO));
        let fd = process.open(&mut fs, path, O_RDWR | O_CREAT, 0o600).unwrap();
        assert_eq!(process.fstat(&fs, fd), process.stat(&fs, path));
        assert_eq!(process.write(&mut fs, &mut NoConsole, fd, b"discard"), Ok(7));
        assert_eq!(process.read(&mut fs, fd, &mut [0xa5; 1]), Ok(0));
        process.close(&mut fs, fd).unwrap();
    }
    let directory = process.open(&mut fs, "/dev", O_DIRECTORY, 0).unwrap();
    let resolved = process.path_at(&fs, directory, "null").unwrap();
    let fd = process.open_resolved(&mut fs, resolved, O_RDWR, 0).unwrap();
    assert_eq!(process.stat_resolved(&fs, resolved), process.fstat(&fs, fd));
    assert_eq!(fs.stat(resolved).err(), Some(cyxia_ai_fs::Error::NotFound));
    process.close_all(&mut fs).unwrap();
}

#[test]
fn null_path_rejects_hidden_directory_socket_and_mutation_aliases() {
    let objects = OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    let mut fs = FileSystem::new();
    device_parent(&mut process, &mut fs);
    assert_eq!(process.mkdir(&mut fs, "/dev/null", 0o700), Err(Errno::Exist));
    assert_eq!(process.socket_path(&fs, "/dev/null", true), Err(Errno::Addrinuse));
    assert_eq!(process.socket_path(&fs, "/dev/null", false), Err(Errno::Connrefused));
    assert_eq!(process.unlink(&mut fs, "/dev/null"), Err(Errno::Rofs));
    assert_eq!(process.chmod(&mut fs, "/dev/null", 0o600), Err(Errno::Rofs));
    assert_eq!(process.rmdir(&mut fs, "/dev/null"), Err(Errno::Notdir));
    assert_eq!(process.chdir(&fs, "/dev/null"), Err(Errno::Notdir));
    assert_eq!(process.stat(&fs, "/dev/null"), Ok(cyxia_posix::NULL_DEVICE_INFO));
    process.close_all(&mut fs).unwrap();
}

#[test]
fn null_path_cannot_be_renamed_or_replaced_by_a_regular_file() {
    let objects = OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    let mut fs = FileSystem::new();
    device_parent(&mut process, &mut fs);
    let other = "/dev/null-other";
    let fd = process.open(&mut fs, other, O_CREAT | O_RDWR, 0o600).unwrap();
    process.write(&mut fs, &mut NoConsole, fd, b"keep").unwrap();
    let source = process.resolved_path(&fs, other).unwrap();
    let device = process.resolved_path(&fs, "/dev/null").unwrap();
    assert_eq!(process.rename_file_resolved(&mut fs, source, device, false), Err(Errno::Rofs));
    assert_eq!(process.rename_file_resolved(&mut fs, device, source, false), Err(Errno::Rofs));
    assert_eq!(process.rename_file_resolved(&mut fs, device, device, false), Err(Errno::Rofs));
    process.lseek(&fs, fd, 0, 0).unwrap();
    let mut bytes = [0; 4];
    assert_eq!(process.read(&mut fs, fd, &mut bytes), Ok(4));
    assert_eq!(&bytes, b"keep");
    assert_eq!(process.stat(&fs, other).unwrap().mode & 0o170000, 0o100000);
    process.close_all(&mut fs).unwrap();
}

#[test]
fn null_intermediate_components_and_trailing_slash_are_not_directories() {
    let objects = OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    let mut fs = FileSystem::new();
    device_parent(&mut process, &mut fs);
    for path in ["/dev/null/", "/dev/null/child", "/dev/null/.", "/dev/null/../null"] {
        assert_eq!(process.resolved_path(&fs, path), Err(Errno::Notdir));
        assert_eq!(process.open(&mut fs, path, O_RDWR | O_CREAT, 0o600), Err(Errno::Notdir));
    }
    process.close_all(&mut fs).unwrap();
}

#[test]
fn null_path_keeps_real_parent_permissions_and_permanent_child_protection() {
    let objects = OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    let mut fs = FileSystem::new();
    device_parent(&mut process, &mut fs);
    assert_eq!(process.rmdir(&mut fs, "/dev"), Err(Errno::Notempty));
    process.chmod(&mut fs, "/dev", 0o600).unwrap();
    assert_eq!(process.open(&mut fs, "/dev/null", O_RDWR, 0), Err(Errno::Access));
    assert_eq!(process.stat(&fs, "/dev/null"), Err(Errno::Access));
    assert_eq!(process.socket_path(&fs, "/dev/null", true), Err(Errno::Access));
    process.close_all(&mut fs).unwrap();
}
