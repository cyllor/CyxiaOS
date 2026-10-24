use cyxia_ai_fs::FileSystem;
use cyxia_posix::*;
#[test]
fn audit_getfl_setfl_round_trip_after_create_does_not_change_access() {
    let o = OpenDescriptions::new();
    let mut p = Process::new(&o, 1).unwrap();
    let mut fs = FileSystem::new();
    let fd = p
        .open(
            &mut fs,
            "/new",
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
            0o600,
        )
        .unwrap();
    let flags = p.flags(fd).unwrap();
    assert_eq!(p.set_flags(fd, flags | O_NONBLOCK), Ok(()));
    assert_eq!(p.flags(fd).unwrap() & 3, O_RDWR);
    assert_eq!(
        p.flags(fd).unwrap() & (O_CREAT | O_EXCL | O_TRUNC | O_CLOEXEC),
        0
    );
    assert!(p.close_on_exec(fd).unwrap());
}
#[test]
fn audit_directory_getfl_round_trip() {
    let o = OpenDescriptions::new();
    let mut p = Process::new(&o, 1).unwrap();
    let mut fs = FileSystem::new();
    let fd = p.open(&mut fs, "/", O_DIRECTORY | O_NOFOLLOW, 0).unwrap();
    assert_eq!(p.set_flags(fd, p.flags(fd).unwrap() | O_NONBLOCK), Ok(()));
    assert_eq!(p.flags(fd).unwrap() & 3, O_RDONLY);
}
#[test]
fn audit_setfl_changes_shared_status_not_access_or_descriptor_flags() {
    let o = OpenDescriptions::new();
    let mut p = Process::new(&o, 1).unwrap();
    let mut fs = FileSystem::new();
    let fd = p
        .open(&mut fs, "/new", O_CREAT | O_RDONLY | O_CLOEXEC, 0o600)
        .unwrap();
    let alias = p.dup(fd).unwrap();
    p.set_flags(
        alias,
        O_WRONLY | O_TRUNC | O_CLOEXEC | O_APPEND | O_NONBLOCK,
    )
    .unwrap();
    assert_eq!(p.flags(fd).unwrap() & 3, O_RDONLY);
    assert_eq!(p.flags(alias), p.flags(fd));
    assert_eq!(
        p.flags(fd).unwrap() & (O_APPEND | O_NONBLOCK),
        O_APPEND | O_NONBLOCK
    );
    assert!(p.close_on_exec(fd).unwrap());
    assert!(!p.close_on_exec(alias).unwrap());
    let before = p.flags(fd);
    assert_eq!(p.set_flags(fd, 1 << 31), Err(Errno::Inval));
    assert_eq!(p.flags(fd), before);
}
