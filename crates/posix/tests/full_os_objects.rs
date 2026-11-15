#![cfg(feature = "full-os")]
use cyxia_ai_fs::FileSystem;
use cyxia_posix::{Errno, OpenDescriptions, Process};

#[test]
fn full_os_accepts_real_desktop_descriptor_shape_with_global_bounds() {
    let objects = OpenDescriptions::new();
    let mut fs = FileSystem::new();
    let mut process = Process::new(&objects, 1).unwrap();
    for expected in 3..64 {
        assert_eq!(process.eventfd(0, 0), Ok(expected));
    }
    assert_eq!(process.eventfd(0, 0), Err(Errno::Mfile));
    process.close_all(&mut fs).unwrap();
    let mut process = Process::new(&objects, 1).unwrap();
    for _ in 0..16 {
        process.epoll_create(0).unwrap();
    }
    assert_eq!(process.epoll_create(0), Err(Errno::Mfile));
    assert_eq!(objects.snapshot().capacity, 256);
    process.close_all(&mut fs).unwrap();
    assert_eq!(objects.snapshot().live, 0);
}
