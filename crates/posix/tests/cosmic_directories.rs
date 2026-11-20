use cyxia_ai_fs::{FileSystem, Kind, Path};
use cyxia_posix::{Errno, runtime_directory as session};

fn path(name: &str) -> Path {
    Path::resolve(Path::ROOT, name).unwrap()
}

#[test]
fn fresh_boot_provides_actual_config_and_state_watch_roots() {
    let mut fs = FileSystem::new();
    session::reset_at_boot(&mut fs).unwrap();
    session::prepare_cosmic(&mut fs).unwrap();
    for name in [
        "/.config/cosmic",
        "/.local/state/cosmic",
        "/run/user/0/.config/cosmic",
        "/run/user/0/.local/state/cosmic",
    ] {
        let entry = fs.stat(path(name)).unwrap();
        assert_eq!(entry.kind, Kind::Directory);
        assert_eq!(entry.mode, 0o700);
    }
}

#[test]
fn reboot_preserves_durable_user_data_and_clears_runtime_data() {
    let mut fs = FileSystem::new();
    session::reset_at_boot(&mut fs).unwrap();
    session::prepare_cosmic(&mut fs).unwrap();
    fs.write(path("/.local/state/cosmic/saved"), b"user", false)
        .unwrap();
    fs.write(
        path("/run/user/0/.local/state/cosmic/stale"),
        b"temporary",
        false,
    )
    .unwrap();
    session::reset_at_boot(&mut fs).unwrap();
    session::prepare_cosmic(&mut fs).unwrap();
    let mut value = [0; 4];
    assert_eq!(
        fs.read(path("/.local/state/cosmic/saved"), &mut value)
            .unwrap(),
        4
    );
    assert_eq!(&value, b"user");
    assert!(
        fs.stat(path("/run/user/0/.local/state/cosmic/stale"))
            .is_err()
    );
}

#[test]
fn repeated_preparation_preserves_existing_modes_and_identity() {
    let mut fs = FileSystem::new();
    session::reset_at_boot(&mut fs).unwrap();
    session::prepare_cosmic(&mut fs).unwrap();
    let directory = path("/.config");
    fs.set_mode(directory, 0o710).unwrap();
    let identity = fs.identity(directory).unwrap();
    session::prepare_cosmic(&mut fs).unwrap();
    assert_eq!(fs.identity(directory).unwrap(), identity);
    assert_eq!(fs.stat(directory).unwrap().mode, 0o710);
}

#[test]
fn conflicting_user_file_is_rejected_without_replacement() {
    let mut fs = FileSystem::new();
    session::reset_at_boot(&mut fs).unwrap();
    fs.write(path("/.local"), b"keep", false).unwrap();
    assert_eq!(session::prepare_cosmic(&mut fs), Err(Errno::Notdir));
    let mut bytes = [0; 4];
    assert_eq!(fs.read(path("/.local"), &mut bytes).unwrap(), 4);
    assert_eq!(&bytes, b"keep");
}
