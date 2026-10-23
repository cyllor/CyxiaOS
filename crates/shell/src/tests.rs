extern crate std;
use super::*;
use std::string::String;
fn send(shell: &mut Shell, s: &[u8]) -> String {
    let mut out = String::new();
    for b in s {
        shell.input(*b, &mut out).unwrap();
    }
    out
}
#[test]
fn storage_requests_are_bounded_and_do_not_claim_durability() {
    let mut shell = Shell::new();
    let first = send(&mut shell, b"storage checkpoint\rstorage status\r");
    assert!(first.contains("STORAGE_REQUEST queued"));
    assert!(first.contains("storage request busy"));
    assert!(!first.contains("STORAGE_DURABLE"));
    assert_eq!(
        shell.take_storage_request(),
        Some(StorageRequest::Checkpoint)
    );
    assert_eq!(shell.take_storage_request(), None);
    assert!(send(&mut shell, b"storage checkpoint extra\r").contains("invalid arguments"));
    assert_eq!(shell.take_storage_request(), None);
}
#[test]
fn interactive_crud_and_ai_status() {
    let mut sh = Shell::new();
    let out = send(
        &mut sh,
        b"mkdir /docs\rcd /docs\rwrite note hello\rappend note world\rcat note\rai status\r",
    );
    assert!(out.contains("helloworld\r\n"));
    // One readable file has no cache contention; its read is a mechanism.
    assert!(out.contains("source=Mechanism"));
    assert!(out.contains("cyxia:/docs>"));
    assert!(!out.contains("error:"));
}
#[test]
fn editing_cancel_crlf_and_escape_keys() {
    let mut sh = Shell::new();
    let out = send(&mut sh, b"pwxx\x7f\x7fd\r\npw\x1b[Ad\rwrite /bad x\x03ls\r");
    assert_eq!(out.matches("cyxia:/>").count(), 4);
    assert!(!out.contains("unknown command"));
    assert_eq!(
        sh.fs.stat(Path::resolve(Path::ROOT, "/bad").unwrap()).err(),
        Some(Error::NotFound)
    );
}
#[test]
fn overflow_discards_entire_command_and_recovers() {
    let mut sh = Shell::new();
    send(&mut sh, b"write /bad ");
    for _ in 0..LINE_BYTES {
        send(&mut sh, b"x");
    }
    let out = send(&mut sh, b"\x7f\rstat /bad\rpwd\r");
    assert!(out.contains("command discarded"));
    assert!(out.contains("NotFound"));
    assert!(!out.contains("unknown command"));
}
#[test]
fn directory_removal_cannot_orphan_cwd_and_touch_preserves_data() {
    let mut sh = Shell::new();
    let out = send(
        &mut sh,
        b"mkdir /a\rcd /a\rrmdir /a\rwrite f content\rtouch f\rcat f\r",
    );
    assert!(out.contains("NotEmpty"));
    assert!(out.contains("content\r\n"));
}
#[test]
fn invalid_arguments_do_not_mutate_and_utf8_text_roundtrips() {
    let mut sh = Shell::new();
    let out = send(
        &mut sh,
        "mkdir /a extra\rstat /a\rwrite /hello 你好\rcat /hello\r".as_bytes(),
    );
    assert!(out.contains("invalid arguments"));
    assert!(out.contains("NotFound"));
    assert!(out.contains("你好\r\n"));
}
#[test]
fn shell_and_fs_fit_reserved_budget() {
    assert!(
        core::mem::size_of::<Shell>() - core::mem::size_of::<cyxia_ai_runtime::Runtime>()
            < 384 * 1024
    );
}

#[test]
fn process_list_keeps_every_supervisor_slot_including_the_last() {
    let mut shell = Shell::new();
    let processes = core::array::from_fn(|index| cyxia_posix::UserStatus {
        pid: index as u32 + 1,
        state: cyxia_posix::UserState::Running,
        ..cyxia_posix::UserStatus::EMPTY
    });
    shell.set_user_processes(processes);
    let out = send(&mut shell, b"posix list\r");
    assert_eq!(
        out.matches("EL0 UserStatus").count(),
        cyxia_posix::usermem::MAX_PROCESSES
    );
    for pid in 1..=cyxia_posix::usermem::MAX_PROCESSES {
        let prefix = std::format!("EL0 UserStatus {{ pid: {pid},");
        let row = out.lines().find(|line| line.contains(&prefix)).unwrap();
        assert!(row.contains("state: Running"));
    }
}

#[test]
fn damaged_input_discards_suffix_even_if_it_is_a_valid_command() {
    let mut sh = Shell::new();
    send(&mut sh, b"write /victim keep\rwrite /long prefix");
    sh.input_error();
    let out = send(&mut sh, b"\x03rm /victim\r\ncat /victim\r");
    assert!(out.contains("damaged input; command discarded"));
    assert!(out.contains("keep\r\n"));
}

#[test]
fn resource_commands_validate_arguments_and_use_owned_memory() {
    let mut sh = Shell::new();
    sh.runtime_mut().bind_devices(true, true).unwrap();
    let out=send(&mut sh,b"mem alloc 2\rmem poke 1 4096 173\rmem peek 1 4096\rmem free 1\rmem peek 1 0\rproc spawn compute 1000 2 1\rproc pause 2\rps\rdev list\rai resources\r");
    assert!(out.contains("byte=173"));
    assert!(out.contains("error: Stale"));
    assert!(out.contains("paused=true"));
    assert!(out.contains("Timer present=true"));
    assert!(out.contains("EL1 cooperative"));
    let before = sh.runtime_mut().memory_status().used;
    let out = send(
        &mut sh,
        b"proc spawn compute 1 1 1 extra\rmem alloc 1 extra\rmem poke 2 0 300\r",
    );
    assert_eq!(out.matches("invalid arguments").count(), 3);
    assert_eq!(sh.runtime_mut().memory_status().used, before);
}
#[test]
fn process_requests_validate_pid_and_preserve_queued_launch() {
    use cyxia_posix::{UserRequest, UserState, UserStatus};
    let mut shell = Shell::new();
    for text in [
        "posix kill 0\r",
        "posix kill -1\r",
        "posix kill 4294967296\r",
        "posix spawn unknown\r",
        "posix pair extra\r",
    ] {
        assert!(send(&mut shell, text.as_bytes()).contains("invalid arguments"));
        assert_eq!(shell.take_user_request(), None);
    }
    send(&mut shell, b"posix pair\rposix kill 2\r");
    assert_eq!(shell.take_user_request(), Some(UserRequest::Pair));
    send(&mut shell, b"posix kill 2\r");
    assert_eq!(shell.take_user_request(), Some(UserRequest::Kill(Some(2))));
    shell.set_user_status(UserStatus {
        state: UserState::Waiting,
        ..UserStatus::EMPTY
    });
    assert!(send(&mut shell, b"posix run demo\r").contains("user process busy"));
    assert_eq!(shell.take_user_request(), None);
    send(&mut shell, b"posix spawn idle\r");
    assert_eq!(shell.take_user_request(), Some(UserRequest::Spawn("idle")));
}

#[test]
fn system_snapshot_requests_are_bounded_read_only_and_not_fabricated() {
    let mut shell = Shell::new();
    assert!(!shell.take_system_request());
    let before = shell.fs.status().revision;
    let output = send(&mut shell, b"ai system extra\rai system\rai system\r");
    assert!(output.contains("invalid arguments"));
    assert_eq!(output.matches("AI_SYSTEM_REQUEST queued").count(), 1);
    assert!(output.contains("error: Busy"));
    // Only the real kernel can supply the full snapshot; parsing does not claim it.
    assert!(!output.contains("AI_SYSTEM_END"));
    assert!(shell.take_system_request());
    assert!(!shell.take_system_request());
    assert_eq!(shell.fs.status().revision, before);
}

#[test]
fn pressure_counts_runnable_work_only_and_clips_to_the_model_domain() {
    let mut shell = Shell::new();
    let mut rows = [cyxia_posix::UserStatus::EMPTY; cyxia_posix::usermem::MAX_PROCESSES];
    rows[0].state = cyxia_posix::UserState::Running;
    rows[1].state = cyxia_posix::UserState::Waiting;
    shell.set_user_processes(rows);
    assert_eq!(shell.runnable_work(), 1);
    send(&mut shell, b"proc spawn compute 10000 1 1\rproc pause 2\r");
    assert_eq!(shell.runnable_work(), 1);
    send(&mut shell, b"proc resume 2\r");
    assert_eq!(shell.runnable_work(), 2);
    for row in &mut rows {
        row.state = cyxia_posix::UserState::Running;
    }
    shell.set_user_processes(rows);
    assert_eq!(shell.runnable_work(), 8);
}
