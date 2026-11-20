//! The exact panel helper and compositor client data are injected from the
//! independently verified full panel source, using its actual system backend.
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use smithay::reexports::wayland_server::{self, Client};
use smithay::reexports::wayland_server::backend::{ClientData, ClientId, DisconnectReason};
use smithay::wayland::compositor::CompositorClientState;

include!(env!("CYXIA_PANEL_ALLOCATION_HELPER"));

fn duplicate_stdout() -> std::io::Result<OwnedFd> {
    // This probe owns no stdout lifetime; cloning yields an independent FD.
    unsafe { BorrowedFd::borrow_raw(1) }.try_clone_to_owned()
}

fn main() {
    println!("PANEL_ALLOCATION_PROBE START");
    let display = wayland_server::Display::<()>::new().unwrap();
    let mut handle = display.handle();
    let (client, stream) = get_client_sock(&mut handle).unwrap();
    let credentials = client.get_credentials(&handle).unwrap();
    assert_eq!(credentials.pid, std::process::id() as i32);
    assert_eq!(credentials.uid, 0);
    assert!(stream.as_fd().try_clone_to_owned().is_ok());
    println!("PANEL_ALLOCATION_PROBE HEALTHY_CLIENT PASS");
    drop((client, stream));

    let mut held = Vec::new();
    loop {
        match duplicate_stdout() {
            Ok(fd) => held.push(fd),
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(24));
                break;
            }
        }
    }
    let error = get_client_sock(&mut handle).err().expect("full FD table must fail");
    assert_eq!(error.raw_os_error(), Some(24));
    println!("PANEL_ALLOCATION_PROBE PAIR_EMFILE PASS");

    assert!(held.len() >= 2);
    drop(held.pop());
    drop(held.pop());
    // The pair fits; the genuine system backend's additional FD clone does not.
    let error = get_client_sock(&mut handle).err().expect("backend clone must fail");
    assert_eq!(error.raw_os_error(), Some(24));
    println!("PANEL_ALLOCATION_PROBE INSERT_EMFILE PASS");
    let mut restored = Vec::new();
    loop {
        match duplicate_stdout() {
            Ok(fd) => restored.push(fd),
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(24));
                break;
            }
        }
    }
    assert_eq!(restored.len(), 2, "failed insertion must return both pair FDs");
    println!("PANEL_ALLOCATION_PROBE FAILURE_REFUND PASS");
    drop((held, restored));
    let (client, stream) = get_client_sock(&mut handle).unwrap();
    assert_eq!(client.get_credentials(&handle).unwrap().pid, std::process::id() as i32);
    drop((client, stream, handle, display));
    println!("PANEL_ALLOCATION_PROBE RECOVERY PASS");
    println!("PANEL_ALLOCATION_PROBE PASS");
}
