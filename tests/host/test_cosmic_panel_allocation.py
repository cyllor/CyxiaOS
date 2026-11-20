"""Execute the actual panel allocation code with backend error injection.

Only containing GUI types and DisplayHandle are test doubles. The UnixStream
pair, helper body and three configured-group expressions are the real code.
The normal guest session separately exercises the genuine system backend.
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from doctor import RUST_BIN, env

BASE = ROOT / 'artifacts/cosmic-sources/cosmic-panel'
PORT = ROOT / 'ports/cosmic/native-panel-allocation-v2'
UTIL = 'cosmic-panel-bin/src/xdg_shell_wrapper/util.rs'
WRAPPER = 'cosmic-panel-bin/src/space/wrapper_space.rs'
PANEL = 'cosmic-panel-bin/src/space/panel_space.rs'


def function(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


class PanelAllocation(unittest.TestCase):
    def test_real_helper_and_configured_groups(self):
        with tempfile.TemporaryDirectory(prefix='cyxia-panel-allocation-test-') as temporary:
            directory = Path(temporary)
            for name in (UTIL, WRAPPER, PANEL):
                target = directory / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(BASE / name, target)
            if os.environ.get('PANEL_ALLOCATION_BASELINE') != '1':
                subprocess.run(['/usr/bin/git', 'apply', str(PORT / 'panel-allocation.patch')],
                               cwd=directory, check=True, capture_output=True)
            util = (directory / UTIL).read_text()
            wrapper = (directory / WRAPPER).read_text()
            helper = function(util, 'pub fn get_client_sock(')
            spawn = function(wrapper, '    fn spawn_clients(')
            begin = spawn.index('            *left_guard = self')
            end = spawn.index('            let mut desktop_ids:', begin)
            groups = spawn[begin:end]
            anchor = '                        let applet_tx_clone = applet_tx_clone.clone();\n'
            begin = spawn.index(anchor, spawn.index('.with_on_exit(')) + len(anchor)
            end = spawn.index('                        let security_context =', begin)
            exit_allocation = spawn[begin:end]
            fixture = r'''
use std::{io::{self, Read, Write}, os::unix::net::UnixStream, sync::{Arc, Mutex}};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicUsize, Ordering};
static INSERTIONS: AtomicUsize = AtomicUsize::new(0);
struct WrapperClientCompositorState { compositor_state: () }
struct Client { stream: UnixStream }
mod wayland_server {
    use super::*;
    pub struct DisplayHandle { pub fail: bool }
    impl DisplayHandle {
        pub fn insert_client(&mut self, stream: UnixStream,
                             data: Arc<WrapperClientCompositorState>) -> io::Result<Client> {
            let _ = data.compositor_state;
            INSERTIONS.fetch_add(1, Ordering::SeqCst);
            if self.fail { Err(io::Error::from_raw_os_error(24)) }
            else { Ok(Client { stream }) }
        }
    }
}
trait Outcome { fn result(self) -> io::Result<(Client, UnixStream)>; }
impl Outcome for (Client, UnixStream) {
    fn result(self) -> io::Result<Self> { Ok(self) }
}
impl Outcome for io::Result<(Client, UnixStream)> {
    fn result(self) -> Self { self }
}
struct PanelClient { name: String, _client: Option<Client>, _stream: Option<UnixStream> }
impl PanelClient {
    fn new(name: String, _: Option<std::path::PathBuf>, client: Client,
           stream: Option<UnixStream>) -> Self {
        Self { name, _client: Some(client), _stream: stream }
    }
    fn pending(name: String) -> Self { Self { name, _client: None, _stream: None } }
}
struct Config;
impl Config {
    fn plugins_left(&self) -> Option<Vec<String>> { Some((0..6).map(|i| format!("left-{i}")).collect()) }
    fn plugins_center(&self) -> Option<Vec<String>> { Some((0..6).map(|i| format!("center-{i}")).collect()) }
    fn plugins_right(&self) -> Option<Vec<String>> { Some((0..6).map(|i| format!("right-{i}")).collect()) }
}
struct Panel {
    config: Config,
    clients_left: Mutex<Vec<PanelClient>>,
    clients_center: Mutex<Vec<PanelClient>>,
    clients_right: Mutex<Vec<PanelClient>>,
}
impl Panel {
    fn configured(&self, mut display: wayland_server::DisplayHandle) -> Vec<String> {
        let mut left_guard = self.clients_left.lock().unwrap();
        let mut center_guard = self.clients_center.lock().unwrap();
        let mut right_guard = self.clients_right.lock().unwrap();
        GROUPS
        left_guard.iter().chain(center_guard.iter()).chain(right_guard.iter())
            .map(|c| c.name.clone()).collect()
    }
}
HELPER
fn allocate_for_exit(is_restarting: bool, err_code: Option<i32>) {
    let mut display_handle = wayland_server::DisplayHandle { fail: false };
    EXIT_ALLOCATION
    let _: Vec<(String, String)> = applet_env;
    let _: Vec<OwnedFd> = fds;
}
#[test]
fn clean_or_stopped_children_do_not_allocate_replacements() {
    for (restarting, code) in [(false, None), (false, Some(1)), (true, None)] {
        INSERTIONS.store(0, Ordering::SeqCst);
        allocate_for_exit(restarting, code);
        assert_eq!(INSERTIONS.load(Ordering::SeqCst), 0);
    }
    INSERTIONS.store(0, Ordering::SeqCst);
    allocate_for_exit(true, Some(1));
    assert_eq!(INSERTIONS.load(Ordering::SeqCst), 1);
}
#[test]
fn configured_ids_do_not_allocate_before_desktop_resolution() {
    INSERTIONS.store(0, Ordering::SeqCst);
    let panel = Panel { config: Config, clients_left: Mutex::new(vec![]),
        clients_center: Mutex::new(vec![]), clients_right: Mutex::new(vec![]) };
    let ids = panel.configured(wayland_server::DisplayHandle { fail: false });
    assert_eq!(ids.len(), 18, "all configured occurrences must remain available for lookup");
    assert_eq!(ids[0], "left-0"); assert_eq!(ids[6], "center-0"); assert_eq!(ids[12], "right-0");
    assert_eq!(INSERTIONS.load(Ordering::SeqCst), 0,
        "missing desktop entries must not allocate Wayland clients");
}
#[test]
fn backend_emfile_is_returned_without_unwinding() {
    let result = std::panic::catch_unwind(|| {
        get_client_sock(&mut wayland_server::DisplayHandle { fail: true }).result()
    });
    assert!(result.is_ok(), "a real backend allocation error must not panic");
    match result.unwrap() {
        Err(error) => assert_eq!(error.raw_os_error(), Some(24)),
        Ok(_) => panic!("backend EMFILE was lost"),
    }
}
#[test]
fn healthy_pair_keeps_both_streams_live() {
    let (mut client, mut stream) = get_client_sock(&mut wayland_server::DisplayHandle { fail: false })
        .result().unwrap();
    stream.write_all(b"ok").unwrap();
    let mut data = [0; 2]; client.stream.read_exact(&mut data).unwrap();
    assert_eq!(&data, b"ok");
}
'''.replace('GROUPS', groups).replace('HELPER', helper).replace('EXIT_ALLOCATION', exit_allocation)
            source = directory / 'allocation.rs'
            source.write_text(fixture)
            binary = directory / 'allocation'
            compiled = subprocess.run([str(RUST_BIN / 'rustc'), '--edition=2024', '--test',
                                       str(source), '-o', str(binary)], env=env(),
                                      capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary), '--test-threads=1'], capture_output=True,
                                 text=True, timeout=10)
            if receipt := os.environ.get('PANEL_ALLOCATION_RECEIPT'):
                Path(receipt).write_text(run.stdout + run.stderr)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main()
