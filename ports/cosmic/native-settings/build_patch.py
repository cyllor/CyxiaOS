#!/usr/bin/env python3
"""Export pinned settings sources and an ordinary native-feature patch; no Cargo.

Run source generation only under the root native lease. Input checkouts remain
read-only. Every replacement has an exact string or digest-bound preimage.
"""
import argparse
import difflib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[3]
PORT = Path(__file__).resolve().parent
SETTINGS_COMMIT = "9e4ae69fc175191f15789d35423806ea0f093c9d"
SETTINGS_TREE = "c2abb89d6b4bdd04a5f6d86cae144ba987639423"
COMP_COMMIT = "41497b42d9744d9963c4c6d17e8add49489b45ee"
COMP_TREE = "d383b640ebdd63b96f9d8ff35388827d693214d1"
RANDR_COMMIT = "6e8e795970fa06d434af22775e415b517f7552d3"
SOURCE_LOCK = "fc741c0a4f9b94a09d89a292aa94b402e1eb9ea4a4426d7e85c85999d8ea854e"
WAYLAND_SYS_VERSION = "0.31.11"
WAYLAND_SYS_PACKAGE = "d8eab23fefc9e41f8e841df4a9c707e8a8c4ed26e944ef69297184de2785e3be"
REGISTRY_CACHE = ROOT / 'artifacts/cosmic-cargo-cache/registry'
REGISTRY_INDEX = 'index.crates.io-1949cf8c6b5b557f'
MAX_LOCK_BYTES = 2 * 1024 * 1024
MAX_PATH_BYTES = 4096


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(path.read_bytes()) if path.exists() else None


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args])


def relative(path):
    path = path.resolve()
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


def read_resolved_lock(path):
    """Read a bounded regular lock input without accepting symlink aliases."""
    path = path.absolute()
    if len(os.fsencode(path)) > MAX_PATH_BYTES:
        raise ValueError('resolved lock path exceeds the bounded path length')
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise ValueError('resolved lock must not use symlinks')
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('resolved lock must be a regular file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_LOCK_BYTES:
            raise ValueError('resolved lock must be a nonempty regular file of at most 2 MiB')
        data = stream.read(MAX_LOCK_BYTES + 1)
        if len(data) != info.st_size or len(data) > MAX_LOCK_BYTES:
            raise ValueError('resolved lock changed size while reading')
    parsed = tomllib.loads(data.decode('utf-8'))
    packages = parsed.get('package')
    if not isinstance(packages, list) or not packages:
        raise ValueError('resolved lock has no package inventory')
    for name, version in (('cosmic-settings-daemon', '1.10.0'), ('cosmic-comp-config', '1.0.0'),
                          ('wayland-sys', WAYLAND_SYS_VERSION)):
        selected = [entry for entry in packages if entry.get('name') == name and entry.get('version') == version]
        if len(selected) != 1 or 'source' in selected[0]:
            raise ValueError(f'resolved lock does not retain the local {name} {version} package')
    return path.resolve(strict=True), data


def snapshot(source, commit, tree):
    source = source.resolve(strict=True)
    if git(source, "rev-parse", "HEAD").decode().strip() != commit:
        raise ValueError(f"wrong source HEAD: {source}")
    if git(source, "rev-parse", "HEAD^{tree}").decode().strip() != tree:
        raise ValueError(f"wrong pinned Git tree: {source}")
    files, content, modes = {}, {}, {}
    for record in git(source, "ls-tree", "-rz", commit).split(b"\0"):
        if not record:
            continue
        header, name = record.split(b"\t", 1)
        mode, kind, blob = header.decode().split()
        name = name.decode()
        if kind != "blob" or mode not in ("100644", "100755"):
            raise ValueError(f"non-regular source entry: {name}")
        path = source / name
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
            raise ValueError(f"symlink source entry: {path}")
        data = git(source, "cat-file", "blob", blob)
        if path.read_bytes() != data:
            raise ValueError(f"modified source preimage: {path}")
        files[name], content[name], modes[name] = digest(data), data, int(mode, 8) & 0o777
    return (dict(path=relative(source), commit=commit, git_tree=tree, files=files,
                 tree_sha256=digest(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())),
            content, modes)


def registry_snapshot(source, archive):
    """Bind registry bytes to the locked .crate checksum, never to a Git identity.

    Modern Cargo cache extraction may omit .cargo-checksum.json. In that case
    the exact checksum-verified archive is the authoritative per-file inventory.
    If the checksum manifest exists, validate it against the same inventory.
    """
    for path in (source, archive):
        if path.is_symlink() or any(parent.is_symlink() for parent in path.absolute().parents):
            raise ValueError(f'symlink registry input: {path}')
    source, archive = source.resolve(strict=True), archive.resolve(strict=True)
    if not source.is_dir() or not archive.is_file() or not 0 < archive.stat().st_size <= MAX_LOCK_BYTES:
        raise ValueError('invalid bounded registry source/archive input')
    packed = archive.read_bytes()
    if digest(packed) != WAYLAND_SYS_PACKAGE:
        raise ValueError('wayland-sys archive differs from the pinned Cargo package checksum')
    prefix = f'wayland-sys-{WAYLAND_SYS_VERSION}/'
    content, modes, expanded = {}, {}, 0
    with tarfile.open(fileobj=io.BytesIO(packed), mode='r:gz') as tar:
        for member in tar:
            if member.isdir():
                continue
            if not member.isfile() or not member.name.startswith(prefix):
                raise ValueError(f'non-regular registry archive member: {member.name}')
            name = member.name[len(prefix):]
            parts = Path(name).parts
            if not parts or Path(name).is_absolute() or any(part in ('.', '..') for part in parts) or name in content:
                raise ValueError(f'invalid registry archive path: {name}')
            expanded += member.size
            if member.size > MAX_LOCK_BYTES or expanded > 32 * 1024 * 1024:
                raise ValueError(f'oversized registry source member: {name}')
            data = tar.extractfile(member).read(MAX_LOCK_BYTES + 1)
            path = source / name
            if path.is_symlink() or any(parent.is_symlink() for parent in path.parents) or not stat.S_ISREG(path.stat().st_mode):
                raise ValueError(f'non-regular registry source entry: {name}')
            if len(data) != member.size or path.read_bytes() != data:
                raise ValueError(f'modified registry preimage: {name}')
            content[name], modes[name] = data, member.mode & 0o777
    if 'LICENSE.txt' not in content:
        raise ValueError('registry source license is missing')
    files = {name: digest(data) for name, data in content.items()}
    observed = set()
    for path in source.rglob('*'):
        if path.is_symlink():
            raise ValueError(f'symlink registry source entry: {path}')
        if path.is_file():
            name = str(path.relative_to(source))
            if name not in ('.cargo-ok', '.cargo-checksum.json'):
                observed.add(name)
        elif not path.is_dir():
            raise ValueError(f'non-regular registry source entry: {path}')
    if observed != set(files):
        raise ValueError('registry extraction inventory differs from the pinned archive')
    checksum_manifest = source / '.cargo-checksum.json'
    checksum_identity = None
    if checksum_manifest.exists():
        checksums = json.loads(checksum_manifest.read_bytes())
        if checksums.get('package') != WAYLAND_SYS_PACKAGE or checksums.get('files') != files:
            raise ValueError('registry checksum manifest differs from the pinned archive inventory')
        checksum_identity = dict(path=relative(checksum_manifest), sha256=sha(checksum_manifest))
    identity = dict(path=relative(source), package='wayland-sys', version=WAYLAND_SYS_VERSION,
                    source='registry+https://github.com/rust-lang/crates.io-index',
                    checksum=WAYLAND_SYS_PACKAGE, archive=relative(archive),
                    archive_sha256=digest(packed), files=files,
                    tree_sha256=digest(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()),
                    checksum_manifest=checksum_identity)
    return identity, content, modes


def materialize(destination, content, modes):
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in content.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(modes[name])


def replace(path, old, new):
    value = path.read_text()
    if value.count(old) != 1:
        raise ValueError(f"ambiguous patch preimage: {path}: {old[:80]!r}")
    path.write_text(value.replace(old, new))


def region(path, start, end, expected, transform):
    """Transform exactly one fixed, SHA256-bound source region."""
    value = path.read_text()
    if value.count(start) != 1:
        raise ValueError(f"ambiguous region start: {path}: {start!r}")
    first = value.index(start)
    if value[first:].count(end) != 1:
        raise ValueError(f"ambiguous region end: {path}: {end!r}")
    last = value.index(end, first)
    old = value[first:last]
    if digest(old.encode()) != expected:
        raise ValueError(f"changed region preimage: {path}: {start!r}")
    path.write_text(value[:first] + transform(old) + value[last:])


def gated_block(old, feature, indent):
    pad = " " * indent
    return pad + f'#[cfg(feature = "{feature}")]\n' + pad + "{\n" + "".join(
        "    " + line if line.strip() else line for line in old.splitlines(keepends=True)
    ) + pad + "}\n"


def gate_mono_branch(old):
    first, body = old.split('\n', 1)
    closing = '                            }'
    if not body.endswith(closing):
        raise ValueError('mono branch closing preimage mismatch')
    body = body[:-len(closing)]
    return first + '\n' + gated_block(body, 'audio', 32) + closing


def patch_wayland_sys(source):
    replace(source / 'Cargo.toml', '[features]\n',
            '[features]\ncyxia-static-client = ["client", "dlopen"]\n')
    client = source / 'src/client.rs'
    replace(client, 'pub enum wl_proxy {}',
            (PORT / 'wayland-client-static.rs.inc').read_text() + 'pub enum wl_proxy {}')
    replace(client, '''    static WAYLAND_CLIENT_OPTION: Lazy<Option<WaylandClient>> = Lazy::new(||{''',
            '''    #[cfg(feature = "cyxia-static-client")]
    static WAYLAND_CLIENT_OPTION: Lazy<Option<WaylandClient>> =
        Lazy::new(|| Some(WaylandClient::linked()));
    #[cfg(not(feature = "cyxia-static-client"))]
    static WAYLAND_CLIENT_OPTION: Lazy<Option<WaylandClient>> = Lazy::new(||{''')
    replace(source / 'build.rs', '''    if std::env::var_os("CARGO_FEATURE_DLOPEN").is_some() {
        // Do not link to anything
        return;
    }''', '''    if std::env::var_os("CARGO_FEATURE_DLOPEN").is_some() {
        if std::env::var_os("CARGO_FEATURE_CYXIA_STATIC_CLIENT").is_some() {
            // The client table contains actual static library addresses. Other
            // dlopen-enabled modules retain their original loading behavior.
            Config::new().statik(true).probe("wayland-client").unwrap();
        }
        return;
    }''')


def patch_config(source):
    manifest = source / "Cargo.toml"
    replace(manifest, 'cosmic-randr-shell = { git = "https://github.com/pop-os/cosmic-randr/", optional = true }',
            f'cosmic-randr-shell = {{ git = "https://github.com/pop-os/cosmic-randr/", rev = "{RANDR_COMMIT}", optional = true }}')
    replace(manifest, 'input = "0.10.0"', 'input = { version = "0.10.0", optional = true }')
    replace(manifest, 'default = []', 'default = ["libinput"]\nlibinput = ["dep:input"]')
    path = source / "src/input.rs"
    replace(path, 'pub use input::{AccelProfile, ClickMethod, ScrollMethod, TapButtonMap};\nuse serde::{Deserialize, Serialize};\n',
            (PORT / "config-enums.rs.inc").read_text())
    for name in ("ClickMethod", "AccelProfile", "ScrollMethod", "TapButtonMap"):
        replace(path, f"use input::{name} as {name}Orig;", f"use super::{name} as {name}Orig;")


def patch_settings(source):
    manifest = source / "Cargo.toml"
    replace(manifest, '[dependencies]\n', '''[features]
default = ["audio", "backlight"]
audio = ["dep:cosmic-settings-audio-server", "dep:cosmic-settings-varlink-server"]
backlight = ["dep:udev", "dep:ddc-hi", "cosmic-comp-config/libinput"]
cyxia-native = ["dep:wayland-sys"]

[dependencies]
wayland-sys = { path = "native-deps/wayland-sys", optional = true, default-features = false, features = ["cyxia-static-client"] }
''')
    with manifest.open('a') as stream:
        stream.write('\n[patch.crates-io]\nwayland-sys = { path = "native-deps/wayland-sys" }\n')
    replace(manifest, 'cosmic-comp-config = { git = "https://github.com/pop-os/cosmic-comp" }',
            'cosmic-comp-config = { path = "native-deps/cosmic-comp-config", default-features = false }')
    for name, location in (("cosmic-settings-audio-server", "./audio-server"),
                           ("cosmic-settings-varlink-server", "./varlink-server")):
        replace(manifest, f'{name} = {{ path = "{location}" }}',
                f'{name} = {{ path = "{location}", optional = true }}')
    replace(manifest, 'ddc-hi = "0.4.1"', 'ddc-hi = { version = "0.4.1", optional = true }')
    replace(manifest, 'udev = "0.9.3"', 'udev = { version = "0.9.3", optional = true }')
    replace(manifest, 'geonames = { path = "geonames" }',
            'geonames = { path = "geonames", default-features = false }')
    replace(manifest, 'tokio = { version = "1.47.1", features = ["macros", "net", "rt", "signal"] }',
            'tokio = { version = "1.47.1", features = ["macros", "net", "rt", "signal", "fs", "process", "sync", "time"] }')
    geo = source / "geonames/Cargo.toml"
    replace(geo, '[dependencies]\n', '''[features]
default = ["generator"]
generator = ["dep:reqwest", "dep:tokio", "dep:zip"]

[[bin]]
name = "geonames"
path = "src/main.rs"
required-features = ["generator"]

[dependencies]
''')
    replace(geo, 'reqwest = "0.12"', 'reqwest = { version = "0.12", optional = true }')
    replace(geo, 'tokio = { version = "1.47", features = ["full"] }',
            'tokio = { version = "1.47", features = ["full"], optional = true }')
    replace(geo, 'zip = "5"', 'zip = { version = "5", optional = true }')

    main = source / "src/main.rs"
    for old in ('use brightness_device::BrightnessDevice;', 'use logind_session::LogindSessionProxy;',
                'use std::io;', 'use std::path::PathBuf;', 'use tokio::io::Interest;',
                'use tokio::io::unix::AsyncFd;', 'mod brightness_device;', 'mod logind_session;'):
        replace(main, old, '#[cfg(feature = "backlight")]\n' + old)
    for old, feature in (
        ('    varlink_daemon: Arc<tokio::sync::Mutex<cosmic_settings_varlink_server::DaemonInner>>,', 'audio'),
        ("    logind_session: Option<LogindSessionProxy<'static>>,", 'backlight'),
        ('    display_brightness_device: BrightnessDevice,', 'backlight'),
        ('                varlink_daemon: varlink_daemon_context.clone(),', 'audio'),
        ('                logind_session: logind_session.ok(),', 'backlight'),
        ('                display_brightness_device,', 'backlight')):
        pad = old[:len(old) - len(old.lstrip())]
        replace(main, old, pad + f'#[cfg(feature = "{feature}")]\n' + old)
    for old in ('fn backlight_enumerate()', 'fn backlight_monitor()',
                'async fn choose_best_backlight(', 'async fn backlight_monitor_task('):
        replace(main, old, '#[cfg(feature = "backlight")]\n' + old)
    region(main, '#[zbus::interface(name = "com.system76.CosmicSettingsDaemon")]',
           '\nimpl SettingsDaemon {\n    async fn watch_config_inner',
           'f1756442455b7fbe29dac155ac967f59e0890263890b80afe04c71ea29064eaf',
           lambda _: (PORT / "interface.rs.inc").read_text())
    # These bindings must remain visible when audio is selected. Wrap the
    # initialization into one cfg-controlled tuple-producing expression.
    region(main, '            let (varlink_daemon, varlink_backend) =', '\n            let backlights =',
           'e88b7f1283a0a845dd3ef226aff8adc2f206db98c50a2ecd28ba2b5b19ab9379',
           lambda old: '''            #[cfg(feature = "audio")]
            let varlink_daemon_context = {
''' + ''.join('    ' + line if line.strip() else line for line in old.splitlines(keepends=True)) +
           '''                varlink_daemon_context
            };
''')
    region(main, '            let backlights =', '\n            let a11y_session =',
           'c0a66a187eed25cf74f18c2c9eb0c88f8b43dd60dbfc8f35126b958314ad7484',
           lambda old: '''            #[cfg(feature = "backlight")]
            let (backlights, display_brightness_device, logind_session) = {
''' + ''.join('    ' + line if line.strip() else line for line in old.splitlines(keepends=True)) +
           '''                (backlights, display_brightness_device, logind_session)
            };
''')
    region(main, '            let conn_clone = connection.clone();\n            task::spawn_local(async move {\n                backlight_monitor_task',
           '\n            tokio::task::spawn_local(battery::low_power_monitor());',
           '51f2145a450b3ba6865afd518ccc196db0a349b6c4a1467ba1c8f66317385afc',
           lambda old: gated_block(old, 'backlight', 12))
    region(main, '                            } else if id.as_str() == cosmic_settings_daemon_config::NAME {',
           '\n                            let read_guard = settings_daemon.watched_configs',
           '10136321c9c1252c32c8f7ee3a8a1173324c171b4b8299befc76f86ad48cb162',
           gate_mono_branch)
    replace(main, '                    tokio::time::sleep(sleep).await;\n                    sleep = sleep.saturating_mul(2);',
            '''                    // Cancellation also works when setup failed before watch_theme's loop.
                    tokio::select! {
                        _ = theme_cancel_rx.recv() => break,
                        _ = tokio::time::sleep(sleep) => {}
                    }
                    sleep = sleep.saturating_mul(2);''')
    # Keep the upstream signal library and its SA_RESTART request unchanged.
    # On a platform that rejects it, report the genuine failure before logging
    # initialization rather than silently presenting a graceful-stop path.
    replace(main, '#[tokio::main(flavor = "current_thread")]\n', '''fn signal_or_report(kind: SignalKind, name: &str) -> Option<tokio::signal::unix::Signal> {
    match tokio::signal::unix::signal(kind) {
        Ok(signal) => Some(signal),
        Err(why) => {
            eprintln!("cosmic-settings-daemon: cannot register {name}: {why}; graceful signal cleanup/restart is unavailable");
            None
        }
    }
}

#[tokio::main(flavor = "current_thread")]
''')
    for kind, name in (("interrupt", "SIGINT"), ("terminate", "SIGTERM"), ("hangup", "SIGHUP")):
        replace(main, f'tokio::signal::unix::signal(SignalKind::{kind}()).ok()',
                f'signal_or_report(SignalKind::{kind}(), "{name}")')
    replace(main, '        .init();\n', '''        .init();

    #[cfg(not(feature = "audio"))]
    log::warn!("Audio integration is disabled; volume methods return NotSupported and no audio Varlink service is registered");
    #[cfg(not(feature = "backlight"))]
    log::warn!("Backlight integration is disabled; brightness reports unavailable and mutations return NotSupported");
''')
    replace(main, '            _ = std::process::Command::new(current_exe).exec();',
            '''            let why = std::process::Command::new(current_exe).exec();
            eprintln!("cosmic-settings-daemon: SIGHUP restart failed: {why}");''')

    theme = source / "src/theme.rs"
    replace(theme, '''    let (_time_handle, time_changes) = crate::time::watch_time_changes().await?;
    futures::pin_mut!(time_changes);''', '''    // Optional system time services must not disable local theme/config watching.
    // A pending tail also prevents a closed system stream from busy-looping.
    let (_time_handle, mut time_changes): (
        Option<crate::time::TimeWatcher>,
        std::pin::Pin<Box<dyn futures::Stream<Item = crate::time::TimeChange>>>,
    ) = match crate::time::watch_time_changes().await {
        Ok((handle, stream)) => (Some(handle), Box::pin(stream.chain(futures::stream::pending()))),
        Err(why) => {
            log::warn!("System time change monitoring is unavailable: {why}; local theme watching remains active");
            (None, Box::pin(futures::stream::pending()))
        }
    };''')


def file_diff(old, new, name):
    """Emit an applicable diff, including Git's missing-final-newline marker."""
    # Decode bytes directly so newline translation cannot change source bytes.
    lines = difflib.unified_diff(
        old.read_bytes().decode().splitlines(keepends=True) if old.exists() else [],
        new.read_bytes().decode().splitlines(keepends=True) if new.exists() else [],
        fromfile=f'a/{name}' if old.exists() else '/dev/null',
        tofile=f'b/{name}' if new.exists() else '/dev/null')
    for line in lines:
        if line.endswith('\n'):
            yield line
        else:
            yield line + '\n\\ No newline at end of file\n'


def build(settings, comp, wayland_sys, wayland_sys_archive, output, patch, manifest,
          recipe_base, recipe, resolved_lock=None):
    settings, comp, output = settings.resolve(), comp.resolve(), output.resolve()
    input_dirs = (settings, comp, wayland_sys.resolve())
    if output.exists() or any(output.is_relative_to(source) for source in input_dirs):
        raise ValueError("output must be fresh and outside source inputs")
    for path in (patch, manifest, recipe):
        if any(path.resolve().is_relative_to(source) for source in input_dirs) or path.resolve() == wayland_sys_archive.resolve():
            raise ValueError("published output must not overwrite source inputs")
    settings_id, settings_files, settings_modes = snapshot(settings, SETTINGS_COMMIT, SETTINGS_TREE)
    comp_id, comp_files, comp_modes = snapshot(comp, COMP_COMMIT, COMP_TREE)
    registry_id, registry_files, registry_modes = registry_snapshot(wayland_sys, wayland_sys_archive)
    if settings_id['files'].get('Cargo.lock') != SOURCE_LOCK:
        raise ValueError("wrong settings Cargo.lock")
    registry_packages = [entry for entry in tomllib.loads(settings_files['Cargo.lock'].decode())['package']
                         if entry.get('name') == 'wayland-sys' and entry.get('version') == WAYLAND_SYS_VERSION]
    if len(registry_packages) != 1 or registry_packages[0].get('source') != registry_id['source'] or registry_packages[0].get('checksum') != WAYLAND_SYS_PACKAGE:
        raise ValueError('wayland-sys package identity differs from the pinned settings lock')
    randr_source = f'git+https://github.com/pop-os/cosmic-randr/#{RANDR_COMMIT}'
    randr_packages = [entry for entry in tomllib.loads(comp_files['Cargo.lock'].decode())['package']
                      if entry.get('name') == 'cosmic-randr-shell']
    if len(randr_packages) != 1 or randr_packages[0].get('source') != randr_source:
        raise ValueError('optional cosmic-randr-shell revision is not bound to the pinned compositor lock')
    support_paths = [Path(__file__), PORT / 'interface.rs.inc', PORT / 'config-enums.rs.inc',
                     PORT / 'wayland-client-static.rs.inc',
                     PORT / 'README.md', recipe_base]
    support_inputs = {relative(path): sha(path) for path in support_paths}
    resolved_bytes = None
    if resolved_lock is not None:
        resolved_lock, resolved_bytes = read_resolved_lock(resolved_lock)
        if any(resolved_lock == path.resolve() for path in (patch, manifest, recipe)):
            raise ValueError('resolved lock input must not be a publication destination')
        support_inputs[relative(resolved_lock)] = digest(resolved_bytes)
    recipe_bytes = recipe_base.read_bytes()
    output.mkdir(parents=True)
    base, work = output / 'base', output / 'source'
    materialize(base, settings_files, settings_modes)
    materialize(work, settings_files, settings_modes)
    # Export the complete genuine config package, plus its upstream license.
    prefix = 'cosmic-comp-config/'
    exported = {name[len(prefix):]: data for name, data in comp_files.items() if name.startswith(prefix)}
    modes = {name[len(prefix):]: mode for name, mode in comp_modes.items() if name.startswith(prefix)}
    exported['LICENSE'], modes['LICENSE'] = comp_files['LICENSE'], comp_modes['LICENSE']
    nested = work / 'native-deps/cosmic-comp-config'
    materialize(nested, exported, modes)
    patch_config(nested)
    # Preserve the complete checksum-bound registry package and its MIT license.
    wayland_nested = work / 'native-deps/wayland-sys'
    materialize(wayland_nested, registry_files, registry_modes)
    patch_wayland_sys(wayland_nested)
    patch_settings(work)
    replace(work / 'Cargo.lock', f'source = "git+https://github.com/pop-os/cosmic-comp#{COMP_COMMIT}"\n', '')
    replace(work / 'Cargo.lock',
            f'name = "wayland-sys"\nversion = "{WAYLAND_SYS_VERSION}"\nsource = "{registry_id["source"]}"\nchecksum = "{WAYLAND_SYS_PACKAGE}"\n',
            f'name = "wayland-sys"\nversion = "{WAYLAND_SYS_VERSION}"\n')
    if resolved_bytes is not None:
        (work / 'Cargo.lock').write_bytes(resolved_bytes)
    names = sorted(set(settings_files) | {str(p.relative_to(work)) for p in work.rglob('*') if p.is_file()})
    before, after, chunks = {}, {}, []
    for name in names:
        old, new = base / name, work / name
        if sha(old) == sha(new):
            continue
        before[name], after[name] = sha(old), sha(new)
        chunks.append(f'diff --git a/{name} b/{name}\n')
        if not old.exists():
            chunks.append(f'new file mode {new.stat().st_mode & 0o777 | 0o100000:o}\n')
        chunks.extend(file_diff(old, new, name))
    patch.write_text(''.join(chunks))
    if snapshot(settings, SETTINGS_COMMIT, SETTINGS_TREE)[0] != settings_id:
        raise ValueError('settings input changed during generation')
    if snapshot(comp, COMP_COMMIT, COMP_TREE)[0] != comp_id:
        raise ValueError('compositor input changed during generation')
    if registry_snapshot(wayland_sys, wayland_sys_archive)[0] != registry_id:
        raise ValueError('registry input changed during generation')
    observed_support = {relative(path): sha(path) for path in support_paths}
    if resolved_lock is not None:
        same_path, same_bytes = read_resolved_lock(resolved_lock)
        if same_path != resolved_lock or same_bytes != resolved_bytes:
            raise ValueError('resolved lock input changed during generation')
        observed_support[relative(same_path)] = digest(same_bytes)
    if observed_support != support_inputs:
        raise ValueError('support input changed during generation')
    if recipe_base.read_bytes() != recipe_bytes:
        raise ValueError('base recipe changed during generation')
    native_recipe = json.loads(recipe_bytes)
    if native_recipe.get('component') != 'cosmic-settings-daemon' or native_recipe.get('commit') != SETTINGS_COMMIT:
        raise ValueError('wrong base recipe component or commit')
    native_recipe.update(default_features=False, features=['cyxia-native'],
                         source_lock_sha256=SOURCE_LOCK, effective_lock_sha256=sha(work / 'Cargo.lock'),
                         patches=[dict(path=str(patch.resolve().relative_to(recipe.parent.resolve())), sha256=sha(patch))])
    recipe.write_text(json.dumps(native_recipe, indent=2) + '\n')
    record = dict(schema_version=1, component='cosmic-settings-daemon',
                  repository='https://github.com/pop-os/cosmic-settings-daemon', commit=SETTINGS_COMMIT,
                  source_lock_sha256=SOURCE_LOCK, effective_lock_sha256=sha(work / 'Cargo.lock'),
                  patch=relative(patch), patch_sha256=sha(patch), before=before, after=after,
                  source_inputs={'settings': settings_id, 'compositor': comp_id},
                  registry_inputs={'wayland-sys': registry_id},
                  support_inputs=support_inputs, source_preserved=True, support_preserved=True,
                  optional_dependency_pins={'cosmic-randr-shell': dict(commit=RANDR_COMMIT,
                      evidence='compositor/Cargo.lock', evidence_sha256=comp_id['files']['Cargo.lock'],
                      source=randr_source)},
                  resolved_lock_input=(dict(path=relative(resolved_lock), sha256=digest(resolved_bytes),
                      bytes=len(resolved_bytes)) if resolved_lock is not None else None),
                  recipe_base=relative(recipe_base), recipe_base_sha256=digest(recipe_bytes),
                  recipe=relative(recipe), recipe_sha256=sha(recipe),
                  preserved_source=relative(work), built=False, guest_tested=False,
                  lock_resolution_verified=False)
    manifest.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    (output / 'generation.json').write_text(json.dumps(dict(status='PATCH_GENERATED_NOT_BUILT',
        manifest=relative(manifest), manifest_sha256=sha(manifest), patch=relative(patch),
        patch_sha256=sha(patch), recipe=relative(recipe), recipe_sha256=sha(recipe)), indent=2) + '\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', type=Path, default=ROOT / 'artifacts/cosmic-sources/cosmic-settings-daemon')
    parser.add_argument('--compositor', type=Path, default=ROOT / 'artifacts/cosmic-sources/cosmic-comp-epoch')
    parser.add_argument('--wayland-sys', type=Path,
                        default=REGISTRY_CACHE / 'src' / REGISTRY_INDEX / f'wayland-sys-{WAYLAND_SYS_VERSION}')
    parser.add_argument('--wayland-sys-archive', type=Path,
                        default=REGISTRY_CACHE / 'cache' / REGISTRY_INDEX / f'wayland-sys-{WAYLAND_SYS_VERSION}.crate')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--patch', type=Path, default=PORT / 'cosmic-settings-native.patch')
    parser.add_argument('--manifest', type=Path, default=PORT / 'native-patch.json')
    parser.add_argument('--recipe-base', type=Path, default=ROOT / 'ports/cosmic/recipes/cosmic-settings-daemon-x86_64.json')
    parser.add_argument('--recipe', type=Path, default=PORT / 'native-recipe.json')
    lock_input = parser.add_mutually_exclusive_group()
    lock_input.add_argument('--resolved-lock', type=Path, default=PORT / 'Cargo.lock',
                        help='preserved, separately resolved lock input; bounded, hashed and rechecked')
    lock_input.add_argument('--no-resolved-lock', action='store_true',
                           help='export the transformed original lock for isolated resolution')
    args = parser.parse_args()
    record = build(args.settings, args.compositor, args.wayland_sys, args.wayland_sys_archive,
                   args.output, args.patch, args.manifest,
                   args.recipe_base, args.recipe, None if args.no_resolved_lock else args.resolved_lock)
    print(json.dumps({key: record[key] for key in ('patch_sha256', 'effective_lock_sha256', 'recipe_sha256')}))


if __name__ == '__main__':
    main()
