#!/usr/bin/env python3
"""Export pinned real sources and generate the native session patch; no Cargo/build.

Run only under the root agent's native lease. Cached checkouts are read-only.
The generated ordinary recipe patch contains the complete pinned launch-pad tree.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]
PORT = Path(__file__).resolve().parent
SESSION_COMMIT = "8093b59bb1262b0612d814e6540ba936303f735a"
SESSION_TREE = "bae4cf7cfb4cba7d3b0ec883506ccbf669963067"
LAUNCH_COMMIT = "5b516ee6a012b5ad4a5acc0cf51b4472fc6733af"
LAUNCH_TREE = "0d423e6603a036c4b59c8a95c5f5ac5e598dd84b"
SOURCE_LOCK = "8cda0355e1b1b55abe8d71f7446a040e5e872cd9c5a1c03147e9c25a94157afd"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(path.read_bytes()) if path.exists() else None


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args])


def relative(path):
    path = path.resolve()
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


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
    identity = dict(path=relative(source), commit=commit, git_tree=tree, files=files,
                    tree_sha256=digest(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()))
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
        raise ValueError(f"ambiguous patch preimage: {path}: {old[:70]!r}")
    path.write_text(value.replace(old, new))


def patch_launch(source):
    manifest = source / "Cargo.toml"
    replace(manifest, "[dependencies]\n", '[dependencies]\nlibc = "0.2"\n')
    replace(manifest, '# Use libc for killing processes on other platforms.\n[target.\'cfg(not(target_os = "linux"))\'.dependencies]\nlibc = "0.2"\n', "")
    replace(manifest, "[workspace]\n", '[features]\ncyxia-native = ["tokio/net"]\n\n[workspace]\n')
    lib = source / "src/lib.rs"
    replace(lib, "        fd::{AsRawFd, BorrowedFd, OwnedFd},", "        fd::{AsRawFd, OwnedFd},")
    replace(lib, "    process::Stdio,\n", "")
    replace(lib, "    process::{Child, Command},\n", "")
    replace(lib, "pub mod util;", '''pub mod util;

#[cfg(feature = "cyxia-native")]
pub mod native_child;
#[cfg(feature = "cyxia-native")]
use native_child::NativeChild as Child;
#[cfg(not(feature = "cyxia-native"))]
use tokio::process::{Child, Command};
#[cfg(not(feature = "cyxia-native"))]
use std::{os::fd::BorrowedFd, process::Stdio};''')
    value = lib.read_text()
    start = value.index("        let mut command = Command::new(&process.executable);")
    end = value.index("        let key = self.inner.write().await.processes.insert(", start)
    value = value[:start] + '''        // Publish manager state only after a real child exists.
        let command = spawn_child(&process.executable, &process.args, &process.env, &raw_fds)
            .map_err(Error::Process)?;
        drop(fd_list);

''' + value[end:]
    start = value.index("        let command = unsafe {")
    end = value.index("        drop(fd_list);", start) + len("        drop(fd_list);\n")
    value = value[:start] + value[end:]
    start = value.index("        let command = unsafe {")
    end = value.index("        process_data.pid = command.id();", start)
    value = value[:start] + '''        let command = spawn_child(
            &process_data.process.executable,
            &process_data.process.args,
            &process_data.process.env,
            &raw_fds,
        ).map_err(Error::Process)?;
''' + value[end:]
    old_stop = '''                    if exit_code.is_none() {
                        if let Err(err) = command.kill().await {
                            log::error!("Failed to kill program. {err:?}");
                        };
                        exit_code = Some(137);
                    }'''
    native_stop = '''                    if exit_code.is_none() {
                        #[cfg(feature = "cyxia-native")]
                        {
                            exit_code = native_force_stop(&mut command).await;
                        }
                        #[cfg(not(feature = "cyxia-native"))]
                        {
                            if let Err(err) = command.kill().await {
                                log::error!("Failed to kill program. {err:?}");
                            };
                            exit_code = Some(137);
                        }
                    }'''
    if value.count(old_stop) != 1:
        raise ValueError("ambiguous cancellation fallback preimage")
    value = value.replace(old_stop, native_stop)
    marker = "new_key_type! { pub struct ProcessKey; }"
    helper = '''#[cfg(feature = "cyxia-native")]
async fn native_force_stop(command: &mut Child) -> Option<i32> {
    if let Err(err) = command.kill().await {
        log::error!("Failed to kill or reap native program. {err:?}");
        return None;
    }
    // Native kill has reaped the child; wait now returns its cached real receipt.
    // This can be a prior graceful exit or TERM, not necessarily a KILL exit.
    match command.wait().await {
        Ok(status) => status.code().or_else(|| status.signal().map(|signal| 128 + signal)),
        Err(err) => {
            log::error!("Failed to read native program exit status. {err:?}");
            None
        }
    }
}

#[cfg(feature = "cyxia-native")]
fn spawn_child(executable: &str, args: &[String], env: &[(String, String)], fds: &[i32]) -> std::io::Result<Child> {
    Child::spawn(executable, args, env, fds)
}

#[cfg(not(feature = "cyxia-native"))]
fn spawn_child(executable: &str, args: &[String], env: &[(String, String)], fds: &[i32]) -> std::io::Result<Child> {
    let raw_fds = fds.to_vec();
    let mut command = Command::new(executable);
    command.args(args).envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::piped()).kill_on_drop(true);
    // SAFETY: the owning callback descriptor list remains alive through spawn;
    // this is the unchanged Unix child-only close-on-exec adjustment.
    unsafe {
        command.pre_exec(move || {
            for fd in &raw_fds {
                util::mark_as_not_cloexec(BorrowedFd::borrow_raw(*fd))?;
            }
            Ok(())
        }).spawn()
    }
}

'''
    if value.count(marker) != 1:
        raise ValueError("ambiguous process-key insertion point")
    lib.write_text(value.replace(marker, helper + marker))
    shutil.copyfile(PORT / "native_child.rs", source / "src/native_child.rs")


def build(session, launch, output, patch, manifest):
    session, launch, output = session.resolve(), launch.resolve(), output.resolve()
    if output.exists() or output.is_relative_to(session) or output.is_relative_to(launch):
        raise ValueError("output must be fresh and outside both input checkouts")
    session_id, session_files, session_modes = snapshot(session, SESSION_COMMIT, SESSION_TREE)
    launch_id, launch_files, launch_modes = snapshot(launch, LAUNCH_COMMIT, LAUNCH_TREE)
    support_paths = [PORT / "native_child.rs", Path(__file__)]
    support_inputs = {relative(path): sha(path) for path in support_paths}
    if session_id["files"].get("Cargo.lock") != SOURCE_LOCK:
        raise ValueError("wrong session Cargo.lock")
    output.mkdir(parents=True)
    base, work = output / "base", output / "source"
    materialize(base, session_files, session_modes)
    materialize(work, session_files, session_modes)
    nested = work / "native-deps/launch-pad"
    materialize(nested, launch_files, launch_modes)
    patch_launch(nested)
    replace(work / "Cargo.toml", 'launch-pad = { git = "https://github.com/pop-os/launch-pad" }',
            'launch-pad = { path = "native-deps/launch-pad" }')
    replace(work / "Cargo.toml", "[features]\n", '[features]\ncyxia-native = ["launch-pad/cyxia-native"]\n')
    replace(work / "Cargo.lock", f'source = "git+https://github.com/pop-os/launch-pad#{LAUNCH_COMMIT}"\n', "")
    names = sorted(set(session_files) | {str(path.relative_to(work)) for path in work.rglob("*") if path.is_file()})
    before, after, chunks = {}, {}, []
    for name in names:
        old, new = base / name, work / name
        if sha(old) == sha(new):
            continue
        before[name], after[name] = sha(old), sha(new)
        chunks.append(f"diff --git a/{name} b/{name}\n")
        if not old.exists():
            chunks.append(f"new file mode {new.stat().st_mode & 0o777 | 0o100000:o}\n")
        chunks.extend(difflib.unified_diff(
            old.read_text().splitlines(keepends=True) if old.exists() else [],
            new.read_text().splitlines(keepends=True) if new.exists() else [],
            fromfile=f"a/{name}" if old.exists() else "/dev/null",
            tofile=f"b/{name}" if new.exists() else "/dev/null"))
    patch.write_text("".join(chunks))
    # Receipt publication requires the same tracked sources and support bytes
    # after export/patch construction, not merely an initial observation.
    if snapshot(session, SESSION_COMMIT, SESSION_TREE)[0] != session_id:
        raise ValueError("session input changed during patch generation")
    if snapshot(launch, LAUNCH_COMMIT, LAUNCH_TREE)[0] != launch_id:
        raise ValueError("launch-pad input changed during patch generation")
    if {relative(path): sha(path) for path in support_paths} != support_inputs:
        raise ValueError("adapter/generator input changed during patch generation")
    record = dict(schema_version=1, component="cosmic-session",
                  repository="https://github.com/pop-os/cosmic-session", commit=SESSION_COMMIT,
                  source_lock_sha256=SOURCE_LOCK, effective_lock_sha256=sha(work / "Cargo.lock"),
                  patch=relative(patch), patch_sha256=sha(patch), before=before, after=after,
                  source_inputs={"session": session_id, "launch_pad": launch_id},
                  support_inputs=support_inputs, source_preserved=True, support_preserved=True,
                  preserved_source=relative(work), built=False, guest_tested=False)
    manifest.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    (output / "generation.json").write_text(json.dumps(dict(status="PATCH_GENERATED_NOT_BUILT",
        manifest=relative(manifest), manifest_sha256=sha(manifest), patch=relative(patch),
        patch_sha256=sha(patch)), indent=2) + "\n")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", type=Path, default=ROOT / "artifacts/cosmic-sources/cosmic-session")
    parser.add_argument("--launch-pad", type=Path, default=ROOT / "artifacts/cosmic-cargo-cache/git/checkouts/launch-pad-93ee12ad4ef22597/5b516ee")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--patch", type=Path, default=PORT / "cosmic-session-native.patch")
    parser.add_argument("--manifest", type=Path, default=PORT / "native-patch.json")
    args = parser.parse_args()
    result = build(args.session, args.launch_pad, args.output, args.patch, args.manifest)
    print(json.dumps({"patch_sha256": result["patch_sha256"], "effective_lock_sha256": result["effective_lock_sha256"]}))


if __name__ == "__main__":
    main()
