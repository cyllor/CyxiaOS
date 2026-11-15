//! x86 NativeOs entries and explicit target-image catalog for the shared OS.
use std::{env, fs, path::{Path, PathBuf}, process::Command};

fn checked(command: &mut Command) {
    let status = command.status().expect("cannot execute OS user compiler");
    assert!(status.success(), "OS user image compilation failed");
}

fn feature(name: &str) -> bool {
    env::var_os(format!("CARGO_FEATURE_{}", name.replace('-', "_").to_uppercase())).is_some()
}

fn word(bytes: &[u8], offset: usize, count: usize) -> u64 {
    let mut value = 0;
    for (shift, byte) in bytes.get(offset..offset + count).expect("truncated user ELF").iter().enumerate() {
        value |= u64::from(*byte) << (shift * 8);
    }
    value
}

/// Validate actual bytes at the embedding boundary; a filename is not an ISA.
fn x86_image(path: &Path) -> Vec<u8> {
    println!("cargo:rerun-if-changed={}", path.display());
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("missing OS image {}: {error}", path.display()));
    assert!(bytes.len() >= 64 && bytes.get(..7) == Some(b"\x7fELF\x02\x01\x01"), "user image must be ELF64 LE");
    assert_eq!(word(&bytes, 16, 2), 2, "user image must be ET_EXEC");
    assert_eq!(word(&bytes, 18, 2), 62, "refuse non-x86 user image");
    let entry = word(&bytes, 24, 8);
    let offset = usize::try_from(word(&bytes, 32, 8)).expect("program-header offset");
    let count = usize::try_from(word(&bytes, 56, 2)).expect("program-header count");
    assert_eq!(word(&bytes, 54, 2), 56, "program-header layout");
    assert!((1..=32).contains(&count), "program-header count");
    let mut executable = false;
    let mut mapped = Vec::new();
    for index in 0..count {
        let at = offset.checked_add(index * 56).expect("program-header overflow");
        let kind = word(&bytes, at, 4);
        assert!(!matches!(kind, 2 | 3), "dynamic/interpreter image requires a real loader");
        if kind != 1 { continue; }
        let flags = word(&bytes, at + 4, 4);
        let file = usize::try_from(word(&bytes, at + 8, 8)).expect("segment file offset");
        let va = word(&bytes, at + 16, 8);
        let file_size = usize::try_from(word(&bytes, at + 32, 8)).expect("segment file size");
        let size = word(&bytes, at + 40, 8);
        let end = va.checked_add(size).expect("segment virtual overflow");
        assert!(file_size as u64 <= size && bytes.get(file..file.checked_add(file_size).expect("file overflow")).is_some(), "segment backing");
        assert!(va >= 4096 && end <= 0x0000_8000_0000_0000 && flags & 3 != 3, "segment user bounds/W^X");
        assert_eq!(word(&bytes, at + 48, 8), 4096, "segment page alignment");
        assert_eq!(va % 4096, file as u64 % 4096, "segment file alignment");
        if size != 0 {
            let first = va / 4096;
            let last = end.div_ceil(4096);
            assert!(mapped.iter().all(|&(old_first, old_last)| last <= old_first || first >= old_last), "overlapping user pages");
            mapped.push((first, last));
        }
        executable |= flags & 1 != 0 && entry >= va && entry < va + file_size as u64;
    }
    assert!(executable, "entry must be file-backed executable code");
    bytes
}

fn assets(directory: &Path, files: &mut Vec<PathBuf>) {
    if !directory.exists() { return; }
    for entry in fs::read_dir(directory).expect("rootfs directory") {
        let entry = entry.expect("rootfs entry");
        let kind = entry.file_type().expect("rootfs file type");
        assert!(!kind.is_symlink(), "rootfs cannot follow links");
        if kind.is_dir() { assets(&entry.path(), files); }
        else { assert!(kind.is_file(), "rootfs must contain regular files"); files.push(entry.path()); }
    }
}

fn catalog(root: &Path, out: &Path) {
    println!("cargo:rerun-if-env-changed=CYXIA_SYSROOT");
    let prefix = env::var_os("CYXIA_SYSROOT").map(PathBuf::from)
        .unwrap_or_else(|| root.join("artifacts/sysroot/x86_64-musl"));
    let mut names = vec!["probe", "xau-probe", "x11-probe", "x11-inspect", "socket-probe", "signal-probe", "desktop-api-probe",
        "pipe-probe", "file-probe", "clock-probe", "event-probe", "timerfd-probe", "edge-probe", "fd-share-probe", "scm-probe",
        "memfd-probe", "rust-std-probe", "wayland-probe", "xkbcommon-probe", "xkb-rules-probe", "cyxia-save", "cyxia-terminal", "cyxia-sh", "pty-probe", "thread-probe", "spawn-probe", "flock-probe", "nested-epoll-probe", "inotify-probe", "thread-exit-probe", "heap-capacity-probe", "heap-pool-probe"];
    let mut required = vec!["probe"];
    for (flag, images) in [
        ("rust-reactor-probe", &["rust-reactor-probe"][..]), ("rust-egl-probe", &["rust-egl-probe"][..]),
        ("mesa-probe", &["egl-probe"][..]), ("smithay-probe", &["smithay-probe"][..]),
        ("smithay-wayland-probe", &["smithay-wayland-probe", "smithay-wayland-client"][..]),
        ("smithay-xdg-probe", &["smithay-xdg-probe", "smithay-xdg-client"][..]),
        ("smithay-multi-probe", &["smithay-multi-probe", "smithay-multi-client"][..]),
        ("smithay-interactive-probe", &["smithay-interactive-probe", "smithay-interactive-client"][..]),
        ("smithay-resize-probe", &["smithay-resize-probe", "smithay-resize-client"][..]),
        ("smithay-dynamic-probe", &["smithay-dynamic-probe", "smithay-dynamic-client"][..]),
        ("wayland-shm-probe", &["wayland-shm-probe"][..]), ("openbox", &["openbox"][..]),
        ("gtk", &["gtk-probe"][..]), ("pcmanfm", &["pcmanfm"][..]), ("lxpanel", &["lxpanel"][..]),
        ("spawn-test", &["glib-spawn-probe"][..]),
        ("cosmic-desktop", &["cosmic-comp"][..]),
    ] {
        if feature(flag) { names.extend_from_slice(images); required.extend_from_slice(images); }
    }
    if prefix.join("Xcyxia.elf").is_file() { names.push("xorg"); }
    let mut text = String::from("const PORTED: &[(&str, &str, &[u8])] = &[\n");
    let mut paths = Vec::new();
    let budget = if feature("full-os") { 96 } else if feature("large-memory") { 52 } else { 48 } * 1024 * 1024;
    let mut total = 0usize;
    if feature("ported") {
        for name in names {
            let variable = if name == "probe" { "CYXIA_PORTED_ELF".into() }
                else { format!("CYXIA_{}_ELF", name.replace('-', "_").to_uppercase()) };
            println!("cargo:rerun-if-env-changed={variable}");
            let image = env::var_os(&variable).map(PathBuf::from).unwrap_or_else(|| prefix.join(if name == "xorg" { "Xcyxia.elf".into() } else { format!("{name}.elf") }));
            if !image.is_file() && !required.contains(&name) { continue; }
            let bytes = x86_image(&image);
            total = total.checked_add(bytes.len()).expect("catalog size overflow");
            assert!(total <= budget, "ported image catalog exceeds existing budget");
            fs::write(out.join(format!("{name}.elf")), bytes).expect("copy actual user image");
            text.push_str(&format!("({name:?}, \"/bin/{name}\", include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{name}.elf\"))),\n"));
            paths.push(format!("/bin/{name}"));
        }
    }
    text.push_str("];\nconst ROOT_FILES: &[(&str, &[u8])] = &[\n");
    for (index, path) in paths.iter().enumerate() { text.push_str(&format!("({path:?}, PORTED[{index}].2),\n")); }
    if feature("ported") {
        let rootfs = prefix.join("rootfs");
        let mut files = Vec::new();
        println!("cargo:rerun-if-changed={}", rootfs.display());
        assets(&rootfs, &mut files);
        files.sort();
        assert!(files.len() + paths.len() <= 128, "rootfs catalog count");
        for (index, file) in files.iter().enumerate() {
            let name = format!("/{}", file.strip_prefix(&rootfs).expect("rootfs prefix").to_str().expect("UTF8 asset path"));
            assert!(name.len() < 96 && !paths.contains(&name), "rootfs asset path conflict/bound");
            let bytes = fs::read(file).expect("read asset");
            total = total.checked_add(bytes.len()).expect("asset size overflow");
            assert!(total <= budget, "rootfs catalog exceeds existing budget");
            fs::write(out.join(format!("asset-{index}")), bytes).expect("copy asset");
            text.push_str(&format!("({name:?}, include_bytes!(concat!(env!(\"OUT_DIR\"), \"/asset-{index}\"))),\n"));
        }
    }
    text.push_str("];\n");
    fs::write(out.join("ported_catalog.rs"), text).expect("write actual target catalog");
}

pub fn build() {
    assert_eq!(env::var("TARGET").as_deref(), Ok("x86_64-unknown-none"), "OS x86 adapter target");
    let kernel = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("kernel manifest"));
    let root = kernel.parent().expect("repository root");
    let user = root.join("user");
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    println!("cargo:rerun-if-changed={}", user.display());
    println!("cargo:rerun-if-env-changed=CYXIA_CC");
    let cc = env::var("CYXIA_CC").unwrap_or_else(|_| "clang".into());
    let mut objects = Vec::new();
    for source in ["start.S", "libc.c", "demo.c"] {
        let object = out.join(format!("{source}.o"));
        checked(Command::new(&cc).args(["--target=x86_64-none-elf", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
            "-mno-red-zone", "-mno-sse", "-mno-mmx", "-msoft-float", "-fno-pic", "-O2", "-Wall", "-Wextra", "-Werror", "-c"])
            .arg("-I").arg(user.join("include")).arg(user.join("src").join(source)).arg("-o").arg(&object));
        objects.push(object);
    }
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let sysroot = Command::new(&rustc).args(["--print", "sysroot"]).output().expect("rust sysroot");
    assert!(sysroot.status.success());
    let lld = PathBuf::from(String::from_utf8(sysroot.stdout).expect("sysroot UTF8").trim())
        .join("lib/rustlib").join(env::var("HOST").expect("compiler host")).join("bin/rust-lld");
    checked(Command::new(lld).args(["-flavor", "gnu", "-m", "elf_x86_64", "-z", "max-page-size=4096", "--build-id=none", "-T"])
        .arg(user.join("linker.ld")).args(objects).arg("-o").arg(out.join("posix-demo.elf")));
    let mut command = Command::new(&rustc);
    command.arg(user.join("rust/services.rs")).args(["--edition=2024", "--target=x86_64-unknown-none", "--check-cfg=cfg(cyxia_large_memory)",
        "-C", "panic=abort", "-C", "opt-level=s", "-C", "relocation-model=static", "-C", "code-model=small", "-C", "no-redzone=yes",
        "-C", "strip=debuginfo", "-C", "link-arg=--build-id=none", "-C", "link-arg=-zmax-page-size=4096", "-D", "warnings"]);
    if feature("large-memory") { command.args(["--cfg", "cyxia_large_memory"]); }
    command.arg("--check-cfg=cfg(cyxia_full_os)");
    command.arg("--check-cfg=cfg(test)");
    if feature("full-os") { command.args(["--cfg", "cyxia_full_os"]); }
    checked(command.arg("-C").arg(format!("link-arg=-T{}", user.join("linker.ld").display())).arg("-o").arg(out.join("native-services.elf")));
    let _ = x86_image(&out.join("posix-demo.elf"));
    let _ = x86_image(&out.join("native-services.elf"));
    catalog(root, &out);
}
