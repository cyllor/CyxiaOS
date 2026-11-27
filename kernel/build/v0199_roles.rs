//! Separate compiler invocations and read-only build manifest for eight
//! ABI3 static PIE bootstrap packages. No downloader or mutable filesystem
//! package resolution is used at guest launch.
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
const ROLES: [u16; 8] = [6, 7, 2, 8, 9, 3, 10, 11];
fn u16at(b: &[u8], n: usize) -> u16 {
    u16::from_le_bytes(b[n..n + 2].try_into().unwrap())
}
fn u32at(b: &[u8], n: usize) -> u32 {
    u32::from_le_bytes(b[n..n + 4].try_into().unwrap())
}
fn u64at(b: &[u8], n: usize) -> u64 {
    u64::from_le_bytes(b[n..n + 8].try_into().unwrap())
}
fn digest(path: &Path) -> [u8; 32] {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("host sha256sum");
    assert!(out.status.success());
    let s = std::str::from_utf8(&out.stdout).unwrap();
    let h = s.split_whitespace().next().unwrap();
    assert_eq!(h.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
}

/// Acceptance input for the ordinary FSYNC client. The mounted kernel
/// sees the actual ABI WRITE bytes, independent of this test oracle.
fn build_fsync_client_fixture(out: &Path) {
    const DEFAULT: &[u8; 29] = b"CyxiaOS V0.20 durable fsync!\n";
    const BLOCK_BYTES: usize = 4096;
    const MAX_BYTES: usize = 2 * BLOCK_BYTES;
    const TEST_INPUT: &str = "CYXIA_FSYNC_TEST_CONTENT";
    println!("cargo:rerun-if-env-changed={TEST_INPUT}");
    let contents = if let Some(path) = env::var_os(TEST_INPUT) {
        let path = PathBuf::from(path);
        println!("cargo:rerun-if-changed={}", path.display());
        let meta = fs::metadata(&path).expect("FSYNC client fixture metadata");
        assert!(meta.is_file() && (DEFAULT.len() as u64..=MAX_BYTES as u64).contains(&meta.len()));
        fs::read(path).expect("FSYNC client fixture input")
    } else {
        DEFAULT.to_vec()
    };
    assert!(
        (DEFAULT.len()..=MAX_BYTES).contains(&contents.len()),
        "FSYNC client file length"
    );
    let mut pages = contents.clone();
    pages.resize(contents.len().div_ceil(BLOCK_BYTES) * BLOCK_BYTES, 0);
    let padded = out.join("fsync-client-page.bin");
    fs::write(&padded, pages).unwrap();
    fs::write(out.join("fsync-client-content.bin"), contents).unwrap();
    fs::write(out.join("fsync-client-digest.bin"), digest(&padded)).unwrap();
}

fn extract_relative(b: &[u8]) -> Vec<(u64, u64, i64)> {
    assert!(b.len() >= 64 && b.len() <= 8 * 1024 * 1024 && &b[..4] == b"\x7fELF");
    assert_eq!((b[4], b[5], u16at(b, 16), u16at(b, 18)), (2, 1, 3, 183));
    let p = usize::try_from(u64at(b, 32)).unwrap();
    let n = usize::from(u16at(b, 56));
    assert!(
        n > 0
            && n <= 16
            && u16at(b, 54) == 56
            && p.checked_add(n * 56).is_some_and(|e| e <= b.len())
    );
    let mut executable = false;
    let mut loads = Vec::new();
    for i in 0..n {
        let at = p + i * 56;
        let ty = u32at(b, at);
        let flags = u32at(b, at + 4);
        assert!(
            matches!(ty, 0 | 1 | 4 | 6 | 0x6474_e551 | 0x6474_e552),
            "dynamic/interpreted role image"
        );
        if ty == 1 {
            assert!(flags & 7 == 4 || flags & 7 == 5 || flags & 7 == 6);
            assert_eq!(u64at(b, at + 48), 4096);
            assert!(u64at(b, at + 40) > 0);
            assert!(
                u64at(b, at + 16)
                    .checked_add(u64at(b, at + 40))
                    .is_some_and(|e| e <= 65536)
            );
            let va = u64at(b, at + 16);
            let end = va.checked_add(u64at(b, at + 40)).unwrap();
            loads.push((va, end, flags));
            executable |= flags & 1 != 0;
        }
    }
    assert!(executable);
    let s = usize::try_from(u64at(b, 40)).unwrap();
    let count = usize::from(u16at(b, 60));
    assert!(
        count > 0 && u16at(b, 58) == 64 && s.checked_add(count * 64).is_some_and(|e| e <= b.len())
    );
    let mut entries = Vec::new();
    let mut rela_table = None;
    let mut dynamic = None;
    for i in 0..count {
        let at = s + i * 64;
        let ty = u32at(b, at + 4);
        let size = u64at(b, at + 32);
        assert!(!matches!(ty, 9 | 19) || size == 0, "REL/RELR unsupported");
        if ty == 4 && size != 0 {
            assert!(rela_table.is_none(), "multiple RELA tables");
            assert_eq!(u64at(b, at + 56), 24);
            let off = usize::try_from(u64at(b, at + 24)).unwrap();
            let n = usize::try_from(size).unwrap();
            assert!(
                size.is_multiple_of(24)
                    && size / 24 <= 512
                    && off.checked_add(n).is_some_and(|e| e <= b.len())
            );
            assert_ne!(u64at(b, at + 8) & 2, 0, "non-allocated relocation section");
            rela_table = Some((u64at(b, at + 16), size));
            for d in b[off..off + n].chunks_exact(24) {
                let offset = u64at(d, 0);
                let info = u64at(d, 8);
                let addend = u64at(d, 16) as i64;
                assert_eq!(info, 1027, "only symbol-zero R_AARCH64_RELATIVE");
                assert!(offset.is_multiple_of(8) && !entries.iter().any(|&(o, _, _)| o == offset));
                assert!(loads.iter().any(|&(a, z, f)| f & 2 != 0
                    && f & 1 == 0
                    && a <= offset
                    && offset.checked_add(8).is_some_and(|e| e <= z)));
                let value = u64::try_from(addend).expect("negative relocation addend");
                assert!(loads.iter().any(|&(a, z, _)| a <= value && value < z));
                entries.push((offset, info, addend));
            }
        }
        if ty == 6 {
            assert!(dynamic.is_none(), "multiple dynamic tables");
            let off = usize::try_from(u64at(b, at + 24)).unwrap();
            let n = usize::try_from(size).unwrap();
            assert!(n % 16 == 0 && off.checked_add(n).is_some_and(|e| e <= b.len()));
            dynamic = Some(&b[off..off + n]);
        }
    }
    // PHDR validation above has already excluded PT_DYNAMIC and PT_INTERP.
    // Any inert section metadata must describe precisely the extracted
    // RELA table; no NEEDED, PLT, RELR, textrel or external symbol resolution.
    let mut rela = None;
    let mut size = None;
    let mut ent = None;
    let mut relacount = None;
    if let Some(dyns) = dynamic {
        let mut terminated = false;
        for d in dyns.chunks_exact(16) {
            let tag = u64at(d, 0);
            let value = u64at(d, 8);
            if terminated {
                assert_eq!((tag, value), (0, 0));
                continue;
            }
            match tag {
                0 => {
                    assert_eq!(value, 0);
                    terminated = true;
                }
                7 => assert!(rela.replace(value).is_none()),
                8 => assert!(size.replace(value).is_none()),
                9 => assert!(ent.replace(value).is_none()),
                0x6fff_fff9 => assert!(relacount.replace(value).is_none()),
                4 | 5 | 6 | 10 | 11 | 21 | 0x6fff_fef5 => (),
                30 => assert!(value & !(2 | 8) == 0, "unsupported DT_FLAGS"),
                0x6fff_fffb => assert!(value & !(0x0800_0000 | 1) == 0, "unsupported DT_FLAGS_1"),
                _ => panic!("unsupported dynamic tag {tag:#x}"),
            }
        }
        assert!(terminated);
    }
    match rela_table {
        Some((addr, n)) => {
            assert_eq!((rela, size, ent), (Some(addr), Some(n), Some(24)));
            assert!(relacount.is_none_or(|v| v == entries.len() as u64));
        }
        None => assert!(rela.is_none() && size.unwrap_or(0) == 0 && relacount.unwrap_or(0) == 0),
    }
    entries
}
pub fn build() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("..");
    let source = root.join("user/v0199-control/main.rs");
    let script = root.join("user/v0199-control/linker.ld");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed={}", script.display());
    for rel in [
        "user/v0199-control/audit.rs",
        "user/v0199-control/audit_hash.rs",
        "user/v0199-control/catalog.rs",
        "user/v0199-control/file_read.rs",
        "user/v0199-control/file_receipt.rs",
        "user/v0199-control/file_fsync.rs",
        "crates/control-model/src/native_v0199.rs",
        "crates/prototype/src/model.rs",
        "crates/prototype/src/learning/seed.rs",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(rel).display());
    }
    println!("cargo:rerun-if-changed=build/v0199_roles.rs");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let model_operator_probe = env::var_os("CARGO_FEATURE_V020_PRODUCTION").is_none()
        && (env::var_os("CARGO_FEATURE_V0199_CONTROL_BRINGUP").is_some()
            || env::var_os("CARGO_FEATURE_V0199_EPOCH_DISK_SELFTEST").is_some());
    let snapshot_catalog = env::var_os("CARGO_FEATURE_V020_PRODUCTION_SNAPSHOT_CATALOG").is_some();
    let file_read = env::var_os("CARGO_FEATURE_V020_PRODUCTION_FILE_READ").is_some();
    let fsync = env::var_os("CARGO_FEATURE_V020_PRODUCTION_FSYNC_SCRATCH").is_some();
    let reopen = env::var_os("CARGO_FEATURE_V020_PRODUCTION_MEDIA_REOPEN").is_some();
    println!("cargo:rustc-check-cfg=cfg(cyxia_fsync_bound_fixture)");
    println!("cargo:rerun-if-env-changed=CYXIA_FSYNC_TEST_BOUND");
    if fsync && !reopen {
        build_fsync_client_fixture(&out);
        if env::var("CYXIA_FSYNC_TEST_BOUND").as_deref() == Ok("1") {
            println!("cargo:rustc-cfg=cyxia_fsync_bound_fixture");
        }
    }
    let file_sessions = env::var_os("CARGO_FEATURE_V020_PRODUCTION_FILE_SESSIONS").is_some();
    let file_volatile_write =
        env::var_os("CARGO_FEATURE_V020_PRODUCTION_FILE_VOLATILE_WRITE").is_some();
    let snapshot_read = env::var_os("CARGO_FEATURE_V020_PRODUCTION_SNAPSHOT_READ").is_some();
    let mut manifest = String::from("[\n");
    let mut hashes = Vec::new();
    for role in ROLES {
        let name = format!("v0199-role-{role}.elf");
        let target = out.join(&name);
        let mut compiler = Command::new(env::var("RUSTC").unwrap());
        if model_operator_probe && matches!(role, 6 | 7) {
            compiler.args(["--cfg", "model_operator_probe"]);
        }
        if snapshot_catalog && matches!(role, 6 | 11) {
            compiler.args(["--cfg", "snapshot_catalog_probe"]);
        }
        if file_read && matches!(role, 6 | 11) {
            compiler.args(["--cfg", "file_read_probe"]);
        }
        if fsync && role == 11 {
            compiler.args([
                "--cfg",
                if reopen {
                    "file_receipt_query_probe"
                } else {
                    "file_fsync_probe"
                },
            ]);
        }
        if file_sessions && role == 11 {
            compiler.args(["--cfg", "file_sessions_probe"]);
        }
        if file_volatile_write && role == 11 {
            compiler.args(["--cfg", "file_volatile_write_probe"]);
        }
        if snapshot_read && role == 11 {
            compiler.args(["--cfg", "snapshot_read_probe"]);
        }
        let status = compiler
            .arg(&source)
            .args([
                "--edition=2024",
                "--check-cfg=cfg(control_role, values(\"2\", \"3\", \"6\", \"7\", \"8\", \"9\", \"10\", \"11\"))",
                "--check-cfg=cfg(model_operator_probe)",
                "--check-cfg=cfg(snapshot_catalog_probe)",
                "--check-cfg=cfg(file_read_probe)",
                "--check-cfg=cfg(file_receipt_query_probe)",
                "--check-cfg=cfg(file_fsync_probe)",
                "--check-cfg=cfg(file_sessions_probe)",
                "--check-cfg=cfg(file_volatile_write_probe)",
                "--check-cfg=cfg(snapshot_read_probe)",
                "--check-cfg=cfg(test)",
                "--target",
                "aarch64-unknown-none-softfloat",
                "--crate-name",
                "cyxia_native_control_role",
                "-C",
                "opt-level=2",
                "-C",
                "panic=abort",
                "-C",
                "relocation-model=pic",
                "-C",
                "overflow-checks=yes",
                "-C",
                "strip=debuginfo",
                "-C",
                "link-arg=-pie",
                "-C",
                "link-arg=--no-dynamic-linker",
                "-C",
                "link-arg=-Bsymbolic",
                "-C",
                "link-arg=--no-undefined",
                "-C",
                "link-arg=--build-id=none",
                "-C",
                "link-arg=-zmax-page-size=4096",
                "-C",
                "link-arg=-zcommon-page-size=4096",
            ])
            .arg("--cfg")
            .arg(format!("control_role=\"{role}\""))
            .arg("-C")
            .arg(format!("link-arg=-T{}", script.display()))
            .arg("-o")
            .arg(&target)
            .status()
            .expect("native role compiler");
        assert!(status.success(), "native role {role} build failed");
        let bytes = fs::read(&target).unwrap();
        assert!(bytes.len() <= 128 * 1024);
        let entries = extract_relative(&bytes);
        let mut canonical = b"CyxiaOS-v0199-relative-sidecar".to_vec();
        canonical.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        let mut rust_entries = String::from("&[");
        for (offset, info, addend) in entries {
            canonical.extend_from_slice(&offset.to_le_bytes());
            canonical.extend_from_slice(&info.to_le_bytes());
            canonical.extend_from_slice(&addend.to_le_bytes());
            rust_entries.push_str(&format!(
                "RelativeRelocation{{offset:{offset},info:{info},addend:{addend}}},"
            ));
        }
        rust_entries.push(']');
        let sidecar = out.join(format!("v0199-role-{role}.relative.bin"));
        fs::write(&sidecar, canonical).unwrap();
        let rel = digest(&sidecar);
        let hash = digest(&target);
        assert!(
            !hashes.contains(&hash),
            "independent role ELF package unexpectedly identical"
        );
        hashes.push(hash);
        manifest.push_str(&format!("BootPackage {{ role_id:{role}, bytes:include_bytes!(concat!(env!(\"OUT_DIR\"),\"/{name}\")), image_sha256:{hash:?}, relative_sha256:{rel:?},relative:{rust_entries} }},\n"));
    }
    manifest.push(']');
    fs::write(out.join("v0199-role-catalog.rs"), manifest).unwrap();
}
