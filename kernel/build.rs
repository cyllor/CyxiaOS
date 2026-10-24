use std::{env, path::PathBuf, process::Command};
fn catalog_budget() -> usize {
    if env::var_os("CARGO_FEATURE_LARGE_MEMORY").is_some() {
        52 * 1024 * 1024
    } else {
        48 * 1024 * 1024
    }
}
fn checked(cmd: &mut Command) {
    let status = cmd.status().expect("cannot run user toolchain");
    assert!(status.success(), "user image build failed");
}
fn assets(directory: &std::path::Path, paths: &mut Vec<PathBuf>) {
    if !directory.exists() {
        return;
    }
    for entry in std::fs::read_dir(directory).expect("read rootfs directory") {
        let entry = entry.expect("read rootfs entry");
        let kind = entry.file_type().expect("rootfs file type");
        assert!(
            !kind.is_symlink(),
            "rootfs boot catalog cannot follow symlinks"
        );
        if kind.is_dir() {
            assets(&entry.path(), paths);
        } else {
            assert!(kind.is_file(), "rootfs must contain regular files");
            paths.push(entry.path());
        }
    }
}
fn main() {
    println!("cargo:rerun-if-env-changed=CYXIA_RUST_EGL_PROBE_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_RUST_REACTOR_PROBE_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_SMITHAY_PROBE_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_SMITHAY_WAYLAND_PROBE_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_SMITHAY_WAYLAND_CLIENT_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_SMITHAY_XDG_PROBE_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_SMITHAY_XDG_CLIENT_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_SMITHAY_MULTI_PROBE_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_SMITHAY_MULTI_CLIENT_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_SMITHAY_INTERACTIVE_PROBE_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_SMITHAY_INTERACTIVE_CLIENT_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_SMITHAY_RESIZE_PROBE_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_SMITHAY_RESIZE_CLIENT_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_SMITHAY_DYNAMIC_PROBE_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_SMITHAY_DYNAMIC_CLIENT_ELF");
    println!("cargo:rerun-if-changed=linker.ld");
    println!(
        "cargo:rustc-link-arg=-T{}/linker.ld",
        env::var("CARGO_MANIFEST_DIR").unwrap()
    );
    println!("cargo:rerun-if-changed=../user");
    println!("cargo:rerun-if-env-changed=CYXIA_CC");
    println!("cargo:rerun-if-env-changed=CYXIA_PORTED_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_EGL_PROBE_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_WAYLAND_SHM_PROBE_ELF");
    println!("cargo:rerun-if-env-changed=CYXIA_CONTROL_FAULT");
    if env::var_os("CARGO_FEATURE_AI_CONTROL_SELFTEST").is_some() {
        let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("..");
        for path in [
            "user/control-service",
            "crates/control-model",
            "ports/control-service",
        ] {
            println!("cargo:rerun-if-changed={}", root.join(path).display());
        }
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());
        let fault = env::var("CYXIA_CONTROL_FAULT").unwrap_or_else(|_| "none".into());
        assert!(
            ["none", "hang", "bad-mask", "snapshot-write", "model-write"].contains(&fault.as_str()),
            "invalid test fault"
        );
        let mut cmd = Command::new(env::var("RUSTC").unwrap());
        cmd.arg(root.join("user/control-service/main.rs"))
            .args([
                "--edition=2024",
                "--target",
                "aarch64-unknown-none-softfloat",
                "--crate-name",
                "cyxia_control_service",
                "-C",
                "opt-level=2",
                "-C",
                "panic=abort",
                "-C",
                "relocation-model=static",
                "-C",
                "overflow-checks=yes",
                "-C",
                "link-arg=--build-id=none",
                "-C",
                "link-arg=-zmax-page-size=4096",
                "-A",
                "dead_code",
            ])
            .arg("--cfg")
            .arg(format!("service_fault=\"{fault}\""))
            .arg("-C")
            .arg(format!(
                "link-arg=-T{}",
                root.join("user/control-service/linker.ld").display()
            ))
            .arg("-o")
            .arg(out.join("control-service.elf"));
        checked(&mut cmd);
        let mode = ["none", "hang", "bad-mask", "snapshot-write", "model-write"]
            .iter()
            .position(|v| *v == fault)
            .unwrap();
        std::fs::write(out.join("control-mode.rs"), mode.to_string()).unwrap();
    }
    if env::var_os("CARGO_FEATURE_MODEL_V13_SELFTEST").is_some() {
        let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("..");
        for path in [
            "user/prototype-control",
            "crates/prototype/src/model.rs",
            "ports/prototype",
        ] {
            println!("cargo:rerun-if-changed={}", root.join(path).display());
        }
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());
        checked(
            Command::new(env::var("RUSTC").unwrap())
                .arg(root.join("user/prototype-control/main.rs"))
                .args([
                    "--edition=2024",
                    "--target",
                    "aarch64-unknown-none-softfloat",
                    "--crate-name",
                    "cyxia_prototype_control",
                    "-C",
                    "opt-level=2",
                    "-C",
                    "strip=debuginfo",
                    "-C",
                    "panic=abort",
                    "-C",
                    "relocation-model=static",
                    "-C",
                    "overflow-checks=yes",
                    "-C",
                    "link-arg=--build-id=none",
                    "-C",
                    "link-arg=-zmax-page-size=4096",
                    "-A",
                    "dead_code",
                ])
                .arg("-C")
                .arg(format!(
                    "link-arg=-T{}",
                    root.join("user/prototype-control/linker.ld").display()
                ))
                .arg("-o")
                .arg(out.join("prototype-control.elf")),
        );
    }
    if env::var_os("CARGO_FEATURE_PROTOTYPE_RUNTIME").is_some() {
        let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("..");
        for path in [
            "user/prototype-runtime",
            "crates/prototype/src/model.rs",
            "crates/prototype/src/features.rs",
            "crates/prototype/src/policy_wire.rs",
            "crates/prototype/src/domains/types.rs",
            "ports/prototype",
        ] {
            println!("cargo:rerun-if-changed={}", root.join(path).display());
        }
        println!("cargo:rerun-if-env-changed=CYXIA_RUNTIME_FAULT");
        let fault = env::var("CYXIA_RUNTIME_FAULT").unwrap_or_else(|_| "none".into());
        assert!(
            ["none", "hang-once", "no-stop-ack"].contains(&fault.as_str()),
            "invalid runtime fault"
        );
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());
        std::fs::write(
            out.join("runtime-fault.rs"),
            match fault.as_str() {
                "hang-once" => "1",
                "no-stop-ack" => "2",
                _ => "0",
            },
        )
        .unwrap();
        checked(
            Command::new(env::var("RUSTC").unwrap())
                .arg(root.join("user/prototype-runtime/main.rs"))
                .args([
                    "--edition=2024",
                    "--target",
                    "aarch64-unknown-none-softfloat",
                    "--crate-name",
                    "cyxia_prototype_runtime",
                    "-C",
                    "opt-level=2",
                    "-C",
                    "strip=debuginfo",
                    "-C",
                    "panic=abort",
                    "-C",
                    "relocation-model=static",
                    "-C",
                    "overflow-checks=yes",
                    "-C",
                    "link-arg=--build-id=none",
                    "-C",
                    "link-arg=-zmax-page-size=4096",
                    "-A",
                    "dead_code",
                ])
                .arg("-C")
                .arg(format!(
                    "link-arg=-T{}",
                    root.join("user/prototype-runtime/linker.ld").display()
                ))
                .arg("-o")
                .arg(out.join("prototype-runtime.elf")),
        );
    }
    if env::var_os("CARGO_FEATURE_UNIFIED_RUNTIME").is_some() {
        println!("cargo:rerun-if-env-changed=CYXIA_CLUSTER_SERVICE_ELF");
        println!("cargo:rerun-if-env-changed=CYXIA_CLUSTER_IDENTITY");
        println!("cargo:rerun-if-env-changed=CYXIA_CLUSTER_UNIX_SECONDS");
        println!("cargo:rerun-if-env-changed=CYXIA_DOMAIN_SELFTEST");
        println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());
        let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("..");
        for name in ["prototype-task", "prototype-client"] {
            let source = root.join("user").join(name);
            println!("cargo:rerun-if-changed={}", source.display());
            checked(
                Command::new(env::var("RUSTC").unwrap())
                    .arg(source.join("main.rs"))
                    .args([
                        "--edition=2024",
                        "--target",
                        "aarch64-unknown-none-softfloat",
                        "--crate-name",
                    ])
                    .arg(format!("cyxia_{}", name.replace('-', "_")))
                    .args([
                        "-C",
                        "opt-level=2",
                        "-C",
                        "panic=abort",
                        "-C",
                        "overflow-checks=yes",
                        "-C",
                        "relocation-model=static",
                        "-C",
                        "link-arg=--build-id=none",
                        "-C",
                        "link-arg=-zmax-page-size=4096",
                    ])
                    .arg("-C")
                    .arg(format!("link-arg=-T{}", source.join("linker.ld").display()))
                    .arg("-o")
                    .arg(out.join(format!("{name}.elf"))),
            );
        }
        for path in [
            "kernel/src/domain_tasks",
            "kernel/src/domain_platform",
            "kernel/src/domain_control",
            "kernel/src/domain_services.rs",
            "kernel/src/domain_storage.rs",
            "kernel/src/domain_network.rs",
            "kernel/src/domain_tasks.rs",
            "kernel/src/domain_platform.rs",
            "kernel/src/domain_control.rs",
            "kernel/src/local_placement.rs",
            "kernel/src/unified.rs",
            "kernel/src/prototype_runtime.rs",
        ] {
            println!("cargo:rerun-if-changed={}", root.join(path).display());
        }
        let selftest = env::var("CYXIA_DOMAIN_SELFTEST").unwrap_or_else(|_| "0".into());
        assert!(
            ["0", "1"].contains(&selftest.as_str()),
            "CYXIA_DOMAIN_SELFTEST must be 0 or 1"
        );
        std::fs::write(
            out.join("domain-selftest.rs"),
            if selftest == "1" { "true" } else { "false" },
        )
        .unwrap();
        let service = PathBuf::from(
            env::var("CYXIA_CLUSTER_SERVICE_ELF")
                .expect("build the per-node EL0 cluster service first"),
        );
        let identity = PathBuf::from(
            env::var("CYXIA_CLUSTER_IDENTITY").expect("per-node provisioned identity directory"),
        );
        println!("cargo:rerun-if-changed={}", service.display());
        std::fs::copy(service, out.join("cluster-service.elf")).unwrap();
        for name in ["local.pin", "peer.pin"] {
            let source = identity.join(name);
            println!("cargo:rerun-if-changed={}", source.display());
            let bytes = std::fs::read(source).unwrap();
            assert_eq!(
                bytes.len(),
                32,
                "NodeID must be SHA256 of raw Ed25519 public key"
            );
            std::fs::write(out.join(format!("{name}32")), bytes).unwrap();
        }
        let unix = env::var("CYXIA_CLUSTER_UNIX_SECONDS")
            .or_else(|_| env::var("SOURCE_DATE_EPOCH"))
            .map(|v| v.parse::<u64>().expect("provisioned clock epoch"))
            .unwrap_or_else(|_| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("UTC clock")
                    .as_secs()
            });
        assert!(
            unix > 0 && unix < (1u64 << 63),
            "provisioned UTC epoch range"
        );
        std::fs::write(out.join("cluster-unix.rs"), unix.to_string()).unwrap();
    }
    if env::var_os("CARGO_FEATURE_SELFTEST").is_some() {
        return;
    }
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../user");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    if env::var_os("CARGO_FEATURE_PORTED").is_some() {
        let directory = root.join("../artifacts/sysroot/aarch64-musl");
        let mut catalog = String::from("const PORTED: &[(&str, &str, &[u8])] = &[\n");
        let mut executable_paths = Vec::new();
        let mut total = 0usize;
        for name in [
            "probe",
            "xau-probe",
            "x11-probe",
            "x11-inspect",
            "socket-probe",
            "signal-probe",
            "desktop-api-probe",
            "pipe-probe",
            "file-probe",
            "clock-probe",
            "event-probe",
            "timerfd-probe",
            "edge-probe",
            "rust-reactor-probe",
            "smithay-probe",
            "smithay-wayland-probe",
            "smithay-wayland-client",
            "smithay-xdg-probe",
            "smithay-xdg-client",
            "smithay-multi-probe",
            "smithay-multi-client",
            "smithay-interactive-probe",
            "smithay-interactive-client",
            "smithay-resize-probe",
            "smithay-resize-client",
            "smithay-dynamic-probe",
            "smithay-dynamic-client",
            "fd-share-probe",
            "scm-probe",
            "memfd-probe",
            "egl-probe",
            "rust-egl-probe",
            "rust-std-probe",
            "wayland-probe",
            "wayland-shm-probe",
            "xkbcommon-probe",
            "cyxia-save",
            "cyxia-terminal",
            "cyxia-sh",
            "pty-probe",
            "thread-probe",
            "glib-spawn-probe",
            "spawn-probe",
            "xorg",
            "twm",
            "openbox",
            "gtk-probe",
            "pcmanfm",
            "lxpanel",
        ] {
            let openbox = env::var_os("CARGO_FEATURE_OPENBOX").is_some();
            if matches!(name, "smithay-dynamic-probe" | "smithay-dynamic-client")
                && env::var_os("CARGO_FEATURE_SMITHAY_DYNAMIC_PROBE").is_none()
            {
                continue;
            }
            if matches!(name, "smithay-resize-probe" | "smithay-resize-client")
                && env::var_os("CARGO_FEATURE_SMITHAY_RESIZE_PROBE").is_none()
            {
                continue;
            }
            if matches!(
                name,
                "smithay-interactive-probe" | "smithay-interactive-client"
            ) && env::var_os("CARGO_FEATURE_SMITHAY_INTERACTIVE_PROBE").is_none()
            {
                continue;
            }
            if matches!(name, "smithay-multi-probe" | "smithay-multi-client")
                && env::var_os("CARGO_FEATURE_SMITHAY_MULTI_PROBE").is_none()
            {
                continue;
            }
            if matches!(name, "smithay-xdg-probe" | "smithay-xdg-client")
                && env::var_os("CARGO_FEATURE_SMITHAY_XDG_PROBE").is_none()
            {
                continue;
            }
            if matches!(name, "smithay-wayland-probe" | "smithay-wayland-client")
                && env::var_os("CARGO_FEATURE_SMITHAY_WAYLAND_PROBE").is_none()
            {
                continue;
            }
            if name == "smithay-probe" && env::var_os("CARGO_FEATURE_SMITHAY_PROBE").is_none() {
                continue;
            }
            if name == "rust-egl-probe" && env::var_os("CARGO_FEATURE_RUST_EGL_PROBE").is_none() {
                continue;
            }
            if name == "rust-reactor-probe"
                && env::var_os("CARGO_FEATURE_RUST_REACTOR_PROBE").is_none()
            {
                continue;
            }
            if name == "egl-probe" && env::var_os("CARGO_FEATURE_MESA_PROBE").is_none() {
                continue;
            }
            if name == "wayland-shm-probe"
                && env::var_os("CARGO_FEATURE_WAYLAND_SHM_PROBE").is_none()
            {
                continue;
            }
            if name == "glib-spawn-probe" && env::var_os("CARGO_FEATURE_SPAWN_TEST").is_none() {
                continue;
            }
            if name == "gtk-probe" && env::var_os("CARGO_FEATURE_GTK").is_none() {
                continue;
            }
            if name == "pcmanfm" && env::var_os("CARGO_FEATURE_PCMANFM").is_none() {
                continue;
            }
            if name == "lxpanel" && env::var_os("CARGO_FEATURE_LXPANEL").is_none() {
                continue;
            }
            if (name == "twm" && openbox) || (name == "openbox" && !openbox) {
                continue;
            }
            let image = if name == "wayland-shm-probe" {
                env::var_os("CYXIA_WAYLAND_SHM_PROBE_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("wayland-shm-probe.elf"))
            } else if name == "smithay-wayland-probe" {
                env::var_os("CYXIA_SMITHAY_WAYLAND_PROBE_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("smithay-wayland-probe.elf"))
            } else if name == "smithay-wayland-client" {
                env::var_os("CYXIA_SMITHAY_WAYLAND_CLIENT_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("smithay-wayland-client.elf"))
            } else if name == "smithay-xdg-probe" {
                env::var_os("CYXIA_SMITHAY_XDG_PROBE_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("smithay-xdg-probe.elf"))
            } else if name == "smithay-xdg-client" {
                env::var_os("CYXIA_SMITHAY_XDG_CLIENT_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("smithay-xdg-client.elf"))
            } else if name == "smithay-multi-probe" {
                env::var_os("CYXIA_SMITHAY_MULTI_PROBE_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("smithay-multi-probe.elf"))
            } else if name == "smithay-multi-client" {
                env::var_os("CYXIA_SMITHAY_MULTI_CLIENT_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("smithay-multi-client.elf"))
            } else if name == "smithay-probe" {
                env::var_os("CYXIA_SMITHAY_PROBE_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("smithay-probe.elf"))
            } else if name == "smithay-dynamic-probe" {
                env::var_os("CYXIA_SMITHAY_DYNAMIC_PROBE_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("smithay-dynamic-probe.elf"))
            } else if name == "smithay-dynamic-client" {
                env::var_os("CYXIA_SMITHAY_DYNAMIC_CLIENT_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("smithay-dynamic-client.elf"))
            } else if name == "smithay-resize-probe" {
                env::var_os("CYXIA_SMITHAY_RESIZE_PROBE_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("smithay-resize-probe.elf"))
            } else if name == "smithay-resize-client" {
                env::var_os("CYXIA_SMITHAY_RESIZE_CLIENT_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("smithay-resize-client.elf"))
            } else if name == "smithay-interactive-probe" {
                env::var_os("CYXIA_SMITHAY_INTERACTIVE_PROBE_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("smithay-interactive-probe.elf"))
            } else if name == "smithay-interactive-client" {
                env::var_os("CYXIA_SMITHAY_INTERACTIVE_CLIENT_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("smithay-interactive-client.elf"))
            } else if name == "rust-reactor-probe" {
                env::var_os("CYXIA_RUST_REACTOR_PROBE_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("rust-reactor-probe.elf"))
            } else if name == "rust-egl-probe" {
                env::var_os("CYXIA_RUST_EGL_PROBE_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("rust-egl-probe.elf"))
            } else if name == "egl-probe" {
                env::var_os("CYXIA_EGL_PROBE_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("egl-probe.elf"))
            } else if name == "probe" {
                env::var_os("CYXIA_PORTED_ELF")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| directory.join("probe.elf"))
            } else {
                directory.join(if name == "xorg" {
                    "Xcyxia.elf".to_owned()
                } else {
                    format!("{name}.elf")
                })
            };
            println!("cargo:rerun-if-changed={}", image.display());
            assert!(
                !matches!(
                    name,
                    "openbox"
                        | "gtk-probe"
                        | "pcmanfm"
                        | "lxpanel"
                        | "glib-spawn-probe"
                        | "egl-probe"
                        | "rust-egl-probe"
                        | "rust-reactor-probe"
                        | "smithay-probe"
                        | "smithay-wayland-probe"
                        | "smithay-wayland-client"
                        | "smithay-xdg-probe"
                        | "smithay-xdg-client"
                        | "smithay-multi-probe"
                        | "smithay-multi-client"
                        | "smithay-interactive-probe"
                        | "smithay-interactive-client"
                        | "smithay-resize-probe"
                        | "smithay-resize-client"
                        | "smithay-dynamic-probe"
                        | "smithay-dynamic-client"
                        | "wayland-shm-probe"
                ) || image.is_file(),
                "requested desktop feature requires its target ELF: use tools/build_openbox.py, tools/build_gtk_foundation.py, tools/build_pcmanfm.py or tools/build_lxpanel.py first"
            );
            if name != "probe" && !image.exists() {
                continue;
            }
            let bytes = std::fs::read(&image)
                .expect("build the target sysroot/probe first: tools/build_sysroot.py");
            total = total.checked_add(bytes.len()).expect("catalog overflow");
            assert!(
                total <= catalog_budget(),
                "ported catalog exceeds selected boot budget"
            );
            std::fs::write(out.join(format!("{name}.elf")), bytes).expect("copy ported ELF");
            catalog.push_str(&format!("({name:?}, \"/bin/{name}\", include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{name}.elf\"))),\n"));
            executable_paths.push(format!("/bin/{name}"));
        }
        catalog.push_str("];\n");
        catalog.push_str("const ROOT_FILES: &[(&str, &[u8])] = &[\n");
        // Publish the very same immutable executable bytes through the VFS.
        // PATH lookup and directory enumeration see real stat/access entries;
        // no second ELF image or mutable shadow file is embedded.
        for (index, path) in executable_paths.iter().enumerate() {
            catalog.push_str(&format!("({path:?}, PORTED[{index}].2),\n"));
        }
        let rootfs = directory.join("rootfs");
        println!("cargo:rerun-if-changed={}", rootfs.display());
        let mut files = Vec::new();
        assets(&rootfs, &mut files);
        files.sort();
        assert!(
            files.len() + executable_paths.len() <= 128,
            "boot rootfs catalog capacity exceeded"
        );
        for (i, path) in files.iter().enumerate() {
            let name = format!("/{}", path.strip_prefix(&rootfs).unwrap().to_str().unwrap());
            assert!(name.len() < 96, "rootfs path exceeds guest path capacity");
            let bytes = std::fs::read(path).expect("read rootfs asset");
            total = total.checked_add(bytes.len()).expect("rootfs overflow");
            assert!(
                total <= catalog_budget(),
                "combined boot catalog exceeds selected budget"
            );
            std::fs::write(out.join(format!("asset-{i}")), bytes).expect("copy rootfs asset");
            catalog.push_str(&format!(
                "({name:?}, include_bytes!(concat!(env!(\"OUT_DIR\"), \"/asset-{i}\"))),\n"
            ));
        }
        catalog.push_str("];\n");
        std::fs::write(out.join("ported_catalog.rs"), catalog).expect("write ported catalog");
    }
    let cc = env::var("CYXIA_CC").unwrap_or_else(|_| "clang".into());
    let mut objects = Vec::new();
    for src in ["start.S", "libc.c", "demo.c"] {
        let obj = out.join(format!("{src}.o"));
        checked(
            Command::new(&cc)
                .args([
                    "--target=aarch64-none-elf",
                    "-ffreestanding",
                    "-fno-builtin",
                    "-fno-stack-protector",
                    "-mgeneral-regs-only",
                    "-fno-pic",
                    "-O2",
                    "-g",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-c",
                ])
                .arg("-I")
                .arg(root.join("include"))
                .arg(root.join("src").join(src))
                .arg("-o")
                .arg(&obj),
        );
        objects.push(obj);
    }
    let rustc = env::var("RUSTC").unwrap();
    let sysroot = Command::new(&rustc)
        .args(["--print", "sysroot"])
        .output()
        .unwrap();
    assert!(sysroot.status.success());
    let lld = PathBuf::from(String::from_utf8(sysroot.stdout).unwrap().trim())
        .join("lib/rustlib")
        .join(env::var("HOST").unwrap())
        .join("bin/rust-lld");
    checked(
        Command::new(lld)
            .args([
                "-flavor",
                "gnu",
                "-m",
                "aarch64elf",
                "-z",
                "max-page-size=4096",
                "-T",
            ])
            .arg(root.join("linker.ld"))
            .args(objects)
            .arg("-o")
            .arg(out.join("posix-demo.elf")),
    );
    checked(
        Command::new(rustc)
            .arg(root.join("rust/services.rs"))
            .args(if env::var_os("CARGO_FEATURE_LARGE_MEMORY").is_some() {
                vec!["--cfg", "cyxia_large_memory"]
            } else {
                vec![]
            })
            .args([
                "--edition=2024",
                "--target=aarch64-unknown-none-softfloat",
                "-C",
                "panic=abort",
                "-C",
                "opt-level=s",
                "-C",
                "relocation-model=static",
                "-C",
                "link-arg=-zmax-page-size=4096",
                "-D",
                "warnings",
            ])
            .arg("-C")
            .arg(format!("link-arg=-T{}", root.join("linker.ld").display()))
            .arg("-o")
            .arg(out.join("native-services.elf")),
    );
}
