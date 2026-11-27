//! Authorized AArch64 TLS package inputs. No test identity is consulted.
use super::startup_catalog::{copy_policy_inputs, load};
use std::{env, fs, path::PathBuf};

const PREDECESSOR: &str = "CYXIA_PREDECESSOR_STARTUP_CATALOG_DIR";
const PRIVATE_KEY: &str = "CYXIA_TLS_SIGNER_KEY_FILE";

pub(super) fn build(default_catalog: bool) {
    println!("cargo:rustc-check-cfg=cfg(cyxia_resident_net)");
    println!("cargo:rustc-check-cfg=cfg(cyxia_network_predecessor)");
    println!("cargo:rerun-if-env-changed={PREDECESSOR}");
    println!("cargo:rerun-if-env-changed={PRIVATE_KEY}");
    let enabled = env::var_os("CARGO_FEATURE_V020_PRODUCTION_RESIDENT_NET").is_some();
    let predecessor = env::var_os(PREDECESSOR);
    let key = env::var_os(PRIVATE_KEY);
    assert!(
        predecessor.is_none() && key.is_none() || default_catalog && enabled,
        "TLS deployment inputs require a production resident catalog"
    );
    if !default_catalog || !enabled {
        return;
    }
    let input = PathBuf::from(
        env::var_os("CYXIA_STARTUP_CATALOG_DIR").expect("TLS startup catalog directory"),
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("startup build output directory"))
        .join("startup-catalog");
    println!("cargo:rerun-if-changed={}", input.display());
    if let Some(previous) = predecessor {
        let previous = PathBuf::from(previous);
        let dst = out.join("predecessor");
        fs::create_dir_all(&dst).expect("startup catalog predecessor output");
        copy_policy_inputs(&previous, &dst);
        println!("cargo:rustc-cfg=cyxia_network_predecessor");
    }
    let manifest = fs::read(out.join("key-manifest.bin")).expect("staged key manifest");
    // Runtime validates the complete signed manifest. The build needs only
    // this marker to avoid pulling deployment images into non-network or
    // revoked boots.
    if !manifest.starts_with(b"CYXNET01") || manifest.get(73) != Some(&1) {
        assert!(key.is_none(), "no Signer key belongs to this boot profile");
        return;
    }
    for (name, min, max) in [
        ("tls-verifier.elf", 64, 4 * 1024 * 1024),
        ("tls-signer.elf", 64, 256 * 1024),
        ("tls-ingress.elf", 64, 64 * 1024),
        ("tls-packages.sig", 64, 64),
    ] {
        fs::write(out.join(name), load(&input, name, min, max)).expect("stage TLS package");
    }
    let key = PathBuf::from(key.expect("active TLS deployment requires CYXIA_TLS_SIGNER_KEY_FILE"));
    assert!(key.is_absolute(), "Signer key path must be absolute");
    let metadata = fs::symlink_metadata(&key).expect("missing provisioned Signer key");
    assert!(
        metadata.is_file() && (1..=256).contains(&metadata.len()),
        "Signer key must be a bounded regular DER file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            metadata.permissions().mode() & 0o077,
            0,
            "Signer key permissions"
        );
    }
    // rustc initializes the one-shot private staging page directly from the
    // provisioned file. Cargo never copies this file into the public catalog.
    println!("cargo:rerun-if-changed={}", key.display());
    println!(
        "cargo:rustc-env=CYXIA_DEPLOYMENT_SIGNER_DER={}",
        key.display()
    );
    println!("cargo:rustc-cfg=cyxia_resident_net");
}
