use std::{env, fs, io::Read, path::Path};

pub(super) const ROLE_PACKAGES_DIR: &str = "CYXIA_STARTUP_ROLE_PACKAGES_DIR";

// These immutable inputs are supported by the default resident image and the
// explicit signed scratch resident profile. Verification runs in the guest.
pub(super) fn build() -> bool {
    const DIR: &str = "CYXIA_STARTUP_CATALOG_DIR";
    println!("cargo:rustc-check-cfg=cfg(cyxia_startup_catalog)");
    println!("cargo:rustc-check-cfg=cfg(cyxia_signed_scratch_catalog)");
    println!("cargo:rustc-check-cfg=cfg(cyxia_signed_resident)");
    println!("cargo:rustc-check-cfg=cfg(cyxia_lifecycle_package_signature)");
    println!("cargo:rerun-if-env-changed={DIR}");
    println!("cargo:rerun-if-env-changed={ROLE_PACKAGES_DIR}");
    let signed_scratch = env::var_os("CARGO_FEATURE_V020_PRODUCTION_SIGNED_RESIDENT").is_some();
    if signed_scratch {
        println!("cargo:rustc-cfg=cyxia_signed_resident");
    }
    let accepts_catalog = env::var_os("CARGO_FEATURE_V020_PRODUCTION").is_some()
        && (env::var_os("CARGO_FEATURE_V020_PRODUCTION_DIAGNOSTIC").is_none() || signed_scratch);
    let catalog = env::var_os(DIR).filter(|_| accepts_catalog);
    assert!(
        env::var_os(ROLE_PACKAGES_DIR).is_none() || (catalog.is_some() && !signed_scratch),
        "{ROLE_PACKAGES_DIR} requires {DIR} on the default production profile"
    );
    let Some(catalog) = catalog else {
        return false;
    };
    let input = Path::new(&catalog);
    let out = env::var_os("OUT_DIR").expect("startup build output directory");
    let out = Path::new(&out).join("startup-catalog");
    fs::create_dir_all(&out).expect("startup catalog build output");

    fs::write(
        out.join("offline-ed25519-pubkey.bin"),
        load(input, "offline-ed25519-pubkey.bin", 32, 32),
    )
    .expect("copy startup catalog trust anchor");
    copy_policy_inputs(input, &out);
    let cfg = if signed_scratch {
        "cyxia_signed_scratch_catalog"
    } else {
        "cyxia_startup_catalog"
    };
    println!("cargo:rustc-cfg={cfg}");
    if !signed_scratch {
        println!("cargo:rustc-cfg=cyxia_signed_resident");
        // Sign OUT_DIR/startup-catalog/lifecycle-packages-to-sign.bin with
        // the offline Ed25519 key, install the detached result here and
        // rebuild with the same role sources/toolchain or prebuilt packages.
        let name = "lifecycle-packages.sig";
        let signature = input.join(name);
        if signature
            .try_exists()
            .expect("startup package signature metadata")
        {
            fs::write(out.join(name), load(input, name, 64, 64))
                .expect("copy startup package signature");
            println!("cargo:rustc-cfg=cyxia_lifecycle_package_signature");
        } else {
            // Watch additions as well as edits to an installed signature.
            println!("cargo:rerun-if-changed={}", input.display());
        }
    }
    !signed_scratch
}

pub(super) fn copy_policy_inputs(input: &Path, out: &Path) {
    for (name, min, max) in [
        ("offline-config.bin", 256 + 256 + 64, 256 + 65_536 + 64),
        ("rule-profile.bin", 32, 65_536),
        ("security-profile.bin", 256, 256),
        ("key-manifest.bin", 1, 65_536),
    ] {
        fs::write(out.join(name), load(input, name, min, max))
            .expect("copy startup catalog build input");
    }
    let generation = load(input, "key-generation.txt", 1, 32);
    let generation = std::str::from_utf8(&generation)
        .expect("startup key generation UTF-8")
        .trim()
        .parse::<u64>()
        .expect("startup key generation u64");
    assert_ne!(generation, 0, "startup key generation must be nonzero");
    fs::write(out.join("key-generation.rs"), generation.to_string())
        .expect("write startup catalog key generation");
    println!("cargo:rerun-if-changed={}", input.display());
    for (data, signature, bytes) in [
        ("recovery-store.bin", "recovery-store.sig", 104),
        ("file-volume.bin", "file-volume.sig", 168),
    ] {
        let present = input
            .join(data)
            .try_exists()
            .expect("catalog data metadata");
        let signed = input
            .join(signature)
            .try_exists()
            .expect("catalog signature metadata");
        assert_eq!(present, signed, "incomplete startup catalog pair {data}");
        for (name, bytes) in [(data, bytes), (signature, 64)] {
            let contents = if present {
                load(input, name, bytes, bytes)
            } else {
                Vec::new()
            };
            fs::write(out.join(name), contents).expect("copy detached startup catalog input");
        }
    }
}

pub(super) fn load(directory: &Path, name: &str, min: usize, max: usize) -> Vec<u8> {
    let path = directory.join(name);
    println!("cargo:rerun-if-changed={}", path.display());
    assert!(
        fs::metadata(&path)
            .unwrap_or_else(|e| panic!("startup input {name}: {e}"))
            .is_file(),
        "startup input {name} is not a regular file"
    );
    let file = fs::File::open(&path).unwrap_or_else(|e| panic!("read startup input {name}: {e}"));
    let mut data = Vec::new();
    file.take((max + 1) as u64)
        .read_to_end(&mut data)
        .expect("read complete startup build input");
    assert!(
        (min..=max).contains(&data.len()),
        "invalid startup input length for {name}"
    );
    data
}
