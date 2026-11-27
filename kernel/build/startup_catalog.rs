use std::{env, fs, io::Read, path::Path};

// These immutable inputs are supported by the default resident image and the
// explicit signed scratch resident profile. Verification runs in the guest.
pub(super) fn build() -> bool {
    const DIR: &str = "CYXIA_STARTUP_CATALOG_DIR";
    println!("cargo:rustc-check-cfg=cfg(cyxia_startup_catalog)");
    println!("cargo:rustc-check-cfg=cfg(cyxia_signed_scratch_catalog)");
    println!("cargo:rustc-check-cfg=cfg(cyxia_signed_resident)");
    println!("cargo:rerun-if-env-changed={DIR}");
    let signed_scratch = env::var_os("CARGO_FEATURE_V020_PRODUCTION_SIGNED_RESIDENT").is_some();
    if signed_scratch {
        println!("cargo:rustc-cfg=cyxia_signed_resident");
    }
    if env::var_os("CARGO_FEATURE_V020_PRODUCTION").is_none()
        || (env::var_os("CARGO_FEATURE_V020_PRODUCTION_DIAGNOSTIC").is_some() && !signed_scratch)
    {
        return false;
    }
    let Some(catalog) = env::var_os(DIR) else {
        return false;
    };
    let input = Path::new(&catalog);
    let out = env::var_os("OUT_DIR").expect("startup build output directory");
    let out = Path::new(&out).join("startup-catalog");
    fs::create_dir_all(&out).expect("startup catalog build output");

    for (name, min, max) in [
        ("offline-ed25519-pubkey.bin", 32, 32),
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
    let cfg = if signed_scratch {
        "cyxia_signed_scratch_catalog"
    } else {
        "cyxia_startup_catalog"
    };
    println!("cargo:rustc-cfg={cfg}");
    if !signed_scratch {
        println!("cargo:rustc-cfg=cyxia_signed_resident");
    }
    !signed_scratch
}

fn load(directory: &Path, name: &str, min: usize, max: usize) -> Vec<u8> {
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
