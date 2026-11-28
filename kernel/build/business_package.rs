use super::startup_catalog::load;
use std::{env, fs, path::Path};

const MAX_ELF_BYTES: usize = 128 * 1024;

pub(super) fn build(default_catalog: bool) {
    println!("cargo:rustc-check-cfg=cfg(cyxia_business_package)");
    println!("cargo:rustc-check-cfg=cfg(cyxia_business_task_services)");
    if !default_catalog {
        return;
    }
    let input = env::var_os("CYXIA_STARTUP_CATALOG_DIR").expect("startup catalog directory");
    let input = Path::new(&input);
    let package = input.join("business-package.elf");
    let signature = input.join("business-package.sig");
    let grants = input.join("business-task-services.bin");
    let grant_signature = input.join("business-task-services.sig");
    // Watch the directory when the optional pair is absent so adding both
    // deployment assets causes Cargo to rebuild the immutable inventory.
    println!("cargo:rerun-if-changed={}", input.display());
    let has_grants = match (grants.try_exists(), grant_signature.try_exists()) {
        (Ok(false), Ok(false)) => false,
        (Ok(true), Ok(true)) => true,
        _ => panic!(
            "business-task-services.bin and business-task-services.sig must be supplied together"
        ),
    };
    match (package.try_exists(), signature.try_exists()) {
        (Ok(false), Ok(false)) if !has_grants => return,
        (Ok(true), Ok(true)) => (),
        _ => panic!("business-package.elf and business-package.sig must be supplied together"),
    }
    let out = env::var_os("OUT_DIR").expect("startup build output directory");
    let out = Path::new(&out).join("startup-catalog");
    for (name, min, max) in [
        ("business-package.elf", 64, MAX_ELF_BYTES),
        ("business-package.sig", 64, 64),
    ] {
        fs::write(out.join(name), load(input, name, min, max)).expect(name);
    }
    println!("cargo:rustc-cfg=cyxia_business_package");
    if has_grants {
        assert!(
            env::var_os("CARGO_FEATURE_PROTOTYPE_MEMORY").is_some(),
            "business task services require native FrameMeta"
        );
        for (name, len) in [
            ("business-task-services.bin", 32),
            ("business-task-services.sig", 64),
        ] {
            fs::write(out.join(name), load(input, name, len, len)).expect(name);
        }
        println!("cargo:rustc-cfg=cyxia_business_task_services");
    }
}
