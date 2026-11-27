use super::startup_catalog::load;
use std::{env, fs, path::Path};

const MAX_ELF_BYTES: usize = 128 * 1024;

pub(super) fn build(default_catalog: bool) {
    println!("cargo:rustc-check-cfg=cfg(cyxia_business_package)");
    if !default_catalog {
        return;
    }
    let input = env::var_os("CYXIA_STARTUP_CATALOG_DIR").expect("startup catalog directory");
    let input = Path::new(&input);
    let package = input.join("business-package.elf");
    let signature = input.join("business-package.sig");
    // Watch the directory when the optional pair is absent so adding both
    // deployment assets causes Cargo to rebuild the immutable inventory.
    println!("cargo:rerun-if-changed={}", input.display());
    match (package.try_exists(), signature.try_exists()) {
        (Ok(false), Ok(false)) => return,
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
}
