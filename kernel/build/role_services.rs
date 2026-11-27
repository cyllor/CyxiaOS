use std::{env, fs, path::Path};

pub(super) fn build(default_catalog: bool) {
    println!("cargo:rustc-check-cfg=cfg(cyxia_role_services)");
    if !default_catalog {
        return;
    }
    let directory = env::var_os("CYXIA_STARTUP_CATALOG_DIR").expect("startup catalog input");
    let input = Path::new(&directory);
    let wire = "role-services.bin";
    let signature = "role-services.sig";
    let exists = |name| {
        input
            .join(name)
            .try_exists()
            .expect("role services metadata")
    };
    let present = exists(wire);
    assert_eq!(
        present,
        exists(signature),
        "incomplete role services signature pair"
    );
    if !present {
        println!("cargo:rerun-if-changed={}", input.display());
        return;
    }
    let output = env::var_os("OUT_DIR").expect("startup catalog output");
    let output = Path::new(&output).join("startup-catalog");
    for (name, size) in [(wire, 88), (signature, 64)] {
        fs::write(
            output.join(name),
            super::startup_catalog::load(input, name, size, size),
        )
        .expect("copy signed role services");
    }
    println!("cargo:rustc-cfg=cyxia_role_services");
}
