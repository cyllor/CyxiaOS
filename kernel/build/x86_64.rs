use std::env;

pub fn build() {
    for (key, _) in env::vars() {
        assert!(
            !key.starts_with("CARGO_FEATURE_") || key == "CARGO_FEATURE_SELFTEST",
            "x86-64 currently supports only the base/selftest platform profile: {key}"
        );
    }
    for name in ["CYXIA_A03_DEMAND", "CYXIA_LEARNING_COLLECTION"] {
        println!("cargo:rerun-if-env-changed={name}");
        assert!(
            env::var_os(name).is_none(),
            "ARM evidence profile is not an x86 profile: {name}"
        );
    }
    println!("cargo:rerun-if-changed=linker/x86_64.ld");
    println!("cargo:rerun-if-changed=../crates/arch-x86_64/src/entry.S");
    println!(
        "cargo:rustc-link-arg=-T{}/linker/x86_64.ld",
        env::var("CARGO_MANIFEST_DIR").unwrap()
    );
    println!("cargo:rustc-link-arg=-zmax-page-size=4096");
    println!("cargo:rustc-link-arg=--build-id=none");
}
