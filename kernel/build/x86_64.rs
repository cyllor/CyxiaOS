use std::env;

pub fn build() {
    let runtime = env::var_os("CARGO_FEATURE_OS_RUNTIME").is_some();
    for (key, _) in env::vars() {
        assert!(
            runtime
                || !key.starts_with("CARGO_FEATURE_")
                || key == "CARGO_FEATURE_SELFTEST"
                || key == "CARGO_FEATURE_SMP_SELFTEST",
            "x86-64 currently supports only the base/selftest/smp-selftest platform profiles: {key}"
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
    println!("cargo:rerun-if-changed=linker/x86_64-runtime.ld");
    println!("cargo:rerun-if-changed=../crates/arch-x86_64/src/entry.S");
    println!("cargo:rerun-if-changed=../crates/arch-x86_64/src/ap_entry.S");
    println!("cargo:rerun-if-changed=../crates/arch-x86_64/src/entry_runtime.S");
    if runtime {
        super::os::build();
    }
    println!(
        "cargo:rustc-link-arg=-T{}/linker/{}",
        env::var("CARGO_MANIFEST_DIR").unwrap(),
        if runtime {
            "x86_64-runtime.ld"
        } else {
            "x86_64.ld"
        }
    );
    println!("cargo:rustc-link-arg=-zmax-page-size=4096");
    println!("cargo:rustc-link-arg=--build-id=none");
}
