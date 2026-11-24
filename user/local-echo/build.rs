use std::{env, fs, path::PathBuf};
fn main() {
    println!("cargo:rerun-if-env-changed=CYXIA_LOCAL_ECHO_IDENTITY");
    if env::var_os("CARGO_FEATURE_GUEST").is_none() {
        return;
    }
    assert_eq!(env::var("CARGO_CFG_TARGET_OS").as_deref(), Ok("none"));
    assert_eq!(env::var("TARGET").as_deref(), Ok("aarch64-unknown-none"),
        "the native read-only Echo service requires EL0 AArch64 FP/SIMD");
    let root=PathBuf::from(env::var_os("CYXIA_LOCAL_ECHO_IDENTITY")
        .expect("provision the local-only Echo service identity directory"));
    let out=PathBuf::from(env::var_os("OUT_DIR").unwrap());
    for name in ["cert.der","key.der","peer.pin"] {
        let source=root.join(name);
        println!("cargo:rerun-if-changed={}",source.display());
        let meta=fs::symlink_metadata(&source).expect("missing provisioned TLS identity");
        assert!(meta.is_file() && !meta.file_type().is_symlink(),
            "identity must be an ordinary local file");
        let bytes=fs::read(&source).expect("read provisioned Echo identity");
        assert!(!bytes.is_empty() && bytes.len() <= 8192,
            "identity material out of bound");
        if name=="peer.pin" { assert_eq!(bytes.len(),32,"peer pin must be SHA256"); }
        fs::write(out.join(name),bytes).expect("copy into private build output");
    }
    let dir=env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg-bin=cyxia-local-echo=-T{dir}/linker.ld");
    println!("cargo:rustc-link-arg-bin=cyxia-local-echo=-zmax-page-size=4096");
}
