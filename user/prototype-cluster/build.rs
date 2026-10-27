use std::{env, fs, path::PathBuf};
fn main() {
    println!("cargo:rerun-if-env-changed=CYXIA_CLUSTER_IDENTITY");
    println!("cargo:rerun-if-env-changed=CYXIA_CLUSTER_LEAVE");
    println!("cargo:rerun-if-env-changed=CYXIA_CLUSTER_FAULT");
    if env::var("TARGET").unwrap() != "aarch64-unknown-none" {
        return;
    }
    let root = PathBuf::from(
        env::var_os("CYXIA_CLUSTER_IDENTITY")
            .expect("set CYXIA_CLUSTER_IDENTITY to externally provisioned OWN identity directory"),
    );
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let fault = env::var("CYXIA_CLUSTER_FAULT").unwrap_or_else(|_| "none".into());
    let fault = match fault.as_str() {
        "none" => 0,
        "after-ready" => 1,
        _ => panic!("CYXIA_CLUSTER_FAULT must be none or after-ready"),
    };
    fs::write(output.join("service-fault.rs"), fault.to_string()).unwrap();
    for name in ["cert.der", "key.der", "peer.pub", "peer.pin"] {
        let path = root.join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        fs::copy(&path, output.join(name)).expect("read own externally provisioned identity");
    }
    println!(
        "cargo:rustc-link-arg-bin=cyxia-prototype-cluster=-T{}/linker.ld",
        env::var("CARGO_MANIFEST_DIR").unwrap()
    );
    println!("cargo:rustc-link-arg-bin=cyxia-prototype-cluster=-zmax-page-size=4096");
}
