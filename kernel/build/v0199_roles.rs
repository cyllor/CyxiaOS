//! Separate compiler invocations and read-only build manifest for eight
//! ABI3 static PIE bootstrap packages. No downloader or mutable filesystem
//! package resolution is used at guest launch.
use std::{env,fs,path::{Path,PathBuf},process::Command};
const ROLES:[u16;8]=[6,7,2,8,9,3,10,11];
fn u16at(b:&[u8],n:usize)->u16{u16::from_le_bytes(b[n..n+2].try_into().unwrap())}
fn u32at(b:&[u8],n:usize)->u32{u32::from_le_bytes(b[n..n+4].try_into().unwrap())}
fn u64at(b:&[u8],n:usize)->u64{u64::from_le_bytes(b[n..n+8].try_into().unwrap())}
fn digest(path:&Path)->[u8;32]{
    let out=Command::new("sha256sum").arg(path).output().expect("host sha256sum");
    assert!(out.status.success());
    let s=std::str::from_utf8(&out.stdout).unwrap();
    let h=s.split_whitespace().next().unwrap();
    assert_eq!(h.len(),64);
    std::array::from_fn(|i|u8::from_str_radix(&h[i*2..i*2+2],16).unwrap())
}
fn verify_no_relocations(b:&[u8]){
    assert!(b.len()>=64 && b.len()<=8*1024*1024 && &b[..4]==b"\x7fELF");
    assert_eq!((b[4],b[5],u16at(b,16),u16at(b,18)),(2,1,3,183));
    let p=usize::try_from(u64at(b,32)).unwrap();let n=usize::from(u16at(b,56));
    assert!(n>0&&n<=16&&u16at(b,54)==56&&p.checked_add(n*56).is_some_and(|e|e<=b.len()));
    let mut executable=false;
    for i in 0..n{
        let at=p+i*56;let ty=u32at(b,at);let flags=u32at(b,at+4);
        assert!(matches!(ty,0|1|4|6|0x6474_e551|0x6474_e552),"dynamic/interpreted role image");
        if ty==1{
            assert!(flags&7==4||flags&7==5||flags&7==6);
            assert_eq!(u64at(b,at+48),4096);
            assert!(u64at(b,at+40)>0);
            assert!(u64at(b,at+16).checked_add(u64at(b,at+40)).is_some_and(|e|e<=65536));
            executable|=flags&1!=0;
        }
    }
    assert!(executable);
    let s=usize::try_from(u64at(b,40)).unwrap();let count=usize::from(u16at(b,60));
    assert!(count>0&&u16at(b,58)==64&&s.checked_add(count*64).is_some_and(|e|e<=b.len()));
    for i in 0..count{
        let at=s+i*64;let ty=u32at(b,at+4);let size=u64at(b,at+32);
        // Empty authenticated RELATIVE sidecar for this initial subset.
        // Any nonempty REL, RELA or RELR is a build failure, never stripped.
        assert!(!matches!(ty,4|9|19)||size==0,"unbound runtime relocation");
        if ty==6{
            let off=usize::try_from(u64at(b,at+24)).unwrap();
            let n=usize::try_from(size).unwrap();
            assert!(n%16==0&&off.checked_add(n).is_some_and(|e|e<=b.len()));
            for d in b[off..off+n].chunks_exact(16){
                assert!(!matches!(u64at(d,0),1|2|7|8|9|17|18|19|23|35|36|37),"dynamic dependency/relocation");
            }
        }
    }
}
pub fn build(){
    let root=PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("..");
    let source=root.join("user/v0199-control/main.rs");
    let script=root.join("user/v0199-control/linker.ld");
    println!("cargo:rerun-if-changed={}",source.display());
    println!("cargo:rerun-if-changed={}",script.display());
    for rel in ["crates/control-model/src/native_v0199.rs","crates/prototype/src/model.rs",
        "crates/prototype/src/learning/seed.rs"]{
        println!("cargo:rerun-if-changed={}",root.join(rel).display());
    }
    println!("cargo:rerun-if-changed=build/v0199_roles.rs");
    let out=PathBuf::from(env::var("OUT_DIR").unwrap());
    let empty=out.join("v0199-empty-relative.bin");
    let mut canonical=b"CyxiaOS-v0199-relative-sidecar".to_vec();
    canonical.extend_from_slice(&0u32.to_le_bytes());fs::write(&empty,canonical).unwrap();
    let rel=digest(&empty);
    let mut manifest=String::from("[\n");
    let mut hashes=Vec::new();
    for role in ROLES{
        let name=format!("v0199-role-{role}.elf");
        let target=out.join(&name);
        let status=Command::new(env::var("RUSTC").unwrap()).arg(&source)
            .args(["--edition=2024","--target","aarch64-unknown-none-softfloat",
                "--crate-name","cyxia_native_control_role","-C","opt-level=2","-C","panic=abort",
                "-C","relocation-model=pic","-C","overflow-checks=yes","-C","strip=debuginfo",
                "-C","link-arg=-pie","-C","link-arg=--no-dynamic-linker","-C","link-arg=-Bsymbolic",
                "-C","link-arg=--no-undefined","-C","link-arg=--build-id=none",
                "-C","link-arg=-zmax-page-size=4096","-C","link-arg=-zcommon-page-size=4096"])
            .arg("--cfg").arg(format!("control_role=\"{role}\""))
            .arg("-C").arg(format!("link-arg=-T{}",script.display()))
            .arg("-o").arg(&target).status().expect("native role compiler");
        assert!(status.success(),"native role {role} build failed");
        let bytes=fs::read(&target).unwrap();assert!(bytes.len()<=128*1024);verify_no_relocations(&bytes);
        let hash=digest(&target);
        assert!(!hashes.contains(&hash),"independent role ELF package unexpectedly identical");
        hashes.push(hash);
        manifest.push_str(&format!("BootPackage {{ role_id:{role}, bytes:include_bytes!(concat!(env!(\"OUT_DIR\"),\"/{name}\")), image_sha256:{hash:?}, relative_sha256:{rel:?} }},\n"));
    }
    manifest.push(']');
    fs::write(out.join("v0199-role-catalog.rs"),manifest).unwrap();
}
