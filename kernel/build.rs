// Build adapters are selected here; PC builds never invoke ARM user compilers.
#[path = "build/aarch64.rs"]
mod aarch64;
#[path = "build/x86_64.rs"]
mod x86_64;

fn main() {
    match std::env::var("TARGET").as_deref() {
        Ok("aarch64-unknown-none-softfloat") => aarch64::build(),
        Ok("x86_64-unknown-none") => x86_64::build(),
        other => panic!("unsupported kernel target: {other:?}"),
    }
}
