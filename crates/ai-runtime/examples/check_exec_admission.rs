//! Host preflight using the same executable-image policy as the guest kernel.
use std::{error::Error, io};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err(io::Error::other("usage: check_exec_admission FREE REQUESTED").into());
    }
    let free: u32 = args[1].parse()?;
    let requested: u32 = args[2].parse()?;
    let (allowed, model) = cyxia_ai_runtime::executable_memory_policy(free, requested)
        .map_err(|_| io::Error::other("outside executable model input domain"))?;
    println!(
        "{{\"free\":{free},\"requested\":{requested},\"allowed\":{allowed},\"model\":{model}}}"
    );
    Ok(())
}
