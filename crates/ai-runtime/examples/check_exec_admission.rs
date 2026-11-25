//! Host preflight using the same executable-image policy as the guest kernel.
use std::{error::Error, io};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    let (profile, free, requested) = match args.as_slice() {
        [_, free, requested] => ("legacy", free, requested),
        [_, option, profile, free, requested] if option == "--profile" => {
            (profile.as_str(), free, requested)
        }
        _ => {
            return Err(io::Error::other(
                "usage: check_exec_admission [--profile legacy|full-os-v1|full-os-v2|full-os-v3] FREE REQUESTED",
            )
            .into());
        }
    };
    let free: u32 = free.parse()?;
    let requested: u32 = requested.parse()?;
    let decision = match profile {
        "legacy" => cyxia_ai_runtime::executable_memory_policy(free, requested),
        "full-os-v1" | "full-os-v2" | "full-os-v3" => {
            cyxia_ai_runtime::full_os_executable_memory_policy(free, requested)
        }
        _ => return Err(io::Error::other("unknown executable admission profile").into()),
    };
    let (allowed, model) =
        decision.map_err(|_| io::Error::other("outside executable model input domain"))?;
    println!(
        "{{\"free\":{free},\"requested\":{requested},\"allowed\":{allowed},\"model\":{model}}}"
    );
    Ok(())
}
