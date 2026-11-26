//! Inspect a real ELF with the guest parser and explicit ISA/layout selection.
//! Page totals are admission inputs, not a model decision or proof of execution.
use cyxia_contracts::{ImageAbi, user_layout::ImageProfile};
use cyxia_posix::executable::{PAGE_SIZE, parse_for_profile};

fn inspect() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let usage =
        "usage: check_elf_layout <legacy|full-os-v1|full-os-v2|full-os-v3> <aarch64|x86_64> <elf>";
    let profile = match args.next().as_deref() {
        Some("legacy") => ImageProfile::Legacy,
        Some("full-os-v1") => ImageProfile::FullOsV1,
        Some("full-os-v2") => ImageProfile::FullOsV2,
        Some("full-os-v3") => ImageProfile::FullOsV3,
        _ => return Err(usage.into()),
    };
    let abi = match args.next().as_deref() {
        Some("aarch64") => ImageAbi::Aarch64,
        Some("x86_64") => ImageAbi::X86_64,
        _ => return Err(usage.into()),
    };
    let path = args.next().ok_or(usage)?;
    if args.next().is_some() {
        return Err(usage.into());
    }
    let bytes = std::fs::read(&path).map_err(|error| format!("{path}: {error}"))?;
    let plan = parse_for_profile(&bytes, abi, profile)
        .map_err(|error| format!("{path}: profile={} abi={abi:?}: {error:?}", profile.name()))?;
    let layout = plan.profile.layout();
    let load_pages = plan.pages().count();
    let required_pages = load_pages + layout.stack_pages;
    println!("path={path}");
    println!("file_bytes={}", bytes.len());
    println!("profile={}", plan.profile.name());
    println!("abi={:?}", plan.abi);
    println!("entry={:#x}", plan.entry);
    println!("phdr={:#x}", plan.phdr_address);
    println!("image_base={:#x}", layout.image_base);
    println!("image_end={:#x}", layout.image_end);
    println!("load_pages={load_pages}");
    println!("stack_base={:#x}", layout.stack_base);
    println!("stack_pages={}", layout.stack_pages);
    println!("stack_size_hint={}", plan.stack_size_hint);
    println!("required_pages={required_pages}");
    println!("exec_pool_pages={}", layout.exec_pool_pages);
    println!("heap_base={:#x}", layout.heap_base);
    println!("heap_pages={}", layout.heap_pages);
    println!(
        "tls_memory_bytes={}",
        plan.tls().map_or(0, |tls| tls.memory_size)
    );
    if required_pages > layout.exec_pool_pages {
        return Err(format!(
            "image and stack need {required_pages} pages, exceeding the backing pool"
        ));
    }
    if plan.stack_size_hint > layout.stack_pages as u64 * PAGE_SIZE {
        return Err("GNU_STACK size hint exceeds the selected stack".into());
    }
    Ok(())
}

fn main() {
    if let Err(error) = inspect() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
