// SPDX-License-Identifier: MPL-2.0
//! Minimal initializer and lifecycle verifier using the real COSMIC libraries.
use cosmic_config::{Config, ConfigGet, ConfigSet};
use cosmic_settings_config::{shortcuts, window_rules};
use std::{error::Error, fs, sync::mpsc, time::Duration};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const PROBE_ID: &str = "org.cyxia.ConfigProbe";

fn defaults() -> Result<()> {
    let config = Config::system(shortcuts::ID, 1)?;
    let bindings: shortcuts::Shortcuts = config.get_system_default("defaults")?;
    let actions: shortcuts::SystemActions = config.get_system_default("system_actions")?;
    let rules: Vec<window_rules::DefaultApplicationException> =
        Config::system(window_rules::ID, 1)?.get_system_default("tiling_exception_defaults")?;
    if bindings.0.is_empty() || actions.is_empty() || rules.is_empty() {
        return Err("upstream defaults unexpectedly empty".into());
    }
    println!("COSMIC_CONFIG DEFAULTS PASS bindings={} actions={} rules={}",
             bindings.0.len(), actions.len(), rules.len());
    Ok(())
}

fn initialize() -> Result<()> {
    defaults()?;
    let config = Config::new(shortcuts::ID, 1)?;
    match config.get_local::<shortcuts::Shortcuts>("custom") {
        Ok(_) => println!("COSMIC_CONFIG CUSTOM_PRESERVED"),
        Err(cosmic_config::Error::NotFound) => {
            config.set("custom", shortcuts::Shortcuts::default())?;
            let value: shortcuts::Shortcuts = config.get_local("custom")?;
            if !value.0.is_empty() { return Err("initial custom shortcuts differ".into()); }
            sync_after_cleanup(shortcuts::ID)?;
            println!("COSMIC_CONFIG CUSTOM_CREATED");
        }
        Err(error) => return Err(error.into()),
    }
    println!("COSMIC_CONFIG READY");
    Ok(())
}

fn config_directory(id: &str) -> Result<std::path::PathBuf> {
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".config")))
        .ok_or("configuration home is unavailable")?;
    Ok(root.join("cosmic").join(id).join("v1"))
}

fn check_clean_directory(id: &str) -> Result<()> {
    for entry in fs::read_dir(config_directory(id)?)? {
        if entry?.file_name().as_encoded_bytes().starts_with(b".atomicwrite") {
            return Err("atomic-write temporary directory leaked".into());
        }
    }
    Ok(())
}

fn sync_after_cleanup(id: &str) -> Result<()> {
    // atomicwrites fsyncs the replacement and its parent before TempDir::drop.
    // Persist the subsequent removal too: otherwise a reboot restores the
    // empty temporary directory from the preceding whole-filesystem snapshot.
    check_clean_directory(id)?;
    fs::File::open(config_directory(id)?)?.sync_all()?;
    Ok(())
}

fn exercise(persist_cleanup: bool) -> Result<()> {
    defaults()?;
    let config = Config::new(PROBE_ID, 1)?;
    let (sender, receiver) = mpsc::channel();
    let watcher = config.watch(move |current, keys| {
        if keys.iter().any(|key| key == "enabled") {
            if let Ok(value) = current.get_local::<bool>("enabled") {
                let _ = sender.send(value);
            }
        }
    })?;
    for expected in [false, true] {
        config.set("enabled", expected)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let value = receiver.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))?;
            if value == expected { break; }
        }
        if Config::new(PROBE_ID, 1)?.get_local::<bool>("enabled")? != expected {
            return Err("atomic replacement readback differs".into());
        }
        check_clean_directory(PROBE_ID)?;
        if persist_cleanup { sync_after_cleanup(PROBE_ID)?; }
        println!("COSMIC_CONFIG NOTIFIED value={expected}");
    }
    // A separate typed key proves more than an empty file or boolean default.
    config.set("generation", 2_u64)?;
    check_clean_directory(PROBE_ID)?;
    if persist_cleanup { sync_after_cleanup(PROBE_ID)?; }
    drop(watcher);
    verify()?;
    println!("COSMIC_CONFIG EXERCISE PASS");
    Ok(())
}

fn verify_values() -> Result<()> {
    let config = Config::new(PROBE_ID, 1)?;
    if !config.get_local::<bool>("enabled")? || config.get_local::<u64>("generation")? != 2 {
        return Err("persisted COSMIC configuration differs".into());
    }
    println!("COSMIC_CONFIG VALUES_RECOVERED PASS");
    Ok(())
}

fn verify() -> Result<()> {
    verify_values()?;
    check_clean_directory(PROBE_ID)?;
    check_clean_directory(shortcuts::ID)?;
    println!("COSMIC_CONFIG RECOVERED PASS");
    Ok(())
}

fn run() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("defaults") => defaults(),
        Some("init") => initialize(),
        Some("exercise") => exercise(true),
        // Independently verify library durability without our cleanup sync.
        Some("exercise-raw") => exercise(false),
        Some("verify") => verify(),
        Some("verify-values") => verify_values(),
        _ => Err("usage: cosmic-config {defaults|init|exercise|exercise-raw|verify|verify-values}".into()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("COSMIC_CONFIG FAIL: {error:?}");
        std::process::exit(1);
    }
}
