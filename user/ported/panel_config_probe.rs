//! Real libcosmic configuration fallback, complete panel schema and user precedence.
use cosmic_config::{Config, ConfigGet, ConfigSet};

fn exercise() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new("com.system76.CosmicPanel", 1)?;
    println!("PANEL_CONFIG_PROBE USER_DIRECTORY PASS");
    let entries: Vec<String> = config.get("entries")?;
    if entries != ["Panel", "Dock"] {
        return Err(format!("wrong entries: {entries:?}").into());
    }
    println!("PANEL_CONFIG_PROBE ENTRIES PASS");
    let mut keys = 1;
    let mut applets = 0;
    for name in &entries {
        let id = format!("com.system76.CosmicPanel.{name}");
        let panel = Config::new(&id, 1)?;
        let observed: String = panel.get("name")?;
        if &observed != name {
            return Err("wrong panel name".into());
        }
        let wings: Option<(Vec<String>, Vec<String>)> = panel.get("plugins_wings")?;
        let center: Option<Vec<String>> = panel.get("plugins_center")?;
        applets += wings.map_or(0, |(left, right)| left.len() + right.len());
        applets += center.map_or(0, |items| items.len());
        for file in std::fs::read_dir(format!("/usr/share/cosmic/{id}/v1"))? {
            let file = file?;
            let key = file.file_name().into_string().map_err(|_| "non-UTF8 key")?;
            let _: serde::de::IgnoredAny = panel.get_system_default(&key)?;
            keys += 1;
        }
    }
    if keys != 45 || applets != 18 {
        return Err(format!("keys={keys} applets={applets}").into());
    }
    println!("PANEL_CONFIG_PROBE COMPLETE_SCHEMA PASS");
    println!("PANEL_CONFIG_PROBE APPLETS_18 PASS");
    config.set("entries", vec![String::from("Dock")])?;
    let override_value: Vec<String> = config.get("entries")?;
    let system: Vec<String> = config.get_system_default("entries")?;
    if override_value != ["Dock"] || system != entries {
        return Err("user override precedence".into());
    }
    let home = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(".config")
        });
    std::fs::remove_file(home.join("cosmic/com.system76.CosmicPanel/v1/entries"))?;
    println!("PANEL_CONFIG_PROBE USER_OVERRIDE PASS");
    Ok(())
}

fn main() {
    println!("PANEL_CONFIG_PROBE START");
    if let Err(error) = exercise() {
        println!("PANEL_CONFIG_PROBE FAIL {error:?}");
        std::process::exit(1);
    }
    println!("PANEL_CONFIG_PROBE PASS");
}
