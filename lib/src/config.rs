use crate::{error::{Error, Result}, storage::StorageConfig};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    pub id: String,
    pub name: String,
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnviConfig {
    pub version: String,
    pub member_name: String,
    pub member_id: String,
    #[serde(alias = "workspaces")]
    pub vaults: Vec<VaultConfig>,
}

fn config_path() -> PathBuf {
    ProjectDirs::from("", "", "envi")
        .map(|d| d.config_dir().join("config.json"))
        .unwrap_or_else(|| PathBuf::from(".envi-config.json"))
}

pub async fn read_config() -> Result<Option<EnviConfig>> {
    match std::fs::read_to_string(config_path()) {
        Ok(json) => Ok(Some(serde_json::from_str(&json)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io(e)),
    }
}

pub async fn write_config(config: &EnviConfig) -> Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(config)?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?
            .write_all(json.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(&path, json)?;

    Ok(())
}

pub async fn delete_config() -> Result<()> {
    match std::fs::remove_file(config_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}
