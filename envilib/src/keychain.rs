use keyring::Entry;

use crate::{
    config::EnviConfig,
    error::{Error, Result},
};

const SERVICE: &str = "envi";
const ACCOUNT: &str = "config";

fn entry() -> Result<Entry> {
    Entry::new(SERVICE, ACCOUNT).map_err(|e| Error::Keychain(e.to_string()))
}

pub fn load_keychain() -> Result<Option<EnviConfig>> {
    match entry()?.get_password() {
        Ok(json) => Ok(Some(serde_json::from_str(&json)?)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(Error::Keychain(e.to_string())),
    }
}

pub fn save_keychain(config: &EnviConfig) -> Result<()> {
    let json = serde_json::to_string(config)?;
    entry()?
        .set_password(&json)
        .map_err(|e| Error::Keychain(e.to_string()))
}

pub fn delete_keychain() -> Result<()> {
    match entry()?.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(Error::Keychain(e.to_string())),
    }
}
