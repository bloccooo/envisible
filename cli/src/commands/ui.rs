use indicatif::{ProgressBar, ProgressStyle};
use lib::{
    config::read_config,
    crypto::derive_private_key,
    error::{Error, Result},
    store::{unlock, Store},
};

use crate::passphrase::prompt_passphrase;

pub async fn run() -> Result<()> {
    let config = read_config().await?.ok_or(Error::NoConfig)?;

    if config.vaults.is_empty() {
        return Err(Error::NoVaults);
    }

    let vault = if config.vaults.len() == 1 {
        config.vaults.into_iter().next().unwrap()
    } else {
        let names: Vec<_> = config.vaults.iter().map(|w| w.name.as_str()).collect();
        let idx = dialoguer::Select::new()
            .with_prompt("Select vault")
            .items(&names)
            .default(0)
            .interact()
            .map_err(|e| Error::Other(e.to_string()))?;
        config.vaults.into_iter().nth(idx).unwrap()
    };

    let store = Store::new(&vault.id, &config.member_id, &vault.storage)?;

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner} {msg}")
            .unwrap(),
    );
    spinner.set_message("Syncing...");
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    let doc = store.pull().await?;

    spinner.finish_and_clear();
    let agent = crate::agent::AgentClient::connect_or_start();
    let private_key = if let Some(ref agent) = agent {
        if let Some(key) = agent.get_key(&vault.id) {
            key
        } else {
            derive_private_key(&prompt_passphrase()?, &vault.id, &config.member_id)?
        }
    } else {
        derive_private_key(&prompt_passphrase()?, &vault.id, &config.member_id)?
    };
    let session = unlock(&doc, &private_key)?;
    if let Some(ref agent) = agent {
        agent.store_key(&vault.id, &private_key);
    }

    crate::tui::run(
        doc,
        store,
        session,
        config.member_name,
        vault.name,
        vault.storage,
    )
    .await
}
