use lib::{
    config::read_config,
    crypto::derive_private_key,
    envi_file::read_envi_file,
    error::{Error, Result},
    secrets::list_secrets,
    store::{unlock, Store},
};

use crate::passphrase::prompt_passphrase;

pub async fn exec(
    tag_arg: Option<String>,
    vault_arg: Option<String>,
    dry_run: bool,
    cmd: Vec<String>,
) -> Result<()> {
    let envi = read_envi_file(".").await?;

    // Resolve tag filter: flag → .envi file → all secrets
    let tag_filter = tag_arg.or(envi.tag);

    // Resolve vault name: flag → .envi file → interactive
    let vault_name = vault_arg.or(envi.vault);

    let config = read_config().await?.ok_or(Error::NoConfig)?;

    if config.vaults.is_empty() {
        return Err(Error::NoVaults);
    }

    let vault = if let Some(ref name) = vault_name {
        config
            .vaults
            .into_iter()
            .find(|v| v.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| Error::Other(format!("vault \"{name}\" not found")))?
    } else if config.vaults.len() == 1 {
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
    let doc = store.pull().await?;
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

    let all_secrets = list_secrets(&doc, &session.dek)?;

    let env_vars: Vec<(String, String)> = all_secrets
        .into_iter()
        .filter(|s| {
            tag_filter
                .as_ref()
                .map(|tag| s.tags.iter().any(|t| t == tag))
                .unwrap_or(true)
        })
        .map(|s| (s.name, s.value))
        .collect();

    if dry_run {
        let label = tag_filter
            .as_deref()
            .map(|t| format!("tag \"{t}\""))
            .unwrap_or_else(|| "all secrets".to_string());
        println!("\nEnv vars that would be injected ({label}):\n");
        for (k, v) in &env_vars {
            println!("  {k}={v}");
        }
        println!();
        return Ok(());
    }

    if cmd.is_empty() {
        return Err(Error::Other(
            "no command given. Usage: envi exec [options] -- <command>".to_string(),
        ));
    }

    let status = std::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .envs(std::env::vars())
        .envs(env_vars)
        .status()
        .map_err(|e| Error::Other(format!("failed to run command: {e}")))?;

    std::process::exit(status.code().unwrap_or(1));
}
