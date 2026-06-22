use lib::{
    config::{read_config, VaultConfig},
    crypto::derive_private_key,
    crypto::unlock_document,
    envi_file::read_envi_file,
    error::{Error, Result},
    secrets::list_secrets,
    vault_document::PlaintextSecret,
    vault_repo::VaultRepo,
};
use std::collections::HashMap;

use crate::passphrase::prompt_passphrase;

pub fn find_vault(vaults: Vec<VaultConfig>, name: &str) -> Result<VaultConfig> {
    vaults
        .into_iter()
        .find(|v| v.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| Error::Other(format!("vault \"{name}\" not found")))
}

pub fn filter_by_tag(secrets: Vec<PlaintextSecret>, tag: Option<&str>) -> Vec<PlaintextSecret> {
    secrets
        .into_iter()
        .filter(|s| {
            tag.map(|t| {
                let tags: Vec<&str> = t.split(',').map(str::trim).collect();
                s.tags.iter().any(|st| tags.contains(&st.as_str()))
            })
            .unwrap_or(true)
        })
        .collect()
}

/// Scans args for `{NAME_AS_FILE_PATH}` and `{NAME}` tokens.
/// Returns `(file_vars, value_vars)` — unique secret names for each kind.
fn collect_templates(args: &[String]) -> (Vec<String>, Vec<String>) {
    let mut file_vars: Vec<String> = Vec::new();
    let mut value_vars: Vec<String> = Vec::new();
    for arg in args {
        let mut s = arg.as_str();
        while let Some(start) = s.find('{') {
            s = &s[start + 1..];
            if let Some(end) = s.find('}') {
                let token = &s[..end];
                if let Some(var_name) = token.strip_suffix("_AS_FILE_PATH") {
                    let var_name = var_name.to_string();
                    if !var_name.is_empty() && !file_vars.contains(&var_name) {
                        file_vars.push(var_name);
                    }
                } else if !token.is_empty() && !value_vars.iter().any(|n| n == token) {
                    value_vars.push(token.to_string());
                }
                s = &s[end + 1..];
            } else {
                break;
            }
        }
    }
    (file_vars, value_vars)
}

/// Replaces `{NAME_AS_FILE_PATH}` tokens with file paths and `{NAME}` tokens with inline values.
fn substitute_templates(
    args: Vec<String>,
    paths: &HashMap<String, String>,
    values: &HashMap<String, String>,
) -> Vec<String> {
    args.into_iter()
        .map(|arg| {
            let mut result = arg;
            for (name, path) in paths {
                result = result.replace(&format!("{{{name}_AS_FILE_PATH}}"), path);
            }
            for (name, value) in values {
                result = result.replace(&format!("{{{name}}}"), value);
            }
            result
        })
        .collect()
}

/// Splits leading `KEY=VALUE` args from the actual command, mirroring shell's `VAR=val cmd` convention.
fn split_inline_env(args: Vec<String>) -> (Vec<(String, String)>, Vec<String>) {
    let mut env_overrides = Vec::new();
    let mut iter = args.into_iter().peekable();
    while let Some(arg) = iter.peek() {
        if let Some((key, val)) = arg.split_once('=') {
            let valid = !key.is_empty()
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && key
                    .chars()
                    .next()
                    .map(|c| !c.is_ascii_digit())
                    .unwrap_or(false);
            if valid {
                env_overrides.push((key.to_string(), val.to_string()));
                iter.next();
                continue;
            }
        }
        break;
    }
    (env_overrides, iter.collect())
}

fn make_temp_dir() -> Result<std::path::PathBuf> {
    use rand::Rng;
    let suffix: [u8; 4] = rand::thread_rng().gen();
    let dir = std::env::temp_dir().join(format!("envi-{}", hex::encode(suffix)));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

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
        find_vault(config.vaults, name)?
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

    let repo = VaultRepo::new(&vault.id, &config.member_id, &vault.storage)?;
    let doc = repo.pull().await?;
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
    let session = unlock_document(&doc, &private_key)?;
    if let Some(ref agent) = agent {
        agent.store_key(&vault.id, &private_key);
    }

    let all_secrets = list_secrets(&doc, &session.dek)?;
    let filtered = filter_by_tag(all_secrets, tag_filter.as_deref());

    let (file_names, value_names) = collect_templates(&cmd);

    // Build file path map: write each secret's value to a temp file
    let mut template_paths: HashMap<String, String> = HashMap::new();
    let mut temp_dir: Option<std::path::PathBuf> = None;

    if !file_names.is_empty() {
        let dir = if !dry_run {
            Some(make_temp_dir()?)
        } else {
            None
        };

        for name in &file_names {
            let secret = filtered
                .iter()
                .find(|s| s.name == *name)
                .ok_or_else(|| Error::Other(format!("secret \"{name}\" not found")))?;

            let path = match &dir {
                Some(d) => {
                    let p = d.join(name);
                    use std::io::Write;
                    use std::os::unix::fs::OpenOptionsExt;
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(0o600)
                        .open(&p)?
                        .write_all(secret.value.as_bytes())?;
                    p.to_string_lossy().into_owned()
                }
                None => std::env::temp_dir()
                    .join(format!("envi-xxxxxxxx/{name}"))
                    .to_string_lossy()
                    .into_owned(),
            };
            template_paths.insert(name.clone(), path);
        }

        temp_dir = dir;
    }

    // Build inline value map: resolve {NAME} tokens directly from secrets
    let mut template_values: HashMap<String, String> = HashMap::new();
    for name in &value_names {
        let secret = filtered
            .iter()
            .find(|s| s.name == *name)
            .ok_or_else(|| Error::Other(format!("secret \"{name}\" not found")))?;
        template_values.insert(name.clone(), secret.value.clone());
    }

    let env_vars: Vec<(String, String)> = filtered.into_iter().map(|s| (s.name, s.value)).collect();

    if dry_run {
        let label = tag_filter
            .as_deref()
            .map(|t| {
                format!(
                    "tags \"{}\"",
                    t.split(',').map(str::trim).collect::<Vec<_>>().join(", ")
                )
            })
            .unwrap_or_else(|| "all secrets".to_string());
        println!("\nEnv vars that would be injected ({label}):\n");
        for (k, v) in &env_vars {
            println!("  {k}={v}");
        }
        let has_substitutions = !template_paths.is_empty() || !template_values.is_empty();
        if has_substitutions {
            if !template_paths.is_empty() {
                println!("\nFile substitutions in command args:\n");
                for (name, path) in &template_paths {
                    println!("  {{{name}_AS_FILE_PATH}} -> {path}");
                }
            }
            if !template_values.is_empty() {
                println!("\nValue substitutions in command args:\n");
                for (name, value) in &template_values {
                    println!("  {{{name}}} -> {value}");
                }
            }
            let rewritten = substitute_templates(cmd, &template_paths, &template_values);
            let (inline_env, actual_cmd) = split_inline_env(rewritten);
            let mut parts: Vec<String> =
                inline_env.iter().map(|(k, v)| format!("{k}={v}")).collect();
            parts.extend(actual_cmd);
            println!("\nRewritten command:\n\n  {}\n", parts.join(" "));
        } else {
            println!();
        }
        return Ok(());
    }

    if cmd.is_empty() {
        return Err(Error::Other(
            "no command given. Usage: envi exec [options] -- <command>".to_string(),
        ));
    }

    let cmd = substitute_templates(cmd, &template_paths, &template_values);
    let (inline_env, cmd) = split_inline_env(cmd);

    if cmd.is_empty() {
        return Err(Error::Other(
            "no command given after env var assignments".to_string(),
        ));
    }

    let status = std::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .envs(std::env::vars())
        .envs(env_vars)
        .envs(inline_env)
        .status()
        .map_err(|e| Error::Other(format!("failed to run command: {e}")))?;

    if let Some(dir) = temp_dir {
        let _ = std::fs::remove_dir_all(&dir);
    }

    std::process::exit(status.code().unwrap_or(1));
}
