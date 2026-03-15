use lib::{
    config::read_config,
    crypto::{derive_private_key, derive_signing_key},
    error::{Error, Result},
    store::Store,
};

use crate::passphrase::prompt_passphrase;

pub async fn run() -> Result<()> {
    let config = read_config().await?.ok_or(Error::NoConfig)?;

    if config.vaults.is_empty() {
        return Err(Error::NoVaults);
    }

    let passphrase = prompt_passphrase()?;

    for vault in &config.vaults {
        print!("Syncing vault '{}'... ", vault.name);
        let store = Store::new(&vault.id, &config.member_id, &vault.storage)?;
        match store.pull().await {
            Ok(mut doc) => {
                let private_key =
                    derive_private_key(&passphrase, &vault.id, &config.member_id)?;
                let signing_key = derive_signing_key(&private_key);
                store.persist(&mut doc, &signing_key).await?;
                println!("ok");
            }
            Err(e) => println!("error: {e}"),
        }
    }

    Ok(())
}
