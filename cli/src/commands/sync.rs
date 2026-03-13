use lib::{
    config::read_config,
    crypto::{derive_private_key, derive_signing_key},
    error::{Error, Result},
    store::Store,
};

use crate::passphrase::prompt_passphrase;

pub async fn run() -> Result<()> {
    let config = read_config().await?.ok_or(Error::NoConfig)?;

    if config.workspaces.is_empty() {
        return Err(Error::NoWorkspaces);
    }

    let passphrase = prompt_passphrase()?;

    for workspace in &config.workspaces {
        print!("Syncing workspace '{}'... ", workspace.name);
        let store = Store::new(&workspace.id, &config.member_id, &workspace.storage)?;
        match store.pull().await {
            Ok(mut doc) => {
                let private_key =
                    derive_private_key(&passphrase, &workspace.id, &config.member_id)?;
                let signing_key = derive_signing_key(&private_key);
                store.persist(&mut doc, &signing_key).await?;
                println!("ok");
            }
            Err(e) => println!("error: {e}"),
        }
    }

    Ok(())
}
