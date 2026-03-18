use crate::error::{Error, Result};
use tokio::fs;

/// .envi file: a tiny TOML-subset config committed to the repo.
/// Example: `tag = "myapp"`
pub struct EnviFile {
    pub tag: Option<String>,
    pub vault: Option<String>,
}

pub async fn read_envi_file(cwd: &str) -> Result<EnviFile> {
    let path = format!("{cwd}/.envi");
    match fs::read_to_string(&path).await {
        Ok(text) => {
            let (mut tag, mut vault) = (None, None);
            for line in text.lines() {
                let line = line.trim();
                for (key, dest) in [("tag", &mut tag), ("vault", &mut vault)] {
                    if dest.is_none() {
                        if let Some(rest) = line.strip_prefix(key) {
                            let rest = rest.trim();
                            if let Some(rest) = rest.strip_prefix('=') {
                                let val = rest.trim().trim_matches('"');
                                if !val.is_empty() {
                                    *dest = Some(val.to_string());
                                }
                            }
                        }
                    }
                }
            }
            Ok(EnviFile { tag, vault })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(EnviFile { tag: None, vault: None }),
        Err(e) => Err(Error::Io(e)),
    }
}

pub async fn write_envi_file(tag: &str, cwd: &str) -> Result<()> {
    let path = format!("{cwd}/.envi");
    fs::write(&path, format!("tag = \"{tag}\"\n")).await?;
    Ok(())
}
