use crate::error::{Error, Result};
use tokio::fs;

/// .envi file: a tiny TOML-subset config committed to the repo.
/// Example: `namespace = "myapp"`
pub struct EnviFile {
    pub namespace: Option<String>,
}

pub async fn read_envi_file(cwd: &str) -> Result<EnviFile> {
    let path = format!("{cwd}/.envi");
    match fs::read_to_string(&path).await {
        Ok(text) => {
            let namespace = text
                .lines()
                .find_map(|line| {
                    let line = line.trim();
                    if let Some(rest) = line.strip_prefix("namespace") {
                        let rest = rest.trim();
                        if let Some(rest) = rest.strip_prefix('=') {
                            let val = rest.trim().trim_matches('"');
                            if !val.is_empty() {
                                return Some(val.to_string());
                            }
                        }
                    }
                    None
                });
            Ok(EnviFile { namespace })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(EnviFile { namespace: None }),
        Err(e) => Err(Error::Io(e)),
    }
}

pub async fn write_envi_file(namespace: &str, cwd: &str) -> Result<()> {
    let path = format!("{cwd}/.envi");
    fs::write(&path, format!("namespace = \"{namespace}\"\n")).await?;
    Ok(())
}
