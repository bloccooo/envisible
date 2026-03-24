use crate::error::{Error, Result};
use futures::StreamExt;
use opendal::{services, Operator};
use serde::{Deserialize, Serialize};
use std::{
    env,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

const DOC_EXTENSION: &str = "envi.enc";
const STORAGE_PREFIX: &str = "_envi/";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum StorageConfig {
    Fs(FsConfig),
    S3(S3Config),
    R2(R2Config),
    Webdav(WebdavConfig),
    Github(GithubConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsConfig {
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R2Config {
    pub account_id: String,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebdavConfig {
    pub endpoint: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubConfig {
    pub token: String,
    pub owner: String,
    pub repo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
}

impl StorageConfig {
    /// Build a `StorageConfig` from environment variables.
    ///
    /// `ENVI_STORAGE` selects the backend (default: `fs`):
    ///
    /// - `fs`     — `FS_ROOT` (default: `./`)
    /// - `s3`     — `S3_BUCKET`, `S3_REGION`, `S3_ACCESS_KEY_ID`,
    ///              `S3_SECRET_ACCESS_KEY`, `S3_ENDPOINT` (optional)
    /// - `r2`     — `R2_ACCOUNT_ID`, `R2_BUCKET`,
    ///              `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`
    /// - `webdav` — `WEBDAV_ENDPOINT`, `WEBDAV_USERNAME`, `WEBDAV_PASSWORD`
    /// - `github` — `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO`,
    ///              `GITHUB_ROOT` (optional)
    pub fn from_env() -> Result<Self> {
        let backend = env::var("ENVI_STORAGE").unwrap_or_else(|_| "fs".into());
        match backend.to_lowercase().as_str() {
            "fs" => Ok(StorageConfig::Fs(FsConfig {
                root: env::var("FS_ROOT").unwrap_or_else(|_| "./".into()),
            })),
            "s3" => Ok(StorageConfig::S3(S3Config {
                bucket: env::var("S3_BUCKET")
                    .map_err(|_| Error::Other("S3_BUCKET not set".into()))?,
                region: env::var("S3_REGION")
                    .map_err(|_| Error::Other("S3_REGION not set".into()))?,
                access_key_id: env::var("S3_ACCESS_KEY_ID")
                    .map_err(|_| Error::Other("S3_ACCESS_KEY_ID not set".into()))?,
                secret_access_key: env::var("S3_SECRET_ACCESS_KEY")
                    .map_err(|_| Error::Other("S3_SECRET_ACCESS_KEY not set".into()))?,
                endpoint: env::var("S3_ENDPOINT").ok(),
            })),
            "r2" => Ok(StorageConfig::R2(R2Config {
                account_id: env::var("R2_ACCOUNT_ID")
                    .map_err(|_| Error::Other("R2_ACCOUNT_ID not set".into()))?,
                bucket: env::var("R2_BUCKET")
                    .map_err(|_| Error::Other("R2_BUCKET not set".into()))?,
                access_key_id: env::var("R2_ACCESS_KEY_ID")
                    .map_err(|_| Error::Other("R2_ACCESS_KEY_ID not set".into()))?,
                secret_access_key: env::var("R2_SECRET_ACCESS_KEY")
                    .map_err(|_| Error::Other("R2_SECRET_ACCESS_KEY not set".into()))?,
            })),
            "webdav" => Ok(StorageConfig::Webdav(WebdavConfig {
                endpoint: env::var("WEBDAV_ENDPOINT")
                    .map_err(|_| Error::Other("WEBDAV_ENDPOINT not set".into()))?,
                username: env::var("WEBDAV_USERNAME").unwrap_or_default(),
                password: env::var("WEBDAV_PASSWORD").unwrap_or_default(),
            })),
            "github" => Ok(StorageConfig::Github(GithubConfig {
                token: env::var("GITHUB_TOKEN")
                    .map_err(|_| Error::Other("GITHUB_TOKEN not set".into()))?,
                owner: env::var("GITHUB_OWNER")
                    .map_err(|_| Error::Other("GITHUB_OWNER not set".into()))?,
                repo: env::var("GITHUB_REPO")
                    .map_err(|_| Error::Other("GITHUB_REPO not set".into()))?,
                root: env::var("GITHUB_ROOT").ok(),
            })),
            other => Err(Error::Other(format!("unknown STORAGE value: {other}"))),
        }
    }
}

pub fn build_operator(config: &StorageConfig) -> Result<Operator> {
    let op = match config {
        StorageConfig::Fs(c) => {
            let builder = services::Fs::default().root(&c.root);
            Operator::new(builder).map_err(Error::Storage)?.finish()
        }
        StorageConfig::S3(c) => {
            let mut builder = services::S3::default()
                .bucket(&c.bucket)
                .region(&c.region)
                .access_key_id(&c.access_key_id)
                .secret_access_key(&c.secret_access_key);
            if let Some(ep) = &c.endpoint {
                builder = builder.endpoint(ep);
            }
            Operator::new(builder).map_err(Error::Storage)?.finish()
        }
        StorageConfig::R2(c) => {
            let endpoint = format!("https://{}.r2.cloudflarestorage.com", c.account_id);
            let builder = services::S3::default()
                .bucket(&c.bucket)
                .region("auto")
                .endpoint(&endpoint)
                .access_key_id(&c.access_key_id)
                .secret_access_key(&c.secret_access_key);
            Operator::new(builder).map_err(Error::Storage)?.finish()
        }
        StorageConfig::Webdav(c) => {
            let mut builder = services::Webdav::default().endpoint(&c.endpoint);
            if !c.username.is_empty() {
                builder = builder.username(&c.username);
            }
            if !c.password.is_empty() {
                builder = builder.password(&c.password);
            }
            Operator::new(builder).map_err(Error::Storage)?.finish()
        }
        StorageConfig::Github(c) => {
            let mut builder = services::Github::default()
                .token(&c.token)
                .owner(&c.owner)
                .repo(&c.repo);
            if let Some(root) = &c.root {
                builder = builder.root(root);
            }
            Operator::new(builder).map_err(Error::Storage)?.finish()
        }
    };
    Ok(op)
}

pub struct StorageBackend {
    op: Operator,
}

impl StorageBackend {
    pub fn new(config: &StorageConfig) -> Result<Self> {
        Ok(Self {
            op: build_operator(config)?,
        })
    }

    pub async fn push(&self, path: &str, data: Vec<u8>) -> Result<()> {
        self.op
            .write(path, data)
            .await
            .map(|_| ())
            .map_err(Error::Storage)
    }

    pub async fn pull(&self, prefix: &str) -> Result<Vec<Vec<u8>>> {
        let results = self.pull_with_progress(prefix, |_| {}).await?;
        Ok(results)
    }

    pub async fn pull_with_progress(
        &self,
        prefix: &str,
        on_progress: impl Fn(u8) + Send + Sync,
    ) -> Result<Vec<Vec<u8>>> {
        let entries = match self.op.list(prefix).await {
            Ok(e) => e,
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(Error::Storage(e)),
        };

        let doc_entries: Vec<_> = entries
            .into_iter()
            .filter(|e| e.path().ends_with(&format!(".{DOC_EXTENSION}")))
            .collect();

        let loaded_count = Arc::new(AtomicU64::new(0));
        let doc_count = doc_entries.len() as u64;
        let on_progress = Arc::new(on_progress);

        const MAX_CONCURRENT: usize = 10;

        let results = futures::stream::iter(doc_entries)
            .map(|e| {
                let path = e.path().to_owned();
                let loaded_count = loaded_count.clone();
                let on_progress = on_progress.clone();

                async move {
                    let file = self.op.read(&path).await;
                    loaded_count.fetch_add(1, Ordering::Relaxed);
                    let loaded_count = loaded_count.load(Ordering::Relaxed);
                    let progress = ((loaded_count) as f64 / (doc_count) as f64 * 100.0) as u8;
                    on_progress(progress);
                    file
                }
            })
            .buffer_unordered(MAX_CONCURRENT)
            .filter_map(|r| async move {
                match r {
                    Ok(buf) => Some(buf.to_bytes().to_vec()),
                    Err(e) if e.kind() == opendal::ErrorKind::NotFound => None,
                    Err(_) => None,
                }
            })
            .collect()
            .await;

        Ok(results)
    }

    /// List vault IDs discovered under the `_envi/` prefix.
    pub async fn list_vault_ids(&self) -> Result<Vec<String>> {
        let entries = match self.op.list(STORAGE_PREFIX).await {
            Ok(e) => e,
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(Error::Storage(e)),
        };

        let ids = entries
            .into_iter()
            .filter_map(|e| {
                let path = e.path();
                // Expect paths like `_envi/{vault_id}/`
                let inner = path.strip_prefix(STORAGE_PREFIX)?;
                let id = inner.trim_end_matches('/');
                if id.is_empty() {
                    None
                } else {
                    Some(id.to_string())
                }
            })
            .collect();

        Ok(ids)
    }

    pub async fn check(&self) -> bool {
        self.op.check().await.is_ok()
    }
}

pub fn push_path(vault_id: &str, member_id: &str) -> String {
    format!("{STORAGE_PREFIX}{vault_id}/{member_id}.{DOC_EXTENSION}")
}

pub fn pull_prefix(vault_id: &str) -> String {
    format!("{STORAGE_PREFIX}{vault_id}/")
}
