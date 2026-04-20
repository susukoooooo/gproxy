use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
    /// Unix milliseconds.
    pub expires_at: u64,
    #[serde(default)]
    pub subscription_type: Option<String>,
    #[serde(default)]
    pub account_email: Option<String>,
}

impl Tokens {
    pub fn is_expired(&self, now_ms: u64, skew_ms: u64) -> bool {
        self.expires_at.saturating_sub(skew_ms) <= now_ms
    }
}

#[derive(Clone)]
pub struct TokenStore {
    path: PathBuf,
    inner: Arc<RwLock<Option<Tokens>>>,
}

impl TokenStore {
    pub async fn load(path: PathBuf) -> Result<Self> {
        let tokens = match tokio::fs::read(&path).await {
            Ok(bytes) => Some(serde_json::from_slice::<Tokens>(&bytes).with_context(|| {
                format!("parse tokens file {}", path.display())
            })?),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(anyhow::Error::from(err)
                    .context(format!("read tokens file {}", path.display())));
            }
        };
        Ok(Self {
            path,
            inner: Arc::new(RwLock::new(tokens)),
        })
    }

    pub async fn get(&self) -> Option<Tokens> {
        self.inner.read().await.clone()
    }

    pub async fn save(&self, tokens: Tokens) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
        let json = serde_json::to_vec_pretty(&tokens)?;
        let tmp = tmp_path(&self.path);
        tokio::fs::write(&tmp, &json)
            .await
            .with_context(|| format!("write {}", tmp.display()))?;
        tokio::fs::rename(&tmp, &self.path)
            .await
            .with_context(|| format!("rename {} -> {}", tmp.display(), self.path.display()))?;
        *self.inner.write().await = Some(tokens);
        Ok(())
    }

}

fn tmp_path(path: &Path) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    file_name.push(".tmp");
    path.with_file_name(file_name)
}
