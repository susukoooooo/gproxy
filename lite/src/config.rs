use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub upstream: UpstreamConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub client_key: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            client_key: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    #[serde(default = "default_tokens_file")]
    pub tokens_file: PathBuf,
    #[serde(default = "default_stats_db")]
    pub stats_db: PathBuf,
    #[serde(default = "default_true")]
    pub inject_claude_code_identity: bool,
    #[serde(default = "default_api_base")]
    pub api_base_url: String,
    #[serde(default = "default_oauth_base")]
    pub oauth_base_url: String,
    #[serde(default = "default_claude_ai_base")]
    pub claude_ai_base_url: String,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            tokens_file: default_tokens_file(),
            stats_db: default_stats_db(),
            inject_claude_code_identity: true,
            api_base_url: default_api_base(),
            oauth_base_url: default_oauth_base(),
            claude_ai_base_url: default_claude_ai_base(),
        }
    }
}

fn default_host() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    8787
}
fn default_tokens_file() -> PathBuf {
    PathBuf::from("./data/tokens.json")
}
fn default_stats_db() -> PathBuf {
    PathBuf::from("./data/stats.db")
}
fn default_true() -> bool {
    true
}
fn default_api_base() -> String {
    "https://api.anthropic.com".into()
}
fn default_oauth_base() -> String {
    // OAuth token endpoint is served from platform.claude.com.
    "https://platform.claude.com".into()
}
fn default_claude_ai_base() -> String {
    "https://claude.ai".into()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read config file {}", path.display()))?;
        let cfg: Config = toml::from_str(&text).context("parse config toml")?;
        if cfg.server.client_key.trim().is_empty() {
            anyhow::bail!("server.client_key must be set in config");
        }
        Ok(cfg)
    }
}
