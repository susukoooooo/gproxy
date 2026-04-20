//! Claude Code OAuth (PKCE) — interactive login + refresh.
//!
//! Implements the same flow the official `claude-cli` uses so an OAuth token
//! issued to Claude Code can be reused.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::tokens::Tokens;

pub const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub const REDIRECT_URI: &str = "https://platform.claude.com/oauth/code/callback";
pub const SCOPE: &str = "user:profile user:inference user:sessions:claude_code";
pub const OAUTH_BETA: &str = "oauth-2025-04-20";
pub const ANTHROPIC_API_VERSION: &str = "2023-06-01";
pub const TOKEN_UA: &str = "claude-cli/2.1.77 (external, cli)";
pub const CLAUDE_CODE_UA: &str = "claude-code/2.1.77 (external, cli)";
pub const REFRESH_SKEW_MS: u64 = 60_000;

pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
    pub state: String,
}

impl Pkce {
    pub fn generate() -> Self {
        let mut v = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut v);
        let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));

        let mut s = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut s);
        let state = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);

        Self {
            verifier,
            challenge,
            state,
        }
    }
}

pub fn build_authorize_url(claude_ai_base: &str, pkce: &Pkce) -> String {
    let params = [
        ("code", "true"),
        ("client_id", CLIENT_ID),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT_URI),
        ("scope", SCOPE),
        ("code_challenge", pkce.challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", pkce.state.as_str()),
    ];
    let query: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect();
    format!(
        "{}/oauth/authorize?{}",
        claude_ai_base.trim_end_matches('/'),
        query.join("&")
    )
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    subscription_type: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

pub async fn exchange_code(
    client: &reqwest::Client,
    api_base: &str,
    claude_ai_base: &str,
    pkce_verifier: &str,
    code: &str,
    state: &str,
) -> Result<Tokens> {
    // Claude Code's callback page sometimes returns "code#state"; take the left side.
    let clean_code = code.split('#').next().unwrap_or(code);
    let clean_code = clean_code.split('&').next().unwrap_or(clean_code);

    let body = format!(
        "grant_type=authorization_code&client_id={}&code={}&redirect_uri={}&code_verifier={}&state={}",
        urlencoding::encode(CLIENT_ID),
        urlencoding::encode(clean_code),
        urlencoding::encode(REDIRECT_URI),
        urlencoding::encode(pkce_verifier),
        urlencoding::encode(state),
    );

    let origin = claude_ai_base.trim_end_matches('/');
    let url = format!("{}/v1/oauth/token", api_base.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header("anthropic-version", ANTHROPIC_API_VERSION)
        .header("anthropic-beta", OAUTH_BETA)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json, text/plain, */*")
        .header("user-agent", TOKEN_UA)
        .header("origin", origin)
        .header("referer", format!("{origin}/"))
        .body(body)
        .send()
        .await
        .context("send oauth token exchange")?;

    let status = resp.status();
    let bytes = resp.bytes().await.context("read oauth token response")?;
    if !status.is_success() {
        bail!(
            "oauth token exchange failed: {} — {}",
            status,
            String::from_utf8_lossy(&bytes)
        );
    }

    let parsed: TokenResponse =
        serde_json::from_slice(&bytes).context("parse oauth token response")?;

    token_response_to_tokens(parsed, now_ms())
}

pub async fn refresh(
    client: &reqwest::Client,
    api_base: &str,
    refresh_token: &str,
) -> Result<Tokens> {
    let body = format!(
        "grant_type=refresh_token&client_id={}&refresh_token={}",
        urlencoding::encode(CLIENT_ID),
        urlencoding::encode(refresh_token),
    );
    let url = format!("{}/v1/oauth/token", api_base.trim_end_matches('/'));

    let resp = client
        .post(&url)
        .header("anthropic-version", ANTHROPIC_API_VERSION)
        .header("anthropic-beta", OAUTH_BETA)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json, text/plain, */*")
        .header("user-agent", TOKEN_UA)
        .body(body)
        .send()
        .await
        .context("send oauth refresh")?;

    let status = resp.status();
    let bytes = resp.bytes().await.context("read oauth refresh response")?;
    if !status.is_success() {
        bail!(
            "oauth refresh failed: {} — {}",
            status,
            String::from_utf8_lossy(&bytes)
        );
    }
    let parsed: TokenResponse = serde_json::from_slice(&bytes).context("parse refresh response")?;
    // The refresh response may omit refresh_token — in that case, carry it forward.
    let mut tokens = token_response_to_tokens(parsed, now_ms())?;
    if tokens.refresh_token.is_empty() {
        tokens.refresh_token = refresh_token.to_string();
    }
    Ok(tokens)
}

#[derive(Debug, Deserialize, Default)]
struct OAuthProfile {
    #[serde(default)]
    account: ProfileAccount,
    #[serde(default)]
    organization: ProfileOrg,
}

#[derive(Debug, Deserialize, Default)]
struct ProfileAccount {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    has_claude_max: bool,
    #[serde(default)]
    has_claude_pro: bool,
}

#[derive(Debug, Deserialize, Default)]
struct ProfileOrg {
    #[serde(default)]
    organization_type: Option<String>,
}

pub async fn fetch_profile_into(
    client: &reqwest::Client,
    api_base: &str,
    tokens: &mut Tokens,
) -> Result<()> {
    let url = format!("{}/api/oauth/profile", api_base.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .header("authorization", format!("Bearer {}", tokens.access_token))
        .header("user-agent", CLAUDE_CODE_UA)
        .header("accept", "application/json")
        .header("anthropic-beta", OAUTH_BETA)
        .send()
        .await
        .context("fetch profile")?;

    if !resp.status().is_success() {
        // profile is best-effort; don't fail login over it
        return Ok(());
    }
    let profile: OAuthProfile = resp.json().await.unwrap_or_default();
    if tokens.account_email.is_none() {
        tokens.account_email = profile.account.email;
    }
    if tokens.subscription_type.is_none() {
        tokens.subscription_type = profile.organization.organization_type.or_else(|| {
            if profile.account.has_claude_max {
                Some("claude_max".into())
            } else if profile.account.has_claude_pro {
                Some("claude_pro".into())
            } else {
                None
            }
        });
    }
    Ok(())
}

fn token_response_to_tokens(resp: TokenResponse, now: u64) -> Result<Tokens> {
    if let Some(err) = resp.error {
        let desc = resp.error_description.unwrap_or_default();
        return Err(anyhow!("oauth error: {err} {desc}"));
    }
    let access_token = resp
        .access_token
        .ok_or_else(|| anyhow!("oauth response missing access_token"))?;
    let expires_in = resp.expires_in.unwrap_or(3600);
    Ok(Tokens {
        access_token,
        refresh_token: resp.refresh_token.unwrap_or_default(),
        expires_at: now.saturating_add(expires_in.saturating_mul(1000)),
        subscription_type: resp.subscription_type,
        account_email: None,
    })
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
