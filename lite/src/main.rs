mod config;
mod dashboard;
mod oauth;
mod proxy;
mod stats;
mod tokens;

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::routing::{any, get};
use clap::{Parser, Subcommand};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::oauth::{Pkce, build_authorize_url};
use crate::proxy::{AppState, build_http_client};
use crate::stats::Stats;
use crate::tokens::TokenStore;

#[derive(Parser)]
#[command(name = "gproxy-lite", about = "Lightweight personal Claude OAuth proxy")]
struct Cli {
    #[arg(long, default_value = "./gproxy.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the OAuth login flow and save tokens to the configured file.
    Login,
    /// Print the current access token (for debugging).
    ShowToken,
    /// Run the proxy server (default).
    Serve,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)
        .with_context(|| format!("load config {}", cli.config.display()))?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::Login => login(&cfg).await,
        Command::ShowToken => show_token(&cfg).await,
        Command::Serve => serve(cfg).await,
    }
}

async fn login(cfg: &Config) -> Result<()> {
    let client = build_http_client();
    let pkce = Pkce::generate();
    let url = build_authorize_url(&cfg.upstream.claude_ai_base_url, &pkce);

    println!("\n== gproxy-lite OAuth login ==\n");
    println!("1) Open this URL in your browser and sign in:\n\n   {url}\n");
    println!("2) After you authorize, Claude will show a page containing an authorization code");
    println!("   (the URL looks like: {REDIRECT}?code=...&state=...).", REDIRECT = oauth::REDIRECT_URI);
    println!("3) Copy the full code (everything shown, including any '#state' suffix) and paste below.\n");

    print!("Paste code (or the full redirected URL): ");
    io::stdout().flush().ok();

    let mut line = String::new();
    io::stdin().read_line(&mut line).context("read stdin")?;
    let input = line.trim();

    let (code, state) = parse_code_and_state(input, &pkce.state);

    let mut tokens = oauth::exchange_code(
        &client,
        &cfg.upstream.oauth_base_url,
        &cfg.upstream.claude_ai_base_url,
        &pkce.verifier,
        &code,
        &state,
    )
    .await
    .context("exchange code for tokens")?;

    // Best-effort profile
    let _ = oauth::fetch_profile_into(&client, &cfg.upstream.api_base_url, &mut tokens).await;

    let store = TokenStore::load(cfg.upstream.tokens_file.clone()).await?;
    store.save(tokens.clone()).await?;

    println!("\n✓ Saved tokens to {}", cfg.upstream.tokens_file.display());
    if let Some(email) = &tokens.account_email {
        println!("  account: {email}");
    }
    if let Some(sub) = &tokens.subscription_type {
        println!("  subscription: {sub}");
    }
    let expires_in = (tokens.expires_at as i64 - oauth::now_ms() as i64) / 1000;
    println!("  access token valid for {expires_in}s (auto-refresh enabled)");
    Ok(())
}

fn parse_code_and_state(input: &str, fallback_state: &str) -> (String, String) {
    // Accept: raw code, "code#state", or the full redirect URL with ?code=&state=
    let raw = input.trim();
    if let Some(q) = raw.split_once('?').map(|(_, q)| q) {
        let mut code = None;
        let mut state = None;
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                match k {
                    "code" => code = Some(urlencoding::decode(v).map(|s| s.into_owned()).unwrap_or_else(|_| v.to_string())),
                    "state" => state = Some(urlencoding::decode(v).map(|s| s.into_owned()).unwrap_or_else(|_| v.to_string())),
                    _ => {}
                }
            }
        }
        if let Some(c) = code {
            return (c, state.unwrap_or_else(|| fallback_state.to_string()));
        }
    }
    if let Some((c, s)) = raw.split_once('#') {
        return (c.to_string(), s.to_string());
    }
    (raw.to_string(), fallback_state.to_string())
}

async fn show_token(cfg: &Config) -> Result<()> {
    let store = TokenStore::load(cfg.upstream.tokens_file.clone()).await?;
    match store.get().await {
        Some(t) => {
            println!("access_token: {}", t.access_token);
            println!("expires_at: {}", t.expires_at);
            println!("account: {:?}", t.account_email);
            println!("subscription: {:?}", t.subscription_type);
        }
        None => println!("no tokens — run `gproxy-lite login`"),
    }
    Ok(())
}

async fn serve(cfg: Config) -> Result<()> {
    let client = build_http_client();
    let tokens = TokenStore::load(cfg.upstream.tokens_file.clone())
        .await
        .context("load tokens file")?;
    let stats = Stats::open(&cfg.upstream.stats_db).context("open stats db")?;

    let state = AppState {
        client,
        tokens,
        upstream: Arc::new(cfg.upstream.clone()),
        stats,
        refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        client_key: cfg.server.client_key.clone(),
    };

    let app = Router::new()
        .route("/", get(dashboard::render))
        .route("/healthz", get(|| async { "ok" }))
        .fallback(any(proxy::handle))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = format!("{}:{}", cfg.server.host, cfg.server.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    info!("gproxy-lite listening on http://{addr}");
    info!("dashboard: http://{addr}/");
    axum::serve(listener, app).await.context("serve")?;
    Ok(())
}
