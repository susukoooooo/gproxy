//! Core proxy: forward requests to Anthropic using the OAuth access token,
//! inject the Claude Code identity into `system`, and refresh tokens as needed.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::Response;
use bytes::Bytes;
use futures::StreamExt;
use reqwest::Client;
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::config::UpstreamConfig;
use crate::oauth::{
    self, ANTHROPIC_API_VERSION, CLAUDE_CODE_UA, OAUTH_BETA, REFRESH_SKEW_MS,
};
use crate::stats::{RequestLog, Stats};
use crate::tokens::{TokenStore, Tokens};

const CLAUDE_CODE_PRELUDE: &str = "You are Claude Code, Anthropic's official CLI for Claude.";

#[derive(Clone)]
pub struct AppState {
    pub client: Client,
    pub tokens: TokenStore,
    pub upstream: Arc<UpstreamConfig>,
    pub stats: Stats,
    pub refresh_lock: Arc<Mutex<()>>,
    pub client_key: String,
}

pub async fn handle(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    uri: axum::http::Uri,
    body: Bytes,
) -> Response {
    let path = uri.path().to_string();
    let full_path = match uri.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.clone(),
    };

    // Client auth
    if !client_key_ok(&headers, &state.client_key) {
        return err_response(StatusCode::UNAUTHORIZED, "invalid client key");
    }

    let start = std::time::Instant::now();

    // Resolve access token (refresh if near expiry)
    let access_token = match ensure_access_token(&state).await {
        Ok(t) => t,
        Err(err) => {
            warn!(error = %err, "token resolution failed");
            return err_response(
                StatusCode::BAD_GATEWAY,
                "upstream token unavailable; run `gproxy-lite login`",
            );
        }
    };

    // Transform body when applicable
    let (body_bytes, model) = transform_body(&method, &path, &body, &state.upstream);

    // Build upstream URL
    let target = format!(
        "{}{}",
        state.upstream.api_base_url.trim_end_matches('/'),
        full_path
    );

    let mut req = state
        .client
        .request(method.clone(), &target)
        .header("authorization", format!("Bearer {}", access_token))
        .header("anthropic-version", ANTHROPIC_API_VERSION)
        .header("user-agent", CLAUDE_CODE_UA);

    // Forward client's anthropic-beta (merged with oauth beta), drop hop-by-hop.
    let forwarded_beta = headers
        .get("anthropic-beta")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let merged_beta = merge_beta(forwarded_beta, OAUTH_BETA);
    req = req.header("anthropic-beta", merged_beta);

    // Forward a minimal set of request headers (non-auth).
    for (name, value) in headers.iter() {
        let n = name.as_str().to_ascii_lowercase();
        if matches!(
            n.as_str(),
            "authorization"
                | "x-api-key"
                | "host"
                | "content-length"
                | "connection"
                | "transfer-encoding"
                | "anthropic-beta"
                | "user-agent"
                | "anthropic-version"
        ) {
            continue;
        }
        if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
            req = req.header(name.as_str(), v);
        }
    }

    let has_body = !body_bytes.is_empty();
    if has_body {
        req = req.header("content-type", "application/json").body(body_bytes);
    }

    let upstream = match req.send().await {
        Ok(r) => r,
        Err(err) => {
            warn!(error = %err, "upstream request failed");
            return err_response(StatusCode::BAD_GATEWAY, &format!("upstream error: {err}"));
        }
    };

    let status = upstream.status();
    let axum_status =
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    // Copy response headers (sans hop-by-hop)
    let mut out_headers = HeaderMap::new();
    for (name, value) in upstream.headers().iter() {
        let n = name.as_str().to_ascii_lowercase();
        if matches!(
            n.as_str(),
            "content-length" | "transfer-encoding" | "connection"
        ) {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            out_headers.insert(hn, hv);
        }
    }

    let is_stream = out_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/event-stream"))
        .unwrap_or(false);

    let model_for_log = model.clone();
    if is_stream {
        let stats = state.stats.clone();
        let stream = upstream.bytes_stream().map(|chunk| {
            chunk.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
        });
        let body = Body::from_stream(stream);
        tokio::spawn(async move {
            stats
                .record(RequestLog {
                    at_ms: chrono::Utc::now().timestamp_millis(),
                    method: method.as_str().to_string(),
                    path,
                    model: model_for_log,
                    status: status.as_u16() as i64,
                    input_tokens: None,
                    output_tokens: None,
                    duration_ms: start.elapsed().as_millis() as i64,
                })
                .await;
        });
        let mut response = Response::new(body);
        *response.status_mut() = axum_status;
        *response.headers_mut() = out_headers;
        return response;
    }

    let bytes = match upstream.bytes().await {
        Ok(b) => b,
        Err(err) => {
            warn!(error = %err, "read upstream body failed");
            return err_response(StatusCode::BAD_GATEWAY, "read upstream body failed");
        }
    };

    let (input_tokens, output_tokens) = extract_usage(&bytes);
    state
        .stats
        .record(RequestLog {
            at_ms: chrono::Utc::now().timestamp_millis(),
            method: method.as_str().to_string(),
            path,
            model: model_for_log,
            status: status.as_u16() as i64,
            input_tokens,
            output_tokens,
            duration_ms: start.elapsed().as_millis() as i64,
        })
        .await;

    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = axum_status;
    *response.headers_mut() = out_headers;
    response
}

fn client_key_ok(headers: &HeaderMap, expected: &str) -> bool {
    if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        if v == expected {
            return true;
        }
    }
    if let Some(v) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(rest) = v.strip_prefix("Bearer ") {
            if rest == expected {
                return true;
            }
        }
    }
    false
}

async fn ensure_access_token(state: &AppState) -> Result<String> {
    let now = oauth::now_ms();
    if let Some(t) = state.tokens.get().await {
        if !t.is_expired(now, REFRESH_SKEW_MS) {
            return Ok(t.access_token);
        }
    }

    let _guard = state.refresh_lock.lock().await;
    // Re-check after acquiring lock
    if let Some(t) = state.tokens.get().await {
        if !t.is_expired(oauth::now_ms(), REFRESH_SKEW_MS) {
            return Ok(t.access_token);
        }
        debug!("refreshing token");
        let refreshed = oauth::refresh(&state.client, &state.upstream.api_base_url, &t.refresh_token)
            .await
            .context("refresh access token")?;
        let mut new_tokens = Tokens {
            access_token: refreshed.access_token,
            refresh_token: refreshed.refresh_token,
            expires_at: refreshed.expires_at,
            subscription_type: refreshed.subscription_type.or(t.subscription_type),
            account_email: t.account_email,
        };
        if new_tokens.account_email.is_none() || new_tokens.subscription_type.is_none() {
            let _ = oauth::fetch_profile_into(&state.client, &state.upstream.api_base_url, &mut new_tokens).await;
        }
        state.tokens.save(new_tokens.clone()).await?;
        return Ok(new_tokens.access_token);
    }
    anyhow::bail!("no tokens available — run `gproxy-lite login`")
}

fn transform_body(
    method: &Method,
    path: &str,
    body: &Bytes,
    upstream: &UpstreamConfig,
) -> (Bytes, Option<String>) {
    if body.is_empty() {
        return (Bytes::new(), None);
    }
    // Only transform JSON for /v1/messages* on POST.
    let is_messages = method == Method::POST && path.starts_with("/v1/messages");
    if !is_messages {
        return (body.clone(), None);
    }
    let Ok(mut json) = serde_json::from_slice::<Value>(body) else {
        return (body.clone(), None);
    };

    if upstream.inject_claude_code_identity {
        inject_claude_code_system(&mut json);
    }
    let model = json
        .get("model")
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    let bytes = serde_json::to_vec(&json).ok().map(Bytes::from).unwrap_or(body.clone());
    (bytes, model)
}

fn inject_claude_code_system(body: &mut Value) {
    let Some(map) = body.as_object_mut() else {
        return;
    };
    if system_has_known_prelude(map.get("system")) {
        return;
    }
    let prelude = serde_json::json!({ "type": "text", "text": CLAUDE_CODE_PRELUDE });
    match map.remove("system") {
        Some(Value::String(text)) => {
            map.insert(
                "system".into(),
                Value::Array(vec![
                    prelude,
                    serde_json::json!({ "type": "text", "text": text }),
                ]),
            );
        }
        Some(Value::Array(mut blocks)) => {
            blocks.insert(0, prelude);
            map.insert("system".into(), Value::Array(blocks));
        }
        Some(other) => {
            map.insert("system".into(), other);
        }
        None => {
            map.insert("system".into(), Value::Array(vec![prelude]));
        }
    }
}

fn system_has_known_prelude(system: Option<&Value>) -> bool {
    let Some(system) = system else {
        return false;
    };
    let contains = |s: &str| {
        let lower = s.to_ascii_lowercase();
        lower.contains("you are claude code") || lower.contains("claude agent sdk")
    };
    match system {
        Value::String(s) => contains(s),
        Value::Array(blocks) => blocks.iter().any(|b| {
            b.get("text")
                .and_then(Value::as_str)
                .map(contains)
                .unwrap_or(false)
        }),
        _ => false,
    }
}

fn merge_beta(incoming: &str, required: &str) -> String {
    let mut out: Vec<String> = incoming
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !out.iter().any(|s| s.eq_ignore_ascii_case(required)) {
        out.push(required.to_string());
    }
    out.join(",")
}

fn extract_usage(bytes: &Bytes) -> (Option<i64>, Option<i64>) {
    let Ok(v) = serde_json::from_slice::<Value>(bytes) else {
        return (None, None);
    };
    let usage = v.get("usage");
    let input = usage
        .and_then(|u| u.get("input_tokens"))
        .and_then(Value::as_i64);
    let output = usage
        .and_then(|u| u.get("output_tokens"))
        .and_then(Value::as_i64);
    (input, output)
}

fn err_response(status: StatusCode, msg: &str) -> Response {
    let body = serde_json::json!({ "error": { "type": "gproxy_lite_error", "message": msg } });
    let mut resp = Response::new(Body::from(body.to_string()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/json"),
    );
    resp
}

pub fn build_http_client() -> Client {
    Client::builder()
        .pool_idle_timeout(Some(Duration::from_secs(90)))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(600))
        .build()
        .expect("build reqwest client")
}
