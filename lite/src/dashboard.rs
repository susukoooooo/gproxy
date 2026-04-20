use axum::extract::State;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};

use crate::oauth::now_ms;
use crate::proxy::AppState;

pub async fn render(State(state): State<AppState>) -> Response {
    let tokens = state.tokens.get().await;
    let summary = state.stats.summary_24h().await.ok();
    let recent = state.stats.recent(50).await.unwrap_or_default();

    let now = now_ms();

    let token_section = match tokens {
        Some(t) => {
            let expires_in_secs = (t.expires_at as i64 - now as i64) / 1000;
            let label = if expires_in_secs > 0 {
                format!("{}s", expires_in_secs)
            } else {
                format!("expired {}s ago", -expires_in_secs)
            };
            format!(
                r#"<table>
                <tr><th>account</th><td>{}</td></tr>
                <tr><th>subscription</th><td>{}</td></tr>
                <tr><th>access token expires in</th><td>{}</td></tr>
                <tr><th>refresh token</th><td>{}</td></tr>
                </table>"#,
                html_escape(t.account_email.as_deref().unwrap_or("—")),
                html_escape(t.subscription_type.as_deref().unwrap_or("—")),
                label,
                if t.refresh_token.is_empty() {
                    "missing"
                } else {
                    "present"
                },
            )
        }
        None => {
            r#"<p class="warn">No tokens yet. Run <code>gproxy-lite login</code> or open <a href="/oauth/login">/oauth/login</a>.</p>"#.to_string()
        }
    };

    let (req_count, input_tokens, output_tokens) = summary
        .map(|s| (s.requests_24h, s.input_tokens_24h, s.output_tokens_24h))
        .unwrap_or((0, 0, 0));

    let mut rows = String::new();
    for r in &recent {
        let ts = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(r.at_ms)
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| r.at_ms.to_string());
        rows.push_str(&format!(
            "<tr><td>{ts}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}/{}</td><td>{}ms</td></tr>",
            html_escape(&r.method),
            html_escape(&r.path),
            html_escape(r.model.as_deref().unwrap_or("—")),
            r.status,
            r.input_tokens.unwrap_or(0),
            r.output_tokens.unwrap_or(0),
            r.duration_ms,
        ));
    }

    let html = format!(
        r#"<!doctype html>
<html><head><meta charset="utf-8"><title>gproxy-lite</title>
<style>
body {{ font-family: -apple-system, Segoe UI, sans-serif; max-width: 960px; margin: 2em auto; color: #222; padding: 0 1em; }}
h1 {{ margin-bottom: 0; }}
h2 {{ margin-top: 2em; border-bottom: 1px solid #ddd; padding-bottom: .3em; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
th, td {{ text-align: left; padding: .4em .6em; border-bottom: 1px solid #eee; }}
th {{ background: #fafafa; }}
.warn {{ background: #fff3cd; padding: .7em 1em; border-radius: 6px; }}
code {{ background: #f2f2f2; padding: .1em .3em; border-radius: 3px; }}
.metrics {{ display: flex; gap: 2em; margin-top: 1em; }}
.metrics div b {{ font-size: 1.6em; display: block; }}
</style></head><body>
<h1>gproxy-lite</h1>
<p style="color:#666;">A lightweight personal Claude OAuth proxy.</p>

<h2>Token</h2>
{token_section}

<h2>Last 24 hours</h2>
<div class="metrics">
  <div><b>{req_count}</b>requests</div>
  <div><b>{input_tokens}</b>input tokens</div>
  <div><b>{output_tokens}</b>output tokens</div>
</div>

<h2>Recent requests</h2>
<table><thead><tr><th>time (UTC)</th><th>method</th><th>path</th><th>model</th><th>status</th><th>in/out tok</th><th>latency</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"#
    );

    let mut resp = Html(html).into_response();
    resp.headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    *resp.status_mut() = StatusCode::OK;
    resp
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
