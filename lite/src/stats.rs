use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct RequestLog {
    pub at_ms: i64,
    pub method: String,
    pub path: String,
    pub model: Option<String>,
    pub status: i64,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub duration_ms: i64,
}

#[derive(Clone)]
pub struct Stats {
    conn: Arc<Mutex<Connection>>,
}

impl Stats {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("open sqlite {}", path.display()))?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS requests (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                at_ms         INTEGER NOT NULL,
                method        TEXT NOT NULL,
                path          TEXT NOT NULL,
                model         TEXT,
                status        INTEGER NOT NULL,
                input_tokens  INTEGER,
                output_tokens INTEGER,
                duration_ms   INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_requests_at_ms ON requests(at_ms DESC);
            "#,
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub async fn record(&self, log: RequestLog) {
        let conn = self.conn.clone();
        let _ = tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO requests (at_ms, method, path, model, status, input_tokens, output_tokens, duration_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    log.at_ms,
                    log.method,
                    log.path,
                    log.model,
                    log.status,
                    log.input_tokens,
                    log.output_tokens,
                    log.duration_ms,
                ],
            )?;
            Ok(())
        })
        .await;
    }

    pub async fn recent(&self, limit: u32) -> Result<Vec<RequestLog>> {
        let conn = self.conn.clone();
        let rows = tokio::task::spawn_blocking(move || -> Result<Vec<RequestLog>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT at_ms, method, path, model, status, input_tokens, output_tokens, duration_ms
                 FROM requests ORDER BY at_ms DESC LIMIT ?1",
            )?;
            let iter = stmt.query_map(params![limit as i64], |row| {
                Ok(RequestLog {
                    at_ms: row.get(0)?,
                    method: row.get(1)?,
                    path: row.get(2)?,
                    model: row.get(3)?,
                    status: row.get(4)?,
                    input_tokens: row.get(5)?,
                    output_tokens: row.get(6)?,
                    duration_ms: row.get(7)?,
                })
            })?;
            let mut out = Vec::new();
            for r in iter {
                out.push(r?);
            }
            Ok(out)
        })
        .await??;
        Ok(rows)
    }

    pub async fn summary_24h(&self) -> Result<Summary> {
        let conn = self.conn.clone();
        let s = tokio::task::spawn_blocking(move || -> Result<Summary> {
            let conn = conn.blocking_lock();
            let since = chrono::Utc::now().timestamp_millis() - 24 * 3600 * 1000;
            let (count, input, output): (i64, Option<i64>, Option<i64>) = conn.query_row(
                "SELECT COUNT(*), COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0)
                 FROM requests WHERE at_ms >= ?1",
                params![since],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            Ok(Summary {
                requests_24h: count,
                input_tokens_24h: input.unwrap_or(0),
                output_tokens_24h: output.unwrap_or(0),
            })
        })
        .await??;
        Ok(s)
    }
}

#[derive(Debug, Clone)]
pub struct Summary {
    pub requests_24h: i64,
    pub input_tokens_24h: i64,
    pub output_tokens_24h: i64,
}
