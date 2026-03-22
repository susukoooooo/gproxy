use std::future::IntoFuture;

use anyhow::{Result, anyhow};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::HeaderName;
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use gproxy_core::management_router;
use gproxy_storage::StorageWriteSinkError;
use tokio::net::TcpListener;
use tokio::task::{JoinError, JoinHandle};
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer, ExposeHeaders};

use crate::bootstrap::runtime::Bootstrap;

mod admin_ui;
mod bootstrap;
mod middleware;

const MAX_AXUM_BODY_BYTES: usize = 50 * 1024 * 1024;

type StorageWriteWorkerHandle = JoinHandle<std::result::Result<(), StorageWriteSinkError>>;

fn parse_author_and_email(authors: &str) -> (String, String) {
    let first = authors
        .split(':')
        .map(str::trim)
        .find(|value| !value.is_empty())
        .unwrap_or_default();
    if first.is_empty() {
        return ("unknown".to_string(), "unknown".to_string());
    }

    if let Some((name, rest)) = first.split_once('<') {
        let email = rest.split_once('>').map(|(value, _)| value).unwrap_or(rest);
        let name = name.trim();
        let email = email.trim();
        return (
            if name.is_empty() {
                "unknown".to_string()
            } else {
                name.to_string()
            },
            if email.is_empty() {
                "unknown".to_string()
            } else {
                email.to_string()
            },
        );
    }

    (first.to_string(), "unknown".to_string())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!("failed to listen for Ctrl+C signal: {err}");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                let _ = stream.recv().await;
            }
            Err(err) => {
                tracing::warn!("failed to listen for SIGTERM: {err}");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }

    tracing::info!("shutdown signal received, starting graceful shutdown");
}

fn storage_write_worker_failure(
    result: std::result::Result<std::result::Result<(), StorageWriteSinkError>, JoinError>,
    stage: &str,
) -> anyhow::Error {
    match result {
        Ok(Ok(())) => anyhow!("storage write worker exited unexpectedly while {stage}"),
        Ok(Err(err)) => anyhow!("storage write worker failed while {stage}: {err}"),
        Err(err) => anyhow!("storage write worker panicked while {stage}: {err}"),
    }
}

async fn flush_storage_write_worker_on_shutdown(
    storage_write_worker: &mut StorageWriteWorkerHandle,
) -> Result<()> {
    match storage_write_worker.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(anyhow!(
            "storage write worker failed while draining shutdown writes: {err}"
        )),
        Err(err) => Err(anyhow!(
            "storage write worker panicked while draining shutdown writes: {err}"
        )),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn,sqlx::query=warn,sea_orm=warn".into()),
        )
        .with_target(false)
        .compact()
        .init();

    let Bootstrap {
        config_path: _config_path,
        config: _config,
        storage: _storage,
        state,
        storage_write_worker,
    } = bootstrap::bootstrap_from_env().await?;
    let config = state.load_config();
    let host = config.global.host.clone();
    let port = config.global.port;
    let username = state
        .load_users()
        .first()
        .map(|user| user.name.clone())
        .unwrap_or_else(|| "admin".to_string());
    let password = config.global.admin_key.clone();
    let bind_addr = format!("{host}:{port}");
    let (author, email) = parse_author_and_email(env!("CARGO_PKG_AUTHORS"));

    println!("========================================");
    println!(
        "gproxy | author: {} | email: {} | version: {}",
        author,
        email,
        env!("CARGO_PKG_VERSION")
    );
    println!("listen: http://{bind_addr}");
    println!("username: {username}");
    println!("password: {password}");
    println!("========================================");

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::any())
        .allow_methods(AllowMethods::any())
        .allow_headers(AllowHeaders::any())
        .expose_headers(ExposeHeaders::list([
            HeaderName::from_static("x-request-id"),
        ]));

    let app = Router::new()
        .route("/favicon.ico", get(admin_ui::favicon))
        .route("/", get(admin_ui::index))
        .route("/assets/{*path}", get(admin_ui::asset))
        .merge(management_router(state.clone()))
        .layer(from_fn_with_state(
            state.clone(),
            middleware::downstream_event::middleware,
        ))
        .layer(cors)
        .layer(DefaultBodyLimit::max(MAX_AXUM_BODY_BYTES));
    let listener = TcpListener::bind(&bind_addr).await?;
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .into_future();
    tokio::pin!(server);
    let mut storage_write_worker = storage_write_worker;

    tokio::select! {
        worker_result = &mut storage_write_worker => {
            let err = storage_write_worker_failure(worker_result, "serving requests");
            tracing::error!(error=%err, "storage write worker exited; terminating process for restart");
            return Err(err);
        }
        server_result = &mut server => {
            server_result?;
        }
    }

    drop(state);
    if let Err(err) = flush_storage_write_worker_on_shutdown(&mut storage_write_worker).await {
        tracing::error!(error=%err, "storage write worker failed during shutdown flush");
        return Err(err);
    }

    Ok(())
}
