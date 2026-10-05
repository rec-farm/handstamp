mod app;
mod config;
mod crypto;
mod db;
mod keys;
mod web;

use anyhow::Result;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::try_from_env("LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    if let Err(error) = run().await {
        tracing::error!("Handstamp can't start: {error:#}");
        std::process::exit(1);
    }
    Ok(())
}

async fn run() -> Result<()> {
    let config = config::Config::from_env()?;
    let pool = db::connect(&config.database_url)?;
    let applied = db::migrate(&pool).await?;
    if !applied.is_empty() {
        tracing::info!(?applied, "migrations applied");
    }
    let keys = keys::Keys::new(pool.clone(), &config.secret_key);
    if let Some(kid) = keys.ensure_active().await? {
        tracing::info!(%kid, "first signing key created");
    }
    let active = keys.open_active().await?;
    tracing::info!(kid = %active["kid"].as_str().unwrap_or_default(), "active signing key opens");

    let (shell, web_dist) = match web::Shell::load(&config.web_dist) {
        Ok(shell) => (shell, Some(config.web_dist.clone())),
        Err(error) => {
            tracing::warn!("{error:#}");
            (web::Shell::bare(), None)
        }
    };
    let state = Arc::new(app::AppState {
        issuer: config.issuer.clone(),
        https: config.https,
        trust_proxy: config.trust_proxy,
        pool,
        keys,
        shell,
    });
    let listener = tokio::net::TcpListener::bind((config.host.as_str(), config.port)).await?;
    tracing::info!(issuer = %config.issuer, addr = %listener.local_addr()?, "Handstamp (Rust spike) is ready");
    axum::serve(listener, app::router(state, web_dist))
        .with_graceful_shutdown(async {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
            tokio::select! { _ = term.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
            tracing::info!("shutting down");
        })
        .await?;
    Ok(())
}
