//! Handstamp: the passwordless OpenID Connect provider for the R.E.C. product family.
//!
//! One binary: `handstamp serve` runs the server; the other commands are the operator CLI
//! (`docker compose exec handstamp handstamp invite`).

#![allow(clippy::result_large_err)]

mod accounts;
mod admin;
mod app;
mod audit;
mod clients;
mod config;
mod console;
mod crypto;
mod db;
mod enrollment;
mod http;
mod identities;
mod interaction;
mod keys;
mod oidc;
mod passkeys;
mod sessions;
mod upstream;
mod web;
mod webauthn;

use std::{net::SocketAddr, process::ExitCode, time::Duration};

use anyhow::{Context, Result};
use deadpool_postgres::Pool;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use crate::{
    app::App,
    audit::Actor,
    clients::{Clients, console_client, console_secret},
    config::Config,
    enrollment::{Enrollments, RECOVERY_MINUTES, Setup},
    keys::Keys,
    upstream::providers::Providers,
};

const USAGE: &str = "Usage: handstamp <command>

Commands:
  serve           Run the server
  keys list       Show signing keys and their state
  keys rotate     Stage a new signing key. It is published now and starts
                  signing after KEY_STAGE_HOURS (or run \"keys promote\")
  keys promote    Start signing with the staged key now
  setup-code      Print a new first-run setup code (only before the instance is claimed)
  invite          Print a one-time invite link (7 days)
  recovery <user> Print a one-time recovery link (30 minutes) for a user, by sub or email.
                  Add --revoke to remove their other passkeys and sessions (\"I lost my device\").
  migrate         Apply database migrations
";

// Only one process runs key lifecycle and cleanup at a time, even with several replicas.
const SCHEDULER_LOCK: i64 = 4_26_19_78;

fn init_logging(level: &str) {
    let level = match level {
        "fatal" => "error",
        other => other,
    };
    let filter = EnvFilter::new(format!("handstamp={level},warn"));
    let _ = tracing_subscriber::fmt().json().with_current_span(false).with_env_filter(filter).try_init();
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");
    if matches!(command, "help" | "--help" | "-h") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            init_logging("error");
            tracing::error!("{error}");
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    init_logging(&config.log_level);
    let result = match command {
        "serve" => serve(config).await,
        _ => cli(config, &args).await,
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "Handstamp can't start");
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

struct Boot {
    pool: Pool,
    migrations: Vec<&'static str>,
    declared_clients: Vec<String>,
    upstream: Vec<String>,
    test_user: Option<Uuid>,
}

/// Shared by the server and the CLI: migrations, the first signing key, declared clients, the
/// console client, env-seeded upstream providers, and the dev test user.
async fn bootstrap(config: &Config) -> Result<Boot> {
    let pool = db::connect(&config.database_url)?;
    let migrations = db::migrate(&pool).await.context("can't reach or migrate the database")?;
    Keys::new(pool.clone(), &config.secret_key).ensure().await?;
    let clients = Clients::new(pool.clone(), &config.secret_key);
    let declared_clients = match &config.clients_file {
        Some(path) => clients.sync_file(path, &config.env).await?,
        None => vec![],
    };
    // Handstamp's own UI signs in through Handstamp (docs/PLAN.md §1.3).
    clients
        .upsert(&console_client(&config.issuer_origin()), Some(&console_secret(&config.secret_key)), "builtin")
        .await?;
    let upstream = Providers::new(pool.clone(), &config.secret_key).sync_env(&config.env).await?;
    let test_user = if config.dev_login { Some(accounts::ensure_test_user(&pool).await?) } else { None };
    Ok(Boot { pool, migrations, declared_clients, upstream, test_user })
}

async fn serve(config: Config) -> Result<ExitCode> {
    let boot = bootstrap(&config).await?;
    if !boot.migrations.is_empty() {
        tracing::info!(migrations = ?boot.migrations, "migrations applied");
    }
    if !boot.declared_clients.is_empty() {
        tracing::info!(clients = ?boot.declared_clients, "declared clients synced");
    }
    if !boot.upstream.is_empty() {
        tracing::info!(providers = ?boot.upstream, "upstream providers synced");
    }
    if boot.test_user.is_some() {
        tracing::warn!("HANDSTAMP_DEV_LOGIN is on: anyone can sign in as the test user");
    }
    let shell = match &config.vite_url {
        Some(url) => web::Shell::vite(url.clone()),
        None => match web::Shell::load(&config.web_dist) {
            Ok(shell) => shell,
            Err(_) => {
                tracing::warn!(dist = %config.web_dist.display(), "the UI build is missing: run pnpm build to get it");
                web::Shell::bare()
            }
        },
    };
    let app = App::new(config.clone(), boot.pool.clone(), shell, boot.test_user);

    // The setup code is the only secret Handstamp ever prints, once, outside request logging.
    if let Some(code) = app.setup.issue_code().await? {
        print!(
            "\n  Handstamp has no admin yet. Open {}/setup and enter this code:\n\n      {code}\n\n  It works for 60 minutes. Restart Handstamp or run \"handstamp setup-code\" for a new one.\n\n",
            app.issuer
        );
    }

    let scheduler = tokio::spawn(schedule(app.clone()));
    let listener = tokio::net::TcpListener::bind((config.host.as_str(), config.port))
        .await
        .with_context(|| format!("can't listen on {}:{}", config.host, config.port))?;
    tracing::info!(address = %listener.local_addr()?, "Server listening");
    tracing::info!(issuer = %app.issuer, "Handstamp is ready");
    axum::serve(listener, app::router(app).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
            let signal = tokio::select! {
                _ = term.recv() => "SIGTERM",
                _ = tokio::signal::ctrl_c() => "SIGINT",
            };
            tracing::info!(signal, "shutting down");
        })
        .await?;
    scheduler.abort();
    boot.pool.close();
    Ok(ExitCode::SUCCESS)
}

/// Key lifecycle and cleanup every minute. The advisory lock keeps it to one process.
async fn schedule(app: App) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        if let Err(error) = tick(&app).await {
            tracing::error!(error = %format!("{error:#}"), "scheduled maintenance failed");
        }
    }
}

async fn tick(app: &App) -> Result<()> {
    let db = app.pool.get().await?;
    let locked: bool = db.query_one("SELECT pg_try_advisory_lock($1)", &[&SCHEDULER_LOCK]).await?.get(0);
    if !locked {
        return Ok(());
    }
    let result = async {
        if app.keys.tick(&app.config.rotation()).await? {
            tracing::info!("signing keys changed");
        }
        let removed = oidc::store::delete_expired(&app.pool).await?;
        if removed > 0 {
            tracing::debug!(removed, "expired protocol state removed");
        }
        anyhow::Ok(())
    }
    .await;
    db.execute("SELECT pg_advisory_unlock($1)", &[&SCHEDULER_LOCK]).await?;
    result
}

async fn cli(config: Config, args: &[String]) -> Result<ExitCode> {
    let boot = bootstrap(&config).await?;
    let pool = boot.pool.clone();
    let keys = Keys::new(pool.clone(), &config.secret_key);
    let rest: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    let code = match (args[0].as_str(), rest.first().copied()) {
        ("migrate", _) => {
            if boot.migrations.is_empty() {
                println!("Already up to date.");
            } else {
                println!("Applied {}", boot.migrations.join(", "));
            }
            ExitCode::SUCCESS
        }
        ("setup-code", _) => {
            match Setup::new(pool.clone()).issue_code().await? {
                Some(code) => println!("Setup code (60 minutes): {code}"),
                None => println!("This instance already has an admin."),
            }
            ExitCode::SUCCESS
        }
        ("invite", _) => {
            let link = Enrollments::new(pool.clone(), config.issuer_origin()).create_invite(Actor::Cli, None).await?;
            println!("Invite link (works once, for {} days):\n\n  {}\n", enrollment::INVITE_DAYS, link.link);
            ExitCode::SUCCESS
        }
        ("recovery", Some(who)) => {
            let db = pool.get().await?;
            let row = match Uuid::parse_str(who) {
                Ok(id) => db.query_opt("SELECT id, display_name FROM users WHERE id = $1", &[&id]).await?,
                Err(_) => {
                    db.query_opt("SELECT id, display_name FROM users WHERE lower(email) = $1", &[&who.to_lowercase()]).await?
                }
            };
            drop(db);
            match row {
                None => {
                    eprintln!("No user matches {who}. Use their sub (from the account page) or email.");
                    ExitCode::FAILURE
                }
                Some(row) => {
                    let (id, name): (Uuid, String) = (row.get(0), row.get(1));
                    let revoke = rest.contains(&"--revoke");
                    let link = Enrollments::new(pool.clone(), config.issuer_origin())
                        .create_recovery(id, revoke, Actor::Cli, None)
                        .await?;
                    println!(
                        "Recovery link for {name} (works once, for {RECOVERY_MINUTES} minutes):\n\n  {}\n\n{}",
                        link.link,
                        if revoke {
                            "Using it removes their other passkeys and signs them out everywhere."
                        } else {
                            "Their existing passkeys keep working. Use --revoke if a device was lost or stolen."
                        }
                    );
                    ExitCode::SUCCESS
                }
            }
        }
        ("keys", Some("list")) => {
            for key in keys.list().await? {
                println!(
                    "{}  {}  {:<8}  {}  {}",
                    key.kid,
                    key.alg,
                    key.state,
                    db::iso(key.created_at),
                    key.retire_after.map(db::iso).unwrap_or_default()
                );
            }
            ExitCode::SUCCESS
        }
        ("keys", Some("rotate")) => {
            let kid = keys.stage(Actor::Cli, None).await?;
            println!("Staged {kid}. It is published now and starts signing in {}h.", config.key_stage_hours);
            ExitCode::SUCCESS
        }
        ("keys", Some("promote")) => {
            match keys.promote(&config.rotation(), Actor::Cli, None).await? {
                Some(kid) => println!("{kid} is now signing. The previous key stays published until it retires."),
                None => println!("No staged key. Run \"keys rotate\" first."),
            }
            ExitCode::SUCCESS
        }
        _ => {
            print!("{USAGE}");
            ExitCode::FAILURE
        }
    };
    pool.close();
    Ok(code)
}
