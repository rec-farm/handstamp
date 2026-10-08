use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod};
use tokio_postgres::NoTls;

include!(concat!(env!("OUT_DIR"), "/migrations.rs"));

// The lock the Node server used too, so processes starting together never race.
const MIGRATION_LOCK: i64 = 4_26_19_77;

pub type Client = Object;

pub fn connect(url: &str) -> Result<Pool> {
    let config: tokio_postgres::Config = url.parse().context("DATABASE_URL is not a valid Postgres URL")?;
    let manager = Manager::from_config(config, NoTls, ManagerConfig { recycling_method: RecyclingMethod::Fast });
    Ok(Pool::builder(manager).max_size(10).build()?)
}

/// Applies migrations/*.sql in order, once each, under an advisory lock.
pub async fn migrate(pool: &Pool) -> Result<Vec<&'static str>> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK]).await?;
    tx.batch_execute(
        "CREATE TABLE IF NOT EXISTS handstamp_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())",
    )
    .await?;
    let mut applied = Vec::new();
    for (name, sql) in MIGRATIONS {
        let seen = tx.query_opt("SELECT 1 FROM handstamp_migrations WHERE name = $1", &[name]).await?;
        if seen.is_some() {
            continue;
        }
        tx.batch_execute(sql).await.with_context(|| format!("migration {name} failed"))?;
        tx.execute("INSERT INTO handstamp_migrations (name) VALUES ($1)", &[name]).await?;
        applied.push(*name);
    }
    tx.commit().await?;
    Ok(applied)
}

/// Dates as JSON.stringify(new Date()) wrote them: UTC, milliseconds, a Z.
pub fn iso(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn iso_opt(at: Option<DateTime<Utc>>) -> serde_json::Value {
    at.map(|at| serde_json::Value::String(iso(at))).unwrap_or(serde_json::Value::Null)
}

/// Postgres unique violation, e.g. a taken email or slug.
pub fn is_unique_violation(error: &tokio_postgres::Error) -> bool {
    error.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION)
}
