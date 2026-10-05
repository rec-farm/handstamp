use anyhow::{Context, Result};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::NoTls;

include!(concat!(env!("OUT_DIR"), "/migrations.rs"));

// packages/db/src/index.ts uses the same lock, so Node and Rust processes never race.
const MIGRATION_LOCK: i64 = 4_26_19_77;

pub fn connect(url: &str) -> Result<Pool> {
    let config: tokio_postgres::Config = url.parse().context("DATABASE_URL is not a valid Postgres URL")?;
    let manager = Manager::from_config(
        config,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    Ok(Pool::builder(manager).max_size(10).build()?)
}

pub async fn migrate(pool: &Pool) -> Result<Vec<&'static str>> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK])
        .await?;
    tx.batch_execute(
        "CREATE TABLE IF NOT EXISTS handstamp_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())",
    )
    .await?;
    let mut applied = Vec::new();
    for (name, sql) in MIGRATIONS {
        let seen = tx
            .query_opt("SELECT 1 FROM handstamp_migrations WHERE name = $1", &[name])
            .await?;
        if seen.is_some() {
            continue;
        }
        tx.batch_execute(sql)
            .await
            .with_context(|| format!("migration {name} failed"))?;
        tx.execute("INSERT INTO handstamp_migrations (name) VALUES ($1)", &[name])
            .await?;
        applied.push(*name);
    }
    tx.commit().await?;
    Ok(applied)
}
