import { readdir, readFile } from 'node:fs/promises';
import pg from 'pg';
import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from './schema.ts';

export * from './schema.ts';
export * from './adapter.ts';
export * from './audit.ts';

export type Database = NodePgDatabase<typeof schema>;

export function connectDatabase(url: string) {
  const pool = new pg.Pool({ connectionString: url, max: 10 });
  return { pool, db: drizzle(pool, { schema, casing: 'snake_case' }) };
}

const MIGRATION_LOCK = 4_26_19_77;

// Applies packages/db/migrations/*.sql in order, once each, under an advisory lock so several
// processes starting together can't race.
export async function migrate(pool: pg.Pool) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1)', [MIGRATION_LOCK]);
    await client.query(
      'CREATE TABLE IF NOT EXISTS handstamp_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())',
    );
    const directory = new URL('../migrations/', import.meta.url);
    const applied: string[] = [];
    for (const name of (await readdir(directory)).filter((n) => n.endsWith('.sql')).sort()) {
      const seen = await client.query('SELECT 1 FROM handstamp_migrations WHERE name = $1', [name]);
      if (seen.rowCount) continue;
      await client.query(await readFile(new URL(name, directory), 'utf8'));
      await client.query('INSERT INTO handstamp_migrations (name) VALUES ($1)', [name]);
      applied.push(name);
    }
    await client.query('COMMIT');
    return applied;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
