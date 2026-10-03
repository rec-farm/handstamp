import { connectDatabase, migrate } from '@handstamp/db';

if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
const { pool } = connectDatabase(process.env.DATABASE_URL);
try {
  const applied = await migrate(pool);
  console.log(applied.length ? `Applied ${applied.join(', ')}` : 'Already up to date.');
} finally {
  await pool.end();
}
