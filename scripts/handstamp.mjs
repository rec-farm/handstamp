// `pnpm handstamp <command>`: the operator CLI against the local .env (node --env-file reads it).
import { spawnSync } from 'node:child_process';

const { status } = spawnSync(
  'cargo',
  ['run', '--quiet', '--manifest-path', 'backend/Cargo.toml', '--', ...process.argv.slice(2)],
  { stdio: 'inherit' },
);
process.exit(status ?? 1);
