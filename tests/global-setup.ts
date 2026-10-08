import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Builds the server once per test run (a debug build: quick to compile, plenty fast for tests).
export default function setup() {
  if (process.env.HANDSTAMP_BIN) return;
  execFileSync('cargo', ['build', '--locked', '--manifest-path', 'backend/Cargo.toml'], {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    stdio: 'inherit',
  });
}
