// Bundles the server, CLI and migrator into plain ESM under dist/, so production runs on `node`
// alone: no tsx, no TypeScript, no node_modules in the image.
import { cp, readFile, rm } from 'node:fs/promises';
import { build } from 'esbuild';

const MIGRATIONS = "new URL('../migrations/', import.meta.url)";

// packages/db finds its SQL next to its source. In the bundle it lives in dist/migrations.
const migrationsNextToBundle = {
  name: 'migrations-next-to-bundle',
  setup(b) {
    b.onLoad({ filter: /packages[\\/]db[\\/]src[\\/]index\.ts$/ }, async ({ path }) => {
      const source = await readFile(path, 'utf8');
      if (!source.includes(MIGRATIONS)) throw new Error(`${path} no longer contains ${MIGRATIONS}`);
      return {
        contents: source.replace(MIGRATIONS, "new URL('./migrations/', import.meta.url)"),
        loader: 'ts',
      };
    });
  },
};

await rm('dist', { recursive: true, force: true });
await build({
  entryPoints: ['src/main.ts', 'src/cli.ts', 'src/migrate.ts'],
  outdir: 'dist',
  bundle: true,
  splitting: true,
  format: 'esm',
  platform: 'node',
  target: 'node24',
  minifySyntax: true,
  // oidc-provider keys TTLs and adapter models by class name, so renaming a class breaks tokens.
  keepNames: true,
  sourcemap: 'linked',
  sourcesContent: false,
  legalComments: 'linked',
  // Chunks stay beside the entry points so every import.meta.url resolves from dist/.
  chunkNames: '[name]-[hash]',
  // Development only (Vite middleware mode), and pg's optional native binding.
  external: ['vite', '@fastify/middie', 'pg-native'],
  // Some bundled CommonJS dependencies still call require().
  banner: {
    js: "import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);",
  },
  plugins: [migrationsNextToBundle],
  logLevel: 'info',
});
await cp('../../packages/db/migrations', 'dist/migrations', { recursive: true });
