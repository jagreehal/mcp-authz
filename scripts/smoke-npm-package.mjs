import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = process.cwd();
const directory = mkdtempSync(join(tmpdir(), 'mcp-authz-package-'));

try {
  execFileSync('pnpm', ['--filter', 'mcp-authz', 'pack', '--pack-destination', directory], {
    cwd: root,
    stdio: 'inherit',
  });
  const archive = readdirSync(directory).find((file) => file.endsWith('.tgz'));
  if (!archive) throw new Error('pnpm pack produced no archive.');

  const consumer = join(directory, 'consumer');
  mkdirSync(consumer);
  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', join(directory, archive)], {
    cwd: consumer,
    stdio: 'inherit',
  });
  execFileSync(
    process.execPath,
    [
      '--input-type=module',
      '--eval',
      "import { createMcpFetch, definePolicy } from 'mcp-authz'; import { reconcile } from 'mcp-authz/policy'; if (![createMcpFetch, definePolicy, reconcile].every(value => typeof value === 'function')) process.exit(1);",
    ],
    { cwd: consumer, stdio: 'inherit' },
  );
  execFileSync(process.execPath, ['node_modules/mcp-authz/dist/cli.js', '--help'], {
    cwd: consumer,
    stdio: 'ignore',
  });

  // `mcp-authz/testing` is the one subpath a production install cannot reach on
  // its own: the client it needs is an optional peer, so npm skips it. Install
  // it the way a consumer would and prove the export map still resolves.
  execFileSync(
    'npm',
    ['install', '--ignore-scripts', '--no-audit', '--no-fund', '@modelcontextprotocol/client'],
    { cwd: consumer, stdio: 'inherit' },
  );
  execFileSync(
    process.execPath,
    [
      '--input-type=module',
      '--eval',
      "import { recordCapabilities, toPermissionsModule } from 'mcp-authz/testing'; if (![recordCapabilities, toPermissionsModule].every(value => typeof value === 'function')) process.exit(1);",
    ],
    { cwd: consumer, stdio: 'inherit' },
  );
  execFileSync(
    process.execPath,
    [
      '--input-type=module',
      '--eval',
      "import { createMcpProxy } from 'mcp-authz/proxy'; if (typeof createMcpProxy !== 'function') process.exit(1);",
    ],
    { cwd: consumer, stdio: 'inherit' },
  );
} finally {
  rmSync(directory, { recursive: true, force: true });
}
