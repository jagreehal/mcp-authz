import { PassThrough } from 'node:stream';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, it } from 'vitest';
import { wrap } from './wrap';
import { quoteWindowsArgument, windowsJobCommand } from './windows-job';

// Runs everywhere: it measures the command line, it does not start one.
it("keeps a server's long arguments off the supervisor's command line", () => {
  const long = 'x'.repeat(30_000);
  const lineFor = (args: string[]) => {
    const job = windowsJobCommand(process.execPath, args);
    try {
      return {
        length: [job.command, ...job.args].map(quoteWindowsArgument).join(' ').length,
        spec: JSON.parse(readFileSync(job.specPath, 'utf8')),
      };
    } finally {
      job.cleanup();
      expect(existsSync(job.specPath)).toBe(false);
    }
  };

  const short = lineFor([]);
  const withLong = lineFor(['--config', long]);

  // CreateProcessW refuses a command line over 32,767 characters. The
  // supervisor's own line is a fixed size; the server's arguments go in the
  // spec file, so they cannot push it over.
  expect(withLong.length).toBe(short.length);
  expect(withLong.length).toBeLessThan(32_767);
  expect(withLong.spec).toEqual({ command: process.execPath, args: ['--config', long] });
});

it.skipIf(process.platform !== 'win32')(
  'preserves stdio, environment and literal arguments through the Windows job',
  async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    let received = '';
    let log = '';
    output.on('data', (chunk) => (received += chunk.toString()));
    const args = ['space value', 'a"b', 'C:\\path\\', '$env:USERPROFILE', '$(Get-Process)', ''];
    const source = `process.stdin.once('data', data => {
    console.log(JSON.stringify({ args: process.argv.slice(1), input: data.toString(), env: process.env.SystemRoot }));
    process.exit(7);
  });`;
    const exited = wrap(
      { command: process.execPath, args: ['-e', source, ...args] },
      { input, output, log: (line) => (log += line) },
    );
    // wrap forwards JSON-RPC only, and forwards it byte for byte.
    const message = '{"jsonrpc":"2.0","method":"notifications/initialized"}';
    input.write(`${message}\n`);
    try {
      await expect(exited).resolves.toBe(7);
      await expect.poll(() => received.trim()).not.toBe('');
      expect(JSON.parse(received)).toEqual({ args, input: `${message}\n`, env: process.env.SystemRoot });
      expect(log).toBe('');
    } finally {
      input.end();
    }
  },
  30_000,
);

it.skipIf(process.platform !== 'win32')(
  'resolves and runs Windows command shims',
  async () => {
    const directory = mkdtempSync(join(tmpdir(), 'mcp-authz-job-'));
    const command = join(directory, 'server shim.cmd');
    writeFileSync(
      command,
      `@echo off\r\n"${process.execPath}" -e "console.log('shim ran');process.exit(9)"\r\n`,
    );
    const input = new PassThrough();
    const output = new PassThrough();
    let received = '';
    output.on('data', (chunk) => (received += chunk.toString()));
    try {
      const exited = wrap({ command, args: [] }, { input, output, log: () => {} });
      await expect(exited).resolves.toBe(9);
      await expect.poll(() => received.trim()).toBe('shim ran');
    } finally {
      input.end();
      rmSync(directory, { recursive: true, force: true });
    }
  },
  30_000,
);

it.skipIf(process.platform !== 'win32')(
  'kills descendants if the job supervisor is forcibly terminated',
  async () => {
    const fixture = fileURLToPath(new URL('./__fixtures__/raw-upstream.mjs', import.meta.url));
    const command = windowsJobCommand(process.execPath, [fixture, 'launcher']);
    const supervisor = spawn(command.command, command.args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let log = '';
    let pid: number | undefined;
    supervisor.stdout.resume();
    supervisor.stderr.on('data', (chunk) => (log += chunk.toString()));
    const exited = new Promise((resolve, reject) => {
      supervisor.once('exit', resolve);
      supervisor.once('error', reject);
    });
    try {
      await expect.poll(() => /server pid (\d+)/.exec(log), { timeout: 15_000 }).toBeTruthy();
      pid = Number(/server pid (\d+)/.exec(log)![1]);
      supervisor.kill('SIGKILL');
      await exited;
      await expect
        .poll(() => {
          try {
            process.kill(pid!, 0);
            return false;
          } catch {
            return true;
          }
        })
        .toBe(true);
    } finally {
      supervisor.kill('SIGKILL');
      supervisor.stdin.end();
      if (pid !== undefined) {
        try {
          process.kill(pid, 'SIGKILL');
        } catch {
          /* Already reaped. */
        }
      }
      await exited;
    }
  },
  30_000,
);
