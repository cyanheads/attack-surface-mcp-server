/**
 * @fileoverview Boots the real entry point over Streamable HTTP and pins the declared session
 * posture: with `MCP_SESSION_MODE` unset the server resolves `stateless`, and an explicit env value
 * still overrides the `createApp` default. Each case spawns `src/index.ts` on an ephemeral port in a
 * scratch working directory, so no developer `.env` or inherited `MCP_*` variable leaks in.
 * @module tests/integration/session-mode.test
 */

import { type ChildProcess, spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

const ENTRY = fileURLToPath(new URL('../../src/index.ts', import.meta.url));
const BOOT_TIMEOUT_MS = 15_000;

interface Booted {
  child: ChildProcess;
  port: number;
  workDir: string;
}

let booted: Booted | undefined;

/** Reserve a free loopback port by binding port 0 and releasing it. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      if (address === null || typeof address === 'string') {
        probe.close();
        reject(new Error('Could not read the reserved port.'));
        return;
      }
      probe.close(() => resolve(address.port));
    });
  });
}

/** Spawn the server over HTTP with every inherited `MCP_*` variable stripped, plus `extraEnv`. */
async function boot(extraEnv: Record<string, string> = {}): Promise<Booted> {
  const port = await freePort();
  const workDir = mkdtempSync(join(tmpdir(), 'attack-surface-session-mode-'));
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.startsWith('MCP_')),
  );
  const child = spawn('bun', [ENTRY], {
    cwd: workDir,
    env: {
      ...env,
      MCP_TRANSPORT_TYPE: 'http',
      MCP_HTTP_HOST: '127.0.0.1',
      MCP_HTTP_PORT: String(port),
      MCP_LOG_LEVEL: 'error',
      LOGS_DIR: workDir,
      ...extraEnv,
    },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  booted = { child, port, workDir };
  return booted;
}

/** Poll plain `GET /mcp` (no SSE Accept header) until the server answers or the deadline passes. */
async function readServerInfo({
  child,
  port,
}: Booted): Promise<{ server: { sessionMode: string } }> {
  let stderr = '';
  child.stderr?.on('data', (chunk: Buffer) => {
    stderr += chunk.toString();
  });
  const deadline = Date.now() + BOOT_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Server exited with code ${child.exitCode} before answering.\n${stderr}`);
    }
    try {
      const res = await fetch(`http://127.0.0.1:${port}/mcp`, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(1_000),
      });
      if (res.ok) return (await res.json()) as { server: { sessionMode: string } };
    } catch {
      // Not listening yet — retry until the deadline.
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error(`Server did not answer GET /mcp within ${BOOT_TIMEOUT_MS}ms.\n${stderr}`);
}

afterEach(async () => {
  if (!booted) return;
  const { child, workDir } = booted;
  booted = undefined;
  if (child.exitCode === null && child.signalCode === null) {
    const exited = new Promise((resolve) => child.once('exit', resolve));
    child.kill('SIGTERM');
    await exited;
  }
  rmSync(workDir, { recursive: true, force: true });
});

describe('HTTP session mode', () => {
  it('resolves stateless when MCP_SESSION_MODE is unset', async () => {
    const info = await readServerInfo(await boot());
    expect(info.server.sessionMode).toBe('stateless');
  });

  it('lets an explicit MCP_SESSION_MODE override the declared default', async () => {
    const info = await readServerInfo(await boot({ MCP_SESSION_MODE: 'stateful' }));
    expect(info.server.sessionMode).toBe('stateful');
  });
});
