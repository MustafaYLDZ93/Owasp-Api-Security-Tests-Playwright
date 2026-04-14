import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';

const PID_FILE   = path.join(__dirname, '.api-server.pid');
const HEALTH_URL = 'http://localhost:3000/api/health';
const SERVER_JS  = path.join(__dirname, 'api-server', 'server.js');

function isReachable(url: string): Promise<boolean> {
  return new Promise(resolve => {
    http.get(url, res => resolve(res.statusCode === 200))
        .on('error', () => resolve(false));
  });
}

async function waitUntilReady(maxMs = 12_000): Promise<void> {
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    if (await isReachable(HEALTH_URL)) return;
    await new Promise(r => setTimeout(r, 250));
  }
  throw new Error(`API server did not become ready within ${maxMs / 1000}s`);
}

export default async function globalSetup() {
  if (await isReachable(HEALTH_URL)) {
    console.log('\n[setup] API server already running on http://localhost:3000\n');
    return; // Don't write PID — teardown won't stop a server we didn't start
  }

  console.log('\n[setup] Starting API server…');
  const server: ChildProcess = spawn(process.execPath, [SERVER_JS], {
    env: {
      ...process.env,
      PORT: '3000',
      JWT_SECRET: process.env.JWT_SECRET ?? 'test-secret-key-for-security-testing',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: false,
  });

  server.stdout?.on('data', (d: Buffer) => process.stdout.write(`  [api] ${d}`));
  server.stderr?.on('data', (d: Buffer) => process.stderr.write(`  [api] ${d}`));

  server.on('error', err => { throw new Error(`Failed to start API server: ${err.message}`); });
  server.on('exit', code => {
    if (code !== null && code !== 0) {
      throw new Error(`API server exited unexpectedly with code ${code}`);
    }
  });

  // Persist PID so globalTeardown can stop it
  fs.writeFileSync(PID_FILE, String(server.pid));

  await waitUntilReady();
  console.log('[setup] API server ready ✓\n');
}
