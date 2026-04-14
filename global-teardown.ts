import * as fs   from 'fs';
import * as path from 'path';

const PID_FILE = path.join(__dirname, '.api-server.pid');

export default async function globalTeardown() {
  if (!fs.existsSync(PID_FILE)) return; // Server was already running — don't touch it

  const pid = parseInt(fs.readFileSync(PID_FILE, 'utf8'), 10);
  fs.unlinkSync(PID_FILE);

  try {
    process.kill(pid);
    console.log(`\n[teardown] API server (PID ${pid}) stopped.\n`);
  } catch {
    // Already gone — that's fine
  }
}
