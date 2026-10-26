const { spawnSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const electronDir = path.join(root, 'node_modules', 'electron');
const electronExe = process.platform === 'win32'
  ? path.join(electronDir, 'dist', 'electron.exe')
  : path.join(electronDir, 'dist', 'electron');

function fail(message) {
  console.error(`\n[DeepGuard] ${message}\n`);
  process.exit(1);
}

if (!fs.existsSync(electronDir)) {
  fail('Electron is not installed. Run: npm install');
}

if (!fs.existsSync(electronExe)) {
  console.log('[DeepGuard] Electron runtime is missing. Repairing Electron installation...');
  const installer = path.join(electronDir, 'install.js');
  if (!fs.existsSync(installer)) {
    fail('Electron package is incomplete. Run: npm install electron --save-dev');
  }
  const r = spawnSync(process.execPath, [installer], {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, ELECTRON_SKIP_BINARY_DOWNLOAD: '' }
  });
  if (r.status !== 0 || !fs.existsSync(electronExe)) {
    fail('Electron runtime repair failed. Try: npm approve-scripts --allow-scripts-pending && npm install');
  }
}

const child = spawn(electronExe, ['.'], { cwd: root, stdio: 'inherit', windowsHide: false });
child.on('error', err => fail(`Could not start Electron: ${err.message}`));
child.on('exit', (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
