/**
 * Electron main process — Camera Discovery Octopus
 *
 * Runs as a desktop application with BrowserWindow:
 *   1. Requests admin elevation (for raw sockets + netsh)
 *   2. Starts the Flask backend
 *   3. Opens the UI in an Electron BrowserWindow (with preload)
 *   4. Sits in the tray — right-click to reopen or quit
 */

const { app, BrowserWindow, Tray, Menu, dialog, shell, nativeImage, ipcMain } = require('electron');
const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const net  = require('net');

// ─── Config ──────────────────────────────────────────────────────────────
const FLASK_PORT           = 5000;
const FLASK_HOST           = '127.0.0.1';
const FLASK_STARTUP_TIMEOUT = 30000;
const APP_URL              = `http://${FLASK_HOST}:${FLASK_PORT}`;
const IS_DEV               = process.argv.includes('--dev');

let tray        = null;
let mainWindow  = null;
let flaskProcess = null;

function getAppRoot() {
  return app.isPackaged ? process.resourcesPath : app.getAppPath();
}

function getPythonCandidates() {
  const envCandidates = [
    process.env.CAMERA_DISCOVERY_PYTHON,
    process.env.PYTHON,
  ].filter(Boolean);

  const root = getAppRoot();
  const bundledCandidates = process.platform === 'win32'
    ? [
        path.join(root, 'python', 'python.exe'),
        path.join(root, 'runtime', 'python.exe'),
      ]
    : [
        path.join(root, 'python', 'bin', 'python3'),
        path.join(root, 'python', 'bin', 'python'),
      ];

  const pathCandidates = process.platform === 'win32'
    ? ['python.exe', 'python', 'py.exe']
    : ['python3', 'python'];

  return [...envCandidates, ...bundledCandidates, ...pathCandidates];
}

function canExecute(command) {
  try {
    const probe = process.platform === 'win32'
      ? `where ${command}`
      : `command -v ${command}`;
    execSync(probe, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function resolvePythonCommand() {
  for (const candidate of getPythonCandidates()) {
    if (!candidate) continue;
    if (candidate.includes(path.sep)) {
      if (fs.existsSync(candidate)) return candidate;
      continue;
    }
    if (canExecute(candidate)) return candidate;
  }
  throw new Error('No usable Python runtime found');
}

// ─── Admin check ─────────────────────────────────────────────────────────

function isRunningAsAdmin() {
  if (process.platform !== 'win32') return true;
  try {
    const out = execSync('whoami /groups /fo csv', { encoding: 'utf8', stdio: ['pipe','pipe','pipe'] });
    return out.includes('S-1-5-32-544');
  } catch {
    return false;
  }
}

function relaunchAsAdmin() {
  const exePath = process.execPath;
  const appPath = app.getAppPath();
  const argList = app.isPackaged ? [] : [appPath];
  const psArgList = argList.length
    ? `@(${argList.map((a) => `'${a.replace(/'/g, "''")}'`).join(', ')})`
    : '@()';
  try {
    spawn('powershell.exe', [
      '-Command',
      `Start-Process -FilePath "${exePath}" -ArgumentList ${psArgList} -Verb RunAs -WorkingDirectory "${getAppRoot()}"`
    ], { detached: true, stdio: 'ignore' });
  } catch (e) {
    console.error('[Electron] Relaunch as admin failed:', e.message);
  }
  app.quit();
}

// ─── Flask backend ────────────────────────────────────────────────────────

function startFlask() {
  return new Promise((resolve, reject) => {
    const pythonCmd = resolvePythonCommand();
    const appRoot = getAppRoot();
    const args = ['-m', 'camdiscover', 'web',
                  '--host', FLASK_HOST, '--port', String(FLASK_PORT), '--no-browser'];

    console.log(`[Flask] Starting: ${pythonCmd} ${args.join(' ')}`);

    const env = {
      ...process.env,
      PYTHONPATH: process.env.PYTHONPATH
        ? `${appRoot}${path.delimiter}${process.env.PYTHONPATH}`
        : appRoot,
    };

    flaskProcess = spawn(pythonCmd, args, {
      cwd: appRoot,
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
    });

    flaskProcess.stdout.on('data', d => console.log('[Flask]', d.toString().trim()));
    flaskProcess.stderr.on('data', d => console.log('[Flask]', d.toString().trim()));
    flaskProcess.on('error', reject);
    flaskProcess.on('close', code => {
      console.log(`[Flask] exited (${code})`);
      flaskProcess = null;
    });

    waitForFlask(FLASK_HOST, FLASK_PORT, FLASK_STARTUP_TIMEOUT)
      .then(resolve).catch(reject);
  });
}

function waitForFlask(host, port, timeout) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    function attempt() {
      const sock = new net.Socket();
      sock.setTimeout(1000);
      sock.on('connect', () => { sock.destroy(); resolve(); });
      sock.on('error',   () => { sock.destroy(); retry(); });
      sock.on('timeout', () => { sock.destroy(); retry(); });
      sock.connect(port, host);
    }
    function retry() {
      if (Date.now() - start > timeout) {
        reject(new Error(`Flask did not start within ${timeout / 1000}s`));
      } else {
        setTimeout(attempt, 500);
      }
    }
    setTimeout(attempt, 800);
  });
}

function stopFlask() {
  if (!flaskProcess) return;
  console.log('[Flask] Stopping...');
  if (process.platform === 'win32') {
    spawn('taskkill', ['/pid', String(flaskProcess.pid), '/f', '/t'], { shell: true });
  } else {
    flaskProcess.kill('SIGTERM');
  }
  flaskProcess = null;
}

async function restartFlask() {
  stopFlask();
  await waitForProcessExit(5000);
  await startFlask();
}

function waitForProcessExit(timeoutMs) {
  return new Promise((resolve) => {
    const deadline = Date.now() + timeoutMs;
    const poll = () => {
      if (!flaskProcess || Date.now() >= deadline) {
        resolve();
        return;
      }
      setTimeout(poll, 100);
    };
    poll();
  });
}

// ─── BrowserWindow ────────────────────────────────────────────────────────

function createWindow() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.show();
    mainWindow.focus();
    return;
  }

  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 900,
    minHeight: 600,
    title: 'Hidden Canopy Network Discovery',
    icon: getIcon(),
    backgroundColor: '#0a0f1a',

    // Frameless with Windows overlay for native titlebar controls
    frame: false,
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#0d1117',
      symbolColor: '#58a6ff',
      height: 36,
    },

    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  mainWindow.loadURL(APP_URL);

  // Open DevTools in dev mode
  if (IS_DEV) {
    mainWindow.webContents.openDevTools();
  }

  // External links open in system browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http://') || url.startsWith('https://')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });

  mainWindow.on('close', (e) => {
    // Minimize to tray instead of closing
    if (tray) {
      e.preventDefault();
      mainWindow.hide();
    }
  });
}

function getIcon() {
  try {
    const icon = nativeImage.createFromPath(path.join(__dirname, 'icons', 'icon.ico'));
    if (!icon.isEmpty()) return icon;
  } catch {}
  return undefined;
}

// ─── Tray ─────────────────────────────────────────────────────────────────

function createTray() {
  let icon;
  try {
    icon = nativeImage.createFromPath(path.join(__dirname, 'icons', 'icon.ico'));
    if (icon.isEmpty()) throw new Error('empty');
  } catch {
    icon = nativeImage.createFromDataURL(
      'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAAdgAAAHYBTnsmCAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAABbSURBVDiNY2AYBUMHMDIy/mdgYPjPQIL+z8DAwMjAwMDw/z8DA8N/BgYGRpI0MDAwMJCggYGBgYEkDQwMDAwkamBgYGAgUQMDAwMDiRoYGBgYSNTAQBIGAEUoB7Fz5oiCAAAAAElFTkSuQmCC'
    );
  }

  tray = new Tray(icon);
  tray.setToolTip('Hidden Canopy Network Discovery');

  const menu = Menu.buildFromTemplate([
    { label: 'Open Dashboard', click: () => createWindow() },
    { type: 'separator' },
    { label: `Backend at ${APP_URL}`, enabled: false },
    { type: 'separator' },
    { label: 'Quit', click: () => { tray = null; stopFlask(); app.quit(); } },
  ]);

  tray.setContextMenu(menu);
  tray.on('click', () => createWindow());
}

ipcMain.handle('app:minimize', () => {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.minimize();
});

ipcMain.handle('app:maximize', () => {
  if (!mainWindow || mainWindow.isDestroyed()) return false;
  if (mainWindow.isMaximized()) {
    mainWindow.unmaximize();
    return false;
  }
  mainWindow.maximize();
  return true;
});

ipcMain.handle('app:isMaximized', () => {
  return !!(mainWindow && !mainWindow.isDestroyed() && mainWindow.isMaximized());
});

ipcMain.handle('app:close', () => {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.close();
});

ipcMain.handle('app:getFlaskUrl', () => APP_URL);

ipcMain.handle('app:restartFlask', async () => {
  await restartFlask();
  if (mainWindow && !mainWindow.isDestroyed()) {
    await mainWindow.loadURL(APP_URL);
  }
  return { ok: true, url: APP_URL };
});

// ─── App lifecycle ────────────────────────────────────────────────────────

// Prevent second instance
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
}

app.on('second-instance', () => {
  createWindow();
});

app.whenReady().then(async () => {
  // Keep running after all windows close (tray app)
  if (process.platform === 'darwin') {
    app.setActivationPolicy('accessory');
  }

  // Admin elevation on Windows
  if (process.platform === 'win32' && !isRunningAsAdmin()) {
    const choice = dialog.showMessageBoxSync({
      type: 'warning',
      title: 'Administrator Required',
      message: 'Camera Discovery needs admin rights for:\n• Raw packet capture (subnet sniffing)\n• netsh IP management\n• ONVIF multicast across all subnets',
      buttons: ['Relaunch as Admin', 'Continue Anyway'],
      defaultId: 0,
    });
    if (choice === 0) { relaunchAsAdmin(); return; }
  }

  // Start Flask
  try {
    await startFlask();
  } catch (err) {
    dialog.showErrorBox('Backend Failed',
      `Could not start Python/Flask.\n\n${err.message}\n\nMake sure Python is installed:\n  pip install -e .`);
    app.quit();
    return;
  }

  // System tray (always created so app survives window close)
  createTray();

  // Open the Electron BrowserWindow
  createWindow();
});

app.on('window-all-closed', () => { /* keep alive in tray */ });
app.on('before-quit', stopFlask);
