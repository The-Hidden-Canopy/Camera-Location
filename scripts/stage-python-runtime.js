const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

function log(message) {
  process.stdout.write(`[stage-python-runtime] ${message}\n`);
}

function rmDir(target) {
  fs.rmSync(target, { recursive: true, force: true });
}

function copyDir(source, target) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.cpSync(source, target, { recursive: true, force: true });
}

function verifyPythonModules(pythonExe, modules) {
  const probe = [
    'import importlib.util, sys',
    `mods = ${JSON.stringify(modules)}`,
    'missing = [m for m in mods if importlib.util.find_spec(m) is None]',
    'print("\\n".join(missing)) if missing else None',
    'sys.exit(1 if missing else 0)',
  ].join('; ');
  return spawnSync(pythonExe, ['-c', probe], { encoding: 'utf8' });
}

function resolveSourceRuntime(repoRoot) {
  const envCandidates = [
    process.env.CAMERA_DISCOVERY_PYTHON_DIR,
    process.env.PYTHON_RUNTIME_DIR,
  ].filter(Boolean);

  const defaultCandidates = [
    path.join(process.env.USERPROFILE || '', '.cache', 'codex-runtimes', 'codex-primary-runtime', 'dependencies', 'python'),
    path.join(repoRoot, '.python-runtime'),
  ];

  for (const candidate of [...envCandidates, ...defaultCandidates]) {
    if (candidate && fs.existsSync(path.join(candidate, 'python.exe'))) {
      return candidate;
    }
  }

  throw new Error(
    'Python runtime not found. Set CAMERA_DISCOVERY_PYTHON_DIR to a portable Python directory containing python.exe.'
  );
}

function main() {
  const repoRoot = path.resolve(__dirname, '..');
  const sourceRuntime = resolveSourceRuntime(repoRoot);
  const bundledRoot = path.join(repoRoot, '.bundled-runtime');
  const targetRuntime = path.join(bundledRoot, 'python');

  rmDir(targetRuntime);
  copyDir(sourceRuntime, targetRuntime);

  const required = ['python.exe', 'python312.dll', 'Lib'];
  const missing = required.filter((entry) => !fs.existsSync(path.join(targetRuntime, entry)));
  if (missing.length) {
    throw new Error(`Bundled runtime is incomplete. Missing: ${missing.join(', ')}`);
  }

  const requiredModules = [
    'flask',
    'jinja2',
    'werkzeug',
    'click',
    'itsdangerous',
    'markupsafe',
  ];
  const probe = verifyPythonModules(path.join(targetRuntime, 'python.exe'), requiredModules);
  if (probe.status !== 0) {
    const missingModules = (probe.stdout || probe.stderr || '')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    throw new Error(
      `Bundled runtime is missing required Python modules: ${missingModules.join(', ')}. ` +
      `Populate the source runtime with app dependencies before packaging.`
    );
  }

  log(`staged runtime from ${sourceRuntime} to ${targetRuntime}`);
}

try {
  main();
} catch (error) {
  console.error(`[stage-python-runtime] ${error.message}`);
  process.exit(1);
}
