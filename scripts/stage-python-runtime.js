const fs = require('fs');
const path = require('path');

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

  log(`staged runtime from ${sourceRuntime} to ${targetRuntime}`);
}

try {
  main();
} catch (error) {
  console.error(`[stage-python-runtime] ${error.message}`);
  process.exit(1);
}
