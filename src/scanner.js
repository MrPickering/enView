import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

const ENV_PATTERNS = [
  '.env', '.env.*',
];

const IGNORE_DIRS = new Set([
  'node_modules', '.git', 'vendor', '__pycache__', '.venv',
  'venv', 'dist', 'build', '.next', '.nuxt', '.output',
  'target', 'coverage', '.terraform', '.cache',
]);

const IGNORE_EXTENSIONS = new Set([
  '.example', '.sample', '.template', '.bak', '.swp',
]);

/**
 * Recursively find .env files under given root directories
 */
export function scanDirectories(roots, opts = {}) {
  const maxDepth = opts.maxDepth ?? 6;
  const results = [];

  for (const root of roots) {
    const absRoot = path.resolve(root);
    if (!fs.existsSync(absRoot)) continue;
    walkDir(absRoot, absRoot, 0, maxDepth, results);
  }

  return groupByProject(results);
}

function walkDir(dir, root, depth, maxDepth, results) {
  if (depth > maxDepth) return;

  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // permission denied, etc.
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (IGNORE_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
      walkDir(fullPath, root, depth + 1, maxDepth, results);
      continue;
    }

    if (!entry.isFile()) continue;
    if (!isEnvFile(entry.name)) continue;

    const info = analyzeEnvFile(fullPath, root);
    if (info) results.push(info);
  }
}

function isEnvFile(filename) {
  if (filename === '.env') return true;
  if (!filename.startsWith('.env.')) return false;

  const suffix = filename.slice(5); // after ".env."
  // Skip example/template files
  if (IGNORE_EXTENSIONS.has('.' + suffix)) return false;
  // Skip .env.keys (dotenvx private key file — never scan)
  if (suffix === 'keys') return false;
  // Skip Windows shortcut files
  if (filename.endsWith('.lnk')) return false;
  return true;
}

function analyzeEnvFile(filePath, scanRoot) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }

  const stat = fs.statSync(filePath);
  const dir = path.dirname(filePath);
  const projectDir = detectProjectRoot(dir, scanRoot);

  const keys = [];
  const encryptedKeys = [];
  const plaintextKeys = [];
  const lines = content.split('\n');

  let hasDotenvxPublicKey = false;
  let hasSopsMetadata = false;

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip comments and empty lines
    if (!trimmed || trimmed.startsWith('#')) {
      if (trimmed.includes('DOTENV_PUBLIC_KEY')) hasDotenvxPublicKey = true;
      continue;
    }

    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;

    const key = trimmed.slice(0, eqIdx).trim();
    const value = trimmed.slice(eqIdx + 1).trim();

    // Skip dotenvx internal keys
    if (key === 'DOTENV_PUBLIC_KEY' || key.startsWith('DOTENV_PUBLIC_KEY_')) continue;

    keys.push(key);

    if (isEncryptedValue(value)) {
      encryptedKeys.push(key);
    } else if (value && !isBoringValue(value)) {
      plaintextKeys.push(key);
    }
  }

  // Check for SOPS metadata
  if (content.includes('sops_version') || content.includes('sops:')) {
    hasSopsMetadata = true;
  }

  const encryption = detectEncryption(hasDotenvxPublicKey, hasSopsMetadata, encryptedKeys, keys);
  const gitInfo = getGitInfo(filePath, dir);

  return {
    filePath,
    fileName: path.basename(filePath),
    projectDir,
    projectName: path.basename(projectDir),
    environment: detectEnvironment(path.basename(filePath)),
    keys,
    encryptedKeys,
    plaintextKeys,
    encryption,
    modifiedAt: stat.mtime,
    size: stat.size,
    gitTracked: gitInfo.tracked,
    gitIgnored: gitInfo.ignored,
    lastCommit: gitInfo.lastCommit,
    inGitRepo: gitInfo.inGitRepo,
    sensitiveKeys: detectSensitiveKeys(plaintextKeys),
  };
}

function isEncryptedValue(value) {
  // dotenvx: "encrypted:..."
  if (value.startsWith('"encrypted:') || value.startsWith('encrypted:')) return true;
  // SOPS-style encrypted values
  if (value.startsWith('ENC[') && value.endsWith(']')) return true;
  // age-encrypted
  if (value.includes('age-encryption.org')) return true;
  return false;
}

function isBoringValue(value) {
  const unquoted = value.replace(/^["']|["']$/g, '');
  // Empty, localhost, true/false, numbers
  if (!unquoted) return true;
  if (/^(true|false|yes|no|on|off)$/i.test(unquoted)) return true;
  if (/^\d+$/.test(unquoted)) return true;
  if (unquoted === 'localhost' || unquoted === '127.0.0.1') return true;
  return false;
}

function detectEncryption(hasDotenvxKey, hasSops, encryptedKeys, allKeys) {
  if (hasDotenvxKey && encryptedKeys.length > 0) {
    return {
      type: 'dotenvx',
      partial: encryptedKeys.length < allKeys.length,
      encryptedCount: encryptedKeys.length,
      totalCount: allKeys.length,
    };
  }
  if (hasSops) {
    return { type: 'sops', partial: false, encryptedCount: allKeys.length, totalCount: allKeys.length };
  }
  if (encryptedKeys.length > 0) {
    return {
      type: 'unknown',
      partial: encryptedKeys.length < allKeys.length,
      encryptedCount: encryptedKeys.length,
      totalCount: allKeys.length,
    };
  }
  return { type: 'none', partial: false, encryptedCount: 0, totalCount: allKeys.length };
}

function detectEnvironment(fileName) {
  if (fileName === '.env') return 'development';
  const suffix = fileName.slice(5); // after ".env."
  const normalized = suffix.toLowerCase();
  const map = {
    'dev': 'development', 'development': 'development',
    'prod': 'production', 'production': 'production',
    'stg': 'staging', 'staging': 'staging',
    'local': 'local', 'test': 'test', 'ci': 'ci',
  };
  return map[normalized] || normalized;
}

const SENSITIVE_PATTERNS = [
  /api.?key/i, /secret/i, /password/i, /passwd/i, /token/i,
  /private.?key/i, /auth/i, /credential/i, /connection.?string/i,
  /database.?url/i, /db.?pass/i, /smtp/i, /stripe/i,
  /aws.?access/i, /aws.?secret/i, /openai/i, /anthropic/i,
  /github.?token/i, /webhook/i, /signing/i, /encryption/i,
];

function detectSensitiveKeys(plaintextKeys) {
  return plaintextKeys.filter(key =>
    SENSITIVE_PATTERNS.some(pattern => pattern.test(key))
  );
}

function detectProjectRoot(dir, scanRoot) {
  let current = dir;
  while (current !== scanRoot && current !== path.dirname(current)) {
    const markers = ['package.json', 'Cargo.toml', 'go.mod', 'pyproject.toml',
      'Gemfile', 'pom.xml', 'build.gradle', 'Makefile', '.git',
      'composer.json', 'mix.exs', 'deno.json'];
    for (const marker of markers) {
      if (fs.existsSync(path.join(current, marker))) return current;
    }
    current = path.dirname(current);
  }
  return dir;
}

function getGitInfo(filePath, dir) {
  const result = { tracked: false, ignored: false, lastCommit: null, inGitRepo: false };

  try {
    execSync('git rev-parse --git-dir', { cwd: dir, stdio: 'pipe' });
    result.inGitRepo = true;
  } catch {
    return result;
  }

  try {
    const status = execSync(`git check-ignore "${filePath}" 2>/dev/null`, {
      cwd: dir, stdio: 'pipe', encoding: 'utf-8',
    });
    result.ignored = status.trim().length > 0;
  } catch {
    result.ignored = false;
  }

  try {
    const log = execSync(
      `git log -1 --format="%H|%aI|%s" -- "${path.basename(filePath)}" 2>/dev/null`,
      { cwd: dir, stdio: 'pipe', encoding: 'utf-8' }
    ).trim();
    if (log) {
      const [hash, date, message] = log.split('|');
      result.tracked = true;
      result.lastCommit = { hash: hash.slice(0, 8), date: new Date(date), message };
    }
  } catch {
    // not tracked
  }

  return result;
}

function groupByProject(files) {
  const projects = new Map();
  for (const file of files) {
    const key = file.projectDir;
    if (!projects.has(key)) {
      projects.set(key, {
        name: file.projectName,
        path: file.projectDir,
        files: [],
      });
    }
    projects.get(key).files.push(file);
  }
  return [...projects.values()].sort((a, b) => a.name.localeCompare(b.name));
}
