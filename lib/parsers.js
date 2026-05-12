'use strict';

const fs = require('node:fs');
const path = require('node:path');

function readJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function addPackage(found, ecosystem, name, version, source, extra = {}) {
  if (!name || !version) return;
  found.push({
    ecosystem,
    name: normalizeName(ecosystem, name),
    version: normalizeVersion(version),
    source,
    ...extra,
  });
}

function normalizeName(ecosystem, name) {
  if (ecosystem === 'pypi') return name.replace(/_/g, '-').toLowerCase();
  return name;
}

function normalizeVersion(version) {
  return String(version).trim().replace(/^v/i, '');
}

function exactVersionFromSpec(spec) {
  if (typeof spec !== 'string') return null;
  const trimmed = spec.trim();
  const exact = trimmed.match(/^(?:=|==)?\s*v?([0-9][0-9A-Za-z.+-]*)$/);
  return exact ? exact[1] : null;
}

function packageNameFromNodeModulesPath(lockPath) {
  const marker = 'node_modules/';
  const index = lockPath.lastIndexOf(marker);
  if (index === -1) return null;
  const tail = lockPath.slice(index + marker.length);
  const segments = tail.split('/');
  if (segments[0] && segments[0].startsWith('@')) return `${segments[0]}/${segments[1]}`;
  return segments[0];
}

function parsePackageLock(root) {
  const file = path.join(root, 'package-lock.json');
  const lock = readJson(file);
  const found = [];
  if (!lock) return found;

  if (lock.packages && typeof lock.packages === 'object') {
    for (const [lockPath, info] of Object.entries(lock.packages)) {
      if (!lockPath || !info || !info.version) continue;
      const name = info.name || packageNameFromNodeModulesPath(lockPath);
      addPackage(found, 'npm', name, info.version, 'package-lock.json');
    }
  }

  if (lock.dependencies && typeof lock.dependencies === 'object') {
    collectLockDependencies(lock.dependencies, found, 'package-lock.json');
  }

  return found;
}

function parseShrinkwrap(root) {
  const file = path.join(root, 'npm-shrinkwrap.json');
  const lock = readJson(file);
  const found = [];
  if (!lock || !lock.dependencies) return found;
  collectLockDependencies(lock.dependencies, found, 'npm-shrinkwrap.json');
  return found;
}

function collectLockDependencies(dependencies, found, source) {
  for (const [name, info] of Object.entries(dependencies)) {
    if (info && info.version) addPackage(found, 'npm', name, info.version, source);
    if (info && info.dependencies) collectLockDependencies(info.dependencies, found, source);
  }
}

function parsePackageJson(root) {
  const pkg = readJson(path.join(root, 'package.json'));
  const found = [];
  if (!pkg) return found;
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const deps = pkg[field];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, spec] of Object.entries(deps)) {
      const version = exactVersionFromSpec(spec);
      if (version) addPackage(found, 'npm', name, version, 'package.json');
    }
  }
  return found;
}

function parseYarnLock(root) {
  const file = path.join(root, 'yarn.lock');
  if (!fs.existsSync(file)) return [];
  const text = fs.readFileSync(file, 'utf8');
  const found = [];
  let currentNames = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trimEnd();
    if (!line.startsWith(' ') && line.endsWith(':')) {
      currentNames = namesFromYarnHeader(line.slice(0, -1));
      continue;
    }
    const versionMatch = line.match(/^\s+version\s+"?([^"\s]+)"?/);
    if (versionMatch && currentNames.length) {
      for (const name of currentNames) addPackage(found, 'npm', name, versionMatch[1], 'yarn.lock');
    }
  }
  return found;
}

function namesFromYarnHeader(header) {
  return header.split(',').map((part) => {
    const spec = part.trim().replace(/^["']|["']$/g, '');
    return npmNameFromSpec(spec);
  }).filter(Boolean);
}

function npmNameFromSpec(spec) {
  const cleaned = spec.replace(/^npm:/, '');
  if (cleaned.startsWith('@')) {
    const secondAt = cleaned.indexOf('@', cleaned.indexOf('/') + 1);
    return secondAt === -1 ? cleaned : cleaned.slice(0, secondAt);
  }
  const at = cleaned.indexOf('@');
  return at === -1 ? cleaned : cleaned.slice(0, at);
}

function parsePnpmLock(root) {
  const file = path.join(root, 'pnpm-lock.yaml');
  if (!fs.existsSync(file)) return [];
  const text = fs.readFileSync(file, 'utf8');
  const found = [];
  let section = null;
  for (const rawLine of text.split(/\r?\n/)) {
    if (!rawLine.trim() || rawLine.trimStart().startsWith('#')) continue;
    const sectionMatch = rawLine.match(/^([A-Za-z][A-Za-z0-9_-]*):\s*$/);
    if (sectionMatch) {
      section = sectionMatch[1];
      continue;
    }
    if (section !== 'packages' && section !== 'snapshots') continue;

    const keyMatch = rawLine.match(/^ {2}(.+?):(?:\s+.*)?$/);
    if (!keyMatch) continue;
    const key = keyMatch[1].replace(/^['"]|['"]$/g, '');
    const parsed = parsePnpmPackageKey(key);
    if (parsed) addPackage(found, 'npm', parsed.name, parsed.version, 'pnpm-lock.yaml');
  }
  return found;
}

function parsePnpmPackageKey(key) {
  let value = key;
  if (value.startsWith('/')) value = value.slice(1);
  if (value.includes('(')) value = value.slice(0, value.indexOf('('));
  if (value.startsWith('@') && value.includes('/')) {
    const slash = value.indexOf('/');
    const versionSlash = value.indexOf('/', slash + 1);
    if (versionSlash !== -1) {
      return validNpmPackage(value.slice(0, versionSlash), value.slice(versionSlash + 1));
    }
  }
  if (!value.startsWith('@') && value.includes('/')) {
    const slash = value.indexOf('/');
    return validNpmPackage(value.slice(0, slash), value.slice(slash + 1));
  }
  if (value.startsWith('@')) {
    const slash = value.indexOf('/');
    if (slash === -1) return null;
    const at = value.indexOf('@', slash + 1);
    if (at === -1) return null;
    return validNpmPackage(value.slice(0, at), value.slice(at + 1));
  }
  const at = value.indexOf('@');
  if (at <= 0) return null;
  return validNpmPackage(value.slice(0, at), value.slice(at + 1));
}

function validNpmPackage(name, version) {
  if (!name || !version) return null;
  if (!/^(?:@[A-Za-z0-9._~-]+\/)?[A-Za-z0-9._~-]+$/.test(name)) return null;
  if (!/^[0-9][0-9A-Za-z.+-]*$/.test(version)) return null;
  return { name, version };
}

function parseRequirements(root) {
  const found = [];
  for (const file of fs.readdirSync(root)) {
    if (!/^requirements.*\.txt$/i.test(file)) continue;
    const text = fs.readFileSync(path.join(root, file), 'utf8');
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.replace(/\s+#.*$/, '').trim();
      const match = line.match(/^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.!+-]+)/);
      if (match) addPackage(found, 'pypi', match[1], match[2], file);
    }
  }
  return found;
}

function parsePoetryLock(root) {
  const file = path.join(root, 'poetry.lock');
  if (!fs.existsSync(file)) return [];
  const text = fs.readFileSync(file, 'utf8');
  const found = [];
  let name = null;
  let version = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === '[[package]]') {
      if (name && version) addPackage(found, 'pypi', name, version, 'poetry.lock');
      name = null;
      version = null;
      continue;
    }
    const nameMatch = line.match(/^name\s*=\s*"([^"]+)"/);
    const versionMatch = line.match(/^version\s*=\s*"([^"]+)"/);
    if (nameMatch) name = nameMatch[1];
    if (versionMatch) version = versionMatch[1];
  }
  if (name && version) addPackage(found, 'pypi', name, version, 'poetry.lock');
  return found;
}

function parseComposerLock(root) {
  const lock = readJson(path.join(root, 'composer.lock'));
  const found = [];
  if (!lock) return found;
  for (const section of ['packages', 'packages-dev']) {
    for (const info of lock[section] || []) {
      addPackage(found, 'packagist', info.name, info.version, 'composer.lock');
    }
  }
  return found;
}

function parseNodeModules(root) {
  const modulesRoot = path.join(root, 'node_modules');
  const found = [];
  if (!fs.existsSync(modulesRoot)) return found;
  for (const packageJson of listNodePackageJsons(modulesRoot)) {
    const info = readJson(packageJson);
    if (!info || !info.name || !info.version) continue;
    const bins = binsFromPackageJson(info);
    addPackage(found, 'npm', info.name, info.version, path.relative(root, packageJson), { bins, packageJson });
  }
  return found;
}

function listNodePackageJsons(modulesRoot) {
  const result = [];
  for (const entry of safeReaddir(modulesRoot)) {
    if (entry === '.bin' || entry.startsWith('.')) continue;
    const full = path.join(modulesRoot, entry);
    const stat = safeStat(full);
    if (!stat || !stat.isDirectory()) continue;
    if (entry.startsWith('@')) {
      for (const scoped of safeReaddir(full)) {
        const packageJson = path.join(full, scoped, 'package.json');
        if (fs.existsSync(packageJson)) result.push(packageJson);
      }
      continue;
    }
    const packageJson = path.join(full, 'package.json');
    if (fs.existsSync(packageJson)) result.push(packageJson);
  }
  return result;
}

function binsFromPackageJson(info) {
  if (!info || !info.bin) return [];
  if (typeof info.bin === 'string') return [info.name.split('/').pop()];
  if (typeof info.bin === 'object') return Object.keys(info.bin);
  return [];
}

function safeReaddir(dir) {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}

function safeStat(filePath) {
  try {
    return fs.statSync(filePath);
  } catch {
    return null;
  }
}

module.exports = {
  parsePackageLock,
  parseShrinkwrap,
  parsePackageJson,
  parseYarnLock,
  parsePnpmLock,
  parseRequirements,
  parsePoetryLock,
  parseComposerLock,
  parseNodeModules,
  binsFromPackageJson,
  readJson,
};
