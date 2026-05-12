'use strict';

const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { flattenAdvisories, SNAPSHOT_DATE } = require('./advisories');
const { queryOsv } = require('./live-osv');
const {
  parsePackageLock,
  parseShrinkwrap,
  parsePackageJson,
  parseYarnLock,
  parsePnpmLock,
  binsFromPackageJson,
  readJson,
} = require('./parsers');

const OFFLINE_ROWS = flattenAdvisories();
const OFFLINE_INDEX = buildOfflineIndex(OFFLINE_ROWS);
const MAX_MANIFEST_BYTES = 1024 * 1024;
const MANIFEST_PROBE_BYTES = 64 * 1024;
const SEMVERISH = '\\d+\\.\\d+\\.\\d+(?:[-+][0-9A-Za-z.-]+)?';
const SEMVERISH_RE = new RegExp(`^${SEMVERISH}$`);

const INSTALL_FILE_PARSERS = [
  parsePackageLock,
  parseShrinkwrap,
  parsePackageJson,
  parseYarnLock,
  parsePnpmLock,
];

const LOCATION_SCANNERS = {
  node_modules: scanNodeModulesLocation,
  'npm-cache': scanNpmCacheLocation,
  'install-root': scanInstallRootLocation,
  'manifest-store': scanManifestStoreLocation,
  'yarn-cache': scanYarnCacheLocation,
  'bun-cache': scanBunCacheLocation,
  'python-site': scanPythonSiteLocation,
  'python-venvs': scanPythonVenvsLocation,
};

const WALK_SKIP_DIRECTORIES = new Set(['.git', '.hg', '.svn', '.DS_Store', '.bin']);

const IOC_MARKERS = [
  'trufflehog',
  'github_token',
  'npm_token',
  'router_runtime',
  'setup.mjs',
  'claude',
  'exfiltrat',
  'process.env',
];

const IOC_CANDIDATES = [
  '.claude/router_runtime.js',
  '.claude/setup.mjs',
  '.vscode/setup.mjs',
  'router_runtime.js',
  'setup.mjs',
  'bun_environment.js',
  '.github/workflows/codeql_analysis.yml',
];

async function scanMachine(options = {}) {
  const locations = options.locations || discoverMachineLocations();
  const packages = dedupePackages(collectMachinePackages(locations, options));
  const binaryMap = collectPackageBinaryMap(packages);
  const findings = matchOffline(packages, binaryMap);
  const iocs = scanMachineIocs();

  let live = { enabled: false, findings: [], error: null };
  if (options.live) {
    live = await queryOsv(packages, { timeoutMs: options.liveTimeoutMs });
    mergeLiveFindings(findings, live.findings || [], binaryMap);
  }

  return {
    machine: os.hostname() || 'local machine',
    home: os.homedir(),
    locations,
    packages,
    findings: dedupeFindings(findings),
    iocs,
    live,
    snapshotDate: SNAPSHOT_DATE,
    advisoryArtifactCount: OFFLINE_ROWS.length,
  };
}

function discoverMachineLocations() {
  const home = os.homedir();
  return dedupeLocations([
    location('npm global', 'node_modules', commandOutput('npm', ['root', '-g'])),
    ...locations('npm cache', 'npm-cache', [
      process.env.npm_config_cache,
      commandOutput('npm', ['config', 'get', 'cache']),
      home && path.join(home, '.npm'),
    ]),
    location('pnpm global', 'node_modules', commandOutput('pnpm', ['root', '-g'])),
    ...locations('pnpm store', 'manifest-store', [
      process.env.PNPM_STORE_PATH,
      commandOutput('pnpm', ['store', 'path']),
      home && path.join(home, 'Library', 'pnpm', 'store'),
      home && path.join(home, '.local', 'share', 'pnpm', 'store'),
      home && path.join(home, '.pnpm-store'),
    ]),
    location('yarn global', 'install-root', commandOutput('yarn', ['global', 'dir'])),
    ...locations('yarn cache', 'yarn-cache', [
      commandOutput('yarn', ['cache', 'dir']),
      home && path.join(home, 'Library', 'Caches', 'Yarn'),
      home && path.join(home, '.cache', 'yarn'),
    ]),
    location('bun global', 'node_modules', home && path.join(home, '.bun', 'install', 'global', 'node_modules')),
    location('bun cache', 'bun-cache', home && path.join(home, '.bun', 'install', 'cache')),
    ...locations('python user site', 'python-site', [
      commandOutput('python3', ['-m', 'site', '--user-site']),
      commandOutput('python', ['-m', 'site', '--user-site']),
    ]),
    location('pipx venvs', 'python-venvs', home && path.join(home, '.local', 'pipx', 'venvs')),
  ]);
}

function collectMachinePackages(locations, options = {}) {
  return locations.flatMap((item) => {
    const scanner = LOCATION_SCANNERS[item.kind];
    return scanner ? scanner(item, options) : [];
  });
}

function scanNodeModulesLocation(locationInfo) {
  return collectNodeModulesPackages(locationInfo.path, locationInfo.label);
}

function scanNpmCacheLocation(locationInfo) {
  return [
    ...collectNpmCacheIndexPackages(locationInfo.path, locationInfo.label),
    ...collectNpxCachePackages(locationInfo.path, locationInfo.label),
  ];
}

function scanInstallRootLocation(locationInfo) {
  return collectInstallRootPackages(locationInfo.path, locationInfo.label);
}

function scanManifestStoreLocation(locationInfo, options = {}) {
  const pnpmIndexPackages = collectPnpmStoreIndexPackages(locationInfo.path, locationInfo.label);
  if (pnpmIndexPackages) return pnpmIndexPackages;

  return collectManifestPackages(locationInfo.path, locationInfo.label, {
    maxBytes: options.maxManifestBytes || MAX_MANIFEST_BYTES,
  });
}

function scanYarnCacheLocation(locationInfo, options = {}) {
  return [
    ...collectManifestPackages(locationInfo.path, locationInfo.label, {
      onlyPackageJson: true,
      maxBytes: options.maxManifestBytes || MAX_MANIFEST_BYTES,
    }),
    ...collectYarnBerryZipPackages(locationInfo.path, locationInfo.label),
  ];
}

function scanBunCacheLocation(locationInfo) {
  return collectBunCacheNamePackages(locationInfo.path, locationInfo.label);
}

function scanPythonSiteLocation(locationInfo) {
  return collectPythonSitePackages(locationInfo.path, locationInfo.label);
}

function scanPythonVenvsLocation(locationInfo) {
  const packages = [];
  for (const venv of safeReaddirEntries(locationInfo.path)) {
    if (!venv.isDirectory()) continue;
    packages.push(...collectPythonVenvPackages(path.join(locationInfo.path, venv.name), locationInfo.label));
  }
  return packages;
}

function collectInstallRootPackages(root, label) {
  const parsed = INSTALL_FILE_PARSERS.flatMap((parser) => parser(root)).map((item) => ({
    ...item,
    source: item.source ? displayPath(path.join(root, item.source)) : displayPath(root),
    location: label,
  }));
  return [
    ...parsed,
    ...collectNodeModulesPackages(path.join(root, 'node_modules'), label),
  ];
}

function collectNodeModulesPackages(modulesRoot, label) {
  const packages = [];
  for (const packageJson of listNodePackageJsonsDeep(modulesRoot)) {
    const info = readJson(packageJson);
    if (!isNpmManifest(info)) continue;
    packages.push(machinePackage('npm', info.name, info.version, label, displayPath(packageJson), {
      bins: binsFromPackageJson(info),
      packageJson: info,
    }));
  }
  return packages;
}

function collectNpxCachePackages(cacheRoot, label) {
  const npxRoot = path.join(cacheRoot, '_npx');
  if (!safeStat(npxRoot).isDirectory()) return [];

  const packages = [];
  for (const entry of safeReaddirEntries(npxRoot)) {
    if (!entry.isDirectory()) continue;
    packages.push(...collectInstallRootPackages(path.join(npxRoot, entry.name), `${label} _npx`));
  }
  return packages;
}

function collectNpmCacheIndexPackages(cacheRoot, label) {
  const cacacheRoot = path.join(cacheRoot, '_cacache');
  if (!safeStat(cacacheRoot).isDirectory()) return [];

  const packages = [];
  for (const entry of safeReaddirEntries(cacacheRoot)) {
    if (!entry.isDirectory() || !/^index-v\d+$/i.test(entry.name)) continue;
    walkFiles(path.join(cacacheRoot, entry.name), (filePath) => {
      for (const line of safeReadText(filePath, 512 * 1024).split(/\r?\n/)) {
        const parsed = npmCacheLinePackage(line);
        if (parsed) packages.push(machinePackage('npm', parsed.name, parsed.version, label, parsed.source));
      }
    });
  }
  return packages;
}

function collectPnpmStoreIndexPackages(storeRoot, label) {
  const indexRoots = [];
  const directIndex = path.join(storeRoot, 'index');
  if (safeStat(directIndex).isDirectory()) indexRoots.push(directIndex);

  for (const entry of safeReaddirEntries(storeRoot)) {
    if (!entry.isDirectory() || !/^v\d+$/i.test(entry.name)) continue;
    const indexRoot = path.join(storeRoot, entry.name, 'index');
    if (safeStat(indexRoot).isDirectory()) indexRoots.push(indexRoot);
  }

  if (!indexRoots.length) return null;

  const packages = [];
  for (const indexRoot of indexRoots) {
    for (const shard of safeReaddirEntries(indexRoot)) {
      if (!shard.isDirectory()) continue;
      const shardPath = path.join(indexRoot, shard.name);
      for (const entry of safeReaddirEntries(shardPath)) {
        if (!entry.isFile() || !entry.name.endsWith('.json')) continue;
        const parsed = pnpmPackageFromIndexName(entry.name);
        if (parsed) {
          packages.push(machinePackage('npm', parsed.name, parsed.version, label, displayPath(path.join(shardPath, entry.name))));
        }
      }
    }
  }
  return packages;
}

function pnpmPackageFromIndexName(fileName) {
  const match = fileName.match(/^[a-f0-9]+-(.+)\.json$/i);
  return match ? npmPackageFromNameVersion(match[1]) : null;
}

function npmCacheLinePackage(line) {
  const tab = line.indexOf('\t');
  if (tab === -1) return null;

  const record = safeJsonParse(line.slice(tab + 1));
  if (!record) return null;

  const tarball = npmPackageFromTarballUrl(record.key) || npmPackageFromTarballUrl(record.metadata && record.metadata.url);
  return tarball ? { ...tarball, source: tarball.url } : null;
}

function npmPackageFromTarballUrl(value) {
  if (!value || typeof value !== 'string' || !value.includes('.tgz')) return null;

  let url;
  try {
    url = new URL(value.startsWith('http') ? value : value.slice(value.indexOf('http')));
  } catch {
    return null;
  }

  const segments = url.pathname.split('/').filter(Boolean).map(decodeUrlSegment);
  const dashIndex = segments.findIndex((segment) => segment === '-');
  if (dashIndex <= 0 || dashIndex >= segments.length - 1) return null;

  const name = segments.slice(0, dashIndex).join('/');
  const version = versionFromTarballName(segments[segments.length - 1]);
  if (!version || !isValidNpmPackageName(name)) return null;

  return { name, version, url: url.href };
}

function versionFromTarballName(fileName) {
  const match = fileName.match(/-(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\.tgz$/);
  return match ? match[1] : null;
}

function collectManifestPackages(root, label, options = {}) {
  const packages = [];
  const maxBytes = options.maxBytes || MAX_MANIFEST_BYTES;

  walkFiles(root, (filePath, entry) => {
    if (options.onlyPackageJson && entry.name !== 'package.json') return;

    const stat = safeStat(filePath);
    if (!stat.isFile() || stat.size <= 2 || stat.size > maxBytes) return;

    const probe = safeReadText(filePath, Math.min(MANIFEST_PROBE_BYTES, maxBytes));
    if (!probe.includes('"name"') || !probe.includes('"version"')) return;

    const text = stat.size <= probe.length ? probe : safeReadText(filePath, maxBytes);
    const info = safeJsonParse(text);
    if (!isNpmManifest(info)) return;

    packages.push(machinePackage('npm', info.name, info.version, label, displayPath(filePath), {
      bins: binsFromPackageJson(info),
      packageJson: info,
    }));
  });

  return packages;
}

function collectYarnBerryZipPackages(cacheRoot, label) {
  const packages = [];
  walkFiles(cacheRoot, (filePath, entry) => {
    if (!entry.name.endsWith('.zip')) return;
    const parsed = yarnBerryPackageFromFilename(entry.name);
    if (parsed) packages.push(machinePackage('npm', parsed.name, parsed.version, label, displayPath(filePath)));
  });
  return packages;
}

function yarnBerryPackageFromFilename(fileName) {
  const match = fileName.match(/^(.+)-npm-(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)-[a-z0-9]+\.zip$/i);
  if (!match) return null;

  const name = match[1].startsWith('@') ? yarnScopedName(match[1]) : match[1];
  if (!name || !isValidNpmPackageName(name)) return null;

  return { name, version: match[2] };
}

function yarnScopedName(cacheName) {
  const parts = cacheName.slice(1).split('-');
  return parts.length < 2 ? null : `@${parts[0]}/${parts.slice(1).join('-')}`;
}

function collectBunCacheNamePackages(cacheRoot, label) {
  const packages = [];
  const seen = new Set();

  for (const entry of safeReaddirEntries(cacheRoot)) {
    if (!entry.isDirectory()) continue;
    const entryPath = path.join(cacheRoot, entry.name);
    addBunCachePackage(packages, seen, entry.name, entryPath, label);

    for (const child of safeReaddirEntries(entryPath)) {
      if (!child.isDirectory()) continue;
      const childPath = path.join(entryPath, child.name);
      addBunCachePackage(packages, seen, `${entry.name}/${child.name}`, childPath, label);

      if (!entry.name.startsWith('@')) continue;
      for (const versionEntry of safeReaddirEntries(childPath)) {
        if (!versionEntry.isDirectory()) continue;
        addBunCachePackage(packages, seen, `${entry.name}/${child.name}/${versionEntry.name}`, path.join(childPath, versionEntry.name), label);
      }
    }
  }
  return packages;
}

function addBunCachePackage(packages, seen, cacheName, sourcePath, label) {
  const parsed = bunPackageFromCacheName(cacheName);
  if (!parsed) return;

  const key = packageKey('npm', parsed.name, parsed.version);
  if (seen.has(key)) return;
  seen.add(key);
  packages.push(machinePackage('npm', parsed.name, parsed.version, label, displayPath(sourcePath)));
}

function collectPythonVenvPackages(venvRoot, label) {
  const packages = [];
  const libRoot = path.join(venvRoot, 'lib');
  for (const pythonDir of safeReaddirEntries(libRoot)) {
    if (!pythonDir.isDirectory() || !pythonDir.name.startsWith('python')) continue;
    packages.push(...collectPythonSitePackages(path.join(libRoot, pythonDir.name, 'site-packages'), label));
  }
  return packages;
}

function collectPythonSitePackages(siteRoot, label) {
  const packages = [];
  walkFiles(siteRoot, (filePath, entry) => {
    if (entry.name !== 'METADATA' && entry.name !== 'PKG-INFO') return;
    const normalized = filePath.split(path.sep).join('/');
    if (!normalized.includes('.dist-info/') && !normalized.includes('.egg-info/')) return;

    const info = parsePythonPackageMetadata(safeReadText(filePath, 512 * 1024));
    if (info) packages.push(machinePackage('pypi', info.name, info.version, label, displayPath(filePath)));
  });
  return packages;
}

function parsePythonPackageMetadata(text) {
  const name = text.match(/^Name:\s*(.+)$/mi);
  const version = text.match(/^Version:\s*(.+)$/mi);
  if (!name || !version) return null;
  return { name: name[1].trim(), version: version[1].trim() };
}

function bunPackageFromCacheName(name) {
  return npmPackageFromNameVersion(name.replace(/@@@\d+$/i, ''));
}

function npmPackageFromNameVersion(value) {
  const decoded = value.replace(/%2f/ig, '/');
  const slash = decoded.lastIndexOf('/');
  if (slash > 0) {
    const name = normalizeEncodedNpmName(decoded.slice(0, slash));
    const version = decoded.slice(slash + 1);
    if (isValidNpmPackageName(name) && isSemverish(version)) return { name, version };
  }

  const at = decoded.lastIndexOf('@');
  if (at <= 0) return null;

  const name = normalizeEncodedNpmName(decoded.slice(0, at));
  const version = decoded.slice(at + 1);
  if (!isValidNpmPackageName(name) || !isSemverish(version)) return null;
  return { name, version };
}

function normalizeEncodedNpmName(name) {
  if (name.startsWith('@') && name.includes('+')) return name.replace('+', '/');
  return name;
}

function listNodePackageJsonsDeep(modulesRoot) {
  const result = [];
  const seenModules = new Set();
  const seenPackages = new Set();

  function visitNodeModules(dir) {
    const real = safeRealpath(dir);
    if (!real || seenModules.has(real)) return;
    seenModules.add(real);

    for (const entry of safeReaddirEntries(dir)) {
      const fullPath = path.join(dir, entry.name);
      if (!isDirectoryLike(entry, fullPath) || entry.name === '.bin' || entry.name.startsWith('.cache')) continue;

      if (entry.name.startsWith('@')) {
        visitScope(fullPath);
        continue;
      }

      visitPackage(fullPath);
    }
  }

  function visitScope(scopeRoot) {
    for (const scoped of safeReaddirEntries(scopeRoot)) {
      const packageRoot = path.join(scopeRoot, scoped.name);
      if (isDirectoryLike(scoped, packageRoot)) visitPackage(packageRoot);
    }
  }

  function visitPackage(packageRoot) {
    const real = safeRealpath(packageRoot);
    if (!real || seenPackages.has(real)) return;
    seenPackages.add(real);

    const packageJson = path.join(packageRoot, 'package.json');
    if (safeStat(packageJson).isFile()) result.push(packageJson);

    const nestedModules = path.join(packageRoot, 'node_modules');
    if (safeStat(nestedModules).isDirectory()) visitNodeModules(nestedModules);
  }

  if (safeStat(modulesRoot).isDirectory()) visitNodeModules(modulesRoot);
  return result;
}

function buildOfflineIndex(rows) {
  const index = new Map();
  for (const row of rows) {
    const key = packageKey(row.ecosystem, row.name, row.version);
    const list = index.get(key) || [];
    list.push(row);
    index.set(key, list);
  }
  return index;
}

function matchOffline(packages, binaryMap) {
  const findings = [];
  for (const item of packages) {
    const rows = OFFLINE_INDEX.get(packageKey(item.ecosystem, item.name, item.version));
    if (!rows) continue;
    for (const row of rows) findings.push(buildFinding(item, row, binaryMap));
  }
  return findings;
}

function mergeLiveFindings(findings, liveFindings, binaryMap) {
  for (const row of liveFindings) findings.push(buildFinding(row, row, binaryMap));
}

function buildFinding(item, advisory, binaryMap) {
  const key = packageKey(item.ecosystem, item.name, item.version);
  const bins = new Set([
    ...(item.bins || []),
    ...(advisory.binaries || []),
    ...(binaryMap.get(key) || []),
  ]);

  return {
    ecosystem: item.ecosystem,
    name: item.name,
    version: item.version,
    locations: item.locations || [item.location].filter(Boolean),
    sources: item.sources || [item.source].filter(Boolean),
    binaries: Array.from(bins).sort(),
    advisory: {
      id: advisory.advisoryId,
      title: advisory.title,
      severity: advisory.severity,
      type: advisory.type,
      source: advisory.source,
      published: advisory.published,
      summary: advisory.summary,
      live: Boolean(advisory.live),
    },
  };
}

function dedupePackages(packages) {
  const merged = new Map();
  for (const item of packages) {
    const key = packageKey(item.ecosystem, item.name, item.version);
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, {
        ...item,
        locations: [item.location].filter(Boolean),
        sources: [item.source].filter(Boolean),
        bins: Array.from(new Set(item.bins || [])),
      });
      continue;
    }

    pushUnique(existing.locations, item.location);
    pushUnique(existing.sources, item.source);
    for (const bin of item.bins || []) pushUnique(existing.bins, bin);
    if (item.packageJson && !existing.packageJson) existing.packageJson = item.packageJson;
  }
  return Array.from(merged.values());
}

function dedupeFindings(findings) {
  const seen = new Set();
  const result = [];

  for (const finding of findings) {
    const key = `${finding.ecosystem}:${finding.name}:${finding.version}:${finding.advisory.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(finding);
  }

  result.sort((a, b) => {
    const aBins = a.binaries.length ? 0 : 1;
    const bBins = b.binaries.length ? 0 : 1;
    if (aBins !== bBins) return aBins - bBins;
    return `${a.ecosystem}:${a.name}`.localeCompare(`${b.ecosystem}:${b.name}`);
  });
  return result;
}

function collectPackageBinaryMap(packages) {
  const map = new Map();
  for (const item of packages) {
    if (item.bins && item.bins.length) map.set(packageKey(item.ecosystem, item.name, item.version), item.bins);
  }
  return map;
}

function scanMachineIocs() {
  const home = os.homedir();
  if (!home) return [];

  const findings = [];
  for (const relativePath of IOC_CANDIDATES) {
    const filePath = path.join(home, relativePath);
    if (!safeStat(filePath).isFile()) continue;

    const lower = safeReadText(filePath, 1024 * 1024).toLowerCase();
    const markerCount = IOC_MARKERS.reduce((count, marker) => count + (lower.includes(marker) ? 1 : 0), 0);
    if (markerCount < 2) continue;

    findings.push({
      path: displayPath(filePath),
      reason: 'File name and contents resemble persistence or credential-exfiltration IOCs from recent npm/PyPI supply-chain campaigns.',
    });
  }
  return findings;
}

function machinePackage(ecosystem, name, version, locationLabel, source, extra = {}) {
  return {
    ecosystem,
    name: ecosystem === 'pypi' ? name.replace(/_/g, '-').toLowerCase() : name,
    version: String(version).trim().replace(/^v/i, ''),
    location: locationLabel,
    source,
    ...extra,
  };
}

function location(label, kind, rawPath) {
  const resolved = normalizePath(rawPath);
  if (!resolved || !safeStat(resolved).isDirectory()) return null;
  return { label, kind, path: resolved };
}

function locations(label, kind, rawPaths) {
  return rawPaths.map((rawPath) => location(label, kind, rawPath)).filter(Boolean);
}

function dedupeLocations(items) {
  const seen = new Set();
  const result = [];

  for (const item of items.filter(Boolean)) {
    const real = safeRealpath(item.path) || item.path;
    const key = `${item.kind}:${real}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(item);
  }

  return result;
}

function commandOutput(command, args) {
  try {
    const output = childProcess.execFileSync(command, args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 2500,
    }).trim();
    return output && output !== 'undefined' && output !== 'null' ? output : null;
  } catch {
    return null;
  }
}

function walkFiles(root, visit) {
  const stack = [root];
  const seen = new Set();

  while (stack.length) {
    const dir = stack.pop();
    const real = safeRealpath(dir);
    if (!real || seen.has(real)) continue;
    seen.add(real);

    for (const entry of safeReaddirEntries(dir)) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!WALK_SKIP_DIRECTORIES.has(entry.name)) stack.push(fullPath);
        continue;
      }
      if (entry.isFile()) visit(fullPath, entry);
    }
  }
}

function isDirectoryLike(entry, fullPath) {
  return entry.isDirectory() || (entry.isSymbolicLink() && safeStat(fullPath).isDirectory());
}

function isNpmManifest(info) {
  return Boolean(
    info &&
    typeof info.name === 'string' &&
    typeof info.version === 'string' &&
    isValidNpmPackageName(info.name) &&
    /^[0-9][0-9A-Za-z.+-]*$/.test(info.version)
  );
}

function isValidNpmPackageName(name) {
  return /^(?:@[A-Za-z0-9._~-]+\/)?[A-Za-z0-9._~-]+$/.test(name);
}

function isSemverish(value) {
  return SEMVERISH_RE.test(value);
}

function packageKey(ecosystem, name, version) {
  return `${String(ecosystem).toLowerCase()}:${String(name).toLowerCase()}:${String(version)}`;
}

function pushUnique(items, item) {
  if (item && !items.includes(item)) items.push(item);
}

function normalizePath(value) {
  if (!value || typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed === 'undefined' || trimmed === 'null') return null;
  if (trimmed.startsWith('~/')) return path.join(os.homedir(), trimmed.slice(2));
  return path.resolve(trimmed);
}

function displayPath(filePath) {
  const home = os.homedir();
  if (home && filePath.startsWith(`${home}${path.sep}`)) return `~/${path.relative(home, filePath).split(path.sep).join('/')}`;
  return filePath.split(path.sep).join('/');
}

function decodeUrlSegment(segment) {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function safeReadText(filePath, maxBytes) {
  let fd = null;
  try {
    fd = fs.openSync(filePath, 'r');
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) return '';

    const length = Math.min(stat.size, maxBytes);
    if (length <= 0) return '';

    const buffer = Buffer.allocUnsafe(length);
    const bytesRead = fs.readSync(fd, buffer, 0, length, 0);
    return buffer.subarray(0, bytesRead).toString('utf8');
  } catch {
    return '';
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {}
    }
  }
}

function safeReaddirEntries(dir) {
  try {
    return fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

function safeRealpath(filePath) {
  try {
    return fs.realpathSync(filePath);
  } catch {
    return null;
  }
}

function safeStat(filePath) {
  try {
    return fs.statSync(filePath);
  } catch {
    return { isFile: () => false, isDirectory: () => false, size: 0 };
  }
}

module.exports = {
  scanMachine,
  discoverMachineLocations,
  collectMachinePackages,
  npmPackageFromTarballUrl,
  packageKey,
};
