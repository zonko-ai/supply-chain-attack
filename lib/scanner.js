'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { flattenAdvisories } = require('./advisories');
const { queryOsv } = require('./live-osv');
const {
  parsePackageLock,
  parseShrinkwrap,
  parsePackageJson,
  parseYarnLock,
  parsePnpmLock,
  parseRequirements,
  parsePoetryLock,
  parseComposerLock,
  parseNodeModules,
} = require('./parsers');

const OFFLINE_ROWS = flattenAdvisories();
const OFFLINE_INDEX = buildOfflineIndex(OFFLINE_ROWS);

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

async function scanProject(root, options = {}) {
  const targetRoot = path.resolve(root || process.cwd());
  const packages = dedupePackages(collectPackages(targetRoot));
  const binaryMap = collectNpmBinaryMap(targetRoot, packages);
  const findings = matchOffline(packages, binaryMap);
  const iocs = scanIocs(targetRoot);

  let live = { enabled: false, findings: [], error: null };
  if (options.live) {
    live = await queryOsv(packages, { timeoutMs: options.liveTimeoutMs });
    mergeLiveFindings(findings, live.findings || [], binaryMap);
  }

  return {
    root: targetRoot,
    snapshotDate: require('./advisories').SNAPSHOT_DATE,
    packages,
    findings: dedupeFindings(findings),
    iocs,
    live,
    advisoryArtifactCount: OFFLINE_ROWS.length,
  };
}

function collectPackages(root) {
  const parsers = [
    parsePackageLock,
    parseShrinkwrap,
    parsePackageJson,
    parseYarnLock,
    parsePnpmLock,
    parseRequirements,
    parsePoetryLock,
    parseComposerLock,
    parseNodeModules,
  ];
  return parsers.flatMap((parser) => parser(root));
}

function dedupePackages(packages) {
  const merged = new Map();
  for (const item of packages) {
    const key = packageKey(item.ecosystem, item.name, item.version);
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, {
        ...item,
        sources: [item.source].filter(Boolean),
        bins: Array.from(new Set(item.bins || [])),
      });
      continue;
    }
    if (item.source && !existing.sources.includes(item.source)) existing.sources.push(item.source);
    for (const bin of item.bins || []) {
      if (!existing.bins.includes(bin)) existing.bins.push(bin);
    }
    if (item.packageJson && !existing.packageJson) existing.packageJson = item.packageJson;
  }
  return Array.from(merged.values());
}

function matchOffline(packages, binaryMap) {
  const findings = [];
  for (const item of packages) {
    const rows = OFFLINE_INDEX.get(packageKey(item.ecosystem, item.name, item.version));
    if (!rows) continue;
    for (const row of rows) {
      findings.push(buildFinding(item, row, binaryMap));
    }
  }
  return findings;
}

function mergeLiveFindings(findings, liveFindings, binaryMap) {
  for (const row of liveFindings) {
    findings.push(buildFinding(row, row, binaryMap));
  }
}

function buildFinding(item, advisory, binaryMap) {
  const bins = new Set([
    ...(item.bins || []),
    ...(advisory.binaries || []),
    ...(binaryMap.get(packageKey(item.ecosystem, item.name, item.version)) || []),
  ]);
  return {
    ecosystem: item.ecosystem,
    name: item.name,
    version: item.version,
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

function collectNpmBinaryMap(root, packages) {
  const map = new Map();
  for (const item of packages) {
    if (item.ecosystem !== 'npm' || !item.bins || !item.bins.length) continue;
    map.set(packageKey(item.ecosystem, item.name, item.version), item.bins);
  }

  const binDir = path.join(root, 'node_modules', '.bin');
  if (!fs.existsSync(binDir)) return map;
  for (const binName of safeReaddir(binDir)) {
    if (/\.(cmd|ps1)$/i.test(binName)) continue;
    const binPath = path.join(binDir, binName);
    const real = safeRealpath(binPath);
    if (!real) continue;
    const packageName = packageNameFromInstalledPath(real);
    if (!packageName) continue;
    for (const item of packages) {
      if (item.ecosystem !== 'npm' || item.name !== packageName) continue;
      const key = packageKey(item.ecosystem, item.name, item.version);
      const bins = new Set(map.get(key) || []);
      bins.add(binName);
      map.set(key, Array.from(bins));
    }
  }
  return map;
}

function packageNameFromInstalledPath(filePath) {
  const normalized = filePath.split(path.sep).join('/');
  const marker = '/node_modules/';
  const index = normalized.lastIndexOf(marker);
  if (index === -1) return null;
  const tail = normalized.slice(index + marker.length);
  const parts = tail.split('/');
  if (parts[0] && parts[0].startsWith('@')) return `${parts[0]}/${parts[1]}`;
  return parts[0] || null;
}

function scanIocs(root) {
  const findings = [];
  for (const relativePath of IOC_CANDIDATES) {
    const filePath = path.join(root, relativePath);
    if (!fs.existsSync(filePath) || !safeStat(filePath).isFile()) continue;
    const text = safeReadText(filePath, 1024 * 1024);
    const lower = text.toLowerCase();
    const markerCount = IOC_MARKERS.reduce((count, marker) => count + (lower.includes(marker) ? 1 : 0), 0);
    if (markerCount < 2) continue;
    findings.push({
      path: relativePath,
      reason: 'File name and contents resemble persistence or credential-exfiltration IOCs from recent npm/PyPI supply-chain campaigns.',
    });
  }
  return findings;
}

function packageKey(ecosystem, name, version) {
  return `${String(ecosystem).toLowerCase()}:${String(name).toLowerCase()}:${String(version)}`;
}

function safeReaddir(dir) {
  try {
    return fs.readdirSync(dir);
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
    return { isFile: () => false };
  }
}

function safeReadText(filePath, maxBytes) {
  try {
    const buffer = fs.readFileSync(filePath);
    return buffer.subarray(0, maxBytes).toString('utf8');
  } catch {
    return '';
  }
}

module.exports = {
  scanProject,
  collectPackages,
  collectNpmBinaryMap,
  packageKey,
};
