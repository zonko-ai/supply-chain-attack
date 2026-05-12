'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { scanMachine, npmPackageFromTarballUrl } = require('../lib/scanner');
const { parseArgs, formatResult, formatEducation, formatNextActions } = require('../lib/cli');

test('detects a compromised globally installed npm CLI package and resolves its binary', async () => {
  const root = makeTempRepo();
  const modulesRoot = path.join(root, 'node_modules');
  const pkgRoot = path.join(modulesRoot, '@rspack', 'cli');
  fs.mkdirSync(path.join(pkgRoot, 'bin'), { recursive: true });
  writeJson(path.join(pkgRoot, 'package.json'), {
    name: '@rspack/cli',
    version: '1.1.7',
    bin: { rspack: 'bin/rspack.js' },
  });
  fs.writeFileSync(path.join(pkgRoot, 'bin', 'rspack.js'), '#!/usr/bin/env node\n');

  const result = await scanMachine({
    live: false,
    locations: [{ label: 'npm global', kind: 'node_modules', path: modulesRoot }],
  });

  const finding = result.findings.find((item) => item.name === '@rspack/cli');
  assert.ok(finding);
  assert.equal(finding.version, '1.1.7');
  assert.deepEqual(finding.locations, ['npm global']);
  assert.deepEqual(finding.binaries, ['rspack']);
});

test('skips oversized package manifests instead of reading them', async () => {
  const root = makeTempRepo();
  const modulesRoot = path.join(root, 'node_modules');
  const pkgRoot = path.join(modulesRoot, '@rspack', 'cli');
  fs.mkdirSync(pkgRoot, { recursive: true });
  fs.writeFileSync(path.join(pkgRoot, 'package.json'), JSON.stringify({
    name: '@rspack/cli',
    version: '1.1.7',
    padding: 'x'.repeat(1024 * 1024),
  }));

  const result = await scanMachine({
    live: false,
    locations: [{ label: 'npm global', kind: 'node_modules', path: modulesRoot }],
  });

  assert.equal(result.findings.length, 0);
});

test('detects symlinked packages in pnpm-style global node_modules', async () => {
  const root = makeTempRepo();
  const storePkg = path.join(root, 'store', '@tanstack', 'store');
  fs.mkdirSync(storePkg, { recursive: true });
  writeJson(path.join(storePkg, 'package.json'), {
    name: '@tanstack/store',
    version: '0.8.0',
  });

  const modulesRoot = path.join(root, 'node_modules', '@tanstack');
  fs.mkdirSync(modulesRoot, { recursive: true });
  fs.symlinkSync(storePkg, path.join(modulesRoot, 'store'), 'dir');

  const result = await scanMachine({
    live: false,
    locations: [{ label: 'pnpm global', kind: 'node_modules', path: path.join(root, 'node_modules') }],
  });

  const finding = result.findings.find((item) => item.name === '@tanstack/store');
  assert.ok(finding);
  assert.deepEqual(finding.locations, ['pnpm global']);
});

test('detects scoped affected packages from npm cache tarball records', async () => {
  const root = makeTempRepo();
  const indexDir = path.join(root, '_cacache', 'index-v5', 'aa', 'bb');
  fs.mkdirSync(indexDir, { recursive: true });
  fs.writeFileSync(path.join(indexDir, 'entry'), [
    'hash\t{"key":"make-fetch-happen:request-cache:https://registry.npmjs.org/@tanstack%2frouter-generator/-/router-generator-1.166.4.tgz"}',
    '',
  ].join('\n'));

  const result = await scanMachine({
    live: false,
    locations: [{ label: 'npm cache', kind: 'npm-cache', path: root }],
  });

  const finding = result.findings.find((item) => item.name === '@tanstack/router-generator');
  assert.ok(finding);
  assert.equal(finding.version, '1.166.4');
  assert.deepEqual(finding.locations, ['npm cache']);
});

test('detects packages installed under the npm npx cache', async () => {
  const root = makeTempRepo();
  const npxRoot = path.join(root, '_npx', 'abc123');
  writeJson(path.join(npxRoot, 'package-lock.json'), {
    lockfileVersion: 3,
    packages: {
      '': { dependencies: { '@tanstack/store': '0.8.0' } },
      'node_modules/@tanstack/store': { version: '0.8.0' },
    },
  });

  const result = await scanMachine({
    live: false,
    locations: [{ label: 'npm cache', kind: 'npm-cache', path: root }],
  });

  const finding = result.findings.find((item) => item.name === '@tanstack/store');
  assert.ok(finding);
  assert.equal(finding.version, '0.8.0');
  assert.deepEqual(finding.locations, ['npm cache _npx']);
});

test('detects packages from content-addressed package stores by manifest', async () => {
  const root = makeTempRepo();
  fs.mkdirSync(path.join(root, 'files', 'aa'), { recursive: true });
  writeJson(path.join(root, 'files', 'aa', 'manifest'), {
    name: '@tanstack/store',
    version: '0.8.0',
  });

  const result = await scanMachine({
    live: false,
    locations: [{ label: 'pnpm store', kind: 'manifest-store', path: root }],
  });

  const finding = result.findings.find((item) => item.name === '@tanstack/store');
  assert.ok(finding);
  assert.equal(finding.version, '0.8.0');
  assert.deepEqual(finding.locations, ['pnpm store']);
});

test('detects pnpm store packages from the fast index', async () => {
  const root = makeTempRepo();
  const indexRoot = path.join(root, 'v10', 'index', '3a');
  fs.mkdirSync(indexRoot, { recursive: true });
  fs.writeFileSync(path.join(indexRoot, 'abc123-@tanstack+store@0.8.0.json'), '{}\n');

  const result = await scanMachine({
    live: false,
    locations: [{ label: 'pnpm store', kind: 'manifest-store', path: root }],
  });

  const finding = result.findings.find((item) => item.name === '@tanstack/store');
  assert.ok(finding);
  assert.equal(finding.version, '0.8.0');
  assert.deepEqual(finding.locations, ['pnpm store']);
});

test('detects Bun cache packages from cache directory names', async () => {
  const root = makeTempRepo();
  fs.mkdirSync(path.join(root, '@tanstack', 'store', '0.8.0@@@1'), { recursive: true });

  const result = await scanMachine({
    live: false,
    locations: [{ label: 'bun cache', kind: 'bun-cache', path: root }],
  });

  const finding = result.findings.find((item) => item.name === '@tanstack/store');
  assert.ok(finding);
  assert.equal(finding.version, '0.8.0');
  assert.deepEqual(finding.locations, ['bun cache']);
});

test('detects affected Python packages from site-packages metadata', async () => {
  const root = makeTempRepo();
  const distInfo = path.join(root, 'lightning-2.6.3.dist-info');
  fs.mkdirSync(distInfo, { recursive: true });
  fs.writeFileSync(path.join(distInfo, 'METADATA'), 'Name: lightning\nVersion: 2.6.3\n');

  const result = await scanMachine({
    live: false,
    locations: [{ label: 'python user site', kind: 'python-site', path: root }],
  });

  const finding = result.findings.find((item) => item.name === 'lightning');
  assert.ok(finding);
  assert.equal(finding.ecosystem, 'pypi');
  assert.deepEqual(finding.locations, ['python user site']);
});

test('parses npm tarball URLs for scoped packages', () => {
  assert.deepEqual(
    npmPackageFromTarballUrl('https://registry.npmjs.org/@rspack%2fcli/-/cli-1.1.7.tgz'),
    {
      name: '@rspack/cli',
      version: '1.1.7',
      url: 'https://registry.npmjs.org/@rspack%2fcli/-/cli-1.1.7.tgz',
    },
  );
});

test('keeps clean machine locations quiet', async () => {
  const root = makeTempRepo();
  const modulesRoot = path.join(root, 'node_modules', 'lodash');
  fs.mkdirSync(modulesRoot, { recursive: true });
  writeJson(path.join(modulesRoot, 'package.json'), {
    name: 'lodash',
    version: '4.17.21',
  });

  const result = await scanMachine({
    live: false,
    locations: [{ label: 'npm global', kind: 'node_modules', path: path.join(root, 'node_modules') }],
  });

  assert.equal(result.findings.length, 0);
  assert.equal(result.iocs.length, 0);
});

test('parses CLI defaults for a machine scan', () => {
  const args = parseArgs(['--json', '--fail-on=none', '--no-interactive']);
  assert.equal(args.json, true);
  assert.equal(args.failOn, 'none');
  assert.equal(args.interactive, false);
});

test('rejects live mode because the CLI is offline-only for now', () => {
  assert.throws(() => parseArgs(['--live']), /unknown option: --live/);
});

test('rejects path arguments because the command is machine-only', () => {
  assert.throws(() => parseArgs(['.']), /always scans this machine/);
});

test('formats human report with compact verdict and privacy-safe evidence', () => {
  const report = formatResult({
    machine: 'test-machine',
    home: '/tmp/home',
    locations: [
      { label: 'npm global' },
      { label: 'npm cache _npx' },
    ],
    packages: [{}, {}, {}],
    findings: [{
      ecosystem: 'npm',
      name: 'zod-to-json-schema',
      version: '3.25.1',
      locations: ['npm global', 'npm cache _npx'],
      sources: [
        '/very/long/path/one/node_modules/zod-to-json-schema/package.json',
        '/very/long/path/two/node_modules/zod-to-json-schema/package.json',
      ],
      binaries: [],
      advisory: {
        id: 'SOCKET-mini-shai-hulud-expansion-2026-05',
        title: 'Mini Shai-Hulud expansion into AI/devtool ecosystem packages',
        severity: 'critical',
        source: 'https://socket.dev/supply-chain-attacks/mini-shai-hulud',
      },
    }],
    iocs: [],
    snapshotDate: '2026-05-12',
    advisoryArtifactCount: 438,
  }, { color: false });

  assert.match(report, /Verdict: YOU MIGHT BE FUCKED, BRO/);
  assert.doesNotMatch(report, /^amifucked/m);
  assert.match(report, /1 package hit/);
  assert.doesNotMatch(report, /skull receipt/);
  assert.doesNotMatch(report, /Share this without doxxing your machine/);
  assert.match(report, /The shit that pinged/);
  assert.match(report, /zod-to-json-schema@3\.25\.1/);
  assert.doesNotMatch(report, /Mini Shai-Hulud/);
  assert.doesNotMatch(report, /╭|╰|│/);
  assert.doesNotMatch(report, /privacy:/);
  assert.doesNotMatch(report, /hiding in:/);
  assert.doesNotMatch(report, /worst:/);
  assert.doesNotMatch(report, /CRITICAL npm/);
  assert.doesNotMatch(report, /machine\s+test-machine/);
  assert.doesNotMatch(report, /home\s+\/tmp\/home/);
  assert.doesNotMatch(report, /seen in/);
  assert.doesNotMatch(report, /\/very\/long\/path/);
});

test('education groups related advisories and explains the attack chain', () => {
  const education = formatEducation(sampleMiniShaiHuludResult(), { color: false });

  assert.equal((education.match(/Mini Shai-Hulud attack/g) || []).length, 1);
  assert.match(education, /Attack chain:/);
  assert.match(education, /Attackers got access to trusted package publishing credentials/);
  assert.match(education, /payload hunts for developer secrets/);
  assert.match(education, /@tanstack\/store@0\.8\.0/);
  assert.match(education, /zod-to-json-schema@3\.25\.1/);
  assert.doesNotMatch(education, /Multiple related advisories matched/);
});

test('next actions prints a copy-paste agent prompt with cleanup commands', () => {
  const actions = formatNextActions(sampleMiniShaiHuludResult(), { color: false });

  assert.match(actions, /copy\/paste this into your agent/);
  assert.match(actions, /```text/);
  assert.match(actions, /npm cache clean --force/);
  assert.match(actions, /rm -rf ~\/\.npm\/_npx/);
  assert.match(actions, /Do not print secrets/);
  assert.doesNotMatch(actions, /Share this without doxxing your machine/);
});

function sampleMiniShaiHuludResult() {
  return {
    machine: 'test-machine',
    home: '/tmp/home',
    locations: [{ label: 'pnpm store' }, { label: 'npm cache _npx' }],
    packages: [{}, {}, {}, {}],
    findings: [
      {
        ecosystem: 'npm',
        name: '@tanstack/store',
        version: '0.8.0',
        locations: ['pnpm store'],
        sources: ['/very/long/path/store/package.json'],
        binaries: [],
        advisory: {
          id: 'GHSA-g7cv-rxg3-hmpx',
          title: 'TanStack npm packages compromised in Mini Shai-Hulud',
          severity: 'critical',
          source: 'https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx',
          summary: 'A compromised npm token published malicious versions of 42 TanStack packages containing credential exfiltration behavior.',
        },
      },
      {
        ecosystem: 'npm',
        name: 'zod-to-json-schema',
        version: '3.25.1',
        locations: ['npm global', 'npm cache _npx'],
        sources: ['/very/long/path/zod-to-json-schema/package.json'],
        binaries: [],
        advisory: {
          id: 'SOCKET-mini-shai-hulud-expansion-2026-05',
          title: 'Mini Shai-Hulud expansion into AI/devtool ecosystem packages',
          severity: 'critical',
          source: 'https://socket.dev/supply-chain-attacks/mini-shai-hulud',
          summary: 'Socket and Snyk reporting showed the Mini Shai-Hulud wave expanding into Mistral, UiPath, Squawk, OpenSearch and related packages.',
        },
      },
    ],
    iocs: [],
    snapshotDate: '2026-05-12',
    advisoryArtifactCount: 438,
  };
}

function makeTempRepo() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'amifcked-test-'));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}
