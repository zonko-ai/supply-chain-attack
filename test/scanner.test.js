'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { scanProject } = require('../lib/scanner');
const { parseArgs } = require('../lib/cli');

test('detects a compromised npm CLI package and resolves its binary', async () => {
  const root = makeTempRepo();
  writeJson(path.join(root, 'package-lock.json'), {
    lockfileVersion: 3,
    packages: {
      '': { dependencies: { '@rspack/cli': '1.1.7' } },
      'node_modules/@rspack/cli': { version: '1.1.7' },
    },
  });
  const pkgRoot = path.join(root, 'node_modules', '@rspack', 'cli');
  fs.mkdirSync(path.join(pkgRoot, 'bin'), { recursive: true });
  writeJson(path.join(pkgRoot, 'package.json'), {
    name: '@rspack/cli',
    version: '1.1.7',
    bin: { rspack: 'bin/rspack.js' },
  });
  fs.writeFileSync(path.join(pkgRoot, 'bin', 'rspack.js'), '#!/usr/bin/env node\n');
  fs.mkdirSync(path.join(root, 'node_modules', '.bin'), { recursive: true });
  fs.symlinkSync(path.join('..', '@rspack', 'cli', 'bin', 'rspack.js'), path.join(root, 'node_modules', '.bin', 'rspack'));

  const result = await scanProject(root, { live: false });

  const finding = result.findings.find((item) => item.name === '@rspack/cli');
  assert.ok(finding);
  assert.equal(finding.version, '1.1.7');
  assert.deepEqual(finding.binaries, ['rspack']);
});

test('detects the TanStack Mini Shai-Hulud package versions from package-lock', async () => {
  const root = makeTempRepo();
  writeJson(path.join(root, 'package-lock.json'), {
    lockfileVersion: 3,
    packages: {
      '': { dependencies: { '@tanstack/router-generator': '1.166.4' } },
      'node_modules/@tanstack/router-generator': { version: '1.166.4' },
    },
  });

  const result = await scanProject(root, { live: false });

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].advisory.id, 'GHSA-g7cv-rxg3-hmpx');
});

test('detects compromised transitive packages in nested npm lock paths', async () => {
  const root = makeTempRepo();
  writeJson(path.join(root, 'package-lock.json'), {
    lockfileVersion: 3,
    packages: {
      '': { dependencies: { wrapper: '1.0.0' } },
      'node_modules/wrapper': { version: '1.0.0' },
      'node_modules/wrapper/node_modules/@tanstack/router-generator': { version: '1.166.4' },
    },
  });

  const result = await scanProject(root, { live: false });

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].name, '@tanstack/router-generator');
});

test('detects AI/PyPI supply-chain packages in requirements files', async () => {
  const root = makeTempRepo();
  fs.writeFileSync(path.join(root, 'requirements.txt'), 'lightning==2.6.3\nrequests==2.32.3\n');

  const result = await scanProject(root, { live: false });

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ecosystem, 'pypi');
  assert.equal(result.findings[0].name, 'lightning');
});

test('pnpm parser ignores importer dependency noise and inline snapshot objects', async () => {
  const root = makeTempRepo();
  fs.writeFileSync(path.join(root, 'pnpm-lock.yaml'), [
    'lockfileVersion: 9.0',
    '',
    'importers:',
    '  .:',
    '    dependencies:',
    '      "@tanstack/store":',
    '        specifier: 0.8.0',
    '        version: 0.8.0',
    '      local-link:',
    '        specifier: link:trpc/server/adapters/ws',
    '        version: link:trpc/server/adapters/ws',
    '',
    'packages:',
    "  '@tanstack/store@0.8.0':",
    '    resolution: {integrity: sha512-example}',
    '',
    'snapshots:',
    "  '@tanstack/store@0.8.0': {}",
    '',
  ].join('\n'));

  const result = await scanProject(root, { live: false });

  const names = result.packages.map((item) => `${item.name}@${item.version}`);
  assert.deepEqual(names, ['@tanstack/store@0.8.0']);
  assert.equal(result.findings.length, 1);
});

test('keeps clean repos quiet', async () => {
  const root = makeTempRepo();
  writeJson(path.join(root, 'package.json'), {
    dependencies: {
      lodash: '4.17.21',
    },
  });

  const result = await scanProject(root, { live: false });

  assert.equal(result.findings.length, 0);
  assert.equal(result.iocs.length, 0);
});

test('parses CLI defaults', () => {
  const args = parseArgs(['--json', '--offline', '--fail-on=none', '.']);
  assert.equal(args.json, true);
  assert.equal(args.live, false);
  assert.equal(args.failOn, 'none');
  assert.equal(args.path, '.');
});

function makeTempRepo() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'amiscrewed-test-'));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}
