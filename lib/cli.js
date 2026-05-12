'use strict';

const path = require('node:path');
const { advisories, SNAPSHOT_DATE, flattenAdvisories } = require('./advisories');
const { scanProject } = require('./scanner');

const APP_NAME = 'amiscrewed';
const DEFAULT_COLOR = process.env.NO_COLOR ? false : process.stdout.isTTY !== false;
const SPINNER_FRAMES = ['-', '\\', '|', '/'];
const SPINNER_MESSAGES = [
  'checking how screwed you are',
  'interrogating lockfiles',
  'asking packages where they were on the night of the incident',
  'checking for poisoned CLIs',
  'looking for suspicious supply-chain glitter',
  'consulting the malware tea leaves',
  'counting tiny red flags',
  'seeing if TanStack is having a normal one',
  'asking OSV for a second opinion',
];

function parseArgs(argv) {
  const args = {
    path: process.cwd(),
    json: false,
    live: true,
    failOn: 'findings',
    listAdvisories: false,
    color: DEFAULT_COLOR,
    timeoutMs: 8000,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') args.help = true;
    else if (arg === '--json') args.json = true;
    else if (arg === '--offline' || arg === '--no-live') args.live = false;
    else if (arg === '--live') args.live = true;
    else if (arg === '--no-color') args.color = false;
    else if (arg === '--color') args.color = true;
    else if (arg === '--list-advisories') args.listAdvisories = true;
    else if (arg === '--fail-on') args.failOn = argv[++index] || 'findings';
    else if (arg.startsWith('--fail-on=')) args.failOn = arg.slice('--fail-on='.length);
    else if (arg === '--timeout-ms') args.timeoutMs = Number(argv[++index] || args.timeoutMs);
    else if (arg.startsWith('--timeout-ms=')) args.timeoutMs = Number(arg.slice('--timeout-ms='.length));
    else if (arg.startsWith('-')) throw new Error(`unknown option: ${arg}`);
    else args.path = arg;
  }

  if (!['findings', 'none'].includes(args.failOn)) {
    throw new Error('--fail-on must be "findings" or "none"');
  }
  if (!Number.isFinite(args.timeoutMs) || args.timeoutMs < 500) {
    throw new Error('--timeout-ms must be a number >= 500');
  }
  return args;
}

async function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    process.stdout.write(helpText());
    return;
  }

  if (args.listAdvisories) {
    const rows = flattenAdvisories();
    const payload = {
      snapshotDate: SNAPSHOT_DATE,
      advisoryCount: advisories.length,
      artifactCount: rows.length,
      advisories,
    };
    process.stdout.write(args.json ? `${JSON.stringify(payload, null, 2)}\n` : formatAdvisoryList(payload, args));
    return;
  }

  const spinner = createSpinner(args);
  spinner.start();
  let result;
  try {
    result = await scanProject(path.resolve(args.path), {
      live: args.live,
      liveTimeoutMs: args.timeoutMs,
    });
    spinner.stop();
  } catch (error) {
    spinner.stop();
    throw error;
  }

  process.stdout.write(args.json ? `${JSON.stringify(result, null, 2)}\n` : formatResult(result, args));

  const hasFindings = result.findings.length > 0 || result.iocs.length > 0;
  if (args.failOn === 'findings' && hasFindings) {
    process.exitCode = 1;
  }
}

function formatResult(result, options = {}) {
  const color = createColor(options.color);
  const binaryCount = result.findings.reduce((count, finding) => count + finding.binaries.length, 0);
  const lines = [];

  lines.push(color.bold('am i screwed?'));
  lines.push(result.findings.length || result.iocs.length
    ? color.red('Looks like something needs attention.')
    : color.green('Not today. No known bad package versions showed up.'));
  lines.push('');
  lines.push(`${color.dim('repo')}      ${result.root}`);
  lines.push(`${color.dim('snapshot')}  ${result.snapshotDate} (${result.advisoryArtifactCount} known package/version artifacts)`);
  if (result.live.enabled) {
    lines.push(result.live.error
      ? `${color.dim('live')}      ${color.yellow(`OSV unavailable: ${result.live.error}`)}`
      : `${color.dim('live')}      OSV checked`);
  } else {
    lines.push(`${color.dim('live')}      disabled`);
  }
  lines.push('');

  if (!result.findings.length && !result.iocs.length) {
    lines.push(color.green('No known supply-chain or AI security package findings were detected.'));
    return `${lines.join('\n')}\n`;
  }

  lines.push(color.bold('Findings'));
  lines.push(`${color.red(String(result.findings.length))} risky package install(s), ${color.yellow(String(binaryCount))} binary command(s), ${color.yellow(String(result.iocs.length))} suspicious IOC file(s)`);
  lines.push('');

  for (const finding of result.findings) {
    const binaries = finding.binaries.length ? finding.binaries.join(', ') : 'none discovered';
    const source = finding.sources && finding.sources.length ? finding.sources.join(', ') : 'unknown';
    lines.push(`${severityColor(finding.advisory.severity, color)(severityLabel(finding.advisory.severity))} ${color.dim(finding.ecosystem)} ${color.bold(`${finding.name}@${finding.version}`)}`);
    lines.push(`  ${color.dim('bins')}     ${finding.binaries.length ? color.yellow(binaries) : color.dim(binaries)}`);
    lines.push(`  ${color.dim('seen in')}  ${source}`);
    lines.push(`  ${color.dim('why')}      ${finding.advisory.id} - ${finding.advisory.title}`);
    lines.push(`  ${color.dim('source')}   ${finding.advisory.source}`);
    lines.push('');
  }

  for (const ioc of result.iocs) {
    lines.push(`${color.red('IOC')} ${color.bold(ioc.path)}`);
    lines.push(`  ${ioc.reason}`);
    lines.push('');
  }

  lines.push(color.bold('Do this next'));
  lines.push('Remove or pin away from the affected version, reinstall from a clean lockfile, rotate exposed credentials, and inspect CI/developer hosts that installed the package.');
  return `${lines.join('\n')}\n`;
}

function formatAdvisoryList(payload, options = {}) {
  const color = createColor(options.color);
  const lines = [
    color.bold(`${APP_NAME} advisory snapshot`),
    `${payload.snapshotDate} - ${payload.advisoryCount} advisories, ${payload.artifactCount} package/version artifacts`,
    '',
  ];
  for (const advisory of payload.advisories) {
    const artifactCount = advisory.packages.reduce((count, item) => count + item.versions.length, 0);
    lines.push(`${color.yellow(advisory.id)} ${advisory.title}`);
    lines.push(`  ${advisory.ecosystem} ${severityColor(advisory.severity, color)(advisory.severity)} ${artifactCount} artifacts`);
    lines.push(`  ${color.dim(advisory.source)}`);
  }
  return `${lines.join('\n')}\n`;
}

function severityLabel(severity) {
  return String(severity || 'unknown').toUpperCase();
}

function severityColor(severity, color) {
  const label = String(severity || '').toLowerCase();
  if (label.includes('critical') || label.includes('high')) return color.red;
  if (label.includes('medium') || label.includes('moderate')) return color.yellow;
  return color.dim;
}

function createColor(enabled = DEFAULT_COLOR) {
  const wrap = (code, value) => enabled ? `\u001b[${code}m${value}\u001b[0m` : String(value);
  return {
    bold: (value) => wrap('1', value),
    dim: (value) => wrap('2', value),
    green: (value) => wrap('32', value),
    red: (value) => wrap('31', value),
    yellow: (value) => wrap('33', value),
  };
}

function createSpinner(options) {
  const enabled = !options.json && process.stderr.isTTY && !process.env.CI;
  if (!enabled) {
    return {
      start() {},
      stop() {},
    };
  }

  const color = createColor(options.color);
  let frameIndex = 0;
  let messageIndex = 0;
  let timer = null;

  function render() {
    const frame = SPINNER_FRAMES[frameIndex % SPINNER_FRAMES.length];
    const message = SPINNER_MESSAGES[messageIndex % SPINNER_MESSAGES.length];
    process.stderr.write(`\r${color.yellow(frame)} ${message}...`);
    frameIndex += 1;
    if (frameIndex % 10 === 0) messageIndex += 1;
  }

  return {
    start() {
      render();
      timer = setInterval(render, 100);
      if (typeof timer.unref === 'function') timer.unref();
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = null;
      process.stderr.write('\r\x1b[2K\n');
    },
  };
}

function helpText() {
  return `Usage: ${APP_NAME} [path]

Find installed packages and binaries tied to known supply-chain attacks or AI security incidents.

Run it in a repo:
  npx ${APP_NAME}

Optional:
  ${APP_NAME} /path/to/repo
  ${APP_NAME} --help

Privacy: the live OSV check sends package names and versions from discovered lockfiles to api.osv.dev.
Set NO_COLOR=1 to disable colors.
`;
}

module.exports = {
  main,
  parseArgs,
  formatResult,
};
