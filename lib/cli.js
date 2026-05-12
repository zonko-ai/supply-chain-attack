'use strict';

const readline = require('node:readline/promises');
const { advisories, SNAPSHOT_DATE, flattenAdvisories } = require('./advisories');
const { scanMachine } = require('./scanner');

const APP_NAME = 'amifcked';
const APP_FACE = [
  '        .-\"\"\"\"-.',
  '      .\'  _    _  \'.',
  '     /   (o)  (o)   \\',
  '    |       ____       |',
  '    |     .\'    \'.     |',
  '     \\    \`----\`    /',
  '      \'.          .\'',
  '        \`-......-\`'
].join('\n');
const DEFAULT_COLOR = process.env.NO_COLOR ? false : process.stdout.isTTY !== false;
const SPINNER_FRAMES = ['-', '\\', '|', '/'];
const SPINNER_MESSAGES = [
  'scanning local package-manager state',
  'checking package-manager caches',
  'checking global installs',
  'checking for poisoned CLIs',
  'checking known risky package versions',
  'checking suspicious local files',
];

const SEVERITY_RANK = {
  critical: 5,
  high: 4,
  medium: 3,
  moderate: 3,
  low: 2,
  info: 1,
  unknown: 0,
};

function parseArgs(argv) {
  const args = {
    json: false,
    failOn: 'findings',
    listAdvisories: false,
    color: DEFAULT_COLOR,
    interactive: true,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') args.help = true;
    else if (arg === '--json') args.json = true;
    else if (arg === '--no-color') args.color = false;
    else if (arg === '--color') args.color = true;
    else if (arg === '--no-interactive') args.interactive = false;
    else if (arg === '--interactive') args.interactive = true;
    else if (arg === '--list-advisories') args.listAdvisories = true;
    else if (arg === '--fail-on') args.failOn = argv[++index] || 'findings';
    else if (arg.startsWith('--fail-on=')) args.failOn = arg.slice('--fail-on='.length);
    else if (arg.startsWith('-')) throw new Error(`unknown option: ${arg}`);
    else throw new Error(`path arguments are not supported; ${APP_NAME} always scans this machine`);
  }

  if (!['findings', 'none'].includes(args.failOn)) {
    throw new Error('--fail-on must be "findings" or "none"');
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
    result = await scanMachine();
    spinner.stop();
  } catch (error) {
    spinner.stop();
    throw error;
  }

  process.stdout.write(args.json ? `${JSON.stringify(result, null, 2)}\n` : formatResult(result, args));
  if (!args.json) await runInteractive(result, args);

  const hasFindings = result.findings.length > 0 || result.iocs.length > 0;
  if (args.failOn === 'findings' && hasFindings) {
    process.exitCode = 1;
  }
}

function formatResult(result, options = {}) {
  const color = createColor(options.color);
  const hasFindings = hasAnyFindings(result);
  const lines = [];

  lines.push(formatVerdictHeader(result, options));
  lines.push('');

  if (!hasFindings) {
    lines.push(color.bold('Tiny reality check'));
    lines.push('No known bad package versions were found in the scanned package-manager state. That is good. It is not a full malware exorcism.');
    lines.push('');
    lines.push(`${color.dim('scan')} ${result.locations.length} store(s), ${result.packages.length} package/version pair(s), snapshot ${result.snapshotDate}`);
    return `${lines.join('\n')}\n`;
  }

  lines.push(color.red(color.bold('The shit that pinged')));
  for (const finding of result.findings.slice(0, 8)) {
    const locations = finding.locations.length ? formatCompactList(finding.locations, 3) : 'unknown location';
    lines.push(`- ${color.dim(finding.ecosystem)} ${color.yellow(color.bold(`${finding.name}@${finding.version}`))} ${color.dim('(')}${color.cyan(locations)}${color.dim(')')}`);
  }
  if (result.findings.length > 8) lines.push(`- ...and ${pluralize(result.findings.length - 8, 'more package hit')}. Run with --json for raw evidence.`);

  if (result.iocs.length) {
    lines.push('');
    lines.push(color.bold('Suspicious local files'));
    for (const ioc of result.iocs.slice(0, 5)) {
      lines.push(`- ${color.red('IOC')} ${color.bold(ioc.path)} — ${ioc.reason}`);
    }
    if (result.iocs.length > 5) lines.push(`- ...and ${pluralize(result.iocs.length - 5, 'more suspicious file')}.`);
  }

  lines.push('');
  lines.push(`${color.dim('scan')} ${result.locations.length} store(s), ${result.packages.length} package/version pair(s), snapshot ${result.snapshotDate}`);
  if (!interactiveCanRun(options)) {
    lines.push(`${color.dim('tip')} run in a real terminal for the interactive menu, or use --json for raw paths.`);
  }

  return `${lines.join('\n')}\n`;
}

async function runInteractive(result, options = {}) {
  if (!interactiveCanRun(options)) return;

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    process.stdout.write('\n');
    while (true) {
      const answer = (await rl.question(formatPrompt(options))).trim().toLowerCase();
      if (!answer || answer === 'q' || answer === 'quit' || answer === 'exit') {
        process.stdout.write('Done. Stay safe.\n');
        break;
      }

      if (answer === '1' || answer === 'e' || answer.includes('educate')) {
        process.stdout.write(`\n${formatEducation(result, options)}\n`);
        continue;
      }

      if (answer === '2' || answer === 'a' || answer.includes('action') || answer.includes('next')) {
        process.stdout.write(`\n${formatNextActions(result, options)}\n`);
        continue;
      }

      process.stdout.write('Try e, a, or q.\n');
    }
  } finally {
    rl.close();
  }
}

function formatPrompt(options = {}) {
  const color = createColor(options.color);
  return [
    color.dim('more?'),
    `${color.cyan('e')} explain`,
    `${color.cyan('a')} actions`,
    `${color.dim('q quit')}`,
    color.bold('› '),
  ].join('  ');
}

function formatVerdictHeader(result, options = {}) {
  const color = createColor(options.color);
  const hasFindings = hasAnyFindings(result);
  const findingCount = result.findings.length;
  const iocCount = result.iocs.length;
  const countLabel = hasFindings
    ? `${pluralize(findingCount, 'package hit')}${iocCount ? ` + ${pluralize(iocCount, 'suspicious file')}` : ''}`
    : '0 known bad hits';

  const verdict = hasFindings
    ? `${color.dim('Verdict:')} ${color.red(color.bold('YOU ARE FUCKED!!'))} — ${color.yellow(color.bold(countLabel))}`
    : `${color.dim('Verdict:')} ${color.green(color.bold('YOU ARE NOT FUCKED'))} — ${color.green(countLabel)}`;

  return `${APP_FACE}\n${verdict}`;
}

function formatEducation(result, options = {}) {
  const color = createColor(options.color);
  const lines = [color.bold('Education mode: what the hell did I just find?')];

  if (!hasAnyFindings(result)) {
    lines.push('No known bad package versions matched the embedded advisory snapshot. That means the scanned package-manager state did not contain the specific versions amifcked knows about.');
    lines.push('It does NOT prove this machine is malware-free. Supply-chain attacks move fast, caches can be weird, and clean snapshots are not force fields.');
    lines.push('The good news: this scan is offline and privacy-safe. Your package list was not uploaded anywhere.');
    return `${lines.join('\n')}\n`;
  }

  const groups = groupFindingsByCampaign(result.findings);
  for (const group of groups) {
    const packages = formatCompactList(group.findings.map((finding) => `${finding.name}@${finding.version}`), 7);
    const locations = formatCompactList(group.findings.flatMap((finding) => finding.locations || []), 5) || 'unknown location';
    const receipts = formatCompactList(group.advisories.map((advisory) => advisory.source), 3);

    lines.push('');
    lines.push(color.bold(`${group.name} attack`));
    lines.push('Attack chain:');
    for (const step of attackExplanation(group)) lines.push(`- ${step}`);
    lines.push(`Your match: ${packages} showed up in ${locations}.`);
    lines.push(`Risk read: ${riskSentence(group.findings)}`);
    lines.push('Translation: cache/store means "this package was present"; global, npx, pipx, or CLI hits mean "this may have executed". Do not treat either as harmless until you inspect active projects.');
    if (receipts) lines.push(`Receipts: ${receipts}`);
  }

  if (result.iocs.length) {
    lines.push('');
    lines.push(`${color.red('IOC')} ${color.bold('Suspicious local-file indicators')}`);
    lines.push('These file names and contents resemble persistence or credential-exfiltration leftovers from recent supply-chain campaigns. That is not cute. Inspect them before deleting so you understand what changed.');
  }

  return `${lines.join('\n')}\n`;
}

function formatNextActions(result, options = {}) {
  const color = createColor(options.color);
  const lines = [color.bold('Next actions: copy/paste this into your agent')];

  lines.push('');
  lines.push('```text');
  lines.push(...buildAgentPrompt(result));
  lines.push('```');

  return `${lines.join('\n')}\n`;
}

function buildAgentPrompt(result) {
  const lines = [];

  if (!hasAnyFindings(result)) {
    lines.push(`I ran \`npx ${APP_NAME}\` on my dev machine. It found 0 known malware-linked package hits in ${result.packages.length} package/version pairs.`);
    lines.push('');
    lines.push('Please help me keep this project safer:');
    lines.push(`1. Add or document a lightweight supply-chain check: \`npx ${APP_NAME} --fail-on findings\`.`);
    lines.push('2. Verify lockfiles are committed and package-manager versions are pinned where practical.');
    lines.push('3. Warn me before adding one-off npx/global CLI installs.');
    lines.push('4. Do not print, store, or ask for secrets.');
    return lines;
  }

  const labels = new Set(result.findings.flatMap((finding) => finding.locations || []));
  const riskyExecution = Array.from(labels).some((label) => /global|_npx|node_modules|python|pipx/i.test(label));
  const commands = cleanupCommands(labels);

  lines.push(`I ran \`npx ${APP_NAME}\` on my dev machine and it flagged possible supply-chain malware exposure.`);
  lines.push('');
  lines.push('Scan summary:');
  lines.push(`- Worst severity: ${worstSeverity(result)}`);
  lines.push(`- Campaigns: ${campaignSummary(result, 5)}`);
  lines.push(`- Risk read: ${riskyExecution ? 'global/npx/CLI-style hit; package code may have installed or run' : 'cache/store hit; package was fetched or stored, execution not proven'}`);
  lines.push('');
  lines.push('Flagged packages/locations:');
  for (const finding of result.findings.slice(0, 12)) {
    const locations = formatCompactList(finding.locations || [], 4) || 'unknown location';
    lines.push(`- ${finding.ecosystem} ${finding.name}@${finding.version} (${campaignName(finding.advisory)}; ${locations})`);
  }
  if (result.findings.length > 12) lines.push(`- ...plus ${pluralize(result.findings.length - 12, 'more package hit')}`);

  if (result.iocs.length) {
    lines.push('');
    lines.push('Suspicious local files:');
    for (const ioc of result.iocs.slice(0, 8)) lines.push(`- ${ioc.path}: ${ioc.reason}`);
    if (result.iocs.length > 8) lines.push(`- ...plus ${pluralize(result.iocs.length - 8, 'more suspicious file')}`);
  }

  lines.push('');
  lines.push('Please help me clean this safely:');
  lines.push('1. Search this repo/workspace lockfiles, manifests, and install scripts for the exact packages/versions above.');
  lines.push('2. If any are present in the project, remove/upgrade them and reinstall from a clean lockfile.');
  lines.push('3. Run or ask me to run these cleanup commands:');
  for (const command of commands) lines.push(`   ${command}`);
  lines.push(`4. Re-run: npx ${APP_NAME}`);
  lines.push(`5. If raw evidence paths are needed, ask me to run: npx ${APP_NAME} --json`);
  if (riskyExecution) {
    lines.push('6. Help me rotate GitHub, npm, cloud, AI-provider, CI/CD, registry, and deploy tokens that may have lived on this machine. Do not print secrets.');
  } else {
    lines.push('6. Treat cache/store hits as evidence of presence, not proof of execution, but still inspect active projects before dismissing.');
  }
  lines.push('');
  lines.push('Rules: explain each change before destructive cleanup, do not delete unfamiliar files blindly, and never echo/exfiltrate/store secrets.');

  return lines;
}

function cleanupCommands(locationLabels) {
  const labels = Array.from(locationLabels).join(' ').toLowerCase();
  const commands = [];
  if (/npm/.test(labels)) {
    commands.push('npm cache clean --force');
    if (/_npx/.test(labels)) commands.push('rm -rf ~/.npm/_npx');
  }
  if (/pnpm/.test(labels)) commands.push('pnpm store prune');
  if (/yarn/.test(labels)) commands.push('yarn cache clean');
  if (/bun/.test(labels)) commands.push('bun pm cache rm');
  if (/python|pipx/.test(labels)) commands.push('python -m pip cache purge  # if supported by your pip');
  if (!commands.length) commands.push('# clear the listed cache/store for the package manager that pinged');
  return Array.from(new Set(commands));
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

function formatCompactList(values, limit = 5) {
  const list = Array.from(new Set(values.filter(Boolean)));
  if (list.length <= limit) return list.join(', ');
  return `${list.slice(0, limit).join(', ')}, +${list.length - limit} more`;
}

function pluralize(count, singular) {
  return `${count} ${singular}${count === 1 ? '' : 's'}`;
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
    cyan: (value) => wrap('36', value),
    magenta: (value) => wrap('35', value),
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
  return `Usage: ${APP_NAME}

Scan this machine's package-manager state for packages and binaries tied to known supply-chain attacks or AI security incidents.

It always scans local machine locations such as npm global installs, npm cache/_npx, pnpm global/store, yarn global/cache, bun global/cache, and Python user/pipx environments when present.

Optional:
  ${APP_NAME} --json
  ${APP_NAME} --list-advisories
  ${APP_NAME} --no-interactive

Text output shows a compact verdict. In a real terminal, an interactive menu can explain the attack chain or print a copy/paste cleanup prompt.

Set NO_COLOR=1 to disable colors.
`;
}

function interactiveCanRun(options = {}) {
  return Boolean(options.interactive && !options.json && process.stdin.isTTY && process.stdout.isTTY && !process.env.CI);
}

function hasAnyFindings(result) {
  return Boolean((result.findings && result.findings.length) || (result.iocs && result.iocs.length));
}

function worstSeverity(result) {
  let worst = result.iocs && result.iocs.length ? 'critical' : 'unknown';
  for (const finding of result.findings || []) {
    const severity = String(finding.advisory && finding.advisory.severity || 'unknown').toLowerCase();
    if ((SEVERITY_RANK[severity] || 0) > (SEVERITY_RANK[worst] || 0)) worst = severity;
  }
  return severityLabel(worst);
}

function campaignSummary(result, limit = 3) {
  const campaigns = (result.findings || []).map((finding) => campaignName(finding.advisory));
  if (result.iocs && result.iocs.length) campaigns.push('local-file IOC');
  return formatCompactList(campaigns, limit) || 'unknown';
}

function campaignName(advisory = {}) {
  const text = `${advisory.title || ''} ${advisory.id || ''}`.toLowerCase();
  if (text.includes('mini shai-hulud')) return 'Mini Shai-Hulud';
  if (text.includes('canisterworm')) return 'CanisterWorm';
  if (text.includes('canistersprawl')) return 'CanisterSprawl';
  if (text.includes('axios')) return 'Axios/plain-crypto-js';
  if (text.includes('rspack')) return 'Rspack compromise';
  if (text.includes('nx') || text.includes('s1ngularity')) return 'Nx s1ngularity';
  return advisory.id || advisory.title || 'unknown campaign';
}

function attackExplanation(group) {
  const name = group.name || '';
  const lower = name.toLowerCase();

  if (lower.includes('mini shai-hulud')) {
    return [
      'Attackers got access to trusted package publishing credentials, then shipped poisoned versions of packages developers already trust.',
      'Those poisoned versions can run during install, npx/global usage, or normal devtool execution depending on the package path.',
      'The payload hunts for developer secrets: npm tokens, GitHub tokens, cloud credentials, CI/CD tokens, and AI-provider keys.',
      'The goal is credential exfiltration first, then more supply-chain access if stolen tokens can publish or deploy elsewhere.',
      'Some variants also drop local tooling files for persistence, so the machine can keep leaking after the first install.',
    ];
  }

  if (lower.includes('canisterworm')) {
    return [
      'Attackers poisoned AI/devtool packages that developers are likely to run locally or in automation.',
      'The malicious code looks for credentials and tokens on the machine or in CI.',
      'The worm angle is that stolen publishing or repo access can be used to compromise more packages/projects.',
      'Treat this as a developer-machine and project-supply-chain problem, not just a vulnerable library problem.',
    ];
  }

  if (lower.includes('canistersprawl')) {
    return [
      'Attackers published fake packages with names that look like real AI, MCP, cloud, or devtool SDKs.',
      'The trick is brand confusion: a developer installs the believable fake package and runs attacker code.',
      'Once installed, the package can steal local tokens, environment variables, config files, or registry credentials.',
      'The fix is to remove the fake package and verify the intended official package name before reinstalling anything.',
    ];
  }

  if (lower.includes('axios')) {
    return [
      'A trusted package release path was compromised and pulled in a malicious dependency.',
      'That dependency could run at install time, before your application ever imports axios directly.',
      'The payload behavior is about executing code on developer or CI machines, where secrets often live.',
      'This is why lockfile review matters: a familiar top-level package can smuggle a malicious transitive dependency.',
    ];
  }

  if (lower.includes('rspack')) {
    return [
      'Attackers shipped malicious Rspack releases into the npm ecosystem.',
      'Because Rspack is a build/devtool package, the dangerous path is install scripts or CLI execution on developer and CI machines.',
      'That kind of access can expose source code, registry tokens, deploy tokens, and environment secrets.',
      'If the hit came from npx or a global install, treat it as possible execution, not just a downloaded tarball.',
    ];
  }

  if (lower.includes('nx')) {
    return [
      'Attackers published malicious Nx-related versions into a widely used developer-tooling supply chain.',
      'Developer tools are high-value because they run in repos, terminals, and CI with broad filesystem and environment access.',
      'The payload class is credential theft: grab tokens/config from the machine, then use them to reach more projects or registries.',
      'If Nx was installed globally, via npx, or in CI, assume the blast radius may include more than one repo.',
    ];
  }

  return [
    'A package version on this machine matches a known malicious or supply-chain advisory in the embedded snapshot.',
    'The risky part is not “your app imported a vulnerable function”; it is that package installation or CLI execution can run attacker code.',
    'That attacker code may read environment variables, local config files, tokens, lockfiles, and project metadata.',
    'Use the package names and locations below to decide whether this was just cached or may have executed.',
  ];
}

function riskSentence(findings) {
  const locations = findings.flatMap((finding) => finding.locations || []);
  const labels = locations.join(' ').toLowerCase();
  const hasBins = findings.some((finding) => finding.binaries && finding.binaries.length);

  if (/_npx|global|pipx/.test(labels) || hasBins) {
    return 'Hot. global/npx/CLI hits mean package code may have installed or run on this machine.';
  }
  if (/cache|store/.test(labels)) {
    return 'Medium-hot. cache/store hits prove the package was fetched or stored here, not necessarily executed.';
  }
  return 'Unknown-hot. The scanner found a matching package/version, but execution risk depends on how it got there.';
}

function groupFindingsByCampaign(findings) {
  const groups = new Map();
  for (const finding of findings || []) {
    const advisory = finding.advisory || {};
    const key = campaignName(advisory);
    if (!groups.has(key)) groups.set(key, { name: key, advisory, advisories: [], findings: [] });
    const group = groups.get(key);
    group.findings.push(finding);
    if (!group.advisories.some((item) => item.id === advisory.id)) group.advisories.push(advisory);
    if (severityRank(advisory.severity) > severityRank(group.advisory.severity)) group.advisory = advisory;
  }
  return Array.from(groups.values()).sort((a, b) => severityRank(groupSeverity(b)) - severityRank(groupSeverity(a)));
}

function groupSeverity(group) {
  let worst = 'unknown';
  for (const advisory of group.advisories || []) {
    if (severityRank(advisory.severity) > severityRank(worst)) worst = String(advisory.severity || 'unknown').toLowerCase();
  }
  return worst;
}

function severityRank(severity) {
  return SEVERITY_RANK[String(severity || 'unknown').toLowerCase()] || 0;
}

module.exports = {
  main,
  parseArgs,
  formatResult,
  formatEducation,
  formatNextActions,
};
