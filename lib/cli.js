'use strict';

const readline = require('node:readline/promises');
const { advisories, SNAPSHOT_DATE, flattenAdvisories } = require('./advisories');
const { scanMachine } = require('./scanner');

const APP_NAME = 'supply-chain-attack';
const COPY = {
  noFindingTitle: 'Summary',
  noFindingBody: 'No known malicious package versions were found in the scanned package-manager state. This is not a complete malware assessment.',
  findingsTitle: 'Matched packages',
  promptPrefix: 'options',
  findingVerdict: 'Potential supply-chain exposure detected',
  cleanVerdict: 'No known bad packages found',
  educationTitle: 'Learn: how to read this scan',
  noMatchExplanation: 'No known malicious package versions matched the embedded advisory snapshot. This means the scanned package-manager state did not contain the specific versions currently known to this tool.',
  noGuarantee: 'It does not prove this machine is malware-free. Supply-chain attacks evolve quickly, and local package-manager state can be incomplete.',
  iocWarning: 'These file names and contents resemble persistence or credential-exfiltration indicators from recent supply-chain campaigns. Inspect them before deleting so you understand what changed.',
  nextActionsTitle: 'Recommended next actions',
};
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

  const hasFindings = result.findings.length > 0 || result.iocs.length > 0 || (result.suspiciousScripts && result.suspiciousScripts.length > 0);
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
    lines.push(color.bold(COPY.noFindingTitle));
    lines.push(COPY.noFindingBody);
    lines.push('');
    lines.push(...formatRecentAttackSummary(result, options));
    lines.push('');
    lines.push(`${color.dim('scan')} ${result.locations.length} store(s), ${result.packages.length} package/version pair(s), snapshot ${result.snapshotDate}`);
    return `${lines.join('\n')}\n`;
  }

  lines.push(...formatRecentAttackSummary(result, options));

  const additionalFindings = findingsOutsideRecentAttacks(result.findings || []);
  if (additionalFindings.length) {
    lines.push('');
    lines.push(color.red(color.bold('Additional matched packages')));
    for (const finding of additionalFindings.slice(0, 8)) {
      const locations = finding.locations.length ? formatCompactList(finding.locations, 3) : 'unknown location';
      lines.push(`- ${color.dim(finding.ecosystem)} ${color.yellow(`${finding.name}@${finding.version}`)} ${color.dim('(')}${color.cyan(locations)}${color.dim(')')}`);
    }
    if (additionalFindings.length > 8) lines.push(`- ...and ${pluralize(additionalFindings.length - 8, 'more package hit')}. Run with --json for raw evidence.`);
  }

  if (result.iocs.length) {
    lines.push('');
    lines.push(color.bold('Suspicious local files'));
    for (const ioc of result.iocs.slice(0, 5)) {
      lines.push(`- ${color.red('IOC')} ${color.bold(ioc.path)} — ${ioc.reason}`);
    }
    if (result.iocs.length > 5) lines.push(`- ...and ${pluralize(result.iocs.length - 5, 'more suspicious file')}.`);
  }

  lines.push('');
  lines.push(color.bold('Packages with postinstall curl'));
  if (result.suspiciousScripts && result.suspiciousScripts.length) {
    for (const script of result.suspiciousScripts.slice(0, 10)) {
      const locations = script.locations && script.locations.length ? formatCompactList(script.locations, 3) : 'unknown location';
      const evidence = script.evidenceFiles && script.evidenceFiles.length ? ` -> ${formatCompactList(script.evidenceFiles, 2)}` : '';
      lines.push(`- ${color.dim(script.ecosystem)} ${color.yellow(`${script.name}@${script.version}`)} ${color.dim('(')}${color.cyan(locations)}${color.dim(')')} ${color.dim(script.command)}${color.dim(evidence)}`);
    }
    if (result.suspiciousScripts.length > 10) lines.push(`- ...and ${pluralize(result.suspiciousScripts.length - 10, 'more install-script hit')}. Run with --json for raw evidence.`);
  } else {
    lines.push('none');
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

      if (answer === '1' || answer === 'l' || answer === 'e' || answer.includes('learn') || answer.includes('educate') || answer.includes('explain')) {
        process.stdout.write(`\n${formatEducation(result, options)}\n`);
        continue;
      }

      if (answer === '2' || answer === 'a' || answer.includes('action') || answer.includes('next')) {
        process.stdout.write(`\n${formatNextActions(result, options)}\n`);
        continue;
      }

      process.stdout.write('Try l, a, or q.\n');
    }
  } finally {
    rl.close();
  }
}

function formatPrompt(options = {}) {
  const color = createColor(options.color);
  return [
    color.dim(COPY.promptPrefix),
    `${color.cyan('l')} learn`,
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
  const scriptCount = result.suspiciousScripts && result.suspiciousScripts.length || 0;
  const countParts = [pluralize(findingCount, 'package hit')];
  if (iocCount) countParts.push(pluralize(iocCount, 'suspicious file'));
  if (scriptCount) countParts.push(pluralize(scriptCount, 'install-script hit'));
  const countLabel = hasFindings ? countParts.join(' + ') : '0 known bad hits';

  const verdict = hasFindings
    ? `${color.dim('Verdict:')} ${color.red(color.bold(COPY.findingVerdict))} — ${color.yellow(color.bold(countLabel))}`
    : `${color.dim('Verdict:')} ${color.green(color.bold(COPY.cleanVerdict))} — ${color.green(countLabel)}`;

  return verdict;
}

function formatEducation(result, options = {}) {
  const color = createColor(options.color);
  const lines = [color.bold('Learn: attacks explained')];
  const recent = recentAdvisories(4);

  recent.forEach((advisory, index) => {
    const hits = (result.findings || []).filter((finding) => finding.advisory && finding.advisory.id === advisory.id);
    const artifactCount = (advisory.packages || []).reduce((count, item) => count + (item.versions || []).length, 0);

    if (index > 0) lines.push('');
    lines.push(color.yellow(`${index + 1}. ${advisory.title}`));
    lines.push(`Published: ${advisory.published}`);
    lines.push(advisory.summary);
    lines.push(`Affected package/version artifacts tracked: ${artifactCount}`);

    if (!hits.length) {
      const clean = !hasAnyFindings(result);
      const message = clean ? 'Nice. You do not have affected packages from this attack.' : 'No affected packages from this attack.';
      lines.push(clean ? color.green(message) : color.dim(message));
    }
  });

  if (result.iocs && result.iocs.length) {
    lines.push('');
    lines.push(`${color.red('IOC')} ${color.bold('Suspicious local-file indicators')}`);
    lines.push(COPY.iocWarning);
  }

  if (result.suspiciousScripts && result.suspiciousScripts.length) {
    lines.push('');
    lines.push(`${color.yellow('SCRIPT')} ${color.bold('postinstall scripts invoking curl')}`);
    lines.push('These are not automatically malicious, but install-time network fetches are risky. Inspect the command, package source, and whether the package is still needed.');
  }

  return `${lines.join('\n')}\n`;
}

function formatRecentAttackSummary(result, options = {}) {
  const color = createColor(options.color);
  const recent = recentAdvisories(4);
  const [latest, ...previous] = recent;
  const lines = [];

  if (latest) {
    lines.push(color.bold('LATEST ATTACK'));
    lines.push(`${color.yellow(latest.title)} ${color.dim(`(${latest.published})`)}`);
    lines.push(...formatAttackHitLines(latest, result, color));
  }

  if (previous.length) {
    lines.push('');
    lines.push(color.bold('Previous attacks'));
    previous.forEach((advisory, index) => {
      if (index > 0) lines.push('');
      lines.push(`${index + 1}. ${color.yellow(advisory.title)} ${color.dim(`(${advisory.published})`)}`);
      lines.push(...formatAttackHitLines(advisory, result, color));
    });
  }

  return lines;
}

function formatAttackHitLines(advisory, result, color) {
  const hits = (result.findings || []).filter((finding) => finding.advisory && finding.advisory.id === advisory.id);
  if (!hits.length) {
    const clean = !hasAnyFindings(result);
    const message = clean ? 'Nice. You do not have affected packages from this attack.' : 'No affected packages from this attack.';
    return [clean ? color.green(message) : color.dim(message)];
  }

  const lines = [color.red(`Affected: ${pluralize(hits.length, 'package')}`), color.bold('Libraries you had:')];
  for (const finding of hits.slice(0, 6)) {
    const locations = formatCompactList(finding.locations || [], 3) || 'unknown location';
    lines.push(`- ${color.dim(finding.ecosystem)} ${color.yellow(`${finding.name}@${finding.version}`)} ${color.dim('(')}${color.cyan(locations)}${color.dim(')')}`);
  }
  if (hits.length > 6) lines.push(`- ...and ${pluralize(hits.length - 6, 'more package hit')}`);
  return lines;
}

function findingsOutsideRecentAttacks(findings) {
  const recentIds = new Set(recentAdvisories(4).map((advisory) => advisory.id));
  return findings.filter((finding) => !finding.advisory || !recentIds.has(finding.advisory.id));
}

function recentAdvisories(limit) {
  return [...advisories]
    .sort((a, b) => String(b.published || '').localeCompare(String(a.published || '')))
    .slice(0, limit);
}

function formatNextActions(result, options = {}) {
  const color = createColor(options.color);
  const lines = [color.bold(COPY.nextActionsTitle)];

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

  const labels = new Set([
    ...(result.findings || []).flatMap((finding) => finding.locations || []),
    ...(result.suspiciousScripts || []).flatMap((script) => script.locations || []),
  ]);
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
  for (const finding of (result.findings || []).slice(0, 12)) {
    const locations = formatCompactList(finding.locations || [], 4) || 'unknown location';
    lines.push(`- ${finding.ecosystem} ${finding.name}@${finding.version} (${campaignName(finding.advisory)}; ${locations})`);
  }
  if ((result.findings || []).length > 12) lines.push(`- ...plus ${pluralize(result.findings.length - 12, 'more package hit')}`);

  if (result.suspiciousScripts && result.suspiciousScripts.length) {
    lines.push('');
    lines.push('Packages with postinstall curl scripts:');
    for (const script of result.suspiciousScripts.slice(0, 12)) {
      const locations = formatCompactList(script.locations || [], 4) || 'unknown location';
      const evidence = script.evidenceFiles && script.evidenceFiles.length ? ` -> ${formatCompactList(script.evidenceFiles, 3)}` : '';
      lines.push(`- ${script.ecosystem} ${script.name}@${script.version} (${locations}): ${script.command}${evidence}`);
    }
    if (result.suspiciousScripts.length > 12) lines.push(`- ...plus ${pluralize(result.suspiciousScripts.length - 12, 'more install-script hit')}`);
  }

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
  // Muted Material-inspired palette: minimal, lower saturation, still readable
  // on dark terminals, while respecting NO_COLOR.
  const palette = {
    red: '210;96;112',
    yellow: '198;128;92',
    green: '150;176;128',
    cyan: '112;164;178',
    magenta: '158;132;176',
    dim: '102;116;128',
  };
  const wrap = (code, value) => enabled ? `\u001b[${code}m${value}\u001b[0m` : String(value);
  const rgb = (name, value) => wrap(`38;2;${palette[name]}`, value);
  return {
    bold: (value) => wrap('1', value),
    dim: (value) => rgb('dim', value),
    green: (value) => rgb('green', value),
    red: (value) => rgb('red', value),
    yellow: (value) => rgb('yellow', value),
    cyan: (value) => rgb('cyan', value),
    magenta: (value) => rgb('magenta', value),
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

Text output shows a compact verdict. In a real terminal, an interactive menu can teach what the attack means or print a copy/paste cleanup prompt.

Set NO_COLOR=1 to disable colors.
`;
}

function interactiveCanRun(options = {}) {
  return Boolean(options.interactive && !options.json && process.stdin.isTTY && process.stdout.isTTY && !process.env.CI);
}

function hasAnyFindings(result) {
  return Boolean(
    (result.findings && result.findings.length) ||
    (result.iocs && result.iocs.length) ||
    (result.suspiciousScripts && result.suspiciousScripts.length)
  );
}

function worstSeverity(result) {
  let worst = (result.iocs && result.iocs.length) || (result.suspiciousScripts && result.suspiciousScripts.length) ? 'critical' : 'unknown';
  for (const finding of result.findings || []) {
    const severity = String(finding.advisory && finding.advisory.severity || 'unknown').toLowerCase();
    if ((SEVERITY_RANK[severity] || 0) > (SEVERITY_RANK[worst] || 0)) worst = severity;
  }
  return severityLabel(worst);
}

function campaignSummary(result, limit = 3) {
  const campaigns = (result.findings || []).map((finding) => campaignName(finding.advisory));
  if (result.iocs && result.iocs.length) campaigns.push('local-file IOC');
  if (result.suspiciousScripts && result.suspiciousScripts.length) campaigns.push('postinstall curl heuristic');
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
      'Attackers obtained publishing access for packages developers already trusted, then released poisoned versions under legitimate package names.',
      'During install or CLI execution, the malicious package gets the same local access as your package manager: repo files, shell environment, home-directory config, and registry credentials.',
      'The payload class is credential theft: npm tokens, GitHub tokens, cloud keys, CI/CD secrets, deploy tokens, and AI-provider keys are the high-value targets.',
      'Stolen tokens are then useful for a second wave: publishing more poisoned packages, reading private repos, modifying CI, or deploying attacker-controlled code.',
      'Some waves also leave behind helper files or persistence-style artifacts, which is why local-file IOCs are treated separately from package hits.',
    ];
  }

  if (lower.includes('canisterworm')) {
    return [
      'Attackers targeted AI/devtool packages because developers run them from terminals, agents, and automation with broad permissions.',
      'The malicious code searches the machine or CI environment for credentials, tokens, project metadata, and registry access.',
      'The worm behavior comes from reuse of stolen access: a compromised token can publish more malware or reach additional repos and packages.',
      'Treat this as both a machine incident and a project supply-chain incident; removing one package is not enough if secrets were exposed.',
    ];
  }

  if (lower.includes('canistersprawl')) {
    return [
      'Attackers published fake packages with names that resemble real AI, MCP, cloud, or devtool SDKs.',
      'The trick is dependency confusion by branding: the name looks plausible enough that a developer, agent, or script installs it.',
      'After installation, the package can read environment variables, config files, registry credentials, SSH/Git settings, or cloud tokens available to the current user.',
      'The fix is to remove the fake package, verify the exact official package name from the vendor, then reinstall from a clean lockfile if needed.',
    ];
  }

  if (lower.includes('axios')) {
    return [
      'A trusted package release path was compromised and a malicious dependency entered through an otherwise familiar package chain.',
      'Install-time code can run before your application imports anything, so “we never called it” is not a safe dismissal.',
      'The valuable target is the install environment: developer laptops and CI often contain registry tokens, GitHub tokens, cloud keys, and deployment credentials.',
      'This is why lockfile review matters: a safe-looking top-level dependency can smuggle an attacker-controlled transitive package.',
    ];
  }

  if (lower.includes('rspack')) {
    return [
      'Attackers shipped malicious Rspack releases into the npm ecosystem under names developers expect to use for builds.',
      'Build tools are high impact because they run in source repos and CI, exactly where source code and deployment credentials are available.',
      'The dangerous path is install-time script execution, npx/global CLI execution, or CI build execution with attacker code in the dependency tree.',
      'If the hit came from npx or a global install, treat it as likely execution until you prove otherwise from shell history, CI logs, and project lockfiles.',
    ];
  }

  if (lower.includes('nx')) {
    return [
      'Attackers published malicious Nx-related versions into a widely used developer-tooling supply chain.',
      'Developer tools are high value because they run inside repos, terminals, and CI with broad filesystem and environment access.',
      'The payload class is credential theft and reconnaissance: grab tokens/config, identify projects, then use access to reach more repos, packages, or pipelines.',
      'If Nx was installed globally, via npx, or in CI, assume the blast radius may include more than one repo until token usage and CI history are reviewed.',
    ];
  }

  return [
    'A package version on this machine matches a known malicious or supply-chain advisory in the embedded snapshot.',
    'The risky part is not “your app imported a vulnerable function”; package installation, postinstall hooks, or CLI execution can run attacker code first.',
    'That attacker code may read environment variables, local config files, tokens, lockfiles, source files, and project metadata.',
    'Use the exact package names, versions, and locations below to decide whether this was only fetched into a cache or likely executed in a project/CLI/CI context.',
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

function locationMeaning(findings) {
  const locations = findings.flatMap((finding) => finding.locations || []);
  const labels = locations.join(' ').toLowerCase();
  const hasBins = findings.some((finding) => finding.binaries && finding.binaries.length);
  const meanings = [];

  if (/cache|store/.test(labels)) meanings.push('cache/store = package artifact was present locally; it may have been downloaded as part of install resolution, but this alone does not prove execution');
  if (/_npx/.test(labels)) meanings.push('npx cache = a one-off CLI install path; treat as likely executed or intended to execute');
  if (/global|pipx/.test(labels) || hasBins) meanings.push('global/pipx/binary = command-line tooling was installed; assume it could have run with your user permissions');
  if (/node_modules|python user site/.test(labels)) meanings.push('project/user environment = inspect lockfiles, install logs, and recent shell/CI history for actual use');

  return meanings.length ? meanings.join('; ') : 'the scanner can identify the package/version, but you need local context to determine whether it executed';
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
  formatRecentAttackSummary,
  formatNextActions,
};
