'use strict';

const MALICIOUS_KEYWORDS = [
  'malware',
  'malicious',
  'supply chain',
  'supply-chain',
  'compromise',
  'compromised',
  'credential',
  'exfiltrat',
  'trojan',
  'backdoor',
  'worm',
  'typosquat',
  'dependency confusion',
  'postinstall',
  'remote access trojan',
];

const ECOSYSTEMS = new Map([
  ['npm', 'npm'],
  ['pypi', 'PyPI'],
  ['packagist', 'Packagist'],
]);

async function queryOsv(packages, options = {}) {
  if (typeof fetch !== 'function') {
    return { enabled: false, findings: [], error: 'Node fetch is unavailable' };
  }

  const queries = [];
  const packageByQuery = [];
  const seen = new Set();
  for (const item of packages) {
    const ecosystem = ECOSYSTEMS.get(item.ecosystem);
    if (!ecosystem || !item.name || !item.version) continue;
    const key = `${ecosystem}:${item.name}:${item.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    queries.push({ package: { ecosystem, name: item.name }, version: item.version });
    packageByQuery.push(item);
  }

  if (!queries.length) return { enabled: true, findings: [], error: null };

  const timeoutMs = options.timeoutMs || 8000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ queries }),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`OSV returned HTTP ${response.status}`);
    const body = await response.json();
    const findings = [];
    for (let index = 0; index < (body.results || []).length; index += 1) {
      const vulns = body.results[index].vulns || [];
      for (const vuln of vulns) {
        if (!isSupplyChainOrAiSecurity(vuln)) continue;
        findings.push(toLiveFinding(packageByQuery[index], vuln));
      }
    }
    return { enabled: true, findings, error: null };
  } catch (error) {
    return { enabled: true, findings: [], error: error.message || String(error) };
  } finally {
    clearTimeout(timer);
  }
}

function isSupplyChainOrAiSecurity(vuln) {
  const text = [
    vuln.id,
    ...(vuln.aliases || []),
    vuln.summary,
    vuln.details,
    ...(vuln.references || []).map((reference) => reference.url),
  ].filter(Boolean).join('\n').toLowerCase();

  if ((vuln.id || '').startsWith('MAL-')) return true;
  if (/\b(ai|llm|mcp|agent|model)\b/.test(text) && /\b(security|vulnerab|injection|exfiltrat|credential|rce|malicious)\b/.test(text)) {
    return true;
  }
  return MALICIOUS_KEYWORDS.some((keyword) => text.includes(keyword));
}

function toLiveFinding(item, vuln) {
  const firstReference = (vuln.references || []).find((reference) => reference.url);
  return {
    advisoryId: vuln.id,
    title: vuln.summary || vuln.id,
    severity: severityFromDatabaseSpecific(vuln),
    type: 'live-osv',
    source: firstReference ? firstReference.url : `https://osv.dev/vulnerability/${vuln.id}`,
    published: vuln.published ? vuln.published.slice(0, 10) : undefined,
    summary: vuln.details || vuln.summary || '',
    ecosystem: item.ecosystem,
    name: item.name,
    version: item.version,
    sources: item.sources || [item.source].filter(Boolean),
    binaries: [],
    live: true,
  };
}

function severityFromDatabaseSpecific(vuln) {
  if ((vuln.id || '').startsWith('MAL-')) return 'critical';
  const severity = (vuln.severity || []).find((entry) => entry.score);
  if (severity) return severity.score;
  return vuln.database_specific && vuln.database_specific.severity
    ? String(vuln.database_specific.severity).toLowerCase()
    : 'unknown';
}

module.exports = {
  queryOsv,
  isSupplyChainOrAiSecurity,
};
