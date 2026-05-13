# supply-chain-attack

Scan local package-manager state for packages and files associated with known supply-chain attacks.

```sh
npx supply-chain-attack
```

The scanner runs offline against an embedded advisory snapshot and checks global installs, temporary `npx` installs, npm/pnpm/Yarn/Bun caches or stores, and Python user/pipx environments when present. It also flags npm packages whose `postinstall` script performs network-fetch behavior (`curl`, `wget`, JavaScript `fetch`, or Node `http`/`https` requests), including when `postinstall` points at a local install file that performs the fetch.

## Output

The default report is compact and terminal-friendly. It highlights the verdict, the latest tracked attacks, affected packages found locally, packages with `postinstall` network-fetch behavior, and scan scope. Colors use a muted minimalist palette and can be disabled with `NO_COLOR=1` or `--no-color`.

```txt
Verdict: Potential supply-chain exposure detected — 4 package hits

LATEST ATTACK
Mini Shai-Hulud expansion into AI/devtool ecosystem packages (2026-05-12)
Affected: 3 packages
Libraries you had:
- npm lightningcss-darwin-arm64@1.30.2 (pnpm store)

scan 5 store(s), 4724 package/version pair(s), snapshot 2026-05-12
```

Interactive terminals include a small menu for context and remediation prompts:

```txt
options  l learn  a actions  q quit  ›
```

## Usage

```sh
npx supply-chain-attack
npx supply-chain-attack --json
npx supply-chain-attack --list-advisories
npx supply-chain-attack --no-interactive
npx supply-chain-attack --no-color
```

By default, the command exits non-zero when findings are detected. Use `--fail-on none` to always exit `0` unless there is a usage or runtime error.

## Coverage

Snapshot: `2026-05-12`  
Tracked artifacts: `438` package/version entries

Local sources include:

- npm global packages, cache records, and `_npx` installs
- pnpm global packages and content-addressed store manifests
- Yarn and Bun global/cache entries
- Python user site-packages and pipx virtual environments
- Selected suspicious home-directory files matching known campaign indicators

## Exit Codes

- `0`: no findings, or `--fail-on none`
- `1`: findings detected
- `2`: usage or runtime error

## Privacy

No discovered package names, versions, paths, or files are sent to a remote service. The default scan uses only the embedded offline snapshot.

## Interpreting Findings

A cache/store hit means the package was present on this machine. A global or `npx` hit is stronger evidence that package code may have been installed or executed.

If you get a hit, treat the machine as potentially exposed: remove affected installs, clear relevant caches, inspect dependent projects, rotate exposed credentials, and check for persistence or workflow changes.

## Limitations

This is a detection aid, not a complete incident-response platform. A clean result does not prove the machine is malware-free, and the embedded advisory snapshot is necessarily dated.

## Development

```sh
npm test
npm run check
node bin/supply-chain-attack.js
```

The package has no runtime npm dependencies and requires Node.js `18` or newer.

## Research

Source notes are maintained in [`RESEARCH.md`](./RESEARCH.md).

## License

MIT
