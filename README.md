# amifcked

Find packages and binaries on this machine tied to known supply-chain attacks, malware campaigns, and AI security incidents.

```sh
npx amifcked
```

`amifcked` is machine-oriented: it scans local package-manager state no matter where you run it from. That includes global installs, temporary `npx` installs, package-manager caches/stores such as npm, pnpm, Yarn, and Bun, plus Python user/pipx environments when present. Scoped packages are included.

A cache/store hit means the package was fetched or stored on this laptop. A global or `npx` hit is stronger evidence that package code may have been installed/executed. Treat either as useful incident-response signal when the concern is a specific developer machine.

## Use It

Run it anywhere:

```sh
npx amifcked
```

It scans this machine, prints a compact verdict plus findings, and exits with a non-zero code when it finds a risky package or suspicious IOC.

In an interactive terminal, `amifcked` then offers a tiny guided menu:

```txt
1) educate me — what the hell is this vulnerability/campaign?
2) next actions — generate a copy/paste cleanup prompt for your agent
q) bail
```

While it scans, `amifcked` shows a tiny loader with short status messages like `scanning local package-manager state` and `checking package-manager caches`. The loader and interactive menu are automatically disabled for JSON output, non-interactive terminals, and CI.

## Example Output

```txt
Verdict: YOU MIGHT BE FUCKED, BRO — 1 package hit

The shit that pinged
- npm @rspack/cli@1.1.7 (npm cache _npx)

scan 6 store(s), 1842 package/version pair(s), snapshot 2026-05-12

Pick your next move:
  1) educate me — what the hell is this vulnerability/campaign?
  2) next actions — generate a copy/paste cleanup prompt for your agent
  q) bail
```

Option `1` explains the actual attack chain: how poisoned package versions get published, how install/CLI execution can happen, what secrets attackers want, and what your cache/global/npx hit means.

Option `2` prints a prompt you can paste into a coding/security agent. The prompt explicitly asks the agent to work through cleanup safely, inspect project lockfiles/manifests, suggest or run cleanup commands, and help with token-rotation without printing secrets.

## What It Checks

The embedded offline snapshot is dated `2026-05-12` and currently covers `438` package/version artifacts.

It checks local machine locations such as:

- npm global packages
- npm cache tarball records
- npm `_npx` temporary installs
- pnpm global packages
- pnpm content-addressed store package manifests
- Yarn global packages and cache entries
- Bun global packages and cache entries
- Python user site-packages and pipx virtual environments

It includes Socket-reported and related advisories for:

- Mini Shai-Hulud and the TanStack npm compromise
- Mistral, UiPath, Squawk, OpenSearch, Lightning, Guardrails AI, SAP CAP, and Intercom package incidents
- Namastex.ai and CanisterWorm
- CanisterSprawl AI brand-squat packages
- Axios and `plain-crypto-js`
- Rspack
- Nx `s1ngularity`

The scanner also looks in common home-directory locations for suspicious files such as `router_runtime.js` and `setup.mjs` when their contents match credential-exfiltration or persistence markers from recent supply-chain campaigns.

## Why Wasn't My TanStack Usage Flagged?

Using TanStack is not itself a finding. `amifcked` flags specific compromised package/version pairs, such as the Mini Shai-Hulud affected TanStack releases from May 2026. If this machine does not have those exact package versions in its package-manager state, the scanner should stay quiet.

## Exit Codes

- `0`: scan completed and no findings were detected.
- `1`: scan completed and findings were detected.
- `2`: CLI usage or runtime error.

## Privacy

`amifcked` uses its embedded advisory snapshot and scans local package-manager state. It does not send discovered package names or versions to a remote service. Set `NO_COLOR=1` if your terminal or CI system should receive plain text without ANSI colors.

## Response Guidance

If the tool reports a hit, treat this machine as potentially exposed. Use the interactive menu for the short version:

- `1` explains the actual attack chain, why the machine was flagged, and whether the hit looks like cache-only evidence or possible execution.
- `2` prints a copy/paste prompt for a coding/security agent, including cleanup commands, project inspection steps, and token-rotation guidance. It tells the agent to work on the cleanup safely and never print/store secrets.

Recommended response:

1. Remove global or `npx` installs of the affected version.
2. Clear the relevant package-manager cache/store entry.
3. Inspect projects that may have installed the package.
4. Rotate tokens and credentials that may have been exposed.
5. Inspect developer-machine persistence files or unexpected workflow changes.

## Limitations

This is a detection tool, not a complete incident-response platform.

- A cache/store hit is evidence that a package was present on the machine, not proof that a particular project imported it.
- The embedded advisory snapshot is curated and dated.
- A clean result does not prove the machine is free of malicious packages.
- Package-manager stores can be content-addressed and metadata-light; some entries may not expose package names and versions.

## Development

Clone the repo and run:

```sh
npm test
npm run check
```

Run the CLI locally:

```sh
node bin/amifcked.js
```

Test the package execution path:

```sh
npm exec --package=. -- amifcked
```

## Publishing

Before publishing:

```sh
npm test
npm run check
npm pack --dry-run
npm publish
```

The package has no runtime npm dependencies and requires Node.js `18` or newer.

## Research

The research trail and source URLs are documented in [`RESEARCH.md`](./RESEARCH.md).

## License

MIT
