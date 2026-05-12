# amiscrewed

Find installed packages and binaries tied to known supply-chain attacks, malware campaigns, and AI security incidents.

```sh
npx amiscrewed
```

`amiscrewed` scans a repository's dependency files and installed package metadata, then reports risky package versions and the executable binaries they expose. It is designed for the incidents that matter during active supply-chain response: compromised npm releases, malicious PyPI packages, AI SDK brand-squats, poisoned CLIs, and persistence indicators from recent campaigns.

## Use It

Run it inside any repository:

```sh
npx amiscrewed
```

That is the main interface. It scans the current directory, prints a readable report, and exits with a non-zero code when it finds a risky package or suspicious IOC.

While it scans, `amiscrewed` shows a tiny loader with rotating status messages like `checking how screwed you are` and `interrogating lockfiles`. The loader is automatically disabled for JSON output, non-interactive terminals, and CI.

## Example Output

```txt
am i screwed?
Looks like something needs attention.

repo      /work/app
snapshot  2026-05-12 (438 known package/version artifacts)
live      OSV checked

Findings: 1 risky package install(s), 1 binary command(s), 0 suspicious IOC file(s)

CRITICAL npm @rspack/cli@1.1.7
  bins     rspack
  seen in  package-lock.json, node_modules/@rspack/cli/package.json
  why      SOCKET-rspack-2025-12 - Rspack npm packages compromised
  source: https://socket.dev/blog/rspack-npm-packages-compromised
```

## What It Checks

The embedded offline snapshot is dated `2026-05-12` and currently covers `438` package/version artifacts.

It includes Socket-reported and related advisories for:

- Mini Shai-Hulud and the TanStack npm compromise
- Mistral, UiPath, Squawk, OpenSearch, Lightning, Guardrails AI, SAP CAP, and Intercom package incidents
- Namastex.ai and CanisterWorm
- CanisterSprawl AI brand-squat packages
- Axios and `plain-crypto-js`
- Rspack
- Nx `s1ngularity`

By default, the tool also queries OSV for live malicious, supply-chain, and AI-related vulnerability records that may have been published after the embedded snapshot.

## Supported Files

npm and JavaScript:

- `package-lock.json`
- `npm-shrinkwrap.json`
- `pnpm-lock.yaml`
- `yarn.lock`
- Exact pins in `package.json`
- Installed `node_modules` package metadata
- Executable links in `node_modules/.bin`

Python:

- `requirements*.txt`
- `poetry.lock`

Composer:

- `composer.lock`

The scanner also looks for suspicious files such as `router_runtime.js` and `setup.mjs` when their contents match credential-exfiltration or persistence markers from recent supply-chain campaigns.

## Why Wasn't My TanStack Usage Flagged?

Using TanStack is not itself a finding. `amiscrewed` flags specific compromised package/version pairs, such as the Mini Shai-Hulud affected TanStack releases from May 2026. If your repo uses TanStack but the lockfile does not contain those affected versions, the scanner should stay quiet.

## Exit Codes

- `0`: scan completed and no findings were detected.
- `1`: scan completed and findings were detected.
- `2`: CLI usage or runtime error.

## CI Usage

Use the same command in CI. It fails the build if a risky package version or suspicious IOC is found:

```sh
npx amiscrewed
```

## Privacy

By default, `amiscrewed` uses its embedded advisory snapshot and asks OSV about discovered package names and versions. Set `NO_COLOR=1` if your terminal or CI system should receive plain text without ANSI colors.

## Response Guidance

If the tool reports a hit, treat any machine or CI job that installed the package as potentially exposed.

Recommended response:

1. Remove or pin away from the affected version.
2. Regenerate the lockfile from a clean environment.
3. Reinstall dependencies.
4. Rotate tokens and credentials that may have been exposed.
5. Inspect developer machines and CI hosts for persistence files or unexpected workflow changes.

## Limitations

This is a detection tool, not a complete incident-response platform.

- The embedded advisory snapshot is curated and dated.
- Live OSV mode improves freshness but depends on OSV coverage and network availability.
- A clean result does not prove a repository is free of malicious packages.
- Lockfiles are the strongest signal. Loose dependency ranges in manifests can only be matched when they are exact pins.
- Binary detection is best for installed npm dependencies where `node_modules` is present.

## Development

Clone the repo and run:

```sh
npm test
npm run check
```

Run the CLI locally:

```sh
node bin/amiscrewed.js
```

Test the package execution path:

```sh
npm exec --package=. -- amiscrewed
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
