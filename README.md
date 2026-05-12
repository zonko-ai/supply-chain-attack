# amifcked

Find packages and binaries on this machine tied to known supply-chain attacks, malware campaigns, and AI security incidents.

```sh
npx amifcked
```

`amifcked` scans local package-manager state wherever you run it: global installs, temporary `npx` installs, npm/pnpm/Yarn/Bun caches or stores, and Python user/pipx environments when present. Scoped packages are included.

A cache/store hit means the package was fetched or stored on this machine. A global or `npx` hit is stronger evidence that package code may have been installed or executed.

## Usage

```sh
npx amifcked
```

The CLI prints a compact verdict and exits non-zero when it finds a risky package or suspicious IOC.

Interactive terminals also get a small menu:

```txt
more?  e explain  a actions  q quit  ›
```

The loader and menu are disabled for JSON output, non-interactive terminals, and CI.

## Example

```txt
        .-""""-.
      .'  _    _  '.
     /   (o)  (o)   \
    |       ____       |
    |     .'    '.     |
     \    `----`    /
      '.          .'
        `-......-`
Verdict: YOU ARE FUCKED!! — 1 package hit

The shit that pinged
- npm @rspack/cli@1.1.7 (npm cache _npx)

scan 6 store(s), 1842 package/version pair(s), snapshot 2026-05-12
```

## What It Checks

The embedded offline snapshot is dated `2026-05-12` and covers `438` package/version artifacts.

Local sources include:

- npm global packages, cache records, and `_npx` installs
- pnpm global packages and content-addressed store manifests
- Yarn and Bun global/cache entries
- Python user site-packages and pipx virtual environments

Advisory coverage includes Mini Shai-Hulud/TanStack, Mistral, UiPath, Squawk, OpenSearch, Lightning, Guardrails AI, SAP CAP, Intercom, Namastex.ai, CanisterWorm, CanisterSprawl, Axios, `plain-crypto-js`, Rspack, and Nx `s1ngularity`.

It also checks common home-directory locations for suspicious files such as `router_runtime.js` and `setup.mjs` when contents match known credential-exfiltration or persistence markers.

## Exit Codes

- `0`: no findings
- `1`: findings detected
- `2`: usage or runtime error

## Privacy

`amifcked` uses its embedded advisory snapshot and does not send discovered package names or versions to a remote service. Set `NO_COLOR=1` for plain text output.

## If You Get a Hit

Treat the machine as potentially exposed:

1. Remove affected global or `npx` installs.
2. Clear relevant package-manager cache/store entries.
3. Inspect projects that may have installed the package.
4. Rotate exposed tokens and credentials.
5. Check for unexpected persistence files or workflow changes.

Use menu option `1` for attack-chain context and option `2` for a cleanup prompt you can paste into a coding/security agent.

## Limitations

This is a detection tool, not a full incident-response platform.

- Cache/store hits show package presence, not project usage.
- The advisory snapshot is curated and dated.
- A clean result does not prove the machine is free of malicious packages.
- Some package-manager stores may not expose package names and versions.

## Development

```sh
npm test
npm run check
node bin/amifcked.js
npm exec --package=. -- amifcked
```

## Publishing

```sh
npm test
npm run check
npm pack --dry-run
npm publish
```

The package has no runtime npm dependencies and requires Node.js `18` or newer.

## Research

The research trail and source URLs are in [`RESEARCH.md`](./RESEARCH.md).

## License

MIT
