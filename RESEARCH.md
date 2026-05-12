# Research Notes

Snapshot date: 2026-05-12.

The scanner data is intentionally split into:

- An embedded offline snapshot in `lib/advisories.js`.

## Sources Used

- Socket Mini Shai-Hulud campaign page: https://socket.dev/supply-chain-attacks/mini-shai-hulud
- GitHub TanStack advisory `GHSA-g7cv-rxg3-hmpx`: https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx
- TanStack postmortem: https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- Snyk TanStack compromise tracker: https://security.snyk.io/TanStack-npm-Supply-Chain-Compromise-May-2026
- Aikido Mini Shai-Hulud/TanStack mirror: https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
- Socket CanisterWorm campaign page: https://socket.dev/supply-chain-attacks/canisterworm
- Socket CanisterSprawl campaign page: https://socket.dev/supply-chain-attacks/canistersprawl
- Socket Axios compromise report: https://socket.dev/blog/axios-npm-package-compromised
- Socket Rspack compromise report: https://socket.dev/blog/rspack-npm-packages-compromised
- Socket Nx compromise report: https://socket.dev/blog/nx-packages-compromised
- OSV live API: https://api.osv.dev

The requested X URL, `https://x.com/SocketSecurity/status/2053950165665386546`, was attempted directly but was not retrievable through the available web tooling. The TanStack/Mini Shai-Hulud package data from that discussion was cross-checked against the official Socket campaign page, the GitHub advisory, and public incident trackers above.

## Current Embedded Coverage

The embedded snapshot currently covers 438 package/version artifacts across npm, PyPI, and Packagist. It includes the May 2026 TanStack/Mini Shai-Hulud wave and related AI/developer-tool package incidents such as Mistral, UiPath, Squawk, OpenSearch, Lightning, Guardrails AI, Namastex/CanisterWorm, CanisterSprawl AI brand-squats, Axios/plain-crypto-js, Rspack, and Nx.

Use:

```sh
node bin/amifcked.js --list-advisories
```

to see the exact artifact count and source URLs embedded in the package.
