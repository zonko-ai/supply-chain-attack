# supply-chain-attack

Professional CLI wrapper around `amifcked` for scanning local package-manager state for known supply-chain attack indicators.

```sh
npx supply-chain-attack
```

This package uses the same scanner and advisory snapshot as `amifcked`, but prints professional output suitable for teams, CI logs, and security reports.

## Options

```sh
supply-chain-attack --json
supply-chain-attack --list-advisories
supply-chain-attack --no-interactive
```
