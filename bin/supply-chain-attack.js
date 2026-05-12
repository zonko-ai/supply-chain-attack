#!/usr/bin/env node
'use strict';

const { main } = require('../lib/cli');

main(process.argv.slice(2)).catch((error) => {
  console.error(`supply-chain-attack: ${error && error.message ? error.message : error}`);
  process.exitCode = 2;
});
