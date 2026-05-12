#!/usr/bin/env node
'use strict';

process.env.AMIFCKED_OUTPUT_STYLE = 'professional';
process.env.AMIFCKED_COMMAND_NAME = 'supply-chain-attack';

const { main } = require('amifcked/lib/cli');

main(process.argv.slice(2)).catch((error) => {
  console.error(`supply-chain-attack: ${error && error.message ? error.message : error}`);
  process.exitCode = 2;
});
