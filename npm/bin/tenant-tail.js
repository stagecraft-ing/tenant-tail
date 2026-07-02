#!/usr/bin/env node
'use strict';

// The launcher. Resolves the prebuilt binary for this host (see lib/platform.js)
// and exec's it, forwarding argv and the child's exit code. It is a pure
// translation layer: no flags added, no arguments rewritten, nothing printed on
// the success path. `tenant-tail <args>` through npm is identical to the native
// binary. NOT a native addon; the Rust verifier runs as a child process.
//
// Mirror of spec-spine's npm/bin/spec-spine.js. Diff against that canonical
// source if the launcher contract changes.

const os = require('node:os');
const { execFileSync } = require('node:child_process');
const { resolveBinaryPath } = require('../lib/platform.js');

let binPath;
try {
  binPath = resolveBinaryPath();
} catch (err) {
  process.stderr.write(`${err.message}\n`);
  process.exit(1);
}

try {
  execFileSync(binPath, process.argv.slice(2), { stdio: 'inherit' });
} catch (err) {
  // Signal termination (SIGINT/SIGSEGV/...) leaves err.status === null and
  // err.signal set to the signal name: forward it as 128 + signal number, the
  // shell convention (Ctrl-C -> 130), instead of flattening it to exit 1.
  if (err.signal) {
    const signalNum = os.constants.signals[err.signal];
    if (typeof signalNum === 'number') {
      process.exit(128 + signalNum);
    }
    process.stderr.write(`tenant-tail: binary terminated by signal ${err.signal}\n`);
    process.exit(1);
  }
  if (typeof err.status === 'number') {
    process.exit(err.status); // forward the binary's own exit code
  }
  process.stderr.write(`tenant-tail: failed to run binary: ${err.message}\n`);
  process.exit(1);
}
