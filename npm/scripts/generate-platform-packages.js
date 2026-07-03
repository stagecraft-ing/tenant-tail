#!/usr/bin/env node
'use strict';

// Assemble the per-triple platform packages (@tenant-tail/cli-<os>-<cpu>) from
// the release archives, at publish time. Each package carries exactly one
// prebuilt binary plus os/cpu fields so npm installs only the matching one.
// Binaries and generated packages are never committed; this script rebuilds
// them from artifacts on demand.
//
// Mirror of spec-spine's npm/scripts/generate-platform-packages.js. Diff against
// that canonical source if the packaging contract changes.
//
// Two input modes:
//   --archives <dir>   extract binaries from tenant-tail-<tag>-<triple>.{tar.gz,zip}
//   --binary <path>    use one already-built binary (requires a single --target)
//
// Options:
//   --version <v>   release version (e.g. 0.1.0 or v0.1.0); default: main package.json version
//   --out <dir>     output root; default: <npm>/dist/packages
//   --target <key>  build only this platform key (repeatable); default: all five
//   --write-main    fail-closed version check: verify the main package.json version
//                   + optionalDependencies already equal --version, and exit non-zero
//                   on any mismatch (it never rewrites package.json)
//   --lock-only     do not generate packages; only run the --write-main check (implies --write-main)

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const NPM_DIR = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(NPM_DIR, '..');

// platform key -> { release triple, node os, node cpu }. Mirrors release.yml and
// lib/platform.js's SUPPORTED map.
const TARGETS = {
  'darwin-arm64': { triple: 'aarch64-apple-darwin', os: 'darwin', cpu: 'arm64' },
  'darwin-x64': { triple: 'x86_64-apple-darwin', os: 'darwin', cpu: 'x64' },
  'linux-x64': { triple: 'x86_64-unknown-linux-gnu', os: 'linux', cpu: 'x64' },
  'linux-arm64': { triple: 'aarch64-unknown-linux-gnu', os: 'linux', cpu: 'arm64' },
  'win32-x64': { triple: 'x86_64-pc-windows-msvc', os: 'win32', cpu: 'x64' },
};

function die(msg) {
  process.stderr.write(`generate-platform-packages: ${msg}\n`);
  process.exit(1);
}

function log(msg) {
  process.stdout.write(`${msg}\n`);
}

function parseArgs(argv) {
  const opts = { targets: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) die(`missing value for ${a}`);
      return argv[i];
    };
    switch (a) {
      case '--version':
        opts.version = next();
        break;
      case '--archives':
        opts.archives = next();
        break;
      case '--binary':
        opts.binary = next();
        break;
      case '--out':
        opts.out = next();
        break;
      case '--target':
        opts.targets.push(next());
        break;
      case '--write-main':
        opts.writeMain = true;
        break;
      case '--lock-only':
        opts.lockOnly = true;
        opts.writeMain = true;
        break;
      default:
        die(`unknown argument: ${a}`);
    }
  }
  return opts;
}

// Strip a leading "v": "v0.1.0" -> "0.1.0".
function normalizeVersion(v) {
  return v.replace(/^v/, '');
}

function mainPackageJsonPath() {
  return path.join(NPM_DIR, 'package.json');
}

function readMainPackage() {
  return JSON.parse(fs.readFileSync(mainPackageJsonPath(), 'utf8'));
}

// Verify an archive against its sibling `<archive>.sha256` sidecar (the format
// release.yml writes: the hex digest as the first whitespace-delimited token,
// e.g. `sha256sum`/`shasum -a 256` output) before anything is extracted from
// it. A missing sidecar is refused, not skipped: the checksum must exist.
function verifyArchiveChecksum(archive) {
  const sidecar = `${archive}.sha256`;
  if (!fs.existsSync(sidecar)) {
    die(`missing checksum sidecar: ${sidecar} (refusing to extract ${archive} without it)`);
  }
  const sidecarText = fs.readFileSync(sidecar, 'utf8').trim();
  const expected = (sidecarText.split(/\s+/)[0] || '').toLowerCase();
  if (!expected) {
    die(`checksum sidecar ${sidecar} is empty or malformed`);
  }
  const actual = crypto.createHash('sha256').update(fs.readFileSync(archive)).digest('hex');
  if (actual !== expected) {
    die(
      `checksum mismatch for ${archive}:\n` +
        `  expected (from ${sidecar}): ${expected}\n` +
        `  actual:                     ${actual}`,
    );
  }
}

// Extract the binary for one target from an archive directory into a temp file;
// returns its path. Tarballs via `tar`, zips via `unzip` (both present on the
// publish runner).
function extractBinary(target, archivesDir, tag, binFile) {
  const t = TARGETS[target];
  const isWin = t.os === 'win32';
  const archive = path.join(
    archivesDir,
    `tenant-tail-${tag}-${t.triple}.${isWin ? 'zip' : 'tar.gz'}`,
  );
  if (!fs.existsSync(archive)) {
    die(`archive not found for ${target}: ${archive}`);
  }
  verifyArchiveChecksum(archive);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tenant-tail-extract-'));
  // Extract the whole archive rather than selecting one member: the release tar
  // is built with `tar -C staging .`, so members are stored "./"-prefixed
  // (./tenant-tail). GNU tar (the Linux runner) will not match a bare
  // `tenant-tail` against `./tenant-tail` and errors "Not found in archive";
  // macOS bsdtar matches leniently. Extracting all members lands the binary at
  // <tmp>/<binFile> on every tar/unzip flavor.
  if (isWin) {
    execFileSync('unzip', ['-o', '-q', archive, '-d', tmp], { stdio: 'inherit' });
  } else {
    execFileSync('tar', ['-C', tmp, '-xzf', archive], { stdio: 'inherit' });
  }
  const extracted = path.join(tmp, binFile);
  if (!fs.existsSync(extracted)) {
    die(`archive ${archive} did not contain ${binFile}`);
  }
  return extracted;
}

function platformPackageJson(target, version) {
  const t = TARGETS[target];
  const pkg = {
    name: `@tenant-tail/cli-${target}`,
    version,
    description: `Prebuilt tenant-tail CLI binary for ${target}. Installed automatically by the \`tenant-tail\` package; do not depend on it directly.`,
    license: 'Apache-2.0',
    repository: {
      type: 'git',
      url: 'git+https://github.com/stagecraft-ing/tenant-tail.git',
    },
    os: [t.os],
    cpu: [t.cpu],
    files: ['bin/'],
    // Scoped packages default to restricted on npm; publishConfig.access is the
    // reliable way to publish them publicly.
    publishConfig: { access: 'public' },
  };
  // The two Linux targets ship a glibc binary; without a `libc` field, npm's
  // install-time platform match still selects this package on a musl host
  // (Alpine), leaving only the runtime guard (lib/platform.js's isMuslLinux)
  // to refuse it after download. Declaring `libc: ["glibc"]` lets npm itself
  // skip the package on musl hosts.
  if (t.os === 'linux') {
    pkg.libc = ['glibc'];
  }
  return pkg;
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function generateOne(target, version, tag, outRoot, opts) {
  const t = TARGETS[target];
  const binFile = t.os === 'win32' ? 'tenant-tail.exe' : 'tenant-tail';

  let source;
  if (opts.binary) {
    source = path.resolve(opts.binary);
    if (!fs.existsSync(source)) die(`--binary not found: ${source}`);
  } else {
    source = extractBinary(target, path.resolve(opts.archives), tag, binFile);
  }

  const pkgDir = path.join(outRoot, '@tenant-tail', `cli-${target}`);
  const binDir = path.join(pkgDir, 'bin');
  fs.rmSync(pkgDir, { recursive: true, force: true });
  fs.mkdirSync(binDir, { recursive: true });

  fs.copyFileSync(source, path.join(binDir, binFile));
  fs.chmodSync(path.join(binDir, binFile), 0o755);

  writeJson(path.join(pkgDir, 'package.json'), platformPackageJson(target, version));

  const license = path.join(REPO_ROOT, 'LICENSE');
  if (fs.existsSync(license)) {
    fs.copyFileSync(license, path.join(pkgDir, 'LICENSE'));
  }
  fs.writeFileSync(
    path.join(pkgDir, 'README.md'),
    `# @tenant-tail/cli-${target}\n\n` +
      `Prebuilt \`tenant-tail\` binary for \`${target}\` (${t.triple}).\n\n` +
      'This package is installed automatically as an optional dependency of the\n' +
      '[`tenant-tail`](https://www.npmjs.com/package/tenant-tail) package. Do not\n' +
      'depend on it directly; its name and contents are an implementation detail.\n',
  );

  log(`  generated ${pkgDir}`);
  return pkgDir;
}

// Verify the committed main package already locks every target to `version`.
// Fail-closed: this is the only check `--write-main` runs (see main()) -- a
// version/tag mismatch must stop the release, not be silently papered over by
// rewriting package.json. Mirrors generate_wheels.py's verify_version_lock.
function verifyMainLock(version) {
  const pkg = readMainPackage();
  const problems = [];
  if (pkg.version !== version) {
    problems.push(`main version is ${pkg.version}, expected ${version}`);
  }
  const deps = pkg.optionalDependencies || {};
  for (const target of Object.keys(TARGETS)) {
    const name = `@tenant-tail/cli-${target}`;
    if (deps[name] !== version) {
      problems.push(`${name} is pinned to ${deps[name]}, expected ${version}`);
    }
  }
  if (problems.length > 0) {
    die(
      `version lock mismatch:\n  - ${problems.join('\n  - ')}\n` +
        'Bump npm/package.json\'s version and optionalDependencies pins to match ' +
        '(or pass the correct --version); this script never rewrites package.json.',
    );
  }
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const version = normalizeVersion(opts.version || readMainPackage().version);
  const tag = `v${version}`;

  if (opts.binary && opts.targets.length !== 1) {
    die('--binary requires exactly one --target');
  }

  // Both --write-main and the default path verify the same lock; there is no
  // write path anymore (see verifyMainLock's comment).
  verifyMainLock(version);

  if (opts.lockOnly) {
    log(`version lock verified: ${version}`);
    return;
  }

  const outRoot = path.resolve(opts.out || path.join(NPM_DIR, 'dist', 'packages'));
  const targets = opts.targets.length > 0 ? opts.targets : Object.keys(TARGETS);
  for (const target of targets) {
    if (!TARGETS[target]) die(`unknown target: ${target}`);
  }

  log(`generating platform packages for ${version} (${tag}):`);
  for (const target of targets) {
    generateOne(target, version, tag, outRoot, opts);
  }
  log(`done -> ${outRoot}`);
}

main();
