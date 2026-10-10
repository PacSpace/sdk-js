// Build @pacspace-io/check.
//
// The checker is the shared verifier (@pacspace/shared, records buyer posture
// plan DfD-39 (A)) bundled so it runs from one file with ethers as its only
// dependency. @pacspace/shared is not published; the exact modules the
// checker needs (scripts/shared-surface.ts) are bundled in by alias, and the
// build refuses any input from outside packages/check and packages/shared/src
// so server-only modules and their dependencies can never ride along.
//
// dist/records-crypto.js carries records-crypto with level 2's asymmetric
// layer; it alone may bundle from node_modules, and only the pinned
// libraries at their pinned paths and versions
// (scripts/records/records-crypto-pins.mjs).
import { build } from 'esbuild';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { pinOf, RECORDS_CRYPTO_PINS } from '../../../scripts/records/records-crypto-pins.mjs';
import { emitRecordsCryptoDeclarations } from '../../../scripts/records/records-crypto-declarations.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const repo = resolve(root, '../..');
const sharedSurface = resolve(here, 'shared-surface.ts');
const sharedSrc = resolve(root, '../shared/src');
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));

rmSync(resolve(root, 'dist'), { recursive: true, force: true });

const common = {
  bundle: true,
  platform: 'node',
  target: 'node20.19',
  format: 'cjs',
  external: ['ethers'],
  alias: { '@pacspace/shared': sharedSurface },
  define: { __PACSPACE_CHECK_VERSION__: JSON.stringify(pkg.version) },
  metafile: true,
  logLevel: 'warning',
  legalComments: 'none',
};

const cli = await build({
  ...common,
  entryPoints: [resolve(root, 'src/cli.ts')],
  outfile: resolve(root, 'dist/cli.js'),
  banner: { js: '#!/usr/bin/env node' },
});
const lib = await build({
  ...common,
  entryPoints: [resolve(root, 'src/index.ts')],
  outfile: resolve(root, 'dist/index.js'),
});
const recordsCrypto = await build({
  ...common,
  entryPoints: [resolve(sharedSrc, 'records-crypto/bundle-entry.ts')],
  outfile: resolve(root, 'dist/records-crypto.js'),
});

const allowed = (file, pinned) => {
  const abs = resolve(root, file);
  if (abs.startsWith(resolve(root, 'src')) || abs === sharedSurface || abs.startsWith(sharedSrc)) return true;
  if (!pinned) return false;
  const pin = pinOf(relative(repo, abs));
  if (!pin) return false;
  const installed = JSON.parse(readFileSync(resolve(repo, pin.path, 'package.json'), 'utf8'));
  return installed.name === pin.name && installed.version === pin.version;
};
for (const [result, pinned] of [[cli, false], [lib, false], [recordsCrypto, true]]) {
  const outside = Object.keys(result.metafile.inputs).filter((file) => !allowed(file, pinned));
  if (outside.length) {
    console.error('Refusing to bundle inputs outside packages/check, packages/shared/src and the pinned records-crypto libraries:');
    for (const file of outside) console.error(`  ${file}`);
    process.exit(1);
  }
}

// Declarations for the library entry only; the CLI is a program.
execFileSync(
  resolve(root, '../../node_modules/.bin/tsc'),
  ['-p', resolve(root, 'tsconfig.json'), '--emitDeclarationOnly', '--declaration', '--outDir', resolve(root, 'dist')],
  { stdio: 'inherit' },
);
emitRecordsCryptoDeclarations(root);

const inputs = Object.keys(cli.metafile.inputs).map((file) => relative(root, resolve(root, file)));
writeFileSync(resolve(root, 'dist/inputs.txt'), `${inputs.sort().join('\n')}\n`);
const bundled = new Set(Object.keys(recordsCrypto.metafile.inputs).map((file) => pinOf(relative(repo, resolve(root, file)))));
const libraries = RECORDS_CRYPTO_PINS.filter((pin) => bundled.has(pin)).map(({ path, name, version }) => ({ path, name, version }));
writeFileSync(resolve(root, 'dist/records-crypto-libraries.json'), `${JSON.stringify(libraries, null, 2)}\n`);
console.log(
  `built @pacspace-io/check ${pkg.version}: dist/cli.js, dist/index.js, dist/records-crypto.js (${inputs.length} inputs, ${libraries.length} pinned libraries, ethers external)`,
);
