// Build @pacspace-io/sdk.
//
// `records.check` runs the shared verifier (@pacspace/shared). That package
// is not published, and until 0.10.0 the SDK named it as an optional peer:
// installed from the registry, the dynamic import failed and the check fell
// back to "some entry is committed", reporting ok on a tampered history. The
// SDK is now bundled the way the standalone checker is: the exact modules the
// check needs (scripts/shared-surface.ts) are bundled in by alias, ethers is
// the one runtime dependency, and the build refuses any input from outside
// packages/sdk and packages/shared/src so server-only modules and their
// dependencies can never ride along.
//
// Three entry points, matching package.json's exports: the SDK
// (dist/index.js), the webhooks subpath (dist/webhooks/index.js) and the
// records-crypto subpath (dist/records-crypto.js). Only records-crypto may
// bundle from node_modules, and only the pinned libraries at their pinned
// paths and versions (scripts/records/records-crypto-pins.mjs).
// Declarations come from tsc over src/ so the public types are unchanged;
// records-crypto's come from tsc over shared's own files.
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

const runtimeDependencies = Object.keys(pkg.dependencies ?? {});
if (runtimeDependencies.join(',') !== 'ethers') {
  console.error(`Expected ethers to be the SDK's only runtime dependency; package.json declares: ${runtimeDependencies.join(', ') || '(none)'}`);
  process.exit(1);
}

rmSync(resolve(root, 'dist'), { recursive: true, force: true });

const common = {
  bundle: true,
  platform: 'node',
  target: 'node20.19',
  format: 'cjs',
  external: runtimeDependencies,
  alias: { '@pacspace/shared': sharedSurface },
  metafile: true,
  logLevel: 'warning',
  legalComments: 'none',
  sourcemap: true,
};

// Encrypted records load their key layer from the records-crypto subpath
// at run time, so every key the SDK makes comes from that one module (a key
// is only usable by the module that made it) and the pinned libraries load
// only when a workspace secret is used. The loader is replaced here by a
// require of the sibling file; only dist/index.js may carry it.
const recordsCryptoLoader = resolve(root, 'src/records-encryption/loader.ts');
const RECORDS_CRYPTO_SUBPATH = './records-crypto.js';
const loaderPlugin = (allowed) => ({
  name: 'records-crypto-loader',
  setup(b) {
    b.onLoad({ filter: /records-encryption[\\/]loader\.ts$/ }, (args) => {
      if (args.path !== recordsCryptoLoader) return undefined;
      if (!allowed) throw new Error('only dist/index.js may load the records-crypto subpath');
      return {
        loader: 'js',
        contents: `let loaded = null;\nexport function loadRecordsCrypto() {\n  if (!loaded) loaded = Promise.resolve().then(() => require(${JSON.stringify(RECORDS_CRYPTO_SUBPATH)}));\n  return loaded;\n}\n`,
      };
    });
    b.onResolve({ filter: /^\.\/records-crypto\.js$/ }, () => ({ path: RECORDS_CRYPTO_SUBPATH, external: true }));
  },
});

const entries = [
  { entry: 'src/index.ts', outfile: 'dist/index.js', pinned: false, loader: true },
  { entry: 'src/webhooks/index.ts', outfile: 'dist/webhooks/index.js', pinned: false, loader: false },
  { entry: '../shared/src/records-crypto/bundle-entry.ts', outfile: 'dist/records-crypto.js', pinned: true, loader: false },
];

const allowed = (file, pinned) => {
  const abs = resolve(root, file);
  if (abs.startsWith(resolve(root, 'src')) || abs === sharedSurface || abs.startsWith(sharedSrc)) return true;
  if (!pinned) return false;
  const pin = pinOf(relative(repo, abs));
  if (!pin) return false;
  const installed = JSON.parse(readFileSync(resolve(repo, pin.path, 'package.json'), 'utf8'));
  return installed.name === pin.name && installed.version === pin.version;
};

const inputs = new Set();
const bundled = new Set();
for (const { entry, outfile, pinned, loader } of entries) {
  const result = await build({
    ...common,
    entryPoints: [resolve(root, entry)],
    outfile: resolve(root, outfile),
    plugins: [loaderPlugin(loader)],
  });
  const outside = Object.keys(result.metafile.inputs).filter((file) => !allowed(file, pinned));
  if (outside.length) {
    console.error('Refusing to bundle inputs outside packages/sdk, packages/shared/src and the pinned records-crypto libraries:');
    for (const file of outside) console.error(`  ${file}`);
    process.exit(1);
  }
  for (const file of Object.keys(result.metafile.inputs)) {
    inputs.add(relative(root, resolve(root, file)));
    const pin = pinOf(relative(repo, resolve(root, file)));
    if (pin) bundled.add(pin);
  }
}

// Declarations for the public types, from the SDK's own sources. The check's
// inputs and results are the SDK's types; nothing from @pacspace/shared is
// part of the declared surface.
execFileSync(
  resolve(root, '../../node_modules/.bin/tsc'),
  ['-p', resolve(root, 'tsconfig.json'), '--emitDeclarationOnly', '--declaration', '--outDir', resolve(root, 'dist')],
  { stdio: 'inherit' },
);
for (const declaration of [
  'dist/index.d.ts',
  'dist/webhooks/index.d.ts',
  'dist/resources/records.d.ts',
  'dist/types/records-encryption.d.ts',
  'dist/records-encryption/pin-store.d.ts',
  'dist/records-encryption/pin-store-file.d.ts',
  'dist/records-encryption/words.d.ts',
  'dist/records-encryption/workspace-secret.d.ts',
]) {
  const text = readFileSync(resolve(root, declaration), 'utf8');
  if (text.includes('@pacspace/shared')) {
    console.error(`${declaration} refers to @pacspace/shared, which the installed package does not carry.`);
    process.exit(1);
  }
}
emitRecordsCryptoDeclarations(root);

const sorted = [...inputs].sort();
writeFileSync(resolve(root, 'dist/inputs.txt'), `${sorted.join('\n')}\n`);
const libraries = RECORDS_CRYPTO_PINS.filter((pin) => bundled.has(pin)).map(({ path, name, version }) => ({ path, name, version }));
writeFileSync(resolve(root, 'dist/records-crypto-libraries.json'), `${JSON.stringify(libraries, null, 2)}\n`);
console.log(
  `built @pacspace-io/sdk ${pkg.version}: dist/index.js, dist/webhooks/index.js, dist/records-crypto.js (${sorted.length} inputs, ${libraries.length} pinned libraries, ethers external)`,
);
