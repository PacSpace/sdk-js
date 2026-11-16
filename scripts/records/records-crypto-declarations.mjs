// Declarations for a package's dist/records-crypto.js (the SDK's and the
// checker's), emitted by tsc from shared's own files under shared's compiler
// settings. Every import in records-crypto is relative, so the emitted tree
// stands alone; the check below refuses one that names a package the
// installed tarball does not carry.
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const sharedDir = resolve(repo, 'packages/shared');
const NOT_CARRIED = /from ['"](?:@pacspace\/shared|hpke|@panva\/|@noble\/)|import\(['"](?:@pacspace\/shared|hpke|@panva\/|@noble\/)/;

function declarationsUnder(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return declarationsUnder(path);
    return entry.name.endsWith('.d.ts') ? [path] : [];
  });
}

export function emitRecordsCryptoDeclarations(packageRoot) {
  const dist = resolve(packageRoot, 'dist');
  const outDir = resolve(dist, 'records-crypto-types');
  const config = resolve(dist, 'tsconfig.records-crypto.json');
  writeFileSync(
    config,
    JSON.stringify({
      extends: relative(dist, resolve(sharedDir, 'tsconfig.json')),
      compilerOptions: {
        rootDir: relative(dist, resolve(sharedDir, 'src')),
        outDir: relative(dist, outDir),
        incremental: false,
        declaration: true,
        emitDeclarationOnly: true,
        declarationMap: false,
        sourceMap: false,
        stripInternal: true,
      },
      files: [relative(dist, resolve(sharedDir, 'src/records-crypto/bundle-entry.ts'))],
      include: [],
    }),
  );
  try {
    execFileSync(resolve(repo, 'node_modules/.bin/tsc'), ['-p', config], { stdio: 'inherit' });
  } finally {
    rmSync(config, { force: true });
  }
  for (const file of declarationsUnder(outDir)) {
    if (NOT_CARRIED.test(readFileSync(file, 'utf8'))) {
      console.error(`${relative(packageRoot, file)} refers to a package the installed tarball does not carry.`);
      process.exit(1);
    }
  }
  writeFileSync(resolve(dist, 'records-crypto.d.ts'), "export * from './records-crypto-types/records-crypto/bundle-entry';\n");
}
