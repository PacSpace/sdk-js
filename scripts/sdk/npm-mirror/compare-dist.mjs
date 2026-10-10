#!/usr/bin/env node
// Compares each package's dist/ with the sha256 list pacspace-api wrote
// when it built the same sources (scripts/sdk/npm-mirror/sync.mjs). Runs in
// pacspace-api and in the public npm mirror, so it uses Node alone.
//
// Usage: node scripts/sdk/npm-mirror/compare-dist.mjs mirror/expected-dist.json
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

function filesUnder(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? filesUnder(path) : [path];
  });
}

export function hashDist(dir) {
  const hashes = {};
  for (const file of filesUnder(dir).sort()) {
    hashes[relative(dir, file).split(sep).join('/')] = createHash('sha256').update(readFileSync(file)).digest('hex');
  }
  return hashes;
}

export function compareDist(root, expected) {
  const lines = [];
  let count = 0;
  if (expected?.schema !== 'pacspace-npm-mirror-dist/v1') return { ok: false, lines: ['expected-dist.json is not pacspace-npm-mirror-dist/v1'], count };
  for (const [pkg, want] of Object.entries(expected.packages)) {
    const manifest = JSON.parse(readFileSync(join(root, pkg, 'package.json'), 'utf8'));
    if (manifest.name !== want.name || manifest.version !== want.version) {
      lines.push(`${pkg}: package.json is ${manifest.name}@${manifest.version}, expected ${want.name}@${want.version}`);
    }
    let got;
    try {
      got = hashDist(join(root, pkg, 'dist'));
    } catch {
      lines.push(`${pkg}: dist/ is missing`);
      continue;
    }
    for (const file of new Set([...Object.keys(want.files), ...Object.keys(got)])) {
      if (!(file in got)) lines.push(`${pkg}/dist/${file}: missing`);
      else if (!(file in want.files)) lines.push(`${pkg}/dist/${file}: not in the source build`);
      else if (got[file] !== want.files[file]) lines.push(`${pkg}/dist/${file}: differs`);
      else count += 1;
    }
  }
  return { ok: lines.length === 0, lines, count };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const path = process.argv[2];
  if (!path) {
    console.error('usage: compare-dist.mjs <expected-dist.json>');
    process.exit(2);
  }
  const expected = JSON.parse(readFileSync(resolve(path), 'utf8'));
  const result = compareDist(process.cwd(), expected);
  for (const line of result.lines) console.error(line);
  if (!result.ok) process.exit(1);
  console.log(`dist matches ${expected.sourceCommit}: ${result.count} files`);
}
