import { BLINDING_FILE_MAX_BYTES, parseBlindingFile } from '@pacspace/shared';
import { BLINDING_WORDS, Blinding, blindingFileText } from './blinding';
import { ValidationError } from './errors';

const FILE_WORDS = {
  different: 'A different blinding file already exists at this path. Nothing was written.',
  notRegular: 'The path for the blinding file is a link or not a regular file. Nothing was written.',
} as const;

/** The name the blinding file takes beside the file it belongs to. */
export const BLINDING_FILE_SUFFIX = '.pacspace.json';

async function nodeFs(): Promise<typeof import('node:fs/promises')> {
  const specifier = 'node:fs/promises';
  return import(/* @vite-ignore */ /* webpackIgnore: true */ specifier);
}

const errorCode = (error: unknown): string | undefined =>
  error && typeof error === 'object' ? (error as { code?: string }).code : undefined;

/**
 * Write the blinding beside its file, as `<filePath>.pacspace.json`, readable
 * by you only (mode 0600; not enforced on Windows). A link or anything but a
 * regular file at that path is refused. The same bytes already there are
 * left as they are; other bytes are refused. Node only. Returns the path.
 */
export async function writeBlindingFile(filePath: string, blinding: Blinding): Promise<string> {
  if (!(blinding instanceof Blinding)) throw new ValidationError(BLINDING_WORDS.notAFile);
  const fs = await nodeFs();
  const target = `${filePath}${BLINDING_FILE_SUFFIX}`;
  const bytes = Buffer.from(blindingFileText(blinding), 'utf8');
  try {
    const existing = await sameOrRefuse(fs, target, bytes);
    if (existing) return target;
    try {
      await fs.writeFile(target, bytes, { flag: 'wx', mode: 0o600 });
    } catch (error) {
      if (errorCode(error) !== 'EEXIST') throw error;
      await sameOrRefuse(fs, target, bytes);
    }
    return target;
  } finally {
    bytes.fill(0);
  }
}

/** True when the same bytes are already there; false when nothing is. Refuses anything else. */
async function sameOrRefuse(fs: typeof import('node:fs/promises'), target: string, bytes: Buffer): Promise<boolean> {
  let stat: import('node:fs').Stats;
  try {
    stat = await fs.lstat(target);
  } catch (error) {
    if (errorCode(error) === 'ENOENT') return false;
    throw error;
  }
  if (stat.isSymbolicLink() || !stat.isFile()) throw new ValidationError(FILE_WORDS.notRegular);
  if (stat.size !== bytes.length) throw new ValidationError(FILE_WORDS.different);
  const current = await fs.readFile(target);
  try {
    if (!current.equals(bytes)) throw new ValidationError(FILE_WORDS.different);
    return true;
  } finally {
    current.fill(0);
  }
}

/** Read a blinding file exactly (at most 1024 bytes, the canonical form only). Node only. */
export async function readBlindingFile(path: string): Promise<Blinding> {
  const fs = await nodeFs();
  const handle = await fs.open(path, 'r');
  const buffer = Buffer.alloc(BLINDING_FILE_MAX_BYTES + 1);
  try {
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    const parsed = parseBlindingFile(buffer.subarray(0, length));
    if (!parsed.ok) throw new ValidationError(BLINDING_WORDS.notAFile);
    try {
      return new Blinding(parsed.blinding.value, parsed.blinding.digest, parsed.blinding.byteLength);
    } finally {
      parsed.blinding.value.fill(0);
    }
  } finally {
    buffer.fill(0);
    await handle.close();
  }
}
