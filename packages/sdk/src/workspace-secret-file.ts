import { RECORDS_KEYRING_MAX_BYTES_V1, parseRecordsKeyringFileV1 } from '@pacspace/shared';
import { RecordsEncryptionError } from './records-encryption/words';

export type WorkspaceSecretEnvironment = 'sandbox' | 'production';

/**
 * The name the dashboard downloads a workspace secret file under. Sandbox's
 * says so, so the two environments' files never share a name (EN1, D-20):
 * `pacspace-workspace-secret-sandbox-v1.json`, and `pacspace-workspace-secret-v1.json`
 * for Production.
 */
export function workspaceSecretFileName(version: number, environment: WorkspaceSecretEnvironment = 'production'): string {
  if (!Number.isSafeInteger(version) || version < 1) throw new RecordsEncryptionError('RECORDS_SECRET_INVALID');
  return `pacspace-workspace-secret-${environment === 'sandbox' ? 'sandbox-' : ''}v${version}.json`;
}

async function nodeFs(): Promise<typeof import('node:fs/promises')> {
  const specifier = 'node:fs/promises';
  return import(/* @vite-ignore */ /* webpackIgnore: true */ specifier);
}

/**
 * Read a workspace secret file, for `records: { secret }`. The file's name
 * doesn't matter: Sandbox's `pacspace-workspace-secret-sandbox-vN.json` and
 * the SDK's own `pacspace-workspace-secret-vN.json` read the same. Anything
 * that isn't a pacspace-workspace-secret/v1 file is refused
 * (RECORDS_SECRET_INVALID). Node only. The text is returned and kept
 * nowhere else.
 */
export async function readWorkspaceSecretFile(path: string): Promise<string> {
  const fs = await nodeFs();
  const handle = await fs.open(path, 'r');
  const buffer = Buffer.alloc(RECORDS_KEYRING_MAX_BYTES_V1 + 1);
  try {
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    if (length > RECORDS_KEYRING_MAX_BYTES_V1) throw new RecordsEncryptionError('RECORDS_SECRET_INVALID');
    const text = buffer.subarray(0, length).toString('utf8');
    if (!parseRecordsKeyringFileV1(text).ok) throw new RecordsEncryptionError('RECORDS_SECRET_INVALID');
    return text;
  } finally {
    buffer.fill(0);
    await handle.close();
  }
}
