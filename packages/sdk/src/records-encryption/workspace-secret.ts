import { generateWorkspaceSecretV1, parseRecordsKeyringFileV1, serializeRecordsKeyringFileV1 } from '@pacspace/shared';
import { RecordsEncryptionError } from './words';

/**
 * A new workspace secret: a pacspace-workspace-secret/v1 file with version
 * 1, drawn in this process. Keep it where the workspace keeps its other
 * secrets; PacSpace never receives it, and a lost secret can't be recovered.
 */
export function generateWorkspaceSecret(): string {
  return serializeRecordsKeyringFileV1([{ version: 1, secret: generateWorkspaceSecretV1() }]);
}

/** The same file with the next version added, drawn here: the input to `records.rotate()`. */
export function nextWorkspaceSecret(keyring: string): string {
  const parsed = parseRecordsKeyringFileV1(keyring);
  if (!parsed.ok) throw new RecordsEncryptionError('RECORDS_SECRET_INVALID');
  const next = Math.max(...parsed.secrets.map((s) => s.version)) + 1;
  return serializeRecordsKeyringFileV1([...parsed.secrets, { version: next, secret: generateWorkspaceSecretV1() }]);
}
