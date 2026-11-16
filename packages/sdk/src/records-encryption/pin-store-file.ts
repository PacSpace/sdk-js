import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { RecordsPin, RecordsPinStore } from './pin-store';

const PIN_FILE_SCHEMA = 'pacspace-pins/v1';
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Pins kept in a JSON file, readable by its owner only (mode 0600). Each
 * write replaces the file whole, so a crash leaves the previous pins. A file
 * that can't be read as pins holds none: every code is confirmed again.
 */
export function filePinStore(path: string): RecordsPinStore {
  const read = async (): Promise<Record<string, RecordsPin>> => {
    let text: string;
    try {
      text = await readFile(path, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') return {};
      throw error;
    }
    try {
      const parsed = JSON.parse(text) as { schema?: unknown; pins?: Record<string, RecordsPin> };
      if (parsed?.schema === PIN_FILE_SCHEMA && parsed.pins && typeof parsed.pins === 'object' && !Array.isArray(parsed.pins)) return parsed.pins;
    } catch {
      // read as no pins below
    }
    return {};
  };
  return {
    async get(workspaceId) {
      const pin = (await read())[workspaceId];
      return pin && typeof pin.publicKeyId === 'string' && HEX64.test(pin.publicKeyId) ? { ...pin } : null;
    },
    async set(workspaceId, pin) {
      const pins = await read();
      pins[workspaceId] = { publicKeyId: pin.publicKeyId, confirmedAt: pin.confirmedAt };
      await mkdir(dirname(path), { recursive: true });
      const next = `${path}.${process.pid}.tmp`;
      await writeFile(next, `${JSON.stringify({ schema: PIN_FILE_SCHEMA, pins }, null, 2)}\n`, { mode: 0o600 });
      await chmod(next, 0o600);
      await rename(next, path);
    },
  };
}
