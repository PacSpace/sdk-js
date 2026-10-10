import type { RecordsEncryptionOptions, RecordsSecretSource } from '../types/records-encryption';
import { fromBase64Url } from './base64url';
import { loadRecordsCrypto, type RecordsCrypto } from './loader';
import { RecordsEncryptionError } from './words';

export type { RecordsEncryptionOptions, RecordsSecretSource };

export type Keyring = Awaited<ReturnType<RecordsCrypto['RecordsKeyringV1']['fromProvider']>>;

function textOf(rc: RecordsCrypto, source: RecordsSecretSource): string {
  if (typeof source === 'string') return source;
  if (!source || typeof source !== 'object' || !Array.isArray(source.secrets)) throw new RecordsEncryptionError('RECORDS_SECRET_INVALID');
  return rc.serializeRecordsKeyringFileV1(
    source.secrets.map((s) => ({ version: s.version, secret: fromBase64Url(String(s.secret)) })),
  );
}

/** Parses a workspace secret into a keyring, or refuses with W-L2d-24. */
export async function keyringOf(source: RecordsSecretSource): Promise<{ rc: RecordsCrypto; ring: Keyring; text: string }> {
  const rc = await loadRecordsCrypto();
  try {
    const text = textOf(rc, source);
    const ring = await rc.RecordsKeyringV1.fromProvider(rc.localRecordsKeyProviderV1(text));
    return { rc, ring, text };
  } catch {
    throw new RecordsEncryptionError('RECORDS_SECRET_INVALID');
  }
}

/**
 * The client's workspace secret, loaded on first use. Without `secret` or
 * `secretProvider` nothing is configured and records are written as 0.12.0
 * wrote them.
 */
export class RecordsKeys {
  private loading: Promise<{ rc: RecordsCrypto; ring: Keyring; text: string }> | null = null;

  constructor(private readonly options: RecordsEncryptionOptions | undefined) {}

  get configured(): boolean {
    return this.options?.secret !== undefined || typeof this.options?.secretProvider === 'function';
  }

  /** The keyring, or W-L2d-23 when no workspace secret is configured. */
  async ring(): Promise<{ rc: RecordsCrypto; ring: Keyring }> {
    if (!this.configured) throw new RecordsEncryptionError('RECORDS_SECRET_REQUIRED');
    if (!this.loading) {
      this.loading = (async () => {
        const source = this.options?.secret !== undefined ? this.options.secret : await this.options!.secretProvider!();
        return keyringOf(source);
      })();
      this.loading.catch(() => {
        this.loading = null;
      });
    }
    const { rc, ring } = await this.loading;
    return { rc, ring };
  }

  /** The keyring file's text, for `rotate` to compare versions. */
  async text(): Promise<string> {
    await this.ring();
    return (await this.loading!).text;
  }

  /** After a rotation: the next keyring is used from here on. */
  replace(next: { rc: RecordsCrypto; ring: Keyring; text: string }): void {
    this.loading = Promise.resolve(next);
  }

  /** The keyring without refusing: null when none is configured. */
  async maybe(): Promise<{ rc: RecordsCrypto; ring: Keyring } | null> {
    return this.configured ? this.ring() : null;
  }
}
