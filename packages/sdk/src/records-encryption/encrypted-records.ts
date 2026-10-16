import {
  RECORD_HISTORY_BUNDLE_SCHEMA_V3,
  admitRecordEntryV1,
  buildRecordCopyV1,
  listPublishedLayouts,
  openReceiptV4,
  recordKeyFromBytesV1,
  verifyRecordHistoryBundleV3,
  type EncryptedReadRefusalV1,
  type RecordHistoryBundleV3,
} from '@pacspace/shared';
import { apiErrorBody, type ClientRequestOptions } from '../client';
import { PacSpaceError } from '../errors';
import type { RequestOptions } from '../types/config';
import type { OpenedRecordEntry, RecordReadOptions } from '../types/records';
import { fromBase64Url, toBase64Url } from './base64url';
import { loadRecordsCrypto, type RecordsCrypto } from './loader';
import { keyringOf, type Keyring, type RecordsKeys, type RecordsSecretSource } from './keys';
import type { RecordsPinStore } from './pin-store';
import type { RecordsTransport } from './transport';
import { RecordsEncryptionError } from './words';

export const RECORDS_SUPPORT_HEADER = 'X-PacSpace-Records-Encryption';
export const RECORDS_GRANT_HEADER = 'X-PacSpace-Grant';
export const RECORDS_HOLDER_HEADER = 'X-PacSpace-Holder-For';
/** The door's step-up proof (card 10, F4): replacing or setting up a key at the key pages only. */
export const RECORDS_STEP_UP_HEADER = 'X-PacSpace-Step-Up';
const ENCRYPTION = '/api/v1/records/encryption';

/** Intake's sentences for the two caps (L2b), reused word for word before anything is sent. */
const SIZE_WORDS = {
  RECORD_ENTRY_TOO_LARGE: 'An encrypted entry fits in 47,104 bytes once encoded. Reference bulk payloads by digest instead.',
  RECORD_ENTRY_BODY_TOO_LARGE: 'An encrypted write fits in 65,536 bytes. Shorten its references, or split the entry.',
} as const;

type RecordKey = Awaited<ReturnType<RecordsCrypto['recordKeyOfV1']>>;
type Seed = Awaited<ReturnType<RecordsCrypto['workspaceSeedFromBytesV1']>>;
type SeedWrapView = { version: number; wrap: unknown };
/** GET identity: the current key (null after PacSpace retires it) and every retired one (card 10, F4). */
type OwnIdentity = {
  workspaceId?: string;
  xwingPublic: string | null;
  xwingPublicId: string | null;
  seedWraps: SeedWrapView[];
  retiredIdentities?: Array<{ xwingPublic: string; xwingPublicId: string; retiredAt: string; seedWraps: SeedWrapView[] }>;
};
/** What a key change returns: the new key, its code to read out, and the new version. */
export interface KeyChange {
  xwingPublicId: string;
  code: string;
  version: number;
  kid: string;
  holders: Array<{ holderId: string; workspaceId: string; wrapped: boolean; code?: string }>;
  holdersNeedingConfirmation: string[];
}
type Envelope = { kid?: unknown };
type Receipt = Record<string, unknown> & { schema?: string; seq?: number; envelopes?: Envelope[] };

const b64u = toBase64Url;
const fromB64u = fromBase64Url;
const unwrap = <T>(body: unknown): T => {
  const b = body as { schema?: unknown; data?: unknown } | null;
  return (b && b.schema === undefined && b.data !== undefined ? b.data : b) as T;
};

export function recordPathOf(recordType: string, entityId: string, suffix: string): string {
  return `/api/v1/records/${encodeURIComponent(recordType)}/${encodeURIComponent(entityId)}${suffix}`;
}

/** A refusal of the shared opener, as the SDK's sentence; entries count from 1. */
export function readRefusal(refusal: EncryptedReadRefusalV1): PacSpaceError {
  const entry = typeof refusal.seq === 'number' ? refusal.seq + 1 : undefined;
  switch (refusal.code) {
    case 'RECORD_HISTORY_WRONG_RECORD':
      return new RecordsEncryptionError('RECORDS_HISTORY_OTHER_RECORD');
    case 'RECORD_ENTRY_HASH_MISMATCH':
      return new RecordsEncryptionError('RECORDS_ENTRY_HASH_MISMATCH', { seq: entry });
    case 'RECORD_ENTRY_REFS_MISMATCH':
      return new RecordsEncryptionError('RECORDS_ENTRY_REFS_MISMATCH', { seq: entry });
    default:
      if (entry !== undefined) return new RecordsEncryptionError('RECORDS_ENTRY_UNOPENED', { seq: entry });
      return new PacSpaceError(refusal.code, 0, refusal.code);
  }
}

const receiptsOf = (history: RecordHistoryBundleV3): Receipt[] =>
  (Array.isArray(history?.receipts) ? history.receipts : []) as unknown as Receipt[];

/** The kids a history's v4 receipts carry, in every receipt's order. */
function kidsOf(receipts: Receipt[]): string[] {
  const kids: string[] = [];
  for (const receipt of receipts) {
    for (const envelope of receipt.envelopes ?? []) {
      if (typeof envelope?.kid === 'string' && !kids.includes(envelope.kid)) kids.push(envelope.kid);
    }
  }
  return kids;
}

/** An owner workspace id a wrap is bound to (card 10, F3), or W-C10-B-17 before any key is used. */
function ownerOf(rc: RecordsCrypto, value: unknown): string {
  if (typeof value !== 'string' || !rc.KEY_WRAP_OWNER_V2.test(value)) throw new RecordsEncryptionError('RECORDS_OWNER_INVALID');
  return value;
}

export interface Pinned {
  workspaceId: string;
  publicKey: Uint8Array;
  publicKeyId: string;
}

/**
 * The encrypted paths of `pac.records`. Keys stay in this process: requests
 * carry wire ids, record hashes, content tags, envelopes and wraps only.
 */
export class EncryptedRecords {
  /** A record's version, once known: `recordType \0 wireRecordId` to version. */
  private readonly versionOf = new Map<string, number>();
  /**
   * The record hash version intake took last (card 10, F1): 2 until intake
   * says it takes only 3. A refusal on one names the other, once.
   */
  private hashVersion: 2 | 3 = 2;
  private workspaceId: string | null = null;

  constructor(
    private readonly client: RecordsTransport,
    readonly keys: RecordsKeys,
    readonly pins: RecordsPinStore,
  ) {}

  // ------------------------------------------------------------ ids

  async wireId(recordType: string, record: string): Promise<string> {
    const { rc, ring } = await this.keys.ring();
    return rc.wireRecordIdV1(ring.idKey, recordType, record);
  }

  async wireReferenceId(referenceId: string): Promise<string> {
    const { rc, ring } = await this.keys.ring();
    return rc.wireReferenceIdV1(ring.idKey, referenceId);
  }

  /** The id a read or a write puts in the path, and whether the record is read as encrypted. */
  async target(recordType: string, record: string | undefined, read: RecordReadOptions = {}): Promise<{ entityId: string; encrypted: boolean }> {
    if (read.wireRecordId) return { entityId: read.wireRecordId, encrypted: true };
    if (record === undefined) return { entityId: '', encrypted: false };
    const encrypted = read.encrypted !== false && (this.keys.configured || read.recordKey !== undefined);
    if (!encrypted) return { entityId: record, encrypted: false };
    return { entityId: await this.wireId(recordType, record), encrypted: true };
  }

  // ------------------------------------------------------------ write

  /** Intake's admission, run here because intake cannot read encrypted content. */
  private admit(recordType: string, lifecycle: string, content: Record<string, unknown>): void {
    const layouts = listPublishedLayouts().filter((l) => l.doc.recordTypeId === recordType);
    if (layouts.length === 0) return;
    let first: { code: string; message: string } | null = null;
    for (const layout of layouts) {
      const admission = admitRecordEntryV1(layout, { lifecycle, content });
      if (admission.ok) return;
      if (!first) {
        first =
          admission.code === 'RECORD_FIELD_RESERVED'
            ? { code: admission.code, message: `fields.${admission.field} is set by PacSpace and cannot be supplied.` }
            : { code: admission.code, message: admission.error.message };
      }
    }
    if (first) throw new PacSpaceError(first.message, 400, first.code);
  }

  async emit(
    input: { recordType: string; record: string; lifecycle: string; content: Record<string, unknown>; idempotencyKey?: string },
    options?: RequestOptions,
  ): Promise<{ response: Record<string, unknown>; wireRecordId: string; wireReferenceId: string }> {
    const { rc, ring } = await this.keys.ring();
    const { recordType, lifecycle, content } = input;
    this.admit(recordType, lifecycle, content);
    const wireRecordId = await rc.wireRecordIdV1(ring.idKey, recordType, input.record);
    const saltKey = rc.newSaltKeyV2();
    const recordHashes = {
      2: (await rc.commitRecordContentV2(content, saltKey)).recordHash,
      3: (await rc.commitRecordContentV3(content, saltKey)).recordHash,
    };
    const outside: Record<string, unknown> = {};
    if (content.amends !== undefined) outside.amends = content.amends;
    if (content.references !== undefined) outside.references = content.references;
    const plaintextBytes = rc.recordEntryPlaintextV1(content, saltKey).length;

    // Card 10, F2: the tag is keyed by the record's version, and the default
    // reference is made from it, so it deduplicates within one version only.
    let wireReferenceId = '';
    const bodyUnder = async (version: number, hashVersion: 2 | 3) => {
      const recordsKey = ring.byVersion(version);
      const tagKey = ring.contentTagKey(version);
      if (!recordsKey || !tagKey) throw new RecordsEncryptionError('RECORDS_VERSION_NOT_HELD', { v: version });
      const contentTag = await rc.contentTagV2(tagKey, { recordType, wireRecordId, content, lifecycle });
      wireReferenceId = await rc.wireReferenceIdV1(ring.idKey, input.idempotencyKey ?? contentTag);
      const fields = {
        lifecycle,
        referenceId: wireReferenceId,
        recordHash: recordHashes[hashVersion],
        ...(hashVersion === 3 ? { recordHashVersion: 3 } : {}),
        contentTag,
        ...outside,
      };
      const size = rc.checkEncryptedWriteSizeV1(fields, recordsKey.id, plaintextBytes);
      if (!size.ok) throw new PacSpaceError(SIZE_WORDS[size.code], 413, size.code);
      const recordKey = await rc.recordKeyOfV1(recordsKey, wireRecordId);
      return { ...fields, envelope: await rc.sealRecordEntryV1({ recordKey, recordType, wireRecordId, content, saltKey }) };
    };

    const cacheKey = `${recordType}\0${wireRecordId}`;
    let version = this.versionOf.get(cacheKey) ?? ring.current.version;
    let hashVersion = this.hashVersion;
    let keyRetried = false;
    let hashRetried = false;
    let claimRetried = false;
    const path = recordPathOf(recordType, wireRecordId, '/transitions');
    let response: Record<string, unknown>;
    for (;;) {
      try {
        response = await this.client.post<Record<string, unknown>>(path, await bodyUnder(version, hashVersion), options);
        break;
      } catch (error) {
        if (!(error instanceof PacSpaceError)) throw error;
        const otherHash =
          (error.code === 'RECORD_HASH_VERSION_NOT_ENABLED' && hashVersion === 3) || (error.code === 'RECORD_FORMAT_RETIRED' && hashVersion === 2);
        if (otherHash && !hashRetried) {
          hashRetried = true;
          hashVersion = hashVersion === 3 ? 2 : 3;
          continue;
        }
        const body = apiErrorBody(error);
        const claimKid = body?.claimKid;
        if (error.code === 'IDEMPOTENCY_CONFLICT' && typeof claimKid === 'string' && !claimRetried) {
          const claimed = ring.byId(claimKid);
          if (!claimed) throw new RecordsEncryptionError('RECORDS_VERSION_NOT_HELD', { v: await this.versionNumberOf(claimKid), write: true });
          if (claimed.version === version) throw error;
          claimRetried = true;
          version = claimed.version;
          continue;
        }
        const recordKid = body?.recordKid;
        if (keyRetried || error.code !== 'RECORD_ENCRYPTION_VERSION_MISMATCH' || typeof recordKid !== 'string') throw error;
        const held = ring.byId(recordKid);
        if (!held) throw new RecordsEncryptionError('RECORDS_VERSION_NOT_HELD', { v: await this.versionNumberOf(recordKid) });
        keyRetried = true;
        version = held.version;
      }
    }
    this.versionOf.set(cacheKey, version);
    this.hashVersion = hashVersion;
    return { response, wireRecordId, wireReferenceId };
  }

  /** A kid's version, from this workspace's own registry; '?' when it isn't there. */
  private async versionNumberOf(kid: string): Promise<number | string> {
    try {
      const { versions } = await this.client.get<{ versions: Array<{ version: number; kid: string }> }>(`${ENCRYPTION}/versions`);
      return versions.find((v) => v.kid === kid)?.version ?? '?';
    } catch {
      return '?';
    }
  }

  // ------------------------------------------------------------ read

  /** Headers for a read: the support header always, and the grant or holder the caller named. */
  readHeaders(read: RecordReadOptions): Record<string, string> {
    return {
      [RECORDS_SUPPORT_HEADER]: '1',
      ...(read.grant ? { [RECORDS_GRANT_HEADER]: read.grant } : {}),
      ...(read.holderFor ? { [RECORDS_HOLDER_HEADER]: read.holderFor } : {}),
    };
  }

  /** The record's key for these receipts: the caller's, a grant's wrap, a holder's wrap, or the keyring. */
  async recordKeyFor(
    record: { recordType: string; wireRecordId: string },
    receipts: Receipt[],
    read: RecordReadOptions,
    options?: RequestOptions,
  ): Promise<{ rc: RecordsCrypto; recordKey: RecordKey; others?: RecordKey[] }> {
    if (read.recordKey !== undefined) {
      const rc = await loadRecordsCrypto();
      const bytes = fromB64u(read.recordKey);
      if (bytes.length !== 32) throw new RecordsEncryptionError('RECORDS_ENTRY_UNOPENED', { seq: 1 });
      return { rc, recordKey: await rc.recordKeyFromBytesV1(bytes) };
    }
    const { rc, ring } = await this.keys.ring();
    const kids = kidsOf(receipts);
    if (read.grant) {
      const owner = ownerOf(rc, read.owner);
      const seeds = await this.ownSeeds();
      const got = unwrap<{ rkid?: string; wrap?: unknown }>(
        await this.client.get(recordPathOf(record.recordType, record.wireRecordId, '/grant-key'), {
          ...options,
          headers: { [RECORDS_GRANT_HEADER]: read.grant },
        }),
      );
      for (const seed of typeof got?.rkid === 'string' ? seeds : []) {
        const opened = await rc.unwrapRecordKeyV2({ seed, wrap: got.wrap, owner, ...record, recordKeyId: got.rkid as string });
        if (opened.ok) return { rc, recordKey: opened.recordKey };
      }
      throw new RecordsEncryptionError('RECORDS_ENTRY_UNOPENED', { seq: 1 });
    }
    if (read.holderFor) {
      const owner = ownerOf(rc, read.holderFor);
      const seeds = await this.ownSeeds();
      const { holdings } = unwrap<{ holdings: Holding[] }>(await this.client.get(`${ENCRYPTION}/holdings`, options));
      const versions: Array<{ version: number; recordKey: RecordKey }> = [];
      for (const holding of holdings ?? []) {
        if (holding.ownerWorkspaceId !== owner) continue;
        for (const w of holding.wraps ?? []) {
          if (w.state === 'refused') continue;
          for (const seed of seeds) {
            if (
              holding.scope === 'record' &&
              typeof w.rkid === 'string' &&
              holding.record?.entityId === record.wireRecordId &&
              holding.record.recordType === record.recordType
            ) {
              const opened = await rc.unwrapRecordKeyV2({ seed, wrap: w.wrap, owner, ...record, recordKeyId: w.rkid });
              if (opened.ok) return { rc, recordKey: opened.recordKey };
            }
            if (holding.scope === 'workspace' && typeof w.version === 'number' && typeof w.kid === 'string' && (kids.length === 0 || kids.includes(w.kid))) {
              const opened = await rc.unwrapRecordsKeyV2({ seed, wrap: w.wrap, owner, version: w.version, recordsKeyId: w.kid });
              if (opened.ok) {
                versions.push({ version: w.version, recordKey: await rc.recordKeyOfV1(opened.recordsKey, record.wireRecordId) });
                break;
              }
            }
          }
        }
      }
      if (versions.length === 0) throw new RecordsEncryptionError('RECORDS_ENTRY_UNOPENED', { seq: 1 });
      versions.sort((a, b) => b.version - a.version);
      return { rc, recordKey: versions[0].recordKey, others: versions.slice(1).map((v) => v.recordKey) };
    }
    const held = kids.map((kid) => ring.byId(kid)).filter((k): k is NonNullable<typeof k> => k !== null);
    if (held.length === 0 && kids.length > 0) {
      throw new RecordsEncryptionError('RECORDS_VERSION_NOT_HELD', { v: await this.versionNumberOf(kids[0]) });
    }
    held.sort((a, b) => b.version - a.version);
    const newest = held[0] ?? ring.current;
    const others = await Promise.all(held.slice(1).map((k) => rc.recordKeyOfV1(k, record.wireRecordId)));
    return { rc, recordKey: await rc.recordKeyOfV1(newest, record.wireRecordId), others };
  }

  /** The record key in the bundled verifier's own form, with the version it came from; the bytes cross in memory only. */
  private async forVerifier(rc: RecordsCrypto, recordKey: RecordKey) {
    return recordKeyFromBytesV1(rc.exportKeyBytesV1(recordKey), recordKey.recordsKeyId);
  }

  /** Opens a v3 history: every v4 receipt and refused envelope, each checked against its record hash. */
  async openHistory(
    body: RecordHistoryBundleV3,
    record: { recordType: string; wireRecordId: string },
    read: RecordReadOptions,
    options?: RequestOptions,
  ): Promise<{ opened: Array<OpenedRecordEntry & { saltKey: string; seq: number }>; recordKey: RecordKey; rc: RecordsCrypto; sealsVerified: boolean }> {
    if (body.recordType !== record.recordType || body.entityId !== record.wireRecordId) {
      throw new RecordsEncryptionError('RECORDS_HISTORY_OTHER_RECORD');
    }
    const receipts = [...receiptsOf(body), ...((body.refused ?? []) as unknown as Array<{ envelope: Envelope }>).map((r) => ({ envelopes: [r.envelope] }))];
    const { rc, recordKey, others = [] } = await this.recordKeyFor(record, receipts, read, options);
    const result = await verifyRecordHistoryBundleV3(body, {
      recordKey: await this.forVerifier(rc, recordKey),
      recordKeys: await Promise.all(others.map((k) => this.forVerifier(rc, k))),
      expect: record,
    });
    if (!result.ok) throw readRefusal(result);
    const opened = result.opened
      .filter((e): e is Extract<typeof e, { content: Record<string, unknown> }> => 'content' in e)
      .map((e) => ({ entry: e.seq + 1, seq: e.seq, recordHash: e.recordHash, content: e.content, saltKey: e.saltKey }));
    return { opened, recordKey, rc, sealsVerified: result.verification.verified };
  }

  /** Opens one v4 receipt, or a v3 record's v5 (card 10). */
  async openReceipt(
    receipt: Receipt,
    record: { recordType: string; wireRecordId: string },
    read: RecordReadOptions,
    options?: RequestOptions,
  ): Promise<OpenedRecordEntry> {
    const { rc, recordKey } = await this.recordKeyFor(record, [receipt], read, options);
    const opened = await openReceiptV4(receipt, { recordKey: await this.forVerifier(rc, recordKey), ...record });
    if (!opened.ok) throw readRefusal(opened);
    return { entry: (receipt.seq as number) + 1, recordHash: opened.recordHash, content: opened.content };
  }

  /** N8's copy file: the history with its record key, for a reader with no workspace. */
  async copyOf(body: RecordHistoryBundleV3, recordKey: RecordKey, rc: RecordsCrypto): Promise<Uint8Array> {
    const copy = buildRecordCopyV1({ recordKey: await this.forVerifier(rc, recordKey), history: body });
    return new TextEncoder().encode(`${JSON.stringify(copy, null, 2)}\n`);
  }

  /** The record's own history, as the owner reads it; null when it has no entries yet. */
  async ownHistory(recordType: string, wireRecordId: string, options?: RequestOptions): Promise<RecordHistoryBundleV3 | null> {
    try {
      const raw = await this.client.getRaw<unknown>(recordPathOf(recordType, wireRecordId, '/bundle'), {
        ...options,
        headers: { [RECORDS_SUPPORT_HEADER]: '1' },
      });
      return unwrap<RecordHistoryBundleV3>(raw.body);
    } catch (error) {
      if (error instanceof PacSpaceError && error.statusCode === 404) return null;
      throw error;
    }
  }

  /** The owner's key for one record: the version its entries carry, or the current one before its first entry. */
  async ownRecordKey(recordType: string, wireRecordId: string, options?: RequestOptions): Promise<{ rc: RecordsCrypto; recordKey: RecordKey; history: RecordHistoryBundleV3 | null }> {
    const history = await this.ownHistory(recordType, wireRecordId, options);
    if (history && history.schema !== RECORD_HISTORY_BUNDLE_SCHEMA_V3) throw new RecordsEncryptionError('RECORDS_NOT_ENCRYPTED');
    const receipts = history ? receiptsOf(history).filter((r) => Array.isArray(r.envelopes)) : [];
    const { rc, recordKey } = await this.recordKeyFor({ recordType, wireRecordId }, receipts, {}, options);
    return { rc, recordKey, history };
  }

  // ------------------------------------------------------------ identity and pins

  async ownIdentity(): Promise<OwnIdentity> {
    return unwrap(await this.client.get(`${ENCRYPTION}/identity`));
  }

  /** This workspace's own id, as the API names it: the owner every wrap it makes is bound to. */
  async ownWorkspaceId(): Promise<string> {
    if (!this.workspaceId) {
      const { rc } = await this.keys.ring();
      this.workspaceId = ownerOf(rc, (await this.ownIdentity())?.workspaceId);
    }
    return this.workspaceId;
  }

  /**
   * One identity's seed, opened with `keyring`: null when no wrap opens,
   * 'outdated' when every wrap is under a version the keyring doesn't hold.
   * A seed that opens to another public key is `mismatch`'s refusal.
   */
  private async openSeedOf(
    rc: RecordsCrypto,
    keyring: Keyring,
    identity: { xwingPublic: string | null; xwingPublicId: string | null; seedWraps?: SeedWrapView[] },
    mismatch: 'RECORDS_IDENTITY_OTHER' | 'RECORDS_RETIRED_KEY_MISMATCH',
  ): Promise<Seed | 'outdated' | null> {
    if (!identity.xwingPublicId) return null;
    const wraps = identity.seedWraps ?? [];
    const held = wraps.filter((w) => keyring.versions.includes(w.version));
    for (const seedWrap of held) {
      const opened = await rc.openSeedWrapV1({ wrap: seedWrap.wrap, publicKeyId: identity.xwingPublicId, keyring });
      if (!opened.ok) continue;
      if (identity.xwingPublic !== b64u(opened.seed.publicKey)) throw new RecordsEncryptionError(mismatch);
      return opened.seed;
    }
    return held.length === 0 && wraps.length > 0 ? 'outdated' : null;
  }

  /** This workspace's seed, opened with its own secret; null when it has no current identity. */
  async ownSeed(ring?: Keyring): Promise<Seed | null> {
    const { rc, ring: current } = await this.keys.ring();
    const own = await this.ownIdentity();
    if (!own?.xwingPublicId) return null;
    const seed = await this.openSeedOf(rc, ring ?? current, own, 'RECORDS_IDENTITY_OTHER');
    if (seed === 'outdated') throw new RecordsEncryptionError('RECORDS_SECRET_FILE_OUTDATED');
    if (!seed) throw new RecordsEncryptionError('RECORDS_IDENTITY_OTHER');
    return seed;
  }

  /**
   * Every seed this workspace's secret opens, current first, then each
   * retired one (card 10, F4): a wrap made to a key before it was replaced
   * still opens. A server still on the file before a replacement opens the
   * retired seeds only; with none, W-C10-B-18.
   */
  async ownSeeds(): Promise<Seed[]> {
    const { rc, ring } = await this.keys.ring();
    const own = await this.ownIdentity();
    const current = await this.openSeedOf(rc, ring, own, 'RECORDS_IDENTITY_OTHER');
    const seeds: Seed[] = current && current !== 'outdated' ? [current] : [];
    for (const retired of own.retiredIdentities ?? []) {
      const seed = await this.openSeedOf(rc, ring, retired, 'RECORDS_RETIRED_KEY_MISMATCH');
      if (seed && seed !== 'outdated') seeds.push(seed);
    }
    if (current === 'outdated' && seeds.length === 0) throw new RecordsEncryptionError('RECORDS_SECRET_FILE_OUTDATED');
    if (own.xwingPublicId && current === null && seeds.length === 0) throw new RecordsEncryptionError('RECORDS_IDENTITY_OTHER');
    return seeds;
  }

  /**
   * The seed of each identity this workspace has had, sealed under
   * `version` of `ring`: the current one must open; a retired one that
   * doesn't is left out (a key PacSpace retired that this workspace never
   * held). Undefined before the first identity.
   */
  private async seedWrapsFor(
    rc: RecordsCrypto,
    ring: Keyring,
    version: number,
    extra?: Seed,
  ): Promise<Record<string, unknown> | undefined> {
    const own = await this.ownIdentity();
    const seeds: Seed[] = [];
    if (own?.xwingPublicId) {
      const current = await this.openSeedOf(rc, ring, own, 'RECORDS_IDENTITY_OTHER');
      if (current === 'outdated') throw new RecordsEncryptionError('RECORDS_SECRET_FILE_OUTDATED');
      if (!current) {
        // A next file made from one older than a replacement reuses the
        // replacement's version number; the file it came from lacks it.
        const { ring: served } = await this.keys.ring();
        if (served !== ring && (await this.openSeedOf(rc, served, own, 'RECORDS_IDENTITY_OTHER')) === 'outdated') {
          throw new RecordsEncryptionError('RECORDS_SECRET_FILE_OUTDATED');
        }
        throw new RecordsEncryptionError('RECORDS_IDENTITY_OTHER');
      }
      seeds.push(current);
    }
    for (const retired of own?.retiredIdentities ?? []) {
      const seed = await this.openSeedOf(rc, ring, retired, 'RECORDS_RETIRED_KEY_MISMATCH');
      if (seed && seed !== 'outdated') seeds.push(seed);
    }
    if (extra) seeds.push(extra);
    if (seeds.length === 0) return undefined;
    const wrapKey = ring.wrapKey(version)!;
    const out: Record<string, unknown> = {};
    for (const seed of seeds) out[seed.publicKeyId] = await rc.sealSeedWrapV1(wrapKey, seed);
    return out;
  }

  /** Registers each version of the secret the API doesn't list yet. */
  async registerVersions(): Promise<void> {
    const { rc, ring } = await this.keys.ring();
    const listed = unwrap<{ versions?: Array<{ version: number }> }>(await this.client.get(`${ENCRYPTION}/versions`));
    const registered = new Set((listed?.versions ?? []).map((v) => v.version));
    for (const version of ring.versions) {
      if (!registered.has(version)) await this.putVersion(rc, ring, version);
    }
  }

  /**
   * PUT versions in format 2 (card 10, F3): the version's records key
   * wrapped to each workspace holder whose pin is held, with the holder set
   * those wraps were made for; read again once if that set changed.
   */
  private async putVersion(
    rc: RecordsCrypto,
    ring: Keyring,
    version: number,
  ): Promise<{ holders: Array<{ holderId: string; workspaceId: string; wrapped: boolean; code?: string }>; holdersNeedingConfirmation: string[] }> {
    const recordsKey = ring.byVersion(version)!;
    const seedWraps = await this.seedWrapsFor(rc, ring, version);
    for (let attempt = 0; ; attempt += 1) {
      const { holderSet, holders, holderWraps } = await this.holderWrapsFor(rc, recordsKey);
      try {
        const put = unwrap<{ holdersNeedingConfirmation?: string[] }>(
          await this.client.put(`${ENCRYPTION}/versions/${version}`, {
            kid: recordsKey.id,
            wrapFormat: 2,
            holderSet,
            holderWraps,
            ...(seedWraps ? { seedWraps } : {}),
          }),
        );
        return { holders, holdersNeedingConfirmation: put?.holdersNeedingConfirmation ?? [] };
      } catch (error) {
        if (attempt === 0 && error instanceof PacSpaceError && error.code === 'RECORDS_HOLDER_SET_CHANGED') continue;
        throw error;
      }
    }
  }

  /** The version's records key wrapped to each workspace holder whose pin is held, with the holder set those wraps were made for. */
  private async holderWrapsFor(
    rc: RecordsCrypto,
    recordsKey: NonNullable<ReturnType<Keyring['byVersion']>>,
  ): Promise<{
    holderSet: string | undefined;
    holders: Array<{ holderId: string; workspaceId: string; wrapped: boolean; code?: string }>;
    holderWraps: Array<{ holderId: string; pinnedId: string; wrap: unknown }>;
  }> {
    const owner = await this.ownWorkspaceId();
    const listed = unwrap<{ holderSet?: string; holders?: HolderView[] }>(await this.client.get(`${ENCRYPTION}/holders`));
    const holders: Array<{ holderId: string; workspaceId: string; wrapped: boolean; code?: string }> = [];
    const holderWraps: Array<{ holderId: string; pinnedId: string; wrap: unknown }> = [];
    for (const holder of listed?.holders ?? []) {
      if (holder.scope !== 'workspace' || holder.removedAt) continue;
      try {
        const pin = await this.pinned(holder.holderWorkspaceId);
        if (pin.publicKeyId !== holder.pinnedId) throw new RecordsEncryptionError('RECORDS_PIN_CHANGED');
        holderWraps.push({ holderId: holder.holderId, pinnedId: pin.publicKeyId, wrap: await rc.wrapRecordsKeyV2(pin.publicKey, recordsKey, owner) });
        holders.push({ holderId: holder.holderId, workspaceId: holder.holderWorkspaceId, wrapped: true });
      } catch (error) {
        if (!(error instanceof RecordsEncryptionError)) throw error;
        holders.push({ holderId: holder.holderId, workspaceId: holder.holderWorkspaceId, wrapped: false, code: error.code });
      }
    }
    return { holderSet: listed?.holderSet, holders, holderWraps };
  }

  /** Registers this workspace's identity and every version of its secret. Idempotent. */
  async registerIdentity(): Promise<{ xwingPublicId: string; code: string; created: boolean }> {
    const { rc, ring } = await this.keys.ring();
    const own = await this.ownIdentity();
    let result: { xwingPublicId: string; code: string; created: boolean };
    if (own?.xwingPublicId && own.xwingPublic) {
      const seed = await this.ownSeed();
      if (!seed) throw new RecordsEncryptionError('RECORDS_IDENTITY_OTHER');
      result = { xwingPublicId: seed.publicKeyId, code: await rc.holderKeyCodeV1(seed.publicKey), created: false };
    } else {
      const seed = await rc.workspaceSeedFromBytesV1(globalThis.crypto.getRandomValues(new Uint8Array(32)));
      const version = ring.current.version;
      const wrap = await rc.sealSeedWrapV1(ring.wrapKey(version)!, seed);
      const put = unwrap<{ xwingPublicId: string; created: boolean }>(
        await this.client.put(`${ENCRYPTION}/identity`, { xwingPublic: b64u(seed.publicKey), seedWrap: { version, wrap } }),
      );
      if (put.xwingPublicId !== seed.publicKeyId) throw new RecordsEncryptionError('RECORDS_IDENTITY_OTHER');
      result = { xwingPublicId: seed.publicKeyId, code: await rc.holderKeyCodeV1(seed.publicKey), created: put.created };
    }
    await this.registerVersions();
    return result;
  }

  /**
   * Another workspace's public key, pinned: the code is computed here from
   * the bytes fetched, never read from an API field. With `confirmedCode`
   * it must equal that code and is then pinned; without, the pin must exist
   * and still name the key served. Refuses before any wrap.
   */
  async pinned(workspaceId: string, confirmedCode?: string): Promise<Pinned> {
    const { rc } = await this.keys.ring();
    const served = unwrap<{ xwingPublic?: string; xwingPublicId?: string }>(
      await this.client.get(`${ENCRYPTION}/workspaces/${encodeURIComponent(workspaceId)}/identity`),
    );
    const publicKey = fromB64u(served?.xwingPublic ?? '');
    const publicKeyId = publicKey.length ? await rc.publicKeyIdV1(publicKey).catch(() => null) : null;
    const pin = await this.pins.get(workspaceId);
    if (confirmedCode === undefined) {
      if (!pin) throw new RecordsEncryptionError('RECORDS_CODE_REQUIRED');
      if (!publicKeyId || publicKeyId !== served.xwingPublicId || publicKeyId !== pin.publicKeyId) throw new RecordsEncryptionError('RECORDS_PIN_CHANGED');
      return { workspaceId, publicKey, publicKeyId };
    }
    const normalized = String(confirmedCode).trim().replace(/\s+/g, ' ');
    const code = publicKeyId ? await rc.holderKeyCodeV1(publicKey) : null;
    if (!publicKeyId || publicKeyId !== served.xwingPublicId || code !== normalized) throw new RecordsEncryptionError('RECORDS_CODE_MISMATCH');
    await this.pins.set(workspaceId, { publicKeyId, confirmedAt: new Date().toISOString() });
    return { workspaceId, publicKey, publicKeyId };
  }

  // ------------------------------------------------------------ holders

  async addHolder(
    input: { workspaceId: string; scope: 'workspace' | 'record'; required: boolean; record?: { recordType: string; wireRecordId: string }; confirmedCode?: string },
  ): Promise<{ holderId: string; created: boolean; wraps: Array<{ version: number | null; state: string }> }> {
    const { rc, ring } = await this.keys.ring();
    const pin = await this.pinned(input.workspaceId, input.confirmedCode);
    const owner = await this.ownWorkspaceId();
    await this.registerVersions();
    const added = unwrap<{ holderId: string; created: boolean }>(
      await this.client.postNow(`${ENCRYPTION}/holders`, {
        workspaceId: input.workspaceId,
        scope: input.scope,
        required: input.required,
        pinnedId: pin.publicKeyId,
        ...(input.record ? { record: { recordType: input.record.recordType, entityId: input.record.wireRecordId } } : {}),
      }),
    );
    const wraps: Array<{ version: number | null; state: string }> = [];
    const holderPath = `${ENCRYPTION}/holders/${encodeURIComponent(added.holderId)}/wraps`;
    if (input.scope === 'workspace') {
      for (const version of ring.versions) {
        const wrap = await rc.wrapRecordsKeyV2(pin.publicKey, ring.byVersion(version)!, owner);
        const stored = unwrap<{ state: string }>(await this.client.put(holderPath, { version, pinnedId: pin.publicKeyId, wrap }));
        wraps.push({ version, state: stored.state });
      }
    } else if (input.record) {
      const { recordKey } = await this.ownRecordKey(input.record.recordType, input.record.wireRecordId);
      const wrap = await rc.wrapRecordKeyV2(pin.publicKey, recordKey, input.record, owner);
      const stored = unwrap<{ state: string }>(await this.client.put(holderPath, { pinnedId: pin.publicKeyId, rkid: recordKey.id, wrap }));
      wraps.push({ version: null, state: stored.state });
    }
    return { holderId: added.holderId, created: added.created, wraps };
  }

  /**
   * Opens each stored wrap with this workspace's seed and confirms it, or
   * refuses it so the writer is told. A workspace wrap's key id is
   * recomputed from the opened bytes; a record wrap is confirmed by opening
   * one of the record's entries, and waits while the record has none.
   */
  async confirmHoldings(): Promise<Array<{ holderId: string; version: number | null; state: string; reason?: string }>> {
    const { rc } = await this.keys.ring();
    // A wrap made to a key before it was replaced still opens with that key's seed (card 10, F4).
    const seeds = await this.ownSeeds();
    if (seeds.length === 0) return [];
    const { holdings } = unwrap<{ holdings: Holding[] }>(await this.client.get(`${ENCRYPTION}/holdings`));
    const results: Array<{ holderId: string; version: number | null; state: string; reason?: string }> = [];
    for (const holding of holdings ?? []) {
      const base = `${ENCRYPTION}/holdings/${encodeURIComponent(holding.holderId)}`;
      const owner = ownerOf(rc, holding.ownerWorkspaceId);
      for (const w of holding.wraps ?? []) {
        if (w.state !== 'stored') {
          results.push({ holderId: holding.holderId, version: w.version, state: w.state });
          continue;
        }
        let kid: string | null = null;
        let reason: 'unopened' | 'kid_mismatch' = 'unopened';
        if (holding.scope === 'workspace' && typeof w.version === 'number' && typeof w.kid === 'string') {
          for (const seed of seeds) {
            const opened = await rc.unwrapRecordsKeyV2({ seed, wrap: w.wrap, owner, version: w.version, recordsKeyId: w.kid });
            if (opened.ok) {
              kid = w.kid;
              break;
            }
            if (opened.code === 'KEY_WRAP_KEY_MISMATCH') reason = 'kid_mismatch';
          }
        } else if (holding.scope === 'record' && holding.record && typeof w.rkid === 'string') {
          const record = { recordType: holding.record.recordType, wireRecordId: holding.record.entityId };
          for (const seed of seeds) {
            const opened = await rc.unwrapRecordKeyV2({ seed, wrap: w.wrap, owner, ...record, recordKeyId: w.rkid });
            if (!opened.ok) continue;
            kid = await this.kidOpenedBy(rc, opened.recordKey, record, owner);
            break;
          }
          if (kid === 'none-yet') {
            results.push({ holderId: holding.holderId, version: null, state: 'stored' });
            continue;
          }
        }
        if (kid) {
          await this.client.postNow(`${base}/confirm`, { ...(w.version !== null ? { version: w.version } : {}), kid });
          results.push({ holderId: holding.holderId, version: w.version, state: 'confirmed' });
        } else {
          await this.client.postNow(`${base}/refuse`, { ...(w.version !== null ? { version: w.version } : {}), reason });
          results.push({ holderId: holding.holderId, version: w.version, state: 'refused', reason });
        }
      }
    }
    return results;
  }

  /** The kid of the first envelope this record key opens, read as a holder; 'none-yet' before any entry. */
  private async kidOpenedBy(
    rc: RecordsCrypto,
    recordKey: RecordKey,
    record: { recordType: string; wireRecordId: string },
    owner: string,
  ): Promise<string | null> {
    let body: RecordHistoryBundleV3;
    try {
      const raw = await this.client.getRaw<unknown>(recordPathOf(record.recordType, record.wireRecordId, '/bundle'), {
        headers: { [RECORDS_SUPPORT_HEADER]: '1', [RECORDS_HOLDER_HEADER]: owner },
      });
      body = unwrap<RecordHistoryBundleV3>(raw.body);
    } catch (error) {
      if (error instanceof PacSpaceError && error.statusCode === 404) return 'none-yet';
      throw error;
    }
    const envelopes = receiptsOf(body).flatMap((r) => r.envelopes ?? []);
    if (envelopes.length === 0) return 'none-yet';
    for (const envelope of envelopes) {
      const opened = await rc.openRecordEntryEnvelopeV1({ envelope, ...record, recordKey });
      if (opened.ok && typeof envelope.kid === 'string') return envelope.kid;
    }
    return null;
  }

  // ------------------------------------------------------------ grants and disclosure wraps

  async grantReaderWrap(
    record: { recordType: string; wireRecordId: string },
    workspaceId: string,
    confirmedCode: string | undefined,
  ): Promise<{ pinnedId: string; rkid: string; wrap: unknown } | null> {
    const { rc, recordKey, history } = await this.ownRecordKey(record.recordType, record.wireRecordId);
    if (!history) return null;
    const pin = await this.pinned(workspaceId, confirmedCode);
    const owner = await this.ownWorkspaceId();
    return { pinnedId: pin.publicKeyId, rkid: recordKey.id, wrap: await rc.wrapRecordKeyV2(pin.publicKey, recordKey, record, owner) };
  }

  async disclosureWrap(handle: string, disclosureKey: Uint8Array, workspaceId: string, confirmedCode: string | undefined) {
    const { rc } = await this.keys.ring();
    const pin = await this.pinned(workspaceId, confirmedCode);
    const owner = await this.ownWorkspaceId();
    return { workspaceId, pinnedId: pin.publicKeyId, wrap: await rc.wrapDisclosureKeyV2(pin.publicKey, disclosureKey, handle, owner) };
  }

  /** A disclosure link's key from this workspace's wrap, or null when the sharer stored none for it. */
  async disclosureKeyFromWrap(handle: string): Promise<Uint8Array | null> {
    if (!this.keys.configured) return null;
    const { rc } = await this.keys.ring();
    let got: { ownerWorkspaceId?: string; wrap?: unknown };
    try {
      got = unwrap(await this.client.postNow(`/api/v1/records/disclosures/key-wrap`, { handle }));
    } catch (error) {
      if (error instanceof PacSpaceError && (error.statusCode === 404 || error.statusCode === 409)) return null;
      throw error;
    }
    const owner = ownerOf(rc, got?.ownerWorkspaceId);
    for (const seed of await this.ownSeeds()) {
      const opened = await rc.unwrapDisclosureKeyV2({ seed, wrap: got?.wrap, owner, handle });
      if (opened.ok) return opened.disclosureKey;
    }
    return null;
  }

  // ------------------------------------------------------------ rotate and re-key

  async rotate(nextSource: RecordsSecretSource): Promise<{
    version: number;
    kid: string;
    holders: Array<{ holderId: string; workspaceId: string; wrapped: boolean; code?: string }>;
    holdersNeedingConfirmation: string[];
  }> {
    const { next, newest } = await this.nextOf(nextSource);
    const recordsKey = next.ring.byVersion(newest)!;
    // The new version carries the seed of each key this workspace holds (card 10, F4).
    const { holders, holdersNeedingConfirmation } = await this.putVersion(next.rc, next.ring, newest);
    this.keys.replace(next);
    return { version: newest, kid: recordsKey.id, holders, holdersNeedingConfirmation };
  }

  /** `nextSource` read and checked to add exactly the next version and keep every earlier one. */
  private async nextOf(nextSource: RecordsSecretSource) {
    const { ring } = await this.keys.ring();
    const next = await keyringOf(nextSource);
    const newest = Math.max(...next.ring.versions);
    const expected = [...ring.versions, Math.max(...ring.versions) + 1];
    const sameEarlier = ring.versions.every((v) => next.ring.byVersion(v)?.id === ring.byVersion(v)?.id);
    if (next.ring.versions.join(',') !== expected.join(',') || !sameEarlier) throw new RecordsEncryptionError('RECORDS_ROTATE_NOT_NEXT');
    return { next, newest };
  }

  /**
   * Replaces this workspace's key, at the key pages' door only (card 10,
   * F4; design v5, D3 a): `stepUp` is the door's step-up proof. The API
   * challenges the current key, this seed answers, and the new key and
   * `nextSource`'s new version are written together. Save `nextSource`'s
   * file before calling: it is the only secret that opens the new key.
   */
  async replaceKey(nextSource: RecordsSecretSource, stepUp: string): Promise<KeyChange> {
    const { next, newest } = await this.nextOf(nextSource);
    const rc = next.rc;
    const current = await this.ownSeed();
    if (!current) throw new RecordsEncryptionError('RECORDS_IDENTITY_OTHER');
    const owner = await this.ownWorkspaceId();
    const fresh = await rc.workspaceSeedFromBytesV1(globalThis.crypto.getRandomValues(new Uint8Array(32)));
    const headers = { [RECORDS_STEP_UP_HEADER]: stepUp };
    const challenge = unwrap<{ challengeId: string; enc: string; fromXwingPublicId: string }>(
      await this.client.postNow(`${ENCRYPTION}/identity/rotations/challenge`, { xwingPublic: b64u(fresh.publicKey) }, { headers }),
    );
    if (challenge?.fromXwingPublicId !== current.publicKeyId) throw new RecordsEncryptionError('RECORDS_IDENTITY_OTHER');
    const binding = { workspaceId: owner, fromId: current.publicKeyId, newId: fresh.publicKeyId, challengeId: challenge.challengeId };
    const proof = await rc.rotationProofV1(current, challenge.enc, binding);
    const recordsKey = next.ring.byVersion(newest)!;
    const seedWraps = await this.seedWrapsFor(rc, next.ring, newest, fresh);
    const { holderSet, holders, holderWraps } = await this.holderWrapsFor(rc, recordsKey);
    const done = unwrap<{ holdersNeedingConfirmation?: string[] }>(
      await this.client.postNow(
        `${ENCRYPTION}/identity/rotations`,
        {
          fromXwingPublicId: current.publicKeyId,
          xwingPublic: b64u(fresh.publicKey),
          challengeId: challenge.challengeId,
          proof,
          token: holderSet,
          version: { number: newest, kid: recordsKey.id, seedWraps, holderWraps },
        },
        { headers },
      ),
    );
    this.keys.replace(next);
    return {
      xwingPublicId: fresh.publicKeyId,
      code: await rc.holderKeyCodeV1(fresh.publicKey),
      version: newest,
      kid: recordsKey.id,
      holders,
      holdersNeedingConfirmation: done?.holdersNeedingConfirmation ?? [],
    };
  }

  /**
   * Sets up a new key after PacSpace retired this workspace's key at its
   * request (card 10, F4; D4 a), at the door only, with `nextSource`'s new
   * version. The new key's seed is sealed under that version only.
   */
  async setUpKey(nextSource: RecordsSecretSource, stepUp: string): Promise<KeyChange> {
    const { next, newest } = await this.nextOf(nextSource);
    const rc = next.rc;
    const fresh = await rc.workspaceSeedFromBytesV1(globalThis.crypto.getRandomValues(new Uint8Array(32)));
    const recordsKey = next.ring.byVersion(newest)!;
    const seedWraps = await this.seedWrapsFor(rc, next.ring, newest, fresh);
    const { holderSet, holders, holderWraps } = await this.holderWrapsFor(rc, recordsKey);
    const done = unwrap<{ holdersNeedingConfirmation?: string[] }>(
      await this.client.postNow(
        `${ENCRYPTION}/identity/registrations`,
        { xwingPublic: b64u(fresh.publicKey), token: holderSet, version: { number: newest, kid: recordsKey.id, seedWraps, holderWraps } },
        { headers: { [RECORDS_STEP_UP_HEADER]: stepUp } },
      ),
    );
    this.keys.replace(next);
    return {
      xwingPublicId: fresh.publicKeyId,
      code: await rc.holderKeyCodeV1(fresh.publicKey),
      version: newest,
      kid: recordsKey.id,
      holders,
      holdersNeedingConfirmation: done?.holdersNeedingConfirmation ?? [],
    };
  }

  /**
   * Re-seals each stored entry's same plaintext under the version's record
   * key, latest entry first (same salt key, so each record hash is
   * unchanged), then wraps the new record key to the record's grants and
   * record holders whose pins are held. Stops at the first refusal.
   */
  async rekey(input: {
    recordType: string;
    wireRecordId: string;
    toVersion: number;
    /** Called after each entry, done or already under the version. */
    onEntry?: (progress: { done: number; total: number }) => void;
  }): Promise<{
    entries: Array<{ entry: number; state: 'swapped' | 'already' }>;
    grants: Array<{ grantId: string; wrapped: boolean; code?: string }>;
    holders: Array<{ holderId: string; wrapped: boolean; code?: string }>;
  }> {
    const { rc, ring } = await this.keys.ring();
    const record = { recordType: input.recordType, wireRecordId: input.wireRecordId };
    const owner = await this.ownWorkspaceId();
    const toKey = ring.byVersion(input.toVersion);
    if (!toKey) throw new RecordsEncryptionError('RECORDS_VERSION_NOT_HELD', { v: input.toVersion });
    const history = await this.ownHistory(record.recordType, record.wireRecordId);
    if (!history || history.schema !== RECORD_HISTORY_BUNDLE_SCHEMA_V3) throw new RecordsEncryptionError('RECORDS_NOT_ENCRYPTED');
    const { opened } = await this.openHistory(history, record, {});
    const newKey = await rc.recordKeyOfV1(toKey, record.wireRecordId);
    const bySeq = new Map(receiptsOf(history).map((r) => [r.seq as number, r]));
    const entries: Array<{ entry: number; state: 'swapped' | 'already' }> = [];
    for (const entry of [...opened].sort((a, b) => b.seq - a.seq)) {
      const receipt = bySeq.get(entry.seq);
      if (receipt?.envelopes?.some((e) => e?.kid === toKey.id)) {
        entries.push({ entry: entry.entry, state: 'already' });
        input.onEntry?.({ done: entries.length, total: opened.length });
        continue;
      }
      try {
        const envelope = await rc.sealRecordEntryV1({ recordKey: newKey, ...record, content: entry.content, saltKey: entry.saltKey });
        await this.client.put(recordPathOf(record.recordType, record.wireRecordId, `/entries/${entry.seq}/envelope`), { envelope });
      } catch {
        throw new RecordsEncryptionError('RECORDS_REKEY_STOPPED', { seq: entry.entry });
      }
      entries.push({ entry: entry.entry, state: 'swapped' });
      input.onEntry?.({ done: entries.length, total: opened.length });
    }

    const grants: Array<{ grantId: string; wrapped: boolean; code?: string }> = [];
    const listed = unwrap<{ grants: Array<{ grantId: string; kind: string; status: string; counterpartyWorkspaceId: string | null; readerWrap: unknown }> }>(
      await this.client.get(recordPathOf(record.recordType, record.wireRecordId, '/grants')),
    );
    for (const grant of listed.grants ?? []) {
      if (grant.status !== 'ACTIVE' || grant.kind !== 'TENANT_BOUND' || !grant.counterpartyWorkspaceId || !grant.readerWrap) continue;
      try {
        const pin = await this.pinned(grant.counterpartyWorkspaceId);
        const wrap = await rc.wrapRecordKeyV2(pin.publicKey, newKey, record, owner);
        await this.client.put(recordPathOf(record.recordType, record.wireRecordId, `/grants/${encodeURIComponent(grant.grantId)}/key-wrap`), {
          pinnedId: pin.publicKeyId,
          rkid: newKey.id,
          wrap,
        });
        grants.push({ grantId: grant.grantId, wrapped: true });
      } catch (error) {
        if (!(error instanceof RecordsEncryptionError)) throw error;
        grants.push({ grantId: grant.grantId, wrapped: false, code: error.code });
      }
    }

    const holders: Array<{ holderId: string; wrapped: boolean; code?: string }> = [];
    const holderList = unwrap<{ holders: Array<HolderView> }>(await this.client.get(`${ENCRYPTION}/holders`));
    for (const holder of holderList.holders ?? []) {
      if (holder.scope !== 'record' || holder.removedAt || holder.record?.entityId !== record.wireRecordId || holder.record.recordType !== record.recordType) continue;
      try {
        const pin = await this.pinned(holder.holderWorkspaceId);
        if (pin.publicKeyId !== holder.pinnedId) throw new RecordsEncryptionError('RECORDS_PIN_CHANGED');
        const wrap = await rc.wrapRecordKeyV2(pin.publicKey, newKey, record, owner);
        await this.client.put(`${ENCRYPTION}/holders/${encodeURIComponent(holder.holderId)}/wraps`, { pinnedId: pin.publicKeyId, rkid: newKey.id, wrap });
        holders.push({ holderId: holder.holderId, wrapped: true });
      } catch (error) {
        if (!(error instanceof RecordsEncryptionError)) throw error;
        holders.push({ holderId: holder.holderId, wrapped: false, code: error.code });
      }
    }
    return { entries, grants, holders };
  }

  /** For `records.recordKey()`: `RK` as base64url. */
  exportRecordKey(rc: RecordsCrypto, recordKey: RecordKey): string {
    return b64u(rc.exportKeyBytesV1(recordKey));
  }

  requestOptions(read: RecordReadOptions, options?: RequestOptions): ClientRequestOptions {
    return { ...options, headers: this.readHeaders(read) };
  }
}

interface Holding {
  holderId: string;
  ownerWorkspaceId: string;
  scope: 'workspace' | 'record';
  record: { recordType: string; entityId: string } | null;
  wraps: Array<{ version: number | null; kid: string | null; rkid?: string | null; wrap: unknown; state: string }>;
}

interface HolderView {
  holderId: string;
  holderWorkspaceId: string;
  scope: 'workspace' | 'record';
  pinnedId: string;
  removedAt?: string | null;
  record: { recordType: string; entityId: string } | null;
}
