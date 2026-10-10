// The shared verifier and the two public-source readers. @pacspace/shared is
// not published; scripts/build.mjs bundles exactly scripts/shared-surface.ts
// in by alias, so the installed package carries the check (since 0.10.0).
import {
  blindedDigest,
  buildRecordDisclosureV1,
  buildRecordLinkCopyV1,
  createMirrorNodeRecordChainReader,
  createRpcRecordChainReader,
  disclosureFormOfV1,
  getPublishedLayoutRegistry,
  matchHeldFile,
  readChainRootsV1,
  recordContentOfReceipt,
  recordEntryKindV1,
  RecordDisclosureError,
  verifyRecordDisclosureV1,
  verifyRecordHistoryBundle,
  verifyRecordSealHistoryV1,
  decryptDisclosureV1,
  readDisclosureFragmentV1,
  RECORD_HISTORY_BUNDLE_SCHEMA_V3,
  type HeldFile,
  type RecordChainReader,
  type RecordHistoryBundle,
  type RecordHistoryBundleV3,
  type RecordDisclosureV1,
  type RecordSealHistoryV1,
} from '@pacspace/shared';
import { BLINDING_WORDS, Blinding, blindingValueOf } from '../blinding';
import { refuseBlindingMaterial } from '../blinding-guard';
import type { HttpClient } from '../client';
import { PacSpaceError, ValidationError, mapApiError } from '../errors';
import { chunksOf, plainRef, type FingerprintInput } from '../fingerprint';
import { EncryptedRecords } from '../records-encryption/encrypted-records';
import { RecordsKeys } from '../records-encryption/keys';
import { memoryPinStore } from '../records-encryption/pin-store';
import { RecordsEncryptionError } from '../records-encryption/words';
import type { RequestOptions } from '../types/config';
import type {
  EntryNumber,
  RecordCheckInput,
  RecordCheckSource,
  RecordDiscloseInput,
  RecordDisclosureFile,
  RecordEmitInput,
  RecordEmitResponse,
  RecordHistory,
  RecordHistoryCheck,
  RecordHistoryEntry,
  RecordHistoryInput,
  RecordReadOptions,
  RecordReceiptInput,
  RecordReceiptResponse,
} from '../types/records';
import { DEFAULT_RECORD_TYPE } from '../types/records';
import type {
  RecordCopyFile,
  RecordOpenOptions,
  RecordOpenResult,
  RecordRekeyInput,
  RecordRekeyResult,
  RecordRotateResult,
  RecordTarget,
  RecordsEncryptionOptions,
  RecordsGrantCreateInput,
  RecordsHolderAddInput,
  RecordsHolderAddResult,
  RecordsHoldingResult,
  RecordsIdentityResult,
  RecordsShareKeyWrapInput,
} from '../types/records-encryption';

function recordPath(recordType: string | undefined, record: string, suffix: string): string {
  const type = encodeURIComponent(recordType || DEFAULT_RECORD_TYPE);
  const id = encodeURIComponent(record);
  return `/api/v1/records/${type}/${id}${suffix}`;
}

/**
 * The SDK counts entries from 1, as every PacSpace page does; the wire counts
 * the same positions from 0 as `seq`. These two functions are the whole
 * conversion, so no caller of the SDK sends or reads a `seq`. An entry below
 * 1 is refused with the sentence that teaches the rule, rather than sent as
 * the wrong entry (0.10 took the wire number under the name `entry`, so
 * `entry: 1` named the second entry; this is the correction, 0.11.0).
 */
function seqOf(entry: EntryNumber, field: string): number {
  if (!Number.isInteger(entry) || entry < 1) {
    throw new ValidationError(
      `${field} is ${String(entry)}. Entries count from 1: the first entry is entry 1. (The HTTP API's seq counts the same positions from 0.)`,
    );
  }
  return entry - 1;
}

function entryOf(seq: number | null | undefined): EntryNumber | null {
  return typeof seq === 'number' ? seq + 1 : null;
}

function payloadsOf(receipt: Record<string, unknown>): Array<{ alg?: string; digest?: string; byteLength?: string }> {
  const content =
    recordContentOfReceipt(receipt) ??
    (receipt.recordContent as Record<string, unknown> | undefined) ??
    ((receipt.sealedRecord as { content?: Record<string, unknown> } | undefined)?.content);
  const payloads = content?.payloads;
  return Array.isArray(payloads) ? payloads : [];
}

function fingerprintKey(ref: { alg?: string; digest?: string; byteLength?: string }): string {
  return `${ref.alg ?? ''}:${String(ref.digest ?? '').toLowerCase()}:${ref.byteLength ?? ''}`;
}

const CHECK_NOTE = 'A blinded entry was not matched. Pass each file with its blinding file to check it.';
const DISCLOSE_NEEDS_SOURCE =
  'records.disclose needs a source: the public ledger to check the file against, as in records.check. Nothing was sent.';
/** A pointer names a field or one item of a list field: at most two segments. */
const REVEAL_POINTER = /^\/[^/]*(\/[^/]*)?$/;

/** A reader of the caller's public source, at the caller's contract or the record's own. */
function readerOf(source: RecordCheckSource, chain: { chainId?: number; contractAddress?: string } | undefined): RecordChainReader | null {
  const contractAddress = source.address || chain?.contractAddress;
  if (!contractAddress) return null;
  return source.kind === 'direct' && source.url
    ? createRpcRecordChainReader({ rpcUrl: source.url, contractAddress, chainId: chain?.chainId })
    : createMirrorNodeRecordChainReader({ mirrorBaseUrl: source.url, contractAddress, chainId: chain?.chainId });
}

/** The answer of `GET .../disclosure-source`: the seal history and the full receipts. */
interface DisclosureSource {
  sealHistory: RecordSealHistoryV1;
  bundle: { schema?: string; receipts?: Array<Record<string, unknown>> };
}

/** The held file's digests, from its bytes; the HMAC only when its blinding is given. */
async function heldFileOf(source: FingerprintInput, blinding: Blinding | null): Promise<HeldFile> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of chunksOf(source)) chunks.push(chunk);
  const plain = await plainRef(chunks);
  if (!blinding) return { sha256: plain.digest, byteLength: plain.byteLength };
  const blinded = await blindedDigest(chunks, blindingValueOf(blinding));
  return {
    sha256: plain.digest,
    byteLength: plain.byteLength,
    hmac: { digest: blinded.digest, blindingDigest: blinding.digest, blindingByteLength: blinding.byteLength },
  };
}

function historyEntries(history: RecordHistory): RecordHistoryEntry[] {
  if (Array.isArray(history.entries) && history.entries.length > 0) {
    return history.entries;
  }
  const committed = (history.receipts ?? []).map((receipt) => ({
    seq: typeof receipt.seq === 'number' ? receipt.seq : null,
    status: (receipt.status as RecordHistoryEntry['status']) || 'committed',
    receiptId: typeof receipt.receiptId === 'string' ? receipt.receiptId : undefined,
  }));
  return [...committed, ...(history.pendingEntries ?? [])].sort(
    (a, b) => (a.seq ?? 0) - (b.seq ?? 0),
  );
}

/** A link's handle as the disclosure is bound to it: decoded, trimmed, lower case. */
function normalizedHandle(handle: string): string {
  let decoded = handle;
  try {
    decoded = decodeURIComponent(handle);
  } catch {
    decoded = handle;
  }
  return decoded.trim().toLowerCase();
}

/** A link route's refusal, with the API's own sentence and code. */
type LinkErrorBody = { message?: unknown; code?: unknown; error?: { message?: unknown; code?: unknown } };

async function linkRefusal(response: Response, path: string): Promise<PacSpaceError> {
  let body: LinkErrorBody | null;
  try {
    body = (await response.json()) as LinkErrorBody | null;
  } catch {
    body = null;
  }
  const message = body?.error?.message ?? body?.message;
  const code = body?.error?.code ?? body?.code;
  return mapApiError(response.status, typeof message === 'string' ? message : response.statusText, path, response.headers, {
    code: typeof code === 'string' ? code : undefined,
  });
}

/** A disclosure key from bytes, a link, its `#dk=` part, or the key as base64url. */
function disclosureKeyOf(value: Uint8Array | string): Uint8Array | null {
  if (value instanceof Uint8Array) return value.length === 32 ? value : null;
  const text = String(value).trim();
  const hash = /^https?:/i.test(text) ? new URL(text).hash : text.startsWith('#') ? text : text.startsWith('dk=') ? `#${text}` : `#dk=${text}`;
  return readDisclosureFragmentV1(hash);
}

export class RecordsResource {
  private readonly encrypted: EncryptedRecords;

  /** This workspace's identity for encrypted records (ADR 0015, N14). */
  readonly identity: {
    /** Draws the seed, registers its public part and the seed wrapped under the current version, and every version's id. Idempotent. */
    register(): Promise<RecordsIdentityResult>;
  };

  /** The workspaces this workspace's keys are wrapped to. Wraps go only to a workspace whose code you confirmed. */
  readonly holders: {
    add(input: RecordsHolderAddInput): Promise<RecordsHolderAddResult>;
    list(): Promise<Record<string, unknown>>;
    remove(holderId: string): Promise<Record<string, unknown>>;
  };

  /** The wraps other workspaces stored for this one. */
  readonly holdings: {
    list(): Promise<Record<string, unknown>>;
    /** Opens each stored wrap, checks it, and confirms it or refuses it so the writer is told. */
    confirm(): Promise<RecordsHoldingResult[]>;
  };

  /** Grants on a record. A grant to a named workspace of an encrypted record carries the record's key, wrapped to it. */
  readonly grants: {
    create(input: RecordsGrantCreateInput): Promise<Record<string, unknown>>;
    list(target: RecordTarget): Promise<Record<string, unknown>>;
    revoke(target: RecordTarget & { grantId: string }): Promise<Record<string, unknown>>;
  };

  constructor(
    private readonly client: HttpClient,
    encryption?: RecordsEncryptionOptions,
  ) {
    this.encrypted = new EncryptedRecords(client, new RecordsKeys(encryption), encryption?.pinStore ?? memoryPinStore());
    const enc = this.encrypted;
    const ENCRYPTION = '/api/v1/records/encryption';
    this.identity = {
      register: () => enc.registerIdentity(),
    };
    this.holders = {
      add: async (input) => {
        const scope = input.scope ?? 'workspace';
        const record =
          scope === 'record' && input.record
            ? { recordType: input.record.recordType || DEFAULT_RECORD_TYPE, wireRecordId: (await this.targetOf(input.record)).entityId }
            : undefined;
        return enc.addHolder({ workspaceId: input.workspaceId, scope, required: input.required === true, record, confirmedCode: input.confirmedCode });
      },
      list: async () => this.client.get(`${ENCRYPTION}/holders`),
      remove: async (holderId) => this.client.delete(`${ENCRYPTION}/holders/${encodeURIComponent(holderId)}`),
    };
    this.holdings = {
      list: async () => this.client.get(`${ENCRYPTION}/holdings`),
      confirm: () => enc.confirmHoldings(),
    };
    this.grants = {
      create: async (input) => {
        const recordType = input.recordType || DEFAULT_RECORD_TYPE;
        const target = await this.targetOf(input);
        const body: Record<string, unknown> = { kind: input.kind };
        if (input.recipientEmail !== undefined) body.recipientEmail = input.recipientEmail;
        if (input.counterpartyWorkspaceId !== undefined) body.counterpartyTenantId = input.counterpartyWorkspaceId;
        if (input.authorizes !== undefined) body.authorizes = input.authorizes;
        if (input.ttlHours !== undefined) body.ttlHours = input.ttlHours;
        if (input.maxUses !== undefined) body.maxUses = input.maxUses;
        if (input.label !== undefined) body.label = input.label;
        if (target.encrypted && enc.keys.configured && input.kind === 'TENANT_BOUND' && input.counterpartyWorkspaceId) {
          const readerWrap = await enc.grantReaderWrap({ recordType, wireRecordId: target.entityId }, input.counterpartyWorkspaceId, input.confirmedCode);
          if (readerWrap) body.readerWrap = readerWrap;
        }
        return this.client.postNow(recordPath(recordType, target.entityId, '/grants'), body);
      },
      list: async (target) => {
        const t = await this.targetOf(target);
        return this.client.get(recordPath(target.recordType, t.entityId, '/grants'));
      },
      revoke: async (target) => {
        const t = await this.targetOf(target);
        return this.client.postNow(recordPath(target.recordType, t.entityId, `/grants/${encodeURIComponent(target.grantId)}/revoke`), {});
      },
    };
  }

  private async targetOf(target: RecordTarget & RecordReadOptions): Promise<{ entityId: string; encrypted: boolean }> {
    return this.encrypted.target(target.recordType || DEFAULT_RECORD_TYPE, target.record, target);
  }

  /** The wire id PacSpace knows a record by, as a webhook names it. Needs the workspace secret. */
  async wireId(input: { recordType?: string; record: string }): Promise<string> {
    return this.encrypted.wireId(input.recordType || DEFAULT_RECORD_TYPE, input.record);
  }

  /** The wire id of an entry's reference id. Needs the workspace secret. */
  async wireReferenceId(referenceId: string): Promise<string> {
    return this.encrypted.wireReferenceId(referenceId);
  }

  async emit(input: RecordEmitInput, options?: RequestOptions): Promise<RecordEmitResponse> {
    const content: Record<string, unknown> = {
      title: input.title,
      occurredAt: input.occurredAt,
      actorId: input.actorId,
      payloads: input.payloads,
    };
    if (input.kind !== undefined) content.kind = input.kind;
    if (input.instructedBy !== undefined) content.instructedBy = input.instructedBy;
    if (input.description !== undefined) content.description = input.description;
    if (input.note !== undefined) content.note = input.note;
    if (input.references) {
      content.references = input.references.map((ref, index) => ({
        recordKey: ref.recordKey,
        seq: seqOf(ref.entry, `references[${index}].entry`),
      }));
    }
    if (input.amends) {
      content.amends = { recordKey: input.amends.recordKey, seq: seqOf(input.amends.entry, 'amends.entry') };
    }
    refuseBlindingMaterial(content);

    let response: Record<string, unknown>;
    let wire: { wireRecordId: string; wireReferenceId: string } | null = null;
    if (this.encrypted.keys.configured && input.encrypt !== false) {
      const sent = await this.encrypted.emit(
        {
          recordType: input.recordType || DEFAULT_RECORD_TYPE,
          record: input.record,
          lifecycle: input.lifecycle ?? 'recorded',
          content,
          idempotencyKey: input.idempotencyKey,
        },
        options,
      );
      response = sent.response;
      wire = { wireRecordId: sent.wireRecordId, wireReferenceId: sent.wireReferenceId };
    } else {
      const body: Record<string, unknown> = {
        lifecycle: input.lifecycle ?? 'recorded',
        content,
      };
      if (input.idempotencyKey) body.referenceId = input.idempotencyKey;
      response = await this.client.post<Record<string, unknown>>(
        recordPath(input.recordType, input.record, '/transitions'),
        body,
        options,
      );
    }
    const encryptedFields = wire
      ? { recordId: input.record, wireRecordId: wire.wireRecordId, wireReferenceId: wire.wireReferenceId, encrypted: true }
      : {};
    if (response.code === 'IDEMPOTENCY_PENDING') {
      return {
        receiptId: '',
        recordType: input.recordType || DEFAULT_RECORD_TYPE,
        entityId: wire?.wireRecordId ?? input.record,
        recordKey: '',
        status: 'QUEUED',
        code: 'IDEMPOTENCY_PENDING',
        retryAfterSeconds: typeof response.retryAfterSeconds === 'number'
          ? response.retryAfterSeconds
          : undefined,
        message: typeof response.message === 'string' ? response.message : undefined,
        ...encryptedFields,
      };
    }
    return {
      intakeId: typeof response.intakeId === 'string' ? response.intakeId : undefined,
      receiptId: String(response.receiptId ?? ''),
      recordType: String(response.recordType ?? input.recordType ?? DEFAULT_RECORD_TYPE),
      entityId: String(response.entityId ?? input.record),
      recordKey: String(response.recordKey ?? ''),
      layoutId: typeof response.layoutId === 'number' ? response.layoutId : undefined,
      layoutVersion: typeof response.layoutVersion === 'number' ? response.layoutVersion : undefined,
      lifecycle: typeof response.lifecycle === 'string' ? response.lifecycle : undefined,
      status: String(response.status ?? 'QUEUED'),
      referenceId: wire ? input.idempotencyKey : typeof response.referenceId === 'string' ? response.referenceId : undefined,
      receivedAt: typeof response.receivedAt === 'string' ? response.receivedAt : undefined,
      queuedViaOverflow: response.queuedViaOverflow === true,
      message: typeof response.message === 'string' ? response.message : undefined,
      ...encryptedFields,
    };
  }

  /**
   * One entry's receipt. An encrypted entry is opened with the workspace
   * secret, a holder wrap, a grant's wrap or a record key, and checked
   * against its sealed record hash (`opened`).
   */
  async receipt(input: RecordReceiptInput, options?: RequestOptions): Promise<RecordReceiptResponse> {
    const recordType = input.recordType || DEFAULT_RECORD_TYPE;
    const target = await this.targetOf(input);
    const path = recordPath(recordType, target.entityId, `/receipts/${seqOf(input.entry, 'entry')}`);
    if (!target.encrypted) {
      return this.client.get<RecordReceiptResponse>(path, input.grant ? this.encrypted.requestOptions({ grant: input.grant }, options) : options);
    }
    const response = await this.client.get<RecordReceiptResponse>(path, this.encrypted.requestOptions(input, options));
    if ((response.receipt as { schema?: unknown })?.schema !== 'semantic-receipt/v4') return response;
    if (response.recordType !== recordType || response.entityId !== target.entityId) throw new RecordsEncryptionError('RECORDS_HISTORY_OTHER_RECORD');
    const opened = await this.encrypted.openReceipt(response.receipt, { recordType, wireRecordId: target.entityId }, input, options);
    return { ...response, opened };
  }

  /**
   * The record's history. An encrypted record's entries are opened and
   * each checked against its sealed record hash and its stored references
   * (`opened`); a history served for another record is refused.
   */
  async history(input: RecordHistoryInput, options?: RequestOptions): Promise<RecordHistory> {
    return this.readHistory(input, '/history', options);
  }

  /** The history as the downloadable file; opened as `history()` opens it. */
  async bundle(input: RecordHistoryInput, options?: RequestOptions): Promise<RecordHistory> {
    return this.readHistory(input, '/bundle', options);
  }

  private async readHistory(input: RecordHistoryInput, route: '/history' | '/bundle', options?: RequestOptions): Promise<RecordHistory> {
    const recordType = input.recordType || DEFAULT_RECORD_TYPE;
    const target = await this.targetOf(input);
    const query = new URLSearchParams();
    if (input.fromEntry !== undefined) query.set('fromSeq', String(seqOf(input.fromEntry, 'fromEntry')));
    if (input.toEntry !== undefined) query.set('toSeq', String(seqOf(input.toEntry, 'toEntry')));
    const suffix = query.toString() ? `${route}?${query.toString()}` : route;
    const raw = await this.client.getRaw<RecordHistory>(
      recordPath(recordType, target.entityId, suffix),
      target.encrypted || input.grant ? this.encrypted.requestOptions(target.encrypted ? input : { grant: input.grant }, options) : options,
    );
    const next = raw.headers.get('x-next-from-seq');
    const history: RecordHistory = {
      ...raw.body,
      nextFromSeq: next !== null ? Number(next) : raw.body.nextFromSeq ?? null,
    };
    if (!target.encrypted || raw.body?.schema !== RECORD_HISTORY_BUNDLE_SCHEMA_V3) return history;
    const { opened } = await this.encrypted.openHistory(
      raw.body as unknown as RecordHistoryBundleV3,
      { recordType, wireRecordId: target.entityId },
      input,
      options,
    );
    return { ...history, opened: opened.map(({ entry, recordHash, content }) => ({ entry, recordHash, content })) };
  }

  /**
   * A copy of one encrypted record (pacspace-record-copy/v1): its history
   * with its record key, for a reader with no workspace. Whoever holds the
   * file can read the record.
   */
  async keepCopy(target: RecordTarget, options?: RequestOptions): Promise<RecordCopyFile> {
    const recordType = target.recordType || DEFAULT_RECORD_TYPE;
    const t = await this.targetOf(target);
    if (!t.encrypted) throw new RecordsEncryptionError('RECORDS_NOT_ENCRYPTED');
    const { rc, recordKey, history } = await this.encrypted.ownRecordKey(recordType, t.entityId, options);
    if (!history) throw new RecordsEncryptionError('RECORDS_NOT_ENCRYPTED');
    await this.encrypted.openHistory(history, { recordType, wireRecordId: t.entityId }, {}, options);
    return { schema: 'pacspace-record-copy/v1', bytes: await this.encrypted.copyOf(history, recordKey, rc) };
  }

  /**
   * One record's key, base64url, for a recipient with no workspace: with a
   * grant on the record they read it as `history({ wireRecordId, grant,
   * recordKey })`. It opens this record only.
   */
  async recordKey(target: RecordTarget, options?: RequestOptions): Promise<string> {
    const recordType = target.recordType || DEFAULT_RECORD_TYPE;
    const t = await this.targetOf(target);
    if (!t.encrypted) throw new RecordsEncryptionError('RECORDS_NOT_ENCRYPTED');
    const { rc, recordKey } = await this.encrypted.ownRecordKey(recordType, t.entityId, options);
    return this.encrypted.exportRecordKey(rc, recordKey);
  }

  /**
   * Stores a disclosure link's key wrapped to a reader workspace whose code
   * you confirmed, so it opens the link without the part after #.
   */
  async shareKeyWrap(input: RecordsShareKeyWrapInput, options?: RequestOptions): Promise<Record<string, unknown>> {
    const recordType = input.recordType || DEFAULT_RECORD_TYPE;
    const t = await this.targetOf(input);
    const key = disclosureKeyOf(input.disclosureKey);
    if (!key) throw new RecordsEncryptionError('RECORDS_LINK_NO_KEY');
    const handle = normalizedHandle(input.handle);
    const body = await this.encrypted.disclosureWrap(handle, key, input.workspaceId, input.confirmedCode);
    return this.client.put(recordPath(recordType, t.entityId, `/share/${encodeURIComponent(handle)}/key-wraps`), body, options);
  }

  /**
   * Opens a disclosure link: its seal history, checked, and its disclosure,
   * opened with the key after # or, when there is none, with this
   * workspace's wrap, then checked against batch roots read from `source`
   * (the public mirror by default), never from PacSpace.
   */
  async open(link: string, input: RecordOpenOptions = {}): Promise<RecordOpenResult> {
    const url = new URL(link, this.client.getBaseUrl());
    const match = /\/c\/([^/]+)\/?$/.exec(url.pathname);
    if (!match) throw new RecordDisclosureError('DISCLOSURE_MALFORMED');
    const handle = normalizedHandle(match[1]);
    const path = (tail: string) => `/api/v1/c/${encodeURIComponent(handle)}${tail}`;
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (input.accessCode) {
      const verified = await this.client.fetchPublic(path('/access/verify'), {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ factor: 'ACCESS_HINT', value: input.accessCode }),
      });
      if (!verified.ok) throw await linkRefusal(verified, path('/access/verify'));
      const cookie = (verified.headers.get('set-cookie') ?? '').split(';')[0];
      if (cookie) headers.Cookie = cookie;
    }
    const seals = await this.client.fetchPublic(path('/history'), { method: 'GET', headers: { ...headers, 'X-Record-Entries': 'all' } });
    if (!seals.ok) throw await linkRefusal(seals, path('/history'));
    const form = (await seals.json()) as RecordSealHistoryV1;
    if (!verifyRecordSealHistoryV1(form, { layouts: getPublishedLayoutRegistry() }).verified) {
      throw new RecordDisclosureError('DISCLOSURE_MALFORMED');
    }
    const answer = await this.client.fetchPublic(path('/disclosure'), { method: 'GET', headers });
    const envelope = answer.ok ? ((await answer.json()) as { envelope?: unknown })?.envelope : undefined;
    if (typeof envelope !== 'string') return { handle, sealHistory: form as unknown as Record<string, unknown>, disclosure: null, entries: [] };

    const key = readDisclosureFragmentV1(url.hash) ?? (await this.encrypted.disclosureKeyFromWrap(handle));
    if (!key) throw new RecordsEncryptionError('RECORDS_LINK_NO_KEY');
    const opened = await decryptDisclosureV1({ envelope, key, handle });
    if (!opened.ok) throw new PacSpaceError(opened.reason, 0, opened.code);
    const disclosure = opened.disclosure as RecordDisclosureV1;
    const disclosureForm = disclosureFormOfV1(form, disclosure);
    if (!disclosureForm) throw new RecordDisclosureError('DISCLOSURE_MALFORMED');
    const { chainRoots } = await readChainRootsV1(
      readerOf(input.source ?? { kind: 'mirror' }, form.chain),
      disclosureForm.entries.map((entry) => entry.batchId),
    );
    const checked = await verifyRecordDisclosureV1({ form: disclosureForm, chainRoots, disclosure });
    if (!checked.ok) throw new PacSpaceError(checked.reason, 0, checked.code);
    return {
      handle,
      sealHistory: form as unknown as Record<string, unknown>,
      disclosure: disclosure as unknown as Record<string, unknown>,
      entries: checked.entries.map((entry) => ({ entry: entry.seq + 1, fields: entry.fields, content: entry.content, withheld: entry.withheld })),
    };
  }

  /**
   * Moves to the next workspace secret: registers its new version, wraps
   * that version's key to every workspace holder whose pin is held, and
   * wraps this workspace's seed under it. Writes under it wait for
   * required holders to confirm.
   */
  async rotate(input: { nextKeyring: string }): Promise<RecordRotateResult> {
    return this.encrypted.rotate(input.nextKeyring);
  }

  /**
   * Re-encrypts a record's stored entries under a newer version, latest
   * first; seals and record hashes are unchanged. Then wraps the record's
   * new key to its grants and record holders whose pins are held.
   */
  async rekey(input: RecordRekeyInput): Promise<RecordRekeyResult> {
    const recordType = input.recordType || DEFAULT_RECORD_TYPE;
    const t = await this.targetOf(input);
    if (!t.encrypted) throw new RecordsEncryptionError('RECORDS_NOT_ENCRYPTED');
    return this.encrypted.rekey({ recordType, wireRecordId: t.entityId, toVersion: input.toVersion });
  }

  async check(input: RecordCheckInput): Promise<RecordHistoryCheck> {
    const entries = historyEntries(input.history);
    const expectRows = (input.expect ?? []).map((row, index) => {
      const seq = seqOf(row.entry, `expect[${index}].entry`);
      refuseBlindingMaterial({ payloads: row.payloads });
      for (const file of row.files ?? []) {
        if (file?.blinding !== undefined && file.blinding !== null && !(file.blinding instanceof Blinding)) {
          throw new ValidationError(BLINDING_WORDS.notAFile);
        }
      }
      return { seq, payloads: row.payloads ?? [], files: row.files ?? [] };
    });
    const expectBySeq = new Map<number, { payloads: typeof expectRows[number]['payloads']; held: HeldFile[] }>();
    for (const row of expectRows) {
      const held: HeldFile[] = [];
      for (const file of row.files) held.push(await heldFileOf(file.source, file.blinding ?? null));
      expectBySeq.set(row.seq, { payloads: row.payloads, held });
    }
    const receiptsBySeq = new Map<number, Record<string, unknown>>();
    for (const receipt of input.history.receipts ?? []) {
      if (typeof receipt.seq === 'number') receiptsBySeq.set(receipt.seq, receipt);
    }

    const blindingFileNeeded: EntryNumber[] = [];
    const entryResults = entries.map((entry) => {
      const result: RecordHistoryCheck['entries'][number] = {
        entry: entryOf(entry.seq),
        status: entry.status,
        code: entry.code,
        sentence: entry.sentence,
      };
      const wanted = entry.seq !== null ? expectBySeq.get(entry.seq) : undefined;
      if (entry.seq !== null && wanted) {
        const committed = payloadsOf(receiptsBySeq.get(entry.seq) ?? {});
        const committedKeys = new Set(committed.map(fingerprintKey));
        const payloadsOk = wanted.payloads.every((ref) => committedKeys.has(fingerprintKey(ref)));
        let filesOk = true;
        for (const held of wanted.held) {
          const match = matchHeldFile(committed, held);
          if (match.matched) continue;
          filesOk = false;
          if (match.blindingNeeded && !blindingFileNeeded.includes(entry.seq + 1)) blindingFileNeeded.push(entry.seq + 1);
        }
        result.expected = payloadsOk && filesOk;
      }
      return result;
    });

    let failedCheck: string | null = null;
    let reason: string | undefined;
    let sourceChecked = false;
    let chainWord: string | undefined;
    const history = input.history as unknown as RecordHistoryBundle;

    if (input.source) {
      try {
        const reader = readerOf(input.source, input.history.chain);
        if (reader) {
          chainWord = await reader.getRecord(input.history.recordKey);
          sourceChecked = true;
        }
      } catch {
        sourceChecked = false;
      }
    }

    // The check itself: every seal, the chain between entries, the file's
    // own digest, and the current word when the public source gave one. A
    // verifier that throws confirms nothing; the result says so and is not ok.
    let bundleOk = false;
    try {
      const verification = await verifyRecordHistoryBundle(history, chainWord !== undefined ? { chainWord } : {});
      bundleOk = verification.verified;
      const verifiedSeqs = new Set(
        (verification.history?.perReceipt ?? []).filter((row) => row.result.verified).map((row) => row.seq),
      );
      for (const [index, entry] of entries.entries()) {
        const receipt = entry.seq !== null && entry.status === 'committed' ? receiptsBySeq.get(entry.seq) : undefined;
        entryResults[index].kind =
          receipt && verifiedSeqs.has(entry.seq as number) && typeof receipt.newWord === 'string'
            ? recordEntryKindV1(history.layout, receipt.newWord).kind
            : null;
      }
      if (!verification.verified) {
        failedCheck = verification.history?.perReceipt.find((row) => !row.result.verified)?.result.failedCheck
          ?? (verification.schemaOk ? (verification.digestOk ? 'semantic' : 'schema') : 'schema');
        reason = verification.reason;
      }
    } catch (error) {
      failedCheck = 'schema';
      reason = `The check did not finish: ${error instanceof Error ? error.message : String(error)}`;
    }
    for (const row of entryResults) if (row.kind === undefined) row.kind = null;

    const expectFailed = entryResults.some((row) => row.expected === false);
    if (expectFailed && !failedCheck) failedCheck = 'semantic';

    const failedEntries = entries.filter((entry) => entry.status === 'failed');
    if (failedEntries.length > 0 && !failedCheck) {
      failedCheck = 'schema';
      reason = failedEntries[0]?.sentence ?? 'A queued write did not commit.';
    }

    const result: RecordHistoryCheck = {
      ok: bundleOk && !expectFailed && failedEntries.length === 0 && failedCheck === null,
      entries: entryResults,
      failedCheck,
      sourceChecked,
      reason,
    };
    if (blindingFileNeeded.length > 0) {
      result.blindingFileNeeded = blindingFileNeeded;
      result.note = CHECK_NOTE;
    }
    return result;
  }

  /**
   * A kept copy revealing the chosen fields of chosen entries: one read of
   * the record's seal history and full receipts, the disclosure built from
   * them, and the disclosure checked against batch roots read from the
   * caller's `source`, never from PacSpace. It uploads nothing and makes no
   * link; the bytes carry only the salts of the revealed fields.
   */
  async disclose(input: RecordDiscloseInput, options?: RequestOptions): Promise<RecordDisclosureFile> {
    if (!input?.source) throw new ValidationError(DISCLOSE_NEEDS_SOURCE);
    const malformed = () => new ValidationError(new RecordDisclosureError('DISCLOSURE_MALFORMED').message);
    if (!Array.isArray(input.entries) || input.entries.length === 0) throw malformed();
    const wanted = new Map<number, 'all' | string[]>();
    input.entries.forEach((item, index) => {
      const seq = seqOf(item?.entry, `entries[${index}].entry`);
      if (wanted.has(seq)) throw malformed();
      const reveal = item.reveal;
      if (reveal !== 'all' && (!Array.isArray(reveal) || reveal.some((p) => typeof p !== 'string' || !REVEAL_POINTER.test(p)))) {
        throw malformed();
      }
      wanted.set(seq, reveal === 'all' ? 'all' : [...reveal].sort());
    });

    const { body: source } = await this.client.getRaw<DisclosureSource>(
      recordPath(input.recordType, input.record, '/disclosure-source'),
      options,
    );
    const form = source?.sealHistory;
    const receipts = new Map<number, Record<string, unknown>>();
    for (const receipt of source?.bundle?.receipts ?? []) {
      if (typeof receipt?.seq === 'number') receipts.set(receipt.seq, receipt);
    }
    if (!verifyRecordSealHistoryV1(form, { layouts: getPublishedLayoutRegistry() }).verified) {
      throw new RecordDisclosureError('DISCLOSURE_MALFORMED');
    }
    for (const [seq, reveal] of wanted) {
      if (reveal !== 'all' && receipts.get(seq)?.schema !== 'semantic-receipt/v3') {
        throw new RecordDisclosureError('DISCLOSURE_MALFORMED');
      }
    }

    const entries = [...wanted.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([seq, reveal]) => {
        const receipt = receipts.get(seq);
        if (!receipt) throw new RecordDisclosureError('DISCLOSURE_MALFORMED');
        return { receipt: receipt as never, reveal };
      });
    const disclosure = await buildRecordDisclosureV1({
      recordKey: form.recordKey,
      chain: form.chain,
      layout: form.layout,
      entries,
    });
    const disclosureForm = disclosureFormOfV1(form, disclosure);
    if (!disclosureForm) throw new RecordDisclosureError('DISCLOSURE_MALFORMED');
    const { chainRoots } = await readChainRootsV1(
      readerOf(input.source, form.chain),
      disclosureForm.entries.map((entry) => entry.batchId),
    );
    const checked = await verifyRecordDisclosureV1({ form: disclosureForm, chainRoots, disclosure });
    if (!checked.ok) throw new PacSpaceError(checked.reason, 0, checked.code);
    const copy = await buildRecordLinkCopyV1({ sealHistory: form, disclosure });
    return { bytes: copy.bytes, schema: 'record-link-copy/v1' };
  }
}
