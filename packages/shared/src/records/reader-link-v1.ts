/**
 * The link's reader record (records prototype build, R5; "Cryptography and proof"; D-3, D-17, D-21, D-24): the
 * entries PacSpace writes, through the records system writer, on `machine-action-record/v1` under entity id
 * `share-<shareId>` (never served) with origin `READER_LINK`.
 *
 * Every entry uses the content forms `record-content-v1.ts` accepts, as the trail index record's do. No field
 * holds a person's name or address, the reader's organisation, the word for the thing shared, a source, a label
 * or an environment: readers receive these entries. People are committed by count and epoch only.
 */
import { payloadDigestV1, trailIndexTime, TRAIL_INDEX_ACTOR, TRAIL_INDEX_RECORD_TYPE, type PayloadDigestV1 } from './trail-index-v1';
import type { SharedRecordAckBodyV2 } from './shared-record-ack-v2';

export const READER_LINK_RECORD_TYPE = TRAIL_INDEX_RECORD_TYPE;

/** The reader's citable reference: `SR-` plus 8 base62 characters, drawn apart from the handle (D-3). */
export const SHARE_REFERENCE_PATTERN = /^SR-[0-9A-Za-z]{8}$/;
export const SHARE_REFERENCE_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

/** A link's access code: two groups of four from the prototype's alphabet (no I, O, 0 or 1). */
export const SHARE_CODE_PATTERN = /^[A-Z2-9]{4}-[A-Z2-9]{4}$/;
export const SHARE_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

/** Wrong codes in a row before a link's code stops (E-15). */
export const SHARE_CODE_TRIES = 5;

export type ReaderLinkKind =
  | 'link-made'
  | 'allowance-changed'
  | 'link-extended'
  | 'person-added'
  | 'person-removed'
  | 'link-key-changed'
  | 'workspace-key-changed'
  | 'record-revealed'
  | 'link-turned-off'
  | 'device-added'
  | 'device-confirmed'
  | 'device-removed'
  | 'request'
  | 'answer'
  | 'acknowledgment'
  | 'flag'
  | 'flag-message';

export interface ReaderLinkContentV1 {
  title: string;
  kind: ReaderLinkKind;
  occurredAt: string;
  actorId: string;
  payloads: PayloadDigestV1[];
  references?: Array<{ recordKey: string; seq: number }>;
}

export type RevealModeV1 = 'seals' | 'fields' | 'all';
export type AnswersByV1 = 'people' | 'agent';

/** What a link commits about what it reveals, who answers and when (D-21, D-22, D-38). */
export interface ReaderLinkTermsV1 {
  reference: string;
  allowance: number | null;
  endsOn: string;
  reveal: { mode: RevealModeV1; fields: string[]; time: boolean };
  answers: { by: AnswersByV1; fields: string[] };
  responseDays: number | null;
}

/** The record's entity id. */
export function readerLinkEntityId(shareId: string): string {
  return `share-${shareId}`;
}

/** The idempotency key of a link event's reader record entry. */
export function shareEventIdempotencyKey(shareId: string, seq: number): string {
  return `share:${shareId}:event:${seq}`;
}

const base = (title: string, kind: ReaderLinkKind, at: Date, payload: PayloadDigestV1): ReaderLinkContentV1 => ({
  title,
  kind,
  occurredAt: trailIndexTime(at),
  actorId: TRAIL_INDEX_ACTOR,
  payloads: [payload],
});

const sorted = (values: readonly string[]) => [...values].sort();

/**
 * "Link made": the digest of the link's terms, never a person's name or address; in an encrypted workspace, a second
 * payload commits the lab's tag of the workspace key for epoch 1.
 */
export function linkMadeContentV1(input: ReaderLinkTermsV1 & { workspaceKeyTag?: string | null; at: Date }): ReaderLinkContentV1 {
  const terms: ReaderLinkTermsV1 = {
    reference: input.reference,
    allowance: input.allowance,
    endsOn: input.endsOn,
    reveal: { mode: input.reveal.mode, fields: sorted(input.reveal.fields), time: input.reveal.time },
    answers: { by: input.answers.by, fields: sorted(input.answers.fields) },
    responseDays: input.responseDays,
  };
  return withKeyTag(base('Link made', 'link-made', input.at, payloadDigestV1(terms)), 1, input.workspaceKeyTag);
}

/**
 * The payload that commits the lab's tag of the workspace key for an epoch (R7; David, 2026-10-26), on "Link made"
 * (epoch 1) and "Link key changed": a reader's browser checks the tag it is served against this, on the link's own
 * record, as well as under its proof key, so a tag PacSpace serves later than the one committed does not hold.
 */
export function workspaceKeyTagPayloadV1(epoch: number, workspaceKeyTag: string): PayloadDigestV1 {
  return payloadDigestV1({ epoch, workspaceKeyTag });
}

const withKeyTag = (content: ReaderLinkContentV1, epoch: number, tag: string | null | undefined): ReaderLinkContentV1 =>
  typeof tag === 'string' ? { ...content, payloads: [...content.payloads, workspaceKeyTagPayloadV1(epoch, tag)] } : content;

/** "Allowance changed": the new allowance and the one before it. */
export function allowanceChangedContentV1(input: { allowance: number | null; from: number | null; at: Date }): ReaderLinkContentV1 {
  return base('Allowance changed', 'allowance-changed', input.at, payloadDigestV1({ allowance: input.allowance, from: input.from }));
}

/** "Link extended": the new last day. */
export function linkExtendedContentV1(input: { endsOn: string; at: Date }): ReaderLinkContentV1 {
  return base('Link extended', 'link-extended', input.at, payloadDigestV1({ endsOn: input.endsOn }));
}

/** "Person added" and "Person removed": how many people the link has after, and the link key's epoch. */
export function personChangedContentV1(input: { change: 'added' | 'removed'; count: number; epoch: number; at: Date }): ReaderLinkContentV1 {
  const added = input.change === 'added';
  return base(added ? 'Person added' : 'Person removed', added ? 'person-added' : 'person-removed', input.at, payloadDigestV1({ count: input.count, epoch: input.epoch }));
}

/** "Link key changed": the new epoch (a person removed), and in an encrypted workspace the tag for it. */
export function linkKeyChangedContentV1(input: { epoch: number; workspaceKeyTag?: string | null; at: Date }): ReaderLinkContentV1 {
  return withKeyTag(base('Link key changed', 'link-key-changed', input.at, payloadDigestV1({ epoch: input.epoch })), input.epoch, input.workspaceKeyTag);
}

/**
 * "Workspace key changed" (R7; David, 2026-10-26): after the workspace identity is rotated, the lab's tag of the new key
 * for the link's current epoch, which takes the place of the epoch's earlier tag. The link key and its epoch stay.
 */
export function workspaceKeyChangedContentV1(input: { epoch: number; workspaceKeyTag: string; at: Date }): ReaderLinkContentV1 {
  return withKeyTag(base('Workspace key changed', 'workspace-key-changed', input.at, payloadDigestV1({ epoch: input.epoch })), input.epoch, input.workspaceKeyTag);
}

/**
 * Whether `tag` is the tag the link's own record committed last for `epoch` (R7; ADR 0019's R7 addendum): the reader's
 * browser calls this before it seals anything to the workspace, after `servedWorkspaceKeyV1`. `entries` is the content
 * of every entry of the link's record, seq 0 upward with none left out, each read from a receipt the browser has
 * checked against the chain (`GET /api/v1/s/:handle/link-record`), and `committedEntries` the number of entries the
 * record's seal history holds once it, too, is checked against the chain's current word. Anything less holds nothing,
 * since a left-out entry, the last included, could be the one that replaced the tag. The tag of an epoch is the last
 * of "Link made" (epoch 1), "Link key changed" and "Workspace key changed" for it; a later entry for the epoch with no
 * tag leaves it untagged.
 */
export function workspaceKeyTagCommittedV1(entries: ReadonlyArray<{ seq: number; content: unknown }>, committedEntries: number, epoch: number, tag: string): boolean {
  if (typeof tag !== 'string' || !/^[0-9a-f]{64}$/.test(tag)) return false;
  const latest = lastWorkspaceKeyTagDigestV1(entries, committedEntries, epoch);
  return latest !== null && latest === workspaceKeyTagPayloadV1(epoch, tag).digest;
}

/**
 * The digest of the tag the link's own record committed last for `epoch`, read as `workspaceKeyTagCommittedV1` reads
 * it, or null where the record commits none for the epoch or is read short. Null is how a link that keeps no key reads
 * on its own record: one made while the workspace was plaintext commits no tag, and a key PacSpace served of its own
 * cannot be told from it by the served flag alone (U3r security review; David, 2026-11-03).
 */
export function lastWorkspaceKeyTagDigestV1(entries: ReadonlyArray<{ seq: number; content: unknown }>, committedEntries: number, epoch: number): string | null {
  if (!Array.isArray(entries) || !Number.isSafeInteger(epoch) || epoch < 1) return null;
  if (!Number.isSafeInteger(committedEntries) || entries.length !== committedEntries) return null;
  const sorted = [...entries].sort((a, b) => a.seq - b.seq);
  if (sorted.some((e, i) => e.seq !== i)) return null;
  const epochDigest = payloadDigestV1({ epoch }).digest;
  let latest: string | null = null;
  for (const { content } of sorted) {
    const c = content as { kind?: unknown; payloads?: unknown } | null;
    if (!c || typeof c !== 'object' || !Array.isArray(c.payloads)) continue;
    const payloads = c.payloads as Array<{ digest?: unknown } | null>;
    const forEpoch =
      c.kind === 'link-made' ? epoch === 1 : (c.kind === 'link-key-changed' || c.kind === 'workspace-key-changed') && payloads[0]?.digest === epochDigest;
    if (!forEpoch) continue;
    const tagged = payloads[1]?.digest;
    latest = typeof tagged === 'string' ? tagged : null;
  }
  return latest;
}

/** "Record {n} revealed": the member's last entry, and the digest of the reveal's ciphertext as uploaded. */
export function recordRevealedContentV1(input: { number: number; recordKey: string; lastSeq: number; envelope: string; at: Date }): ReaderLinkContentV1 {
  return {
    ...base(`Record ${input.number} revealed`, 'record-revealed', input.at, payloadDigestV1({ envelope: input.envelope })),
    references: [{ recordKey: input.recordKey.toLowerCase(), seq: input.lastSeq }],
  };
}

/** "Link turned off". */
export function linkTurnedOffContentV1(input: { at: Date }): ReaderLinkContentV1 {
  return base('Link turned off', 'link-turned-off', input.at, payloadDigestV1({ turnedOffOn: trailIndexTime(input.at).slice(0, 10) }));
}

/** How a device was confirmed (D-16): its code read back, a proof of the link key, or another confirmed device. */
export type DeviceConfirmedByV1 = 'code' | 'proof' | 'device';
export type DeviceKindV1 = 'browser' | 'agent';

/** "Device added", "Device confirmed" and "Device removed": the device's code, its kind and how it was confirmed. */
export function deviceChangedContentV1(input: {
  change: 'added' | 'confirmed' | 'removed';
  code: string;
  kind: DeviceKindV1;
  confirmedBy: DeviceConfirmedByV1 | null;
  at: Date;
}): ReaderLinkContentV1 {
  const titles = { added: 'Device added', confirmed: 'Device confirmed', removed: 'Device removed' } as const;
  return base(titles[input.change], `device-${input.change}`, input.at, payloadDigestV1({ code: input.code, kind: input.kind, confirmedBy: input.confirmedBy }));
}

/** A request's pick as committed: the member's number, the entry, the seal served for it, and how it was picked. */
export interface RequestItemV1 {
  number: number;
  seq: number;
  seal: string;
  picked: 'random' | 'chosen' | 'mismatch';
}

/** `pacspace-sample/v1` as a request commits it (D-14). */
export interface RequestSampleV1 {
  method: 'pacspace-sample/v1';
  seed: string;
  poolDigest: string;
  poolSize: number;
  leftOut: Array<{ number: number; seq: number }>;
  spread: 'any' | 'records' | 'days';
  removed: Array<{ number: number; seq: number }>;
}

/** What a request's entry commits: its picks, the sample, the question, and what the server worked out. */
export interface RequestManifestV1 {
  ref: string;
  items: RequestItemV1[];
  sample: RequestSampleV1 | null;
  question: string | null;
  beyond: number;
  dueOn: string | null;
}

/** "Request {Q-ref}": references each asked entry; the payload is the digest of the request manifest, the sample included. */
export function requestContentV1(input: { manifest: RequestManifestV1; recordKeys: ReadonlyMap<number, string>; at: Date }): ReaderLinkContentV1 {
  const references = input.manifest.items.map((i) => {
    const recordKey = input.recordKeys.get(i.number);
    if (!recordKey) throw new Error('every asked entry names its record');
    return { recordKey: recordKey.toLowerCase(), seq: i.seq };
  });
  return { ...base(`Request ${input.manifest.ref}`, 'request', input.at, payloadDigestV1(input.manifest)), references };
}

/** Why an entry was declined, in the answer form's reasons, or Other with its sentence. */
export type AnswerDeclineV1 = { kind: 'legal_hold' | 'personal_data' | 'beyond_sample' | 'past_retention' } | { kind: 'other'; note: string };

/** One item of an answer: shown with its declared fields and its disclosure's digest, or declined with its reason. Never a value. */
export type AnswerItemV1 =
  | { number: number; seq: number; outcome: 'shown'; declaredFields: string[]; disclosureDigest: string }
  | { number: number; seq: number; outcome: 'declined'; reason: AnswerDeclineV1 };

/** What an answer's entry commits (D-22): the outcomes, the declared field names, the reasons, who sent it, each disclosure's digest, and the reply's. */
export interface AnswerManifestV1 {
  ref: string;
  items: AnswerItemV1[];
  replyDigest: string | null;
  sentBy: 'person' | 'agent';
}

/** "Answer to {Q-ref}": the digest of the answer manifest. */
export function answerContentV1(input: { manifest: AnswerManifestV1; at: Date }): ReaderLinkContentV1 {
  return base(`Answer to ${input.manifest.ref}`, 'answer', input.at, payloadDigestV1(input.manifest));
}

/** A reader's acknowledgment on a link, ACK-0001 and up. */
export const ACKNOWLEDGMENT_REF_PATTERN = /^ACK-\d{4,6}$/;

/** "Acknowledgment {ACK-ref}" (R7): the digest of the `shared-record-ack/v2` body both signatures cover. */
export function acknowledgmentContentV1(input: { ref: string; body: SharedRecordAckBodyV2; at: Date }): ReaderLinkContentV1 {
  if (!ACKNOWLEDGMENT_REF_PATTERN.test(input.ref)) throw new Error('an acknowledgment is numbered ACK-0001 and up');
  return base(`Acknowledgment ${input.ref}`, 'acknowledgment', input.at, payloadDigestV1(input.body));
}
