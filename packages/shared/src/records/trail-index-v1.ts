/**
 * The trail index record (records prototype build, R4; "Cryptography and proof"; D-4, D-7, D-17): the entries
 * PacSpace writes, through the records system writer, on `machine-action-record/v1` under entity id
 * `trail-<trailId>` (never served) with origin `TRAIL_INDEX`.
 *
 * Every entry uses the content forms `record-content-v1.ts` accepts: a payload is `{alg, digest, byteLength}`
 * over the JCS bytes hashed, and a reference is `{recordKey, seq}`. No field holds the word for the thing
 * itself, a reader's name, a source's name, a label or an environment (the neutrality rules): readers receive
 * these entries. The scope and the reasons are the operator's own words for readers, the only free text. A
 * rule's labels are committed only inside the salted digest.
 */
import { ethers } from 'ethers';
import { canonicalizeJcs } from '../proof/jcs';
import type { TrailRuleV1 } from './trail-rule';

export const TRAIL_INDEX_RECORD_TYPE = 'machine-action-record';
export const TRAIL_INDEX_ACTOR = 'pacspace';
export const TRAIL_RULE_SALT_BYTES = 32;

export type TrailIndexKind =
  | 'rule-committed'
  | 'rule-changed'
  | 'scope-reworded'
  | 'record-joined'
  | 'record-removed'
  | 'entry-erased'
  | 'legal-hold-placed'
  | 'legal-hold-released';

export interface PayloadDigestV1 {
  alg: 'sha-256';
  digest: string;
  byteLength: string;
}

export interface TrailIndexContentV1 {
  title: string;
  kind: TrailIndexKind;
  occurredAt: string;
  actorId: string;
  payloads: PayloadDigestV1[];
  description?: string;
  note?: string;
  references?: Array<{ recordKey: string; seq: number }>;
}

/** The record's entity id. */
export function trailIndexEntityId(trailId: string): string {
  return `trail-${trailId}`;
}

/** The idempotency key of a trail event's index entry. */
export function trailEventIdempotencyKey(trailId: string, seq: number): string {
  return `trail:${trailId}:event:${seq}`;
}

function base64url(bytes: Uint8Array): string {
  return ethers.encodeBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** The payload form over the JCS of a value: SHA-256 of its UTF-8 bytes, and their length. */
export function payloadDigestV1(value: unknown): PayloadDigestV1 {
  const bytes = ethers.toUtf8Bytes(canonicalizeJcs(value));
  return { alg: 'sha-256', digest: ethers.sha256(bytes).slice(2), byteLength: String(bytes.length) };
}

/** What a rule's digest commits: the rule and its salt, so equal rules on two trails commit different digests. */
export function trailRuleDigestInput(rule: TrailRuleV1, salt: Uint8Array): { v: 1; rule: TrailRuleV1; salt: string } {
  if (salt.length !== TRAIL_RULE_SALT_BYTES) throw new Error(`A rule's salt is ${TRAIL_RULE_SALT_BYTES} bytes.`);
  return { v: 1, rule, salt: base64url(salt) };
}

/** The close's facts a join commits (D-7). */
export interface TrailJoinFactsV1 {
  recordKey: string;
  lastSeq: number;
  lastSeal: string;
  closedBy: 'code' | 'timeout';
  number: number;
  ruleVersion: number;
}

/** UTC to the second, as entries carry it. */
export function trailIndexTime(at: Date): string {
  return at.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

const base = (title: string, kind: TrailIndexKind, at: Date, payload: PayloadDigestV1) => ({
  title,
  kind,
  occurredAt: trailIndexTime(at),
  actorId: TRAIL_INDEX_ACTOR,
  payloads: [payload],
});

/** "Rule committed": the scope as the description, and the salted rule's digest. */
export function ruleCommittedContentV1(input: { scope: string; rule: TrailRuleV1; salt: Uint8Array; at: Date }): TrailIndexContentV1 {
  return { ...base('Rule committed', 'rule-committed', input.at, payloadDigestV1(trailRuleDigestInput(input.rule, input.salt))), description: input.scope };
}

/** "Rule changed": the new salted rule's digest, and the reason. */
export function ruleChangedContentV1(input: { rule: TrailRuleV1; salt: Uint8Array; reason: string; at: Date }): TrailIndexContentV1 {
  return { ...base('Rule changed', 'rule-changed', input.at, payloadDigestV1(trailRuleDigestInput(input.rule, input.salt))), note: input.reason };
}

/** "Scope reworded": the new scope and the reason; the payload is the digest of both. */
export function scopeRewordedContentV1(input: { scope: string; reason: string; at: Date }): TrailIndexContentV1 {
  return {
    ...base('Scope reworded', 'scope-reworded', input.at, payloadDigestV1({ scope: input.scope, reason: input.reason })),
    description: input.scope,
    note: input.reason,
  };
}

/** "Record {n} joined": the member's last entry at its close, and the digest of the close's facts. */
export function recordJoinedContentV1(input: TrailJoinFactsV1 & { at: Date }): TrailIndexContentV1 {
  const facts: TrailJoinFactsV1 = {
    recordKey: input.recordKey.toLowerCase(),
    lastSeq: input.lastSeq,
    lastSeal: input.lastSeal.toLowerCase(),
    closedBy: input.closedBy,
    number: input.number,
    ruleVersion: input.ruleVersion,
  };
  return {
    ...base(`Record ${input.number} joined`, 'record-joined', input.at, payloadDigestV1(facts)),
    references: [{ recordKey: facts.recordKey, seq: facts.lastSeq }],
  };
}

/**
 * "Record {n} removed": the member's last entry at its close, and the reason. `n` is the member's number, the same
 * `n` its "Record {n} joined" entry committed; the payload's digest also names that join's event number on the
 * trail (`joinedEvent`), so the removal is bound to the one join it takes back.
 */
export function recordRemovedContentV1(input: { number: number; joinedEvent: number; recordKey: string; lastSeq: number; reason: string; at: Date }): TrailIndexContentV1 {
  const recordKey = input.recordKey.toLowerCase();
  const facts = { recordKey, lastSeq: input.lastSeq, number: input.number, joinedEvent: input.joinedEvent, reason: input.reason };
  return {
    ...base(`Record ${input.number} removed`, 'record-removed', input.at, payloadDigestV1(facts)),
    references: [{ recordKey, seq: input.lastSeq }],
    note: input.reason,
  };
}

/**
 * G3 (D-33): "Record {n} entry {seq} erased", with the reason the operator chose. It references the entry, whose leaf,
 * seal and number stay committed, so every check of it is unchanged.
 */
export function entryErasedContentV1(input: { number: number; recordKey: string; seq: number; reason: string; at: Date }): TrailIndexContentV1 {
  const recordKey = input.recordKey.toLowerCase();
  const facts = { number: input.number, recordKey, seq: input.seq, reason: input.reason };
  return {
    ...base(`Record ${input.number} entry ${input.seq} erased`, 'entry-erased', input.at, payloadDigestV1(facts)),
    references: [{ recordKey, seq: input.seq }],
    note: input.reason,
  };
}

/**
 * G3 (D-33): a legal hold on the whole of what the index record covers, or on one of its records by number. Never
 * served to readers, and it names no person: the hold's id binds its release to it.
 */
export function legalHoldPlacedContentV1(input: {
  holdId: string;
  on: 'whole' | { number: number; recordKey: string };
  reason: string;
  at: Date;
}): TrailIndexContentV1 {
  const on = input.on === 'whole' ? 'whole' : { number: input.on.number, recordKey: input.on.recordKey.toLowerCase() };
  return { ...base('Legal hold placed', 'legal-hold-placed', input.at, payloadDigestV1({ holdId: input.holdId, on, reason: input.reason })), note: input.reason };
}

/** G3 (D-33): the release of the hold whose id it names, with its reason. */
export function legalHoldReleasedContentV1(input: { holdId: string; reason: string; at: Date }): TrailIndexContentV1 {
  return { ...base('Legal hold released', 'legal-hold-released', input.at, payloadDigestV1({ holdId: input.holdId, reason: input.reason })), note: input.reason };
}
