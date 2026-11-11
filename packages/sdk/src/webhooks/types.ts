/**
 * Known webhook events currently emitted by production workers.
 */
export type KnownWebhookEventType =
  | 'delta.verified'
  | 'delta.failed'
  | 'record.committed'
  | 'record.failed'
  | 'record.closed';

/**
 * Event type union with forward-compat support for unknown future events.
 */
export type WebhookEventType = KnownWebhookEventType | (string & {});

// ---------------------------------------------------------------------------
// delta.verified
// ---------------------------------------------------------------------------

export interface DeltaVerifiedPayload {
  receiptId: string;
  /**
   * Per-customer monotonic sequence number for the delta.
   * Null for non-credit-delta records.
   */
  deltaIndex: number | null;
  status: 'verified';
  verifiedAt: string;
  verificationId: string;

  delta: {
    customerId: string | null;
    amount: number | null;
    reason: string | null;
    referenceId: string | null;
    metadata: Record<string, unknown>;
    submittedAt: string | null;
  };

  proof: {
    proofHash: string;
    contentHash: string | null;
    itemHashes: string[];
    previousProofHash: string | null;
  };

  verification: {
    verified: boolean;
    latencyMs: number;
    discrepancies: string[];
  };

  period?: {
    id: string;
    deltaCount: number;
    netDelta: number;
  };

  usage?: {
    plan: string;
    /**
     * Billing period for this usage snapshot (UTC YYYY-MM).
     * May differ from top-level period.id on month-boundary verifications.
     */
    periodId: string;
    includedDeltas: number;
    /**
     * Immutable acceptance-time usage watermark for this anchor.
     */
    consumedDeltas: number;
    remainingDeltas: number;
    overageRate: string;
  };
}

// ---------------------------------------------------------------------------
// delta.failed
// ---------------------------------------------------------------------------

export interface DeltaFailedPayload {
  recordId: string;
  receiptId: string | null;
  customerId: string | null;
  status: 'FAILED';
  reason: string;
  failedAt: string;
  delta?: {
    customerId: string | null;
    amount: number | null;
    reason: string | null;
    referenceId: string | null;
    metadata?: Record<string, unknown>;
    submittedAt: string | null;
  };
}

export interface RecordCommittedRecord {
  itemId: string | null;
  seq: number | null;
  kind: 'transition' | 'attempt' | string;
  applied: boolean | null;
  recordType: string | null;
  entityId: string | null;
  referenceId: string | null;
}

export interface RecordCommittedPayload {
  receiptId: string;
  status: 'committed';
  verifiedAt: string;
  verificationId: string | null;
  itemCount: number;
  records: RecordCommittedRecord[];
  verification: {
    verified: boolean;
    latencyMs?: number;
    discrepancies: string[];
  };
}

export interface RecordFailedPayload {
  recordType: string | null;
  entityId: string | null;
  seq: number;
  code: string;
  sentence: string;
}

/**
 * A record was closed, by your code (`records.close`) or by PacSpace after
 * the source's timeout. A close writes no entry. `entityId` is the wire id
 * of an encrypted record; `lastSeq` is the wire's number, counted from 0.
 */
export interface RecordClosedPayload {
  recordType: string;
  entityId: string;
  closedBy: 'code' | 'timeout';
  lastSeq: number;
  lastSeal: string | null;
  /** The day of the close, YYYY-MM-DD (UTC). */
  closedOn: string;
}

/**
 * Map from event type to its payload shape.
 */
export interface WebhookEventMap {
  'delta.verified': DeltaVerifiedPayload;
  'delta.failed': DeltaFailedPayload;
  'record.committed': RecordCommittedPayload;
  'record.failed': RecordFailedPayload;
  'record.closed': RecordClosedPayload;
}

/**
 * A typed webhook event.
 */
export interface WebhookEvent<T extends WebhookEventType = WebhookEventType> {
  /** The event type. */
  event: T;
  /** ISO 8601 timestamp of when the webhook was sent. */
  timestamp: string;
  /** Event-specific data. */
  data: T extends KnownWebhookEventType ? WebhookEventMap[T] : unknown;
}

/**
 * Headers sent with every webhook delivery.
 */
export interface WebhookHeaders {
  'x-pacspace-signature': string;
  /**
   * Unix epoch timestamp string as sent by current webhook workers.
   * Current production uses milliseconds.
   */
  'x-pacspace-timestamp': string;
  'x-webhook-event'?: string;
  'x-event-id'?: string;
  [key: string]: string | undefined;
}
