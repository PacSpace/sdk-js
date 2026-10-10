import type { RecordStatus, CheckpointType } from './common';
import type { RequestOptions } from './config';

// ---------------------------------------------------------------------------
// Emit (POST /balance/delta)
// ---------------------------------------------------------------------------

/**
 * Options for `balance.emit()`.
 */
export type AdjustsRef = { referenceId: string } | { recordId: string };

export interface EmitOptions extends RequestOptions {
  /** Your internal reference ID for correlation. */
  referenceId?: string;
  /** Arbitrary key-value metadata to store with the delta. */
  metadata?: Record<string, unknown>;
  /**
   * The committed entry this delta adjusts (E1d). Either the original's
   * `referenceId` or its `recordId`. Omitted on an ordinary emit.
   */
  adjusts?: AdjustsRef;
}

/**
 * Options for `balance.emitAndWait()`.
 */
export interface EmitAndWaitOptions extends EmitOptions {
  /**
   * Maximum time (ms) to wait for verification before throwing.
   * @default 60000
   */
  timeout?: number;
  /**
   * Interval (ms) between status polls.
   * @default 2000
   */
  pollInterval?: number;
}

/**
 * Response from `balance.emit()` — records a usage event as a verified delta.
 */
export interface EmitResponse {
  /** Unique identifier for this recorded submission. */
  recordId: string;
  /** The customer account this delta belongs to. */
  customerId: string;
  /** The recorded adjustment amount. */
  delta: number;
  /** Monotonic per-customer sequence number used for gap detection. */
  sequenceNumber?: string;
  /** Current processing status. */
  status: RecordStatus;
  /**
   * Stable opaque identifier of the receipt for this submission. Use it with
   * `receipts.*` to retrieve the receipt document. It is not the proof root
   * and cannot be derived from it.
   */
  receiptId: string;
  /** Root covering the items in this submission. Share it so anyone can verify. */
  proofRoot: string;
  /**
   * Individual content fingerprints for each item.
   * Same content always produces the same fingerprint.
   * @alias contentFingerprints
   */
  itemHashes: string[];
  /** Estimated number of verified deltas this submission will produce. */
  estimatedVerifiedDeltas: number;
  /** Estimated credits that will be consumed upon verification. */
  estimatedCredits: number;
  /** ISO 8601 timestamp of when the submission was received. */
  receivedAt: string;
  /** Human-readable status message. */
  message: string;

}

/**
 * Developer-friendly alias: `proofRoot` is the proof root — the single
 * fingerprint covering every item in a submission or derivation.
 */
export type ProofRoot = string;

/**
 * Developer-friendly alias: `itemHashes` are content fingerprints — each
 * one uniquely identifies a single item's content.
 */
export type ContentFingerprint = string;

// ---------------------------------------------------------------------------
// Derive (GET /balance/derive/:customerId)
// ---------------------------------------------------------------------------

/**
 * Options for `balance.derive()` — computes the neutral, independently
 * verifiable balance from all verified deltas.
 */
type DeriveWindowOptions =
  | {
      period: string;
      timePreset?: never;
      startDate?: never;
      endDate?: never;
    }
  | {
      timePreset: 'current_month' | 'last_30_days' | 'last_90_days';
      period?: never;
      startDate?: never;
      endDate?: never;
    }
  | {
      timePreset: 'custom';
      startDate: string;
      endDate: string;
      period?: never;
    }
  | {
      period?: never;
      timePreset?: never;
      startDate?: never;
      endDate?: never;
    };

type DeriveScopeMode = {
  startingCheckpoint?: never;
  startingCheckpointType?: never;
} & DeriveWindowOptions;

type DeriveCheckpointMode = {
  startingCheckpoint: string;
  startingCheckpointType?: CheckpointType;
  period?: never;
  timePreset?: never;
  startDate?: never;
  endDate?: never;
};

export type DeriveOptions = RequestOptions &
  {
    /**
     * Starting balance to derive from.
     * @default 0
     */
    startingBalance?: number;
    /** Number of deltas to return per page (1-1000). Balance is always computed from all deltas. */
    limit?: number;
    /** Number of deltas to skip. */
    offset?: number;
  } & (DeriveScopeMode | DeriveCheckpointMode);

export interface BalanceScopeSummary {
  kind: 'period' | 'preset' | 'custom';
  periodId: string | null;
  preset: CheckpointTimePreset | null;
  startDate: string;
  endDateExclusive: string;
  label: string;
}

export interface MonthlyBreakdownEntry {
  period: string;
  periodStart: string;
  periodEndExclusive: string;
  deltaCount: number;
  netDelta: number;
  runningBalance: number;
  checkpoint: {
    checkpointId: string;
    proofRoot: string | null;
    status: RecordStatus;
  } | null;
}

/**
 * A single verified delta — a usage event that has been permanently recorded
 * and can be independently verified by any party.
 */
export interface VerifiedDelta {
  recordId: string;
  /** Content fingerprint — confirms this delta's content hasn't been altered. */
  itemHash: ContentFingerprint;
  /** Proof root — the single fingerprint covering the group this delta belongs to. */
  proofRoot: ProofRoot;
  /** Stable opaque receipt identifier; not the proof root. */
  receiptId: string;
  /** Monotonic per-customer sequence number used for gap detection. */
  sequenceNumber: string | null;
  delta: number;
  reason: string | null;
  referenceId: string | null;
  window: string;
  declaredTimestamp: string | null;
  blockTimestamp: string | null;
  dataPurged: boolean;
  verified: true;
}

/**
 * Summary of deltas within a time window.
 */
export interface WindowSummary {
  window: string;
  deltasCount: number;
  netDelta: number;
  firstBlockTimestamp: string | null;
  lastBlockTimestamp: string | null;
}

/**
 * Response from `balance.derive()`.
 */
export interface DeriveResponse {
  customerId: string;
  startingBalance: number;
  startingCheckpoint: string;
  startingCheckpointType: CheckpointType;
  deltasCount: number;
  computedBalance: number;
  latestCheckpoint: string | null;
  latestReceiptId: string | null;
  deltas: VerifiedDelta[];
  windowSummaries: WindowSummary[];
  verificationProof: {
    proofRoot: string | null;
    message: string;
  };
  scope: BalanceScopeSummary | null;
  monthlyBreakdown?: MonthlyBreakdownEntry[];
  cumulativeBalance?: number;
  /** Pagination info for the deltas array. */
  pagination: {
    total: number;
    limit: number;
    offset: number;
  };
  /** Hint to use checkpoints for large delta counts. Only present when delta count exceeds threshold. */
  _hint?: {
    message: string;
    recommendation: string;
    docsUrl: string;
  };
}

// ---------------------------------------------------------------------------
// Compare (POST /balance/compare)
// ---------------------------------------------------------------------------

/**
 * Options for `balance.compare()`.
 */
export type CompareOptions = RequestOptions &
  {
    /**
     * Starting balance for derivation.
     * @default 0
     */
    startingBalance?: number;
  } & (
    | ({
        startingCheckpoint?: never;
        startingCheckpointType?: never;
      } & DeriveWindowOptions)
    | {
        startingCheckpoint: string;
        startingCheckpointType?: CheckpointType;
        period?: never;
        timePreset?: never;
        startDate?: never;
        endDate?: never;
      }
  );

/**
 * Balances to compare — your view vs. their view.
 */
export interface CompareBalances {
  /** Your calculated balance. */
  yours: number;
  /** Customer's claimed balance. */
  theirs: number;
}

/**
 * Discrepancy details when balances don't match.
 */
export interface DiscrepancyReport {
  amount: number;
  resolution: string;
  divergentParty: 'yours' | 'theirs' | 'both';
  windowsToReview: Array<{
    window: string;
    netDelta: number;
    deltasCount: number;
    timeRange: string;
  }>;
  recommendation: string;
  /** Top 5 most impactful windows, sorted by absolute netDelta. */
  relevantWindows: Array<{
    window: string;
    netDelta: number;
    deltasCount: number;
    timeRange: string;
  }>;
}

/**
 * Response from `balance.compare()` — surfaces the exact point of divergence
 * between two parties' views of a balance. PacSpace doesn't decide who's
 * right; it shows where the numbers diverge so the math resolves the dispute.
 */
export interface CompareResponse {
  customerId: string;
  yourBalance: number;
  theirBalance: number;
  neutralBalance: number;
  matchesYours: boolean;
  matchesTheirs: boolean;
  deltasVerified: number;
  discrepancyReport: DiscrepancyReport | null;
  proof: {
    proofRoot: string | null;
    latestCheckpoint: string | null;
    windowSummaries: WindowSummary[];
  };
  scope: BalanceScopeSummary | null;
  monthlyBreakdown?: MonthlyBreakdownEntry[];
  cumulativeBalance?: number;
}

// ---------------------------------------------------------------------------
// Receipt (GET /balance/receipt/:customerId)
// ---------------------------------------------------------------------------

/**
 * Response from `balance.receipt()` — a proof document covering all verified
 * activity for a period. Share with your customer or auditor; they can verify
 * every line item independently.
 */
export interface ReceiptResponse {
  customerId: string;
  generatedAt: string;
  deltasCount: number;
  finalBalance: number;
  /** Proof root — the single fingerprint covering all deltas in this receipt. */
  proofRoot: ProofRoot | null;
  receiptId: string | null;
  latestCheckpoint: string | null;
  deltas: VerifiedDelta[];
  windowSummaries: WindowSummary[];
  verification: {
    message: string;
    /** Content fingerprints for each delta in the receipt. */
    itemHashes: ContentFingerprint[];
  };
}

export interface ReceiptStatementRow {
  rowId: string;
  timestamp: string;
  description: string;
  delta: number;
  runningBalance: number;
  status: 'verified' | 'pending' | 'failed';
  referenceId: string | null;
  dataPurged: boolean;
}

export interface ReceiptDailyTotal {
  date: string;
  deltaCount: number;
  netDelta: number;
  closingBalance: number;
}

export interface ReceiptDocument {
  schemaVersion: 'v1';
  receiptId: string;
  checkpointId: string | null;
  status: 'verified' | 'pending' | 'failed';
  locale: string;
  timezone: string;
  unit: 'credits';
  customerId: string | null;
  customerDisplayName: string | null;
  period: {
    label: string;
    startDate: string;
    endDateExclusive: string;
    timezoneLabel: string;
  };
  summary: {
    openingBalance: number;
    netDelta: number;
    closingBalance: number;
    deltaCount: number;
  };
  statementRows: ReceiptStatementRow[];
  dailyTotals: ReceiptDailyTotal[];
  tenant: {
    tenantId: string;
    name: string;
    disputeUrl: string | null;
    brandingRevision: number;
    embedOrigins: string[];
  };
  verification: {
    /**
     * Present only on authorized presentations (tenant-authenticated fetch or
     * a chain-bearing access grant). Ordinary receipt links strip direct
     * chain-correlation fields and carry only proofRootPrefix (ADR 0008 §5).
     */
    proofRoot: string | null;
    proofRootPrefix?: string | null;
    verificationReference: string | null;
    recordedAt: string;
    dataPurged: boolean;
  };
  links: {
    permalink: string;
    pdf: string;
  };
}

export interface ReceiptListItem {
  receiptId: string;
  checkpointId: string | null;
  period: string | null;
  status: 'verified' | 'pending' | 'failed';
  recordedAt: string;
  receiptUrl: string;
}

export interface ReceiptGetOptions extends RequestOptions {
  customerDisplayName?: boolean;
  locale?: string;
  timezone?: string;
  unit?: 'credits';
}

export interface ReceiptListOptions extends RequestOptions {
  limit?: number;
}

// ---------------------------------------------------------------------------
// Receipt access grants (POST/GET /balance/receipt/:receiptId/grants)
// ---------------------------------------------------------------------------

/**
 * BEARER: anyone holding the grant token may retrieve the receipt.
 * RECIPIENT_BOUND: retrieval additionally requires presenting the recipient
 * email the grant was issued to.
 */
export type ReceiptGrantKind = 'BEARER' | 'RECIPIENT_BOUND';

/**
 * SEMANTIC: record contents only — chain-correlation fields stay stripped.
 * CHAIN_BEARING: a self-contained receipt that also carries the proof root
 * and chain reference for independent verification.
 */
export type ReceiptGrantScope = 'SEMANTIC' | 'CHAIN_BEARING';

/**
 * Display status derived from stored state: `expired` and `exhausted` are
 * computed from expiry and use limits; only `revoked` is an explicit action.
 */
export type ReceiptGrantStatus = 'active' | 'revoked' | 'expired' | 'exhausted';

export interface ReceiptAccessGrant {
  grantId: string;
  receiptId: string;
  /** SHARED_RECORD entries mirror customer-link step-up and are read-only here. */
  kind: ReceiptGrantKind | 'SHARED_RECORD';
  scope: ReceiptGrantScope;
  status: ReceiptGrantStatus;
  label: string | null;
  /** Masked recipient email (for example `a***@counterparty.com`). */
  recipientLabel: string | null;
  expiresAt: string | null;
  maxUses: number | null;
  useCount: number;
  lastUsedAt: string | null;
  revokedAt: string | null;
  revokeReason: string | null;
  createdAt: string | null;
  /** Grants are managed here; `customer_link` entries at the Shared Record. */
  managedBy: 'grant' | 'customer_link';
  revocable: boolean;
}

export interface CreateReceiptGrantParams {
  kind: ReceiptGrantKind;
  /** Defaults to SEMANTIC. */
  scope?: ReceiptGrantScope;
  /** ISO timestamp. Mutually exclusive with ttlHours; expiresAt wins. */
  expiresAt?: string;
  ttlHours?: number;
  maxUses?: number;
  /** Required when kind is RECIPIENT_BOUND. */
  recipientEmail?: string;
  label?: string;
}

export interface CreateReceiptGrantResponse {
  grant: ReceiptAccessGrant;
  /** Shown once — only its hash is stored. Deliver it to the counterparty. */
  token: string;
  /** Receipt permalink with the grant token attached. */
  grantUrl: string;
}

export interface CheckpointTimelinePoint {
  checkpointId: string;
  period: string;
  status: string;
  proofRoot: string | null;
  deltaCount: number;
  recordedAt: string;
}

export interface CheckpointTimelineGap {
  startDate: string;
  endDateExclusive: string;
  daysWithoutCheckpoint: number;
}

export interface CheckpointTimelineResponse {
  customerId: string;
  range: {
    startDate: string;
    endDateExclusive: string;
    label: string;
  };
  points: CheckpointTimelinePoint[];
  gaps: CheckpointTimelineGap[];
  summary: {
    checkpointCount: number;
    coveredDays: number;
    expectedDays: number;
    gapCount: number;
  };
}

export interface ListCheckpointTimelineOptions extends RequestOptions {
  monthsBack?: number;
  startDate?: string;
  endDate?: string;
}

export interface CheckpointDiffResponse {
  customerId: string;
  left: {
    checkpointId: string;
    status: string;
    recordedAt: string;
    proofRoot: string | null;
    deltaCount: number;
    netDelta: number;
  };
  right: {
    checkpointId: string;
    status: string;
    recordedAt: string;
    proofRoot: string | null;
    deltaCount: number;
    netDelta: number;
  };
  difference: {
    deltaCountDiff: number;
    netDeltaDiff: number;
    addedFingerprintsCount: number;
    removedFingerprintsCount: number;
    addedFingerprints: string[];
    removedFingerprints: string[];
  };
  dailyDivergence: Array<{
    date: string;
    leftNet: number;
    rightNet: number;
    divergence: number;
  }>;
}

// ---------------------------------------------------------------------------
// Checkpoint (POST /balance/checkpoint)
// ---------------------------------------------------------------------------

export type CheckpointTimePreset = 'current_month' | 'last_30_days' | 'last_90_days' | 'custom';
export type CheckpointMode = 'full_scope' | 'selected_only';

export interface CheckpointScopeOptions {
  /**
   * Backward-compatible billing period in YYYY-MM format.
   */
  period?: string;
  /**
   * Preset scope selector.
   */
  timePreset?: CheckpointTimePreset;
  /**
   * Custom scope start date (ISO) used when timePreset=custom.
   */
  startDate?: string;
  /**
   * Custom scope end date (ISO) used when timePreset=custom.
   */
  endDate?: string;
}

/**
 * Options for `balance.checkpoint()`.
 */
export interface CheckpointOptions extends CheckpointScopeOptions, RequestOptions {
  /**
   * Checkpoint computation mode.
   */
  mode?: CheckpointMode;
  /**
   * Required when mode=selected_only.
   */
  fingerprints?: string[];
}

export interface CheckpointScopeSummary {
  preset: CheckpointTimePreset;
  startDate: string;
  endDateExclusive: string;
  label: string;
}

/**
 * Response from `balance.checkpoint()` — locks all verified activity for
 * a billing period into a single proof. Include it on your invoice so your
 * customer can verify every charge.
 */
export interface CheckpointResponse {
  checkpointId: string;
  period: string;
  /** Proof root — the single fingerprint covering every delta in this period. */
  proofRoot: ProofRoot;
  scope?: CheckpointScopeSummary;
  mode?: CheckpointMode;
  deltaCount: number;
  selectedFingerprintCount?: number;
  eligibleFingerprintCount?: number;
  selectedFingerprints?: string[];
  fromIndex: number;
  toIndex: number;
  customerId: string;
  status: RecordStatus;
  message: string;
}

/**
 * Options for `balance.listCheckpoints()`.
 */
export interface ListCheckpointsOptions extends CheckpointScopeOptions, RequestOptions {
  /** Filter checkpoints by customer ID. */
  customerId?: string;
  /** Number of results per page (max 100). */
  limit?: number;
  /** Number of results to skip. */
  offset?: number;
}

/** A single checkpoint in the list response. */
export interface CheckpointSummary {
  checkpointId: string;
  period: string;
  /** Proof root for this checkpoint period. */
  proofRoot: ProofRoot | null;
  scope?: Partial<CheckpointScopeSummary>;
  mode?: CheckpointMode;
  deltaCount: number;
  selectedFingerprintCount?: number;
  eligibleFingerprintCount?: number;
  customerId: string;
  status: RecordStatus;
  verificationReference: string | null;
  verifiedAt: string | null;
  receivedAt: string;
}

/**
 * Response from `balance.listCheckpoints()`.
 */
export interface ListCheckpointsResponse {
  checkpoints: CheckpointSummary[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
  };
}

// ---------------------------------------------------------------------------
// Delta Status (GET /balance/delta/:recordId)
// ---------------------------------------------------------------------------

/**
 * Response from `balance.deltaStatus()` — check the processing status of
 * a submitted delta. Once verified, the delta becomes a permanent record.
 */
export interface DeltaStatusResponse {
  recordId: string;
  status: RecordStatus;
  /** Number of deltas in this record. */
  deltaCount: number;
  /** customerId of the first delta (convenience accessor). */
  customerId: string | null;
  /** delta amount of the first delta (convenience accessor). */
  delta: number | null;
  /** All deltas in this record. */
  deltas: Array<{
    customerId: string | null;
    delta: number | null;
    sequenceNumber: string | null;
  }>;
  receiptId: string | null;
  /** Verification reference: the permanent reference recorded on infrastructure no party controls. */
  verificationReference: string | null;
  receivedAt: string;
  verifiedAt: string | null;
}

/**
 * Options for `balance.waitForVerified()`.
 */
export interface WaitForVerifiedOptions extends RequestOptions {
  /**
   * Maximum time (ms) to wait before throwing a timeout.
   * @default 60000
   */
  timeout?: number;
  /**
   * Poll interval in milliseconds.
   * @default 2000
   */
  pollInterval?: number;
}

/**
 * Plan metadata returned by `balance.usage()`.
 */
export interface UsagePlanSummary {
  tier: string;
  monthlyAllotment: number;
  [key: string]: unknown;
}

/**
 * Usage counters returned by `balance.usage()`.
 */
export interface UsageCounters {
  period: string;
  bucketTouchesUsed: number;
  overageCount: number;
  overageChargesUsd: number | string;
  remaining: number;
  [key: string]: unknown;
}

/**
 * Response from `balance.usage()`.
 */
export interface UsageResponse {
  plan: UsagePlanSummary;
  usage: UsageCounters;
  allowed: boolean;
  reason: string | null;
  remaining: number;
}

// ---------------------------------------------------------------------------
// Sequence gaps (GET /balance/gaps/:customerId)
// ---------------------------------------------------------------------------

/** Options for `balance.gaps()` gap detection queries. */
export interface SequenceGapsOptions extends RequestOptions {
  /** Optional inclusive start sequence for scanning. */
  fromSequence?: string;
  /** Optional inclusive end sequence for scanning. */
  toSequence?: string;
  /** Maximum number of missing ranges to return (max 500). */
  limit?: number;
}

/** A missing sequence range. */
export interface SequenceGapRange {
  startSequence: string;
  endSequence: string;
  missingCount: string;
}

/** Response from `balance.gaps()`. */
export interface SequenceGapsResponse {
  customerId: string;
  customerReference: string;
  customerPartition: string;
  nextSequence: string;
  rangeStart: string;
  rangeEnd: string;
  gaps: SequenceGapRange[];
  hasGaps: boolean;
  missingRanges: number;
  missingCountInPage: string;
  truncated: boolean;
}

// ---------------------------------------------------------------------------
// Webhook Deliveries (GET /balance/webhooks)
// ---------------------------------------------------------------------------

/**
 * Options for `balance.listWebhookDeliveries()`.
 */
export interface ListWebhookDeliveriesOptions extends RequestOptions {
  status?: 'pending' | 'delivered' | 'failed';
  limit?: number;
  offset?: number;
}

/**
 * A single webhook delivery record.
 */
export interface WebhookDelivery {
  eventId: string;
  status: string;
  attempts: number;
  url: string | null;
  payload: any | null;
  deliveredAt: string | null;
  nextAttemptAt: string | null;
  createdAt: string;
  dataPurged: boolean;
}

/**
 * Response from `balance.listWebhookDeliveries()`.
 */
export interface ListWebhookDeliveriesResponse {
  deliveries: WebhookDelivery[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
  };
}

// ---------------------------------------------------------------------------
// Customer Records (GET /balance/customers, /balance/customers/:customerId)
// ---------------------------------------------------------------------------

/** A customer record summary (returned from list endpoint). */
export interface CustomerRecordSummary {
  customerId: string;
  customerReference: string;
  totalDeltas: number;
  firstDeltaAt: string | null;
  lastDeltaAt: string | null;
}

/** A single activity item in the customer record detail. */
export interface CustomerRecordActivity {
  amount: number;
  reason: string | null;
  referenceId: string | null;
  status: string;
  time: string;
}

/** Full customer record detail (returned from detail endpoint). */
export interface CustomerRecordDetail extends CustomerRecordSummary {
  customerPartition: string;
  computedBalance: number;
  period?: {
    id: string;
    startDate: string;
    endDateExclusive: string;
    label: string;
  };
  mostRecentActivePeriod?: string | null;
  latestCheckpoint: string | null;
  privacyNote: string;
  recentActivity: {
    items: CustomerRecordActivity[];
    pagination: {
      total: number;
      page: number;
      limit: number;
      totalPages: number;
    };
  };
}

/** Options for listing customer records. */
export interface ListCustomersOptions extends RequestOptions {
  /** Filter by customer ID (case-insensitive). */
  search?: string;
  /** Results per page (max 100). */
  limit?: number;
  /** Page number (1-indexed). */
  page?: number;
}

/** Options for getting customer record detail. */
export interface GetCustomerOptions extends RequestOptions {
  /** Page of recent activity (1-indexed). */
  deltaPage?: number;
  /** Activity items per page. */
  deltaLimit?: number;
  /** Optional month selector in YYYY-MM format. */
  period?: string;
}

/** Response from listing customer records. */
export interface ListCustomersResponse {
  customers: CustomerRecordSummary[];
  pagination: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  };
}

// ---------------------------------------------------------------------------
// Invoice Proof
// ---------------------------------------------------------------------------

/** Options for generating an invoice proof. */
export interface InvoiceProofOptions extends RequestOptions {
  /** Billing period in YYYY-MM format. */
  period?: string;
  /** Scope preset. */
  timePreset?: CheckpointTimePreset;
  /** Custom scope start date (ISO). */
  startDate?: string;
  /** Custom scope end date (ISO). */
  endDate?: string;
}

/** A single delta included in the invoice proof. */
export interface InvoiceProofDelta {
  delta: number;
  reason: string | null;
  referenceId: string | null;
  status: string;
  time: string;
  /** Content fingerprint for this delta. */
  itemHash: ContentFingerprint | null;
}

/** Window summary for the invoice proof period. */
export interface InvoiceProofWindowSummary {
  window: string;
  deltasCount: number;
  netDelta: number;
  firstDeltaAt: string | null;
  lastDeltaAt: string | null;
}

/** Verification metadata for the invoice proof. */
export interface InvoiceProofVerification {
  proofRoot: string | null;
  totalBalance: number;
  periodBalance: number;
}

/** Response from the invoice proof endpoint. */
export interface InvoiceProofResponse {
  customerId: string;
  period: string;
  proofRoot: string;
  /** Verification reference: unique identifier on the proof layer. */
  verificationReference: string | null;
  /** Machine verification endpoint for tools, agents, and auditors. */
  verificationApiUrl: string | null;
  /**
   * @deprecated Legacy compatibility field with endpoint-specific semantics.
   * Use `verificationApiUrl` for machine verification and `verifyUrl` for
   * human invoice links. Retained until a future major version.
   */
  verificationExplorerUrl: string | null;
  /**
   * Shareable verification URL. When Shared Record is enabled, this may be a
   * persistent /c/{handle} permalink instead of a period-specific proof URL.
   */
  verifyUrl: string | null;
  /** Step-up access code for the customer Shared Record, when exposed by the API. */
  accessHint?: string | null;
  /** Persistent customer Shared Record URL, when exposed by the API. */
  customerLinkUrl?: string | null;
  /** Hostname backing the customer Shared Record URL, when exposed by the API. */
  customerLinkHost?: string | null;
  deltaCount: number;
  startingBalance: number;
  finalBalance: number;
  windowSummary: InvoiceProofWindowSummary;
  deltas: InvoiceProofDelta[];
  verification: InvoiceProofVerification;
}

// ---------------------------------------------------------------------------
// Verify (GET /api/v1/verify/:proofRoot) — no auth required
// ---------------------------------------------------------------------------

/**
 * Summary of verified records.
 *
 * @deprecated Never returned by the verify endpoint since the move to
 * proof-only verification (ADR 0008). Retained for compile compatibility.
 */
export interface VerifySummary {
  recordCount: number;
  netChange: number;
  startingBalance: number;
  endingBalance: number;
  firstRecordAt: string | null;
  lastRecordAt: string | null;
}

/**
 * A single record in the verify response.
 *
 * @deprecated Never returned by the verify endpoint since the move to
 * proof-only verification (ADR 0008). Retained for compile compatibility.
 */
export interface VerifyRecord {
  amount: number;
  reason: string | null;
  referenceId: string | null;
  status: string;
  time: string;
  /** Content fingerprint: recompute from the original data to confirm nothing changed. */
  itemFingerprint: ContentFingerprint | null;
}

/** Verification metadata from the verify endpoint. */
export interface VerifyVerification {
  verificationReference: string | null;
  verificationExplorerUrl: string | null;
  batchId: string | null;
  note: string;
}

export type VerifySource = 'db' | 'chain' | 'both';

export interface VerifySourceResult {
  source: 'db' | 'chain';
  available: boolean;
  verified: boolean | null;
  reason: string;
  checkedAt: string;
  proofRoot: string;
  verificationReference: string | null;
  chainId: number | null;
  contractAddress: string | null;
  observedProofRoot: string | null;
  algorithm: string;
  cache: 'none' | 'hit' | 'write';
}

/**
 * Response from the verify endpoint (no auth required).
 * Anyone with the proof root can call this to independently confirm a proof
 * exists. The response is proof-only: validity, timestamps, and chain
 * references. Record contents are never returned (ADR 0008).
 */
export interface VerifyResponse {
  verified: boolean;
  processing?: boolean;
  proofRoot: string;
  chainId?: number;
  contractAddress?: string | null;
  recordedAt?: string;
  environment?: string;
  /** @deprecated Never returned; the verify endpoint is proof-only (ADR 0008). */
  summary?: VerifySummary;
  /** @deprecated Never returned; the verify endpoint is proof-only (ADR 0008). */
  records?: VerifyRecord[];
  verification?: VerifyVerification;
  requestedSource?: VerifySource;
  overallVerified?: boolean;
  dbVerification?: VerifySourceResult;
  chainVerification?: VerifySourceResult;
  itemsRootAlgorithm?: string;
  sourceConsistency?: 'consistent' | 'mismatch' | 'insufficient_data';
  message: string;
}
