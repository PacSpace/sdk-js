// ---------------------------------------------------------------------------
// Verify (GET /api/v1/verify/:proofRoot): no auth required
// ---------------------------------------------------------------------------

/**
 * Developer-friendly alias: a content fingerprint uniquely identifies a
 * single item's content.
 */
export type ContentFingerprint = string;

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
