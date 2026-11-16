/**
 * Submission automation profiles.
 *
 * - `daily`: one tenant-produced summary per customer per 24h window.
 * - `sub_daily`: higher-frequency summary submission (enterprise only).
 * - `immediate`: submit each queued summary as soon as it is enqueued (enterprise only).
 */
export type SubmissionProfile = 'daily' | 'sub_daily' | 'immediate';

/**
 * A tenant-produced usage summary for one customer and one usage window.
 *
 * The SDK submits this summary as a delta. The SDK does not infer or meter
 * raw product usage events.
 */
export interface CustomerUsageSummary {
  customerId: string;
  delta: number;
  windowStart: string;
  windowEnd: string;
  reason?: string;
  referenceId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Options for SDK-managed summary submission automation.
 */
export interface SubmissionAutomationOptions {
  /**
   * Submission profile.
   * @default 'daily'
   */
  profile?: SubmissionProfile;
  /**
   * Flush cadence in milliseconds.
   * Defaults by profile:
   * - daily: 86_400_000
   * - sub_daily: 21_600_000 (6 hours)
   * - immediate: 0
   */
  cadenceMs?: number;
  /**
   * Enables enterprise-only profiles (`sub_daily`, `immediate`).
   * @default false
   */
  enterprise?: boolean;
  /**
   * Start the scheduler when the first summary is enqueued.
   * @default true
   */
  autoStart?: boolean;
  /**
   * Attempt a best-effort flush on process shutdown signals.
   * @default true
   */
  autoFlushOnShutdown?: boolean;
  /**
   * Maximum deltas per outbound submission request.
   * The API cap is 100.
   * @default 100
   */
  maxDeltasPerRequest?: number;
  /**
   * Max outbound submission requests per minute for client-side pacing.
   * @default 10
   */
  maxRequestsPerMinute?: number;
  /**
   * Default reason used when summary.reason is omitted.
   * @default 'usage_summary'
   */
  defaultReason?: string;
}

/**
 * Internal queued summary shape with deterministic reference and queue metadata.
 */
export interface QueuedUsageSummary extends CustomerUsageSummary {
  key: string;
  referenceId: string;
  queuedAt: string;
}

/**
 * Snapshot of scheduler queue state.
 */
export interface SubmissionQueueState {
  profile: SubmissionProfile;
  cadenceMs: number;
  enterprise: boolean;
  queuedCount: number;
  isRunning: boolean;
  nextFlushAt: string | null;
}

/**
 * Manual flush options.
 */
export interface FlushSummariesOptions {
  /**
   * Limit number of queued summaries included in this flush.
   * Omit to flush all.
   */
  maxItems?: number;
}

/**
 * One failed item from a flush attempt.
 */
export interface SummaryFlushFailure {
  customerId: string;
  referenceId: string;
  error: string;
}

/**
 * Summary of one flush execution.
 */
export interface SummaryFlushResult {
  profile: SubmissionProfile;
  startedAt: string;
  finishedAt: string;
  attempted: number;
  submitted: number;
  failed: number;
  replayed: number;
  requestCount: number;
  queuedAfterFlush: number;
  failures: SummaryFlushFailure[];
}
