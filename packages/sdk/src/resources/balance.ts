import type { HttpClient } from '../client';
import type {
  EmitOptions,
  EmitAndWaitOptions,
  EmitResponse,
  DeriveOptions,
  DeriveResponse,
  CompareOptions,
  CompareBalances,
  CompareResponse,
  ReceiptResponse,
  CheckpointOptions,
  CheckpointResponse,
  ListCheckpointsOptions,
  ListCheckpointsResponse,
  DeltaStatusResponse,
  WaitForVerifiedOptions,
  UsageResponse,
  SequenceGapsOptions,
  SequenceGapsResponse,
  ListWebhookDeliveriesOptions,
  ListWebhookDeliveriesResponse,
  ListCustomersOptions,
  ListCustomersResponse,
  GetCustomerOptions,
  CustomerRecordDetail,
  InvoiceProofOptions,
  InvoiceProofResponse,
  CheckpointTimelineResponse,
  CheckpointDiffResponse,
  ListCheckpointTimelineOptions,
} from '../types/balance';
import type { RequestOptions } from '../types/config';
import type { CheckpointType, RecordStatus } from '../types/common';
import type {
  CustomerUsageSummary,
  FlushSummariesOptions,
  QueuedUsageSummary,
  SubmissionAutomationOptions,
  SubmissionQueueState,
  SummaryFlushResult,
} from '../types/submission';
import { pollUntilTerminal } from '../utils/polling';
import { SubmissionCoordinator } from './submission';
import { submitInternalBatch } from './internal/batch-transport';
import { ReceiptsResource } from './receipts';

const toRecordStatus = (status: unknown): RecordStatus => {
  const normalized = String(status ?? '').toUpperCase();
  if (normalized === 'PROCESSING') return 'PROCESSING';
  if (normalized === 'VERIFIED') return 'VERIFIED';
  if (normalized === 'FAILED') return 'FAILED';
  return 'QUEUED';
};

const toCheckpointType = (value: unknown): CheckpointType => {
  return String(value) === 'recordId' ? 'recordId' : 'proofRoot';
};

const toApiCheckpointType = (
  value?: CheckpointType,
): 'proofRoot' | 'recordId' | undefined => {
  if (!value) return undefined;
  return value;
};

type DeriveHelperOptions = RequestOptions & {
  startingBalance?: number;
  limit?: number;
  offset?: number;
};

type ScopedReceiptOptions = InvoiceProofOptions &
  (
    | { period: string }
    | { timePreset: NonNullable<InvoiceProofOptions['timePreset']> }
    | { startDate: string }
    | { endDate: string }
  );

/**
 * PacSpace Balance API resource.
 *
 * Provides methods for the five core Balance API operations:
 * - `emit()` — Record a credit/debit delta
 * - `emitAndWait()` — Record a delta and wait for verification
 * - `derive()` — Derive balance from verified deltas
 * - `compare()` — Compare balances against neutral truth
 * - `receipt()` — Legacy receipt helper (customer-scoped proof generation)
 * - `receipts.*` — Headless receipt document APIs by `receiptId`
 * - `checkpoint()` — Commit a period-end checkpoint
 */
export class BalanceResource {
  /**
   * Submission automation coordinator for tenant-produced summaries.
   */
  readonly submission: SubmissionCoordinator;
  /** Headless receipt helpers (get/list/preview/PDF/email). */
  readonly receipts: ReceiptsResource;

  /** @internal */
  constructor(
    private readonly client: HttpClient,
    submissionOptions?: SubmissionAutomationOptions,
  ) {
    this.submission = new SubmissionCoordinator({
      submitBatch: (deltas) => submitInternalBatch(this.client, deltas),
      options: submissionOptions,
    });
    this.receipts = new ReceiptsResource(this.client);
  }

  // -------------------------------------------------------------------------
  // Emit
  // -------------------------------------------------------------------------

  /**
   * Record a credit or debit delta for a customer.
   *
   * The delta is queued, independently verified, and confirmed via webhook.
   * Returns immediately with `status: 'QUEUED'`. Use `emitAndWait()` to
   * block until verification completes.
   *
   * @param customerId - Unique identifier for the customer account.
   * @param delta - Amount to adjust. Positive = credit, negative = debit.
   * @param reason - Human-readable reason for the adjustment (audit trail).
   * @param options - Optional reference ID, metadata, `adjusts` link, and request overrides.
   * @returns The queued delta with its `receiptId`.
   *
   * @example
   * ```typescript
   * const delta = await pac.balance.emit('cust_123', -42.50, 'usage_charge');
   * console.log(delta.receiptId); // Store this for verification
   *
   * const adjustment = await pac.balance.emit('cust_123', -10, 'adjustment', {
   *   adjusts: { referenceId: 'inv_001' },
   * });
   * ```
   */
  async emit(
    customerId: string,
    delta: number,
    reason: string,
    options?: EmitOptions,
  ): Promise<EmitResponse> {
    const { referenceId, metadata, adjusts, ...requestOptions } = options ?? {};

    const body: Record<string, unknown> = {
      customerId,
      delta,
      reason,
    };

    if (referenceId !== undefined) body.referenceId = referenceId;
    if (metadata !== undefined) body.metadata = metadata;
    if (adjusts !== undefined) body.adjusts = adjusts;

    const response = await this.client.post<Record<string, unknown>>(
      '/api/v1/balance/delta',
      body,
      requestOptions,
    );
    return this.normalizeEmitResponse(response);
  }

  /**
   * Record a delta and wait for it to be verified.
   *
   * Combines `emit()` with status polling. Resolves when the delta reaches
   * a terminal status (`VERIFIED` or `FAILED`), or throws `TimeoutError`
   * if the timeout is exceeded.
   *
   * @param customerId - Unique identifier for the customer account.
   * @param delta - Amount to adjust. Positive = credit, negative = debit.
   * @param reason - Human-readable reason for the adjustment.
   * @param options - Polling timeout, interval, and emit options.
   * @returns The verified delta.
   *
   * @example
   * ```typescript
   * const verified = await pac.balance.emitAndWait('cust_123', -42.50, 'usage', {
   *   timeout: 30_000,
   *   pollInterval: 1000,
   * });
   * console.log(verified.status); // 'VERIFIED' or 'FAILED'
   * ```
   */
  async emitAndWait(
    customerId: string,
    delta: number,
    reason: string,
    options?: EmitAndWaitOptions,
  ): Promise<EmitResponse> {
    const {
      timeout = 60_000,
      pollInterval = 2_000,
      signal,
      ...emitOpts
    } = options ?? {};

    const initial = await this.emit(customerId, delta, reason, {
      ...emitOpts,
      signal,
    });

    // If already terminal, return immediately
    if (['VERIFIED', 'FAILED'].includes(initial.status)) {
      return initial;
    }

    // Poll for terminal status using the balance delta endpoint, then merge
    // the latest status with the original emit metadata.
    const terminalStatus = await pollUntilTerminal<DeltaStatusResponse>(
      () =>
        this.deltaStatus(initial.recordId, { signal } as RequestOptions),
      { timeout, pollInterval, signal },
    );
    return this.mergeEmitWithStatus(initial, terminalStatus);
  }

  /**
   * Check the status of a previously emitted delta.
   *
   * @param recordId - The record ID returned from emit.
   * @param options - Request overrides.
   * @returns Delta status with receipt and transaction details.
   *
   * @example
   * ```typescript
   * const status = await pac.balance.deltaStatus('rec_abc123');
   * console.log(status.status); // 'QUEUED', 'PROCESSING', etc.
   * ```
   */
  async deltaStatus(
    recordId: string,
    options?: RequestOptions,
  ): Promise<DeltaStatusResponse> {
    const response = await this.client.get<Record<string, unknown>>(
      `/api/v1/balance/delta/${encodeURIComponent(recordId)}`,
      options,
    );
    return this.normalizeDeltaStatusResponse(response);
  }

  /**
   * Alias for `deltaStatus()` with lifecycle-oriented naming.
   */
  async getRecordStatus(
    recordId: string,
    options?: RequestOptions,
  ): Promise<DeltaStatusResponse> {
    return this.deltaStatus(recordId, options);
  }

  /**
   * Poll record lifecycle until it reaches a terminal status.
   *
   * Terminal statuses are `VERIFIED` and `FAILED`.
   */
  async waitForVerified(
    recordId: string,
    options?: WaitForVerifiedOptions,
  ): Promise<DeltaStatusResponse> {
    const {
      timeout = 60_000,
      pollInterval = 2_000,
      signal,
      ...requestOptions
    } = options ?? {};

    return pollUntilTerminal<DeltaStatusResponse>(
      () =>
        this.getRecordStatus(recordId, {
          ...requestOptions,
          signal,
        }),
      { timeout, pollInterval, signal },
    );
  }

  /**
   * Retrieve tenant usage counters and remaining allotment.
   */
  async usage(options?: RequestOptions): Promise<UsageResponse> {
    return this.client.get<UsageResponse>('/api/v1/balance/usage', options);
  }

  /**
   * Detect missing per-customer sequence ranges.
   *
   * Use this to identify gaps and re-emit missing deltas safely.
   */
  async gaps(
    customerId: string,
    options?: SequenceGapsOptions,
  ): Promise<SequenceGapsResponse> {
    const {
      fromSequence,
      toSequence,
      limit,
      ...requestOptions
    } = options ?? {};

    const params = new URLSearchParams();
    if (fromSequence !== undefined) params.set('fromSequence', fromSequence);
    if (toSequence !== undefined) params.set('toSequence', toSequence);
    if (limit !== undefined) params.set('limit', String(limit));

    const query = params.toString();
    const path = `/api/v1/balance/gaps/${encodeURIComponent(customerId)}${query ? `?${query}` : ''}`;
    const response = await this.client.get<Record<string, unknown>>(path, requestOptions);
    return this.normalizeSequenceGapsResponse(response);
  }

  /**
   * Queue one tenant-produced summary for SDK-managed submission.
   */
  queueSummary(summary: CustomerUsageSummary): QueuedUsageSummary {
    return this.submission.queueSummary(summary);
  }

  /**
   * Queue multiple tenant-produced summaries.
   */
  queueSummaries(summaries: CustomerUsageSummary[]): QueuedUsageSummary[] {
    return this.submission.queueSummaries(summaries);
  }

  /**
   * Flush queued summaries immediately.
   */
  async flushSummaries(
    options?: FlushSummariesOptions,
  ): Promise<SummaryFlushResult> {
    return this.submission.flushSummaries(options);
  }

  /**
   * Start periodic summary submission scheduling.
   */
  startSummaryScheduler(): void {
    this.submission.start();
  }

  /**
   * Stop periodic summary submission scheduling.
   */
  stopSummaryScheduler(): void {
    this.submission.stop();
  }

  /**
   * Get queue/scheduler state for summary submission automation.
   */
  getSummaryQueueState(): SubmissionQueueState {
    return this.submission.getQueueState();
  }

  /**
   * Stop scheduler and flush queued summaries (best for graceful shutdown).
   */
  async shutdownSummaryScheduler(): Promise<void> {
    await this.submission.shutdown();
  }

  // -------------------------------------------------------------------------
  // Derive
  // -------------------------------------------------------------------------

  /**
   * Derive a customer's balance from all verified deltas.
   *
   * Any party can independently compute the same balance from the same deltas.
   * Supports checkpointing to avoid replaying from genesis at scale.
   *
   * @param customerId - The customer account to derive balance for.
   * @param options - Starting balance, checkpoint, and request overrides.
   * @returns Derived balance with delta history and window summaries.
   *
   * @example
   * ```typescript
   * const { computedBalance, latestReceiptId } = await pac.balance.derive('cust_123');
   *
   * // Use checkpoint for efficient subsequent derivations:
   * const next = await pac.balance.derive('cust_123', {
   *   startingBalance: computedBalance,
   *   startingCheckpoint: latestReceiptId,
   * });
   * ```
   */
  async derive(
    customerId: string,
    options?: DeriveOptions,
  ): Promise<DeriveResponse> {
    const {
      startingBalance,
      startingCheckpoint,
      startingCheckpointType,
      limit,
      offset,
      period,
      timePreset,
      startDate,
      endDate,
      ...requestOptions
    } = options ?? {};

    // Build query string
    const params = new URLSearchParams();
    if (startingBalance !== undefined) {
      params.set('startingBalance', String(startingBalance));
    }
    if (startingCheckpoint !== undefined) {
      params.set('startingCheckpoint', startingCheckpoint);
    }
    const apiCheckpointType = toApiCheckpointType(startingCheckpointType);
    if (apiCheckpointType !== undefined) {
      params.set('startingCheckpointType', apiCheckpointType);
    }
    if (limit !== undefined) {
      params.set('limit', String(limit));
    }
    if (offset !== undefined) {
      params.set('offset', String(offset));
    }
    if (period !== undefined) {
      params.set('period', period);
    }
    if (timePreset !== undefined) {
      params.set('timePreset', timePreset);
    }
    if (startDate !== undefined) {
      params.set('startDate', startDate);
    }
    if (endDate !== undefined) {
      params.set('endDate', endDate);
    }

    const query = params.toString();
    const path = `/api/v1/balance/derive/${encodeURIComponent(customerId)}${query ? `?${query}` : ''}`;

    const response = await this.client.get<Record<string, unknown>>(path, requestOptions);
    return this.normalizeDeriveResponse(response);
  }

  /**
   * Convenience helper for deriving the current UTC month.
   */
  async deriveCurrentMonth(
    customerId: string,
    options?: DeriveHelperOptions,
  ): Promise<DeriveResponse> {
    return this.derive(customerId, {
      ...options,
      timePreset: 'current_month',
    });
  }

  /**
   * Convenience helper for deriving a specific UTC month (`YYYY-MM`).
   */
  async deriveForPeriod(
    customerId: string,
    period: string,
    options?: DeriveHelperOptions,
  ): Promise<DeriveResponse> {
    return this.derive(customerId, {
      ...options,
      period,
    });
  }

  /**
   * Convenience helper for deriving a rolling window of recent UTC months.
   *
   * For example, `months = 3` resolves from the start of month N-2 through the
   * end of the current UTC month.
   */
  async deriveMonthsBack(
    customerId: string,
    months: number,
    options?: DeriveHelperOptions,
  ): Promise<DeriveResponse> {
    if (!Number.isInteger(months) || months < 1) {
      throw new TypeError('months must be a positive integer');
    }

    const now = new Date();
    const endExclusive = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1),
    );
    const start = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - (months - 1), 1),
    );

    return this.derive(customerId, {
      ...options,
      timePreset: 'custom',
      startDate: start.toISOString(),
      endDate: endExclusive.toISOString(),
    });
  }

  /**
   * Convenience helper for deriving the previous N UTC days.
   */
  async deriveDaysBack(
    customerId: string,
    days: number,
    options?: DeriveHelperOptions,
  ): Promise<DeriveResponse> {
    if (!Number.isInteger(days) || days < 1) {
      throw new TypeError('days must be a positive integer');
    }

    const now = new Date();
    const endExclusive = new Date(
      Date.UTC(
        now.getUTCFullYear(),
        now.getUTCMonth(),
        now.getUTCDate() + 1,
        0,
        0,
        0,
        0,
      ),
    );
    const start = new Date(endExclusive);
    start.setUTCDate(start.getUTCDate() - days);

    return this.derive(customerId, {
      ...options,
      timePreset: 'custom',
      startDate: start.toISOString(),
      endDate: endExclusive.toISOString(),
    });
  }

  // -------------------------------------------------------------------------
  // Compare
  // -------------------------------------------------------------------------

  /**
   * Compare balances against neutral truth for dispute resolution.
   *
   * Submit your balance and your counterparty's balance. PacSpace derives
   * the neutral truth from verified deltas and returns a discrepancy report
   * showing which party matches and which window(s) diverged.
   *
   * @param customerId - The customer account to compare.
   * @param balances - Your balance and their balance.
   * @param options - Starting balance, checkpoint, and request overrides.
   * @returns Comparison result with discrepancy report.
   *
   * @example
   * ```typescript
   * const report = await pac.balance.compare('cust_123', {
   *   yours: 95000,
   *   theirs: 98000,
   * });
   *
   * if (report.matchesYours) {
   *   console.log('Your balance is correct');
   * }
   * ```
   */
  async compare(
    customerId: string,
    balances: CompareBalances,
    options?: CompareOptions,
  ): Promise<CompareResponse> {
    const {
      startingBalance = 0,
      startingCheckpoint,
      startingCheckpointType,
      period,
      timePreset,
      startDate,
      endDate,
      ...requestOptions
    } = options ?? {};

    const body: Record<string, unknown> = {
      customerId,
      yourBalance: balances.yours,
      theirBalance: balances.theirs,
      startingBalance,
    };

    if (startingCheckpoint !== undefined) {
      body.startingCheckpoint = startingCheckpoint;
    }
    const apiCheckpointType = toApiCheckpointType(startingCheckpointType);
    if (apiCheckpointType !== undefined) {
      body.startingCheckpointType = apiCheckpointType;
    }
    if (period !== undefined) {
      body.period = period;
    }
    if (timePreset !== undefined) {
      body.timePreset = timePreset;
    }
    if (startDate !== undefined) {
      body.startDate = startDate;
    }
    if (endDate !== undefined) {
      body.endDate = endDate;
    }

    const response = await this.client.post<Record<string, unknown>>(
      '/api/v1/balance/compare',
      body,
      requestOptions,
    );
    return this.normalizeCompareResponse(response);
  }

  // -------------------------------------------------------------------------
  // Receipt
  // -------------------------------------------------------------------------

  /**
   * Generate a verifiable receipt for a customer.
   *
   * When `options.period` is provided, returns a period-specific receipt (proof root,
   * verifyUrl, verificationReference) suitable for sharing on invoices. When
   * omitted, returns the full record receipt with all verified deltas.
   *
   * @param customerId - The customer account to generate a receipt for.
   * @param options - Optional period (YYYY-MM) and request overrides.
   * @returns Receipt with verification data; shape depends on whether period is set.
   *
   * @example
   * ```typescript
   * // Period-specific receipt (shareable proof for invoices)
   * const receipt = await pac.balance.receipt('cust_123', { period: '2026-02' });
   * console.log(receipt.proofRoot);   // Include on invoice
   * console.log(receipt.verifyUrl);   // Share with counterparty
   *
   * // Full record receipt
   * const full = await pac.balance.receipt('cust_123');
   * console.log(full.finalBalance);
   * ```
   */
  receipt(
    customerId: string,
    options: ScopedReceiptOptions,
  ): Promise<InvoiceProofResponse>;
  receipt(customerId: string, options?: RequestOptions): Promise<ReceiptResponse>;
  async receipt(
    customerId: string,
    options?: InvoiceProofOptions & RequestOptions,
  ): Promise<ReceiptResponse | InvoiceProofResponse> {
    const opts = options ?? {};
    const hasScopedReceipt =
      opts.period !== undefined ||
      opts.timePreset !== undefined ||
      opts.startDate !== undefined ||
      opts.endDate !== undefined;
    if (hasScopedReceipt) {
      return this.receiptForPeriod(customerId, opts);
    }
    const { period: _period, timePreset: _timePreset, startDate: _startDate, endDate: _endDate, ...requestOptions } = opts;
    const hasOverrides = Object.keys(requestOptions).length > 0;
    const response = await this.client.get<Record<string, unknown>>(
      `/api/v1/balance/receipt/${encodeURIComponent(customerId)}`,
      hasOverrides ? requestOptions : undefined,
    );
    return this.normalizeReceiptResponse(response);
  }

  /**
   * @internal
   * Generate a period-specific receipt (proof root, verifyUrl). Used by receipt().
   */
  private async receiptForPeriod(
    customerId: string,
    options?: InvoiceProofOptions,
  ): Promise<InvoiceProofResponse> {
    const { period, timePreset, startDate, endDate, ...requestOptions } = options ?? {};

    const params = new URLSearchParams();
    if (period !== undefined) params.set('period', period);
    if (timePreset !== undefined) params.set('timePreset', timePreset);
    if (startDate !== undefined) params.set('startDate', startDate);
    if (endDate !== undefined) params.set('endDate', endDate);

    const query = params.toString();
    const path = `/api/v1/balance/invoice-proof/${encodeURIComponent(customerId)}${query ? `?${query}` : ''}`;

    const response = await this.client.get<Record<string, unknown>>(path, requestOptions);
    return this.normalizeInvoiceProofResponse(response);
  }

  // -------------------------------------------------------------------------
  // Checkpoint
  // -------------------------------------------------------------------------

  /**
   * Commit a period-end checkpoint.
   *
   * Computes a proof root over all verified deltas in the billing window
   * and records it on the proof layer. The proof root can be
   * included in invoices for instant counterparty verification.
   *
   * @param customerId - Customer to checkpoint (omit for all customers).
   * @param options - Period (YYYY-MM) and request overrides.
   * @returns Checkpoint details with proof root and status.
   *
   * @example
   * ```typescript
   * const checkpoint = await pac.balance.checkpoint('cust_123', {
   *   period: '2026-02',
   * });
   * console.log(checkpoint.proofRoot); // Include in your invoice
   * ```
   */
  async checkpoint(
    customerId?: string,
    options?: CheckpointOptions,
  ): Promise<CheckpointResponse> {
    const {
      period,
      timePreset,
      startDate,
      endDate,
      mode,
      fingerprints,
      ...requestOptions
    } = options ?? {};

    const body: Record<string, unknown> = {};
    if (customerId !== undefined) body.customerId = customerId;
    if (period !== undefined) body.period = period;
    if (timePreset !== undefined) body.timePreset = timePreset;
    if (startDate !== undefined) body.startDate = startDate;
    if (endDate !== undefined) body.endDate = endDate;
    if (mode !== undefined) body.mode = mode;
    if (fingerprints !== undefined) body.fingerprints = fingerprints;

    const response = await this.client.post<Record<string, unknown>>(
      '/api/v1/balance/checkpoint',
      body,
      requestOptions,
    );
    return this.normalizeCheckpointResponse(response);
  }

  // -------------------------------------------------------------------------
  // List Checkpoints
  // -------------------------------------------------------------------------

  /**
   * List committed checkpoints for your tenant.
   *
   * Returns a paginated list of checkpoints, optionally filtered by
   * customer ID and/or billing period.
   *
   * @param options - Filter and pagination options.
   * @returns Paginated list of checkpoints.
   *
   * @example
   * ```typescript
   * const { checkpoints } = await pac.balance.listCheckpoints({
   *   period: '2026-02',
   *   limit: 10,
   * });
   * ```
   */
  async listCheckpoints(
    options?: ListCheckpointsOptions,
  ): Promise<ListCheckpointsResponse> {
    const { customerId, period, timePreset, startDate, endDate, limit, offset, ...requestOptions } =
      options ?? {};

    const params = new URLSearchParams();
    if (customerId !== undefined) params.set('customerId', customerId);
    if (period !== undefined) params.set('period', period);
    if (timePreset !== undefined) params.set('timePreset', timePreset);
    if (startDate !== undefined) params.set('startDate', startDate);
    if (endDate !== undefined) params.set('endDate', endDate);
    if (limit !== undefined) params.set('limit', String(limit));
    if (offset !== undefined) params.set('offset', String(offset));

    const query = params.toString();
    const path = `/api/v1/balance/checkpoints${query ? `?${query}` : ''}`;

    const response = await this.client.get<Record<string, unknown>>(path, requestOptions);
    return this.normalizeListCheckpointsResponse(response);
  }

  /**
   * List checkpoint timeline points and detected coverage gaps.
   */
  async listCheckpointTimeline(
    customerId: string,
    options?: ListCheckpointTimelineOptions,
  ): Promise<CheckpointTimelineResponse> {
    const { monthsBack, startDate, endDate, ...requestOptions } = options ?? {};

    const params = new URLSearchParams();
    if (monthsBack !== undefined) params.set('monthsBack', String(monthsBack));
    if (startDate !== undefined) params.set('startDate', startDate);
    if (endDate !== undefined) params.set('endDate', endDate);

    const query = params.toString();
    const path = `/api/v1/balance/checkpoint-timeline/${encodeURIComponent(customerId)}${query ? `?${query}` : ''}`;
    return this.client.get<CheckpointTimelineResponse>(path, requestOptions);
  }

  /**
   * Compare two checkpoints and return fingerprint and daily divergence deltas.
   */
  async diffCheckpoints(
    customerId: string,
    leftCheckpointId: string,
    rightCheckpointId: string,
    options?: RequestOptions,
  ): Promise<CheckpointDiffResponse> {
    return this.client.post<CheckpointDiffResponse>(
      `/api/v1/balance/checkpoint-diff/${encodeURIComponent(customerId)}`,
      {
        leftCheckpointId,
        rightCheckpointId,
      },
      options,
    );
  }

  // -------------------------------------------------------------------------
  // Webhook Deliveries
  // -------------------------------------------------------------------------

  /**
   * List webhook delivery history.
   *
   * @param options - Filter and pagination options.
   * @returns Paginated list of webhook deliveries.
   *
   * @example
   * ```typescript
   * const { deliveries } = await pac.balance.listWebhookDeliveries({
   *   status: 'failed',
   *   limit: 10,
   * });
   * ```
   */
  async listWebhookDeliveries(
    options?: ListWebhookDeliveriesOptions,
  ): Promise<ListWebhookDeliveriesResponse> {
    const { status, limit, offset, ...requestOptions } = options ?? {};

    const params = new URLSearchParams();
    if (status !== undefined) params.set('status', status);
    if (limit !== undefined) params.set('limit', String(limit));
    if (offset !== undefined) params.set('offset', String(offset));

    const query = params.toString();
    const path = `/api/v1/balance/webhooks${query ? `?${query}` : ''}`;

    return this.client.get<ListWebhookDeliveriesResponse>(path, requestOptions);
  }

  /**
   * Retry a failed webhook delivery.
   *
   * @param eventId - The event ID of the failed delivery.
   * @param options - Request overrides.
   *
   * @example
   * ```typescript
   * await pac.balance.retryWebhook('evt_abc123');
   * ```
   */
  async retryWebhook(
    eventId: string,
    options?: RequestOptions,
  ): Promise<{ eventId: string; status: string; message: string }> {
    return this.client.post(
      `/api/v1/balance/webhooks/${encodeURIComponent(eventId)}/retry`,
      {},
      options,
    );
  }

  // -------------------------------------------------------------------------
  // Customer Ledgers
  // -------------------------------------------------------------------------

  /**
   * List all customer balance records for your account.
   *
   * Each unique customerId passed to emit() automatically creates an
   * isolated customer record. This method returns a paginated list.
   *
   * @param options - Search, pagination, and request overrides.
   * @returns Paginated list of customer records.
   *
   * @example
   * ```typescript
   * const { customers } = await pac.balance.customers();
   * for (const c of customers) {
   *   console.log(c.customerId, c.totalDeltas);
   * }
   * ```
   */
  async customers(
    options?: ListCustomersOptions,
  ): Promise<ListCustomersResponse> {
    const { search, limit, page, ...requestOptions } = options ?? {};

    const params = new URLSearchParams();
    if (search !== undefined) params.set('search', search);
    if (limit !== undefined) params.set('limit', String(limit));
    if (page !== undefined) params.set('page', String(page));

    const query = params.toString();
    const path = `/api/v1/balance/customers${query ? `?${query}` : ''}`;

    const response = await this.client.get<Record<string, unknown>>(path, requestOptions);
    return this.normalizeListCustomersResponse(response);
  }

  /**
   * Get the full record detail for a specific customer.
   *
   * Returns the derived customer reference, computed balance, delta count,
   * and latest checkpoint. The customer reference is deterministic.
   *
   * @param customerId - The customer to look up.
   * @param options - Activity pagination and request overrides.
   * @returns Customer detail including balance and references.
   *
   * @example
   * ```typescript
   * const customer = await pac.balance.customer('cust_001');
   * console.log(customer.customerReference); // 0xA1b2...Ef34
   * console.log(customer.computedBalance);   // 4500.00
   * ```
   */
  async customer(
    customerId: string,
    options?: GetCustomerOptions,
  ): Promise<CustomerRecordDetail> {
    const { deltaPage, deltaLimit, period, ...requestOptions } = options ?? {};

    const params = new URLSearchParams();
    if (deltaPage !== undefined) params.set('deltaPage', String(deltaPage));
    if (deltaLimit !== undefined) params.set('deltaLimit', String(deltaLimit));
    if (period !== undefined) params.set('period', period);

    const query = params.toString();
    const path = `/api/v1/balance/customers/${encodeURIComponent(customerId)}${query ? `?${query}` : ''}`;

    const response = await this.client.get<Record<string, unknown>>(path, requestOptions);
    return this.normalizeCustomerDetailResponse(response);
  }

  private normalizeEmitResponse(data: Record<string, unknown>): EmitResponse {
    // ADR 0008 §5 (N-4): receiptId and proofRoot are distinct identifiers and
    // neither stands in for the other.
    return {
      recordId: String(data.recordId ?? ''),
      customerId: String(data.customerId ?? ''),
      delta: Number(data.delta ?? 0),
      sequenceNumber:
        data.sequenceNumber == null ? undefined : String(data.sequenceNumber),
      status: toRecordStatus(data.status),
      receiptId: String(data.receiptId ?? ''),
      proofRoot: String(data.proofRoot ?? ''),
      itemHashes: Array.isArray(data.itemHashes)
        ? data.itemHashes.map((value) => String(value))
        : [],
      estimatedVerifiedDeltas: Number(data.estimatedVerifiedDeltas ?? 0),
      estimatedCredits: Number(data.estimatedCredits ?? 0),
      receivedAt: String(data.receivedAt ?? ''),
      message: String(data.message ?? ''),
    };
  }

  private mergeEmitWithStatus(
    initial: EmitResponse,
    status: DeltaStatusResponse,
  ): EmitResponse {
    const firstDelta = status.deltas[0];
    const customerId =
      status.customerId ?? firstDelta?.customerId ?? initial.customerId;
    const delta = status.delta ?? firstDelta?.delta ?? initial.delta;
    const sequenceNumber = firstDelta?.sequenceNumber ?? initial.sequenceNumber;

    return {
      ...initial,
      recordId: status.recordId || initial.recordId,
      customerId: customerId == null ? initial.customerId : String(customerId),
      delta: delta == null ? initial.delta : Number(delta),
      sequenceNumber: sequenceNumber ?? undefined,
      status: status.status,
      receiptId: status.receiptId ?? initial.receiptId,
      // The status response carries no proof root; the one from the emit stands.
      proofRoot: initial.proofRoot,
      receivedAt: status.receivedAt || initial.receivedAt,
      message:
        status.status === 'VERIFIED'
          ? 'Delta verified.'
          : status.status === 'FAILED'
            ? 'Delta verification failed.'
            : initial.message,
    };
  }

  private normalizeDeltaStatusResponse(
    data: Record<string, unknown>,
  ): DeltaStatusResponse {
    const deltas = Array.isArray(data.deltas)
      ? data.deltas.map((entry) => {
          const item = entry as Record<string, unknown>;
          return {
            customerId:
              item.customerId == null ? null : String(item.customerId),
            delta: item.delta == null ? null : Number(item.delta),
            sequenceNumber:
              item.sequenceNumber == null ? null : String(item.sequenceNumber),
          };
        })
      : [];

    return {
      recordId: String(data.recordId ?? ''),
      status: toRecordStatus(data.status),
      deltaCount: Number(data.deltaCount ?? deltas.length),
      customerId: data.customerId == null ? null : String(data.customerId),
      delta: data.delta == null ? null : Number(data.delta),
      deltas,
      receiptId: data.receiptId == null ? null : String(data.receiptId),
      verificationReference:
        data.verificationReference == null ? null : String(data.verificationReference),
      receivedAt: String(data.receivedAt ?? ''),
      verifiedAt: data.verifiedAt == null ? null : String(data.verifiedAt),
    };
  }

  private normalizeDeriveResponse(data: Record<string, unknown>): DeriveResponse {
    const deltas = Array.isArray(data.deltas)
      ? data.deltas.map((entry) => {
          const item = entry as Record<string, unknown>;
          return {
            recordId: String(item.recordId ?? ''),
            itemHash: String(item.itemHash ?? ''),
            proofRoot: String(item.proofRoot ?? ''),
            receiptId: String(item.receiptId ?? ''),
            sequenceNumber:
              item.sequenceNumber == null ? null : String(item.sequenceNumber),
            delta: Number(item.delta ?? 0),
            reason: item.reason == null ? null : String(item.reason),
            referenceId:
              item.referenceId == null ? null : String(item.referenceId),
            window: String(item.window ?? ''),
            declaredTimestamp:
              item.declaredTimestamp == null
                ? null
                : String(item.declaredTimestamp),
            blockTimestamp:
              item.blockTimestamp == null ? null : String(item.blockTimestamp),
            dataPurged: Boolean(item.dataPurged),
            verified: true as const,
          };
        })
      : [];

    const verificationProof = (data.verificationProof ??
      {}) as Record<string, unknown>;

    const windowSummaries = Array.isArray(data.windowSummaries)
      ? data.windowSummaries.map((entry) => {
          const item = entry as Record<string, unknown>;
          return {
            window: String(item.window ?? ''),
            deltasCount: Number(item.deltasCount ?? 0),
            netDelta: Number(item.netDelta ?? 0),
            firstBlockTimestamp:
              item.firstBlockTimestamp == null
                ? null
                : String(item.firstBlockTimestamp),
            lastBlockTimestamp:
              item.lastBlockTimestamp == null
                ? null
                : String(item.lastBlockTimestamp),
          };
        })
      : [];

    const scope = (data.scope ?? null) as Record<string, unknown> | null;
    const monthlyBreakdown = Array.isArray(data.monthlyBreakdown)
      ? data.monthlyBreakdown.map((entry) => {
          const item = entry as Record<string, unknown>;
          const checkpoint = (item.checkpoint ?? null) as
            | Record<string, unknown>
            | null;

          return {
            period: String(item.period ?? ''),
            periodStart: String(item.periodStart ?? ''),
            periodEndExclusive: String(item.periodEndExclusive ?? ''),
            deltaCount: Number(item.deltaCount ?? 0),
            netDelta: Number(item.netDelta ?? 0),
            runningBalance: Number(item.runningBalance ?? 0),
            checkpoint: checkpoint
              ? {
                  checkpointId: String(checkpoint.checkpointId ?? ''),
                  proofRoot:
                    checkpoint.proofRoot == null
                      ? null
                      : String(checkpoint.proofRoot),
                  status: toRecordStatus(checkpoint.status),
                }
              : null,
          };
        })
      : undefined;

    const pagination = (data.pagination ?? {}) as Record<string, unknown>;
    const hint = data._hint as Record<string, unknown> | undefined;

    return {
      customerId: String(data.customerId ?? ''),
      startingBalance: Number(data.startingBalance ?? 0),
      startingCheckpoint: String(data.startingCheckpoint ?? 'genesis'),
      startingCheckpointType: toCheckpointType(data.startingCheckpointType),
      deltasCount: Number(data.deltasCount ?? deltas.length),
      computedBalance: Number(data.computedBalance ?? 0),
      latestCheckpoint:
        data.latestCheckpoint == null ? null : String(data.latestCheckpoint),
      latestReceiptId:
        data.latestReceiptId == null ? null : String(data.latestReceiptId),
      deltas,
      windowSummaries,
      verificationProof: {
        proofRoot:
          verificationProof.proofRoot == null
            ? null
            : String(verificationProof.proofRoot),
        message: String(verificationProof.message ?? ''),
      },
      scope: scope
        ? {
            kind:
              String(scope.kind ?? 'period') === 'custom'
                ? 'custom'
                : String(scope.kind ?? 'period') === 'preset'
                  ? 'preset'
                  : 'period',
            periodId:
              scope.periodId == null ? null : String(scope.periodId),
            preset:
              scope.preset == null
                ? null
                : (String(scope.preset) as NonNullable<
                    DeriveResponse['scope']
                  >['preset']),
            startDate: String(scope.startDate ?? ''),
            endDateExclusive: String(scope.endDateExclusive ?? ''),
            label: String(scope.label ?? ''),
          }
        : null,
      monthlyBreakdown,
      cumulativeBalance:
        data.cumulativeBalance == null
          ? undefined
          : Number(data.cumulativeBalance),
      pagination: {
        total: Number(pagination.total ?? deltas.length),
        limit: Number(pagination.limit ?? deltas.length),
        offset: Number(pagination.offset ?? 0),
      },
      _hint:
        hint == null
          ? undefined
          : {
              message: String(hint.message ?? ''),
              recommendation: String(hint.recommendation ?? ''),
              docsUrl: String(hint.docsUrl ?? ''),
            },
    };
  }

  private normalizeCompareResponse(
    data: Record<string, unknown>,
  ): CompareResponse {
    const proof = (data.proof ?? {}) as Record<string, unknown>;
    const scope = (data.scope ?? null) as Record<string, unknown> | null;
    const monthlyBreakdown = Array.isArray(data.monthlyBreakdown)
      ? data.monthlyBreakdown.map((entry) => {
          const item = entry as Record<string, unknown>;
          const checkpoint = (item.checkpoint ?? null) as
            | Record<string, unknown>
            | null;

          return {
            period: String(item.period ?? ''),
            periodStart: String(item.periodStart ?? ''),
            periodEndExclusive: String(item.periodEndExclusive ?? ''),
            deltaCount: Number(item.deltaCount ?? 0),
            netDelta: Number(item.netDelta ?? 0),
            runningBalance: Number(item.runningBalance ?? 0),
            checkpoint: checkpoint
              ? {
                  checkpointId: String(checkpoint.checkpointId ?? ''),
                  proofRoot:
                    checkpoint.proofRoot == null
                      ? null
                      : String(checkpoint.proofRoot),
                  status: toRecordStatus(checkpoint.status),
                }
              : null,
          };
        })
      : undefined;

    return {
      customerId: String(data.customerId ?? ''),
      yourBalance: Number(data.yourBalance ?? 0),
      theirBalance: Number(data.theirBalance ?? 0),
      neutralBalance: Number(data.neutralBalance ?? 0),
      matchesYours: Boolean(data.matchesYours),
      matchesTheirs: Boolean(data.matchesTheirs),
      deltasVerified: Number(data.deltasVerified ?? 0),
      discrepancyReport:
        (data.discrepancyReport as CompareResponse['discrepancyReport']) ?? null,
      proof: {
        proofRoot: proof.proofRoot == null ? null : String(proof.proofRoot),
        latestCheckpoint:
          proof.latestCheckpoint == null ? null : String(proof.latestCheckpoint),
        windowSummaries:
          (proof.windowSummaries as CompareResponse['proof']['windowSummaries']) ??
          [],
      },
      scope: scope
        ? {
            kind:
              String(scope.kind ?? 'period') === 'custom'
                ? 'custom'
                : String(scope.kind ?? 'period') === 'preset'
                  ? 'preset'
                  : 'period',
            periodId:
              scope.periodId == null ? null : String(scope.periodId),
            preset:
              scope.preset == null
                ? null
                : (String(scope.preset) as NonNullable<
                    CompareResponse['scope']
                  >['preset']),
            startDate: String(scope.startDate ?? ''),
            endDateExclusive: String(scope.endDateExclusive ?? ''),
            label: String(scope.label ?? ''),
          }
        : null,
      monthlyBreakdown,
      cumulativeBalance:
        data.cumulativeBalance == null
          ? undefined
          : Number(data.cumulativeBalance),
    };
  }

  private normalizeReceiptResponse(
    data: Record<string, unknown>,
  ): ReceiptResponse {
    const verification = (data.verification ?? {}) as Record<string, unknown>;
    return {
      customerId: String(data.customerId ?? ''),
      generatedAt: String(data.generatedAt ?? ''),
      deltasCount: Number(data.deltasCount ?? 0),
      finalBalance: Number(data.finalBalance ?? 0),
      proofRoot: data.proofRoot == null ? null : String(data.proofRoot),
      receiptId: data.receiptId == null ? null : String(data.receiptId),
      latestCheckpoint:
        data.latestCheckpoint == null ? null : String(data.latestCheckpoint),
      deltas: (data.deltas as ReceiptResponse['deltas']) ?? [],
      windowSummaries:
        (data.windowSummaries as ReceiptResponse['windowSummaries']) ?? [],
      verification: {
        message: String(verification.message ?? ''),
        itemHashes: Array.isArray(verification.itemHashes)
          ? verification.itemHashes.map((value) => String(value))
          : [],
      },
    };
  }

  private normalizeInvoiceProofResponse(
    data: Record<string, unknown>,
  ): InvoiceProofResponse {
    return {
      customerId: String(data.customerId ?? ''),
      period: String(data.period ?? ''),
      proofRoot: String(data.proofRoot ?? ''),
      verificationReference:
        data.verificationReference == null
          ? null
          : String(data.verificationReference),
      verificationApiUrl:
        data.verificationApiUrl == null ? null : String(data.verificationApiUrl),
      verificationExplorerUrl:
        data.verificationExplorerUrl == null
          ? null
          : String(data.verificationExplorerUrl),
      verifyUrl: data.verifyUrl == null ? null : String(data.verifyUrl),
      accessHint: data.accessHint == null ? null : String(data.accessHint),
      customerLinkUrl:
        data.customerLinkUrl == null ? null : String(data.customerLinkUrl),
      customerLinkHost:
        data.customerLinkHost == null ? null : String(data.customerLinkHost),
      deltaCount: Number(data.deltaCount ?? 0),
      startingBalance: Number(data.startingBalance ?? 0),
      finalBalance: Number(data.finalBalance ?? 0),
      windowSummary:
        (data.windowSummary as InvoiceProofResponse['windowSummary']) ??
        ({
          window: '',
          deltasCount: 0,
          netDelta: 0,
          firstDeltaAt: null,
          lastDeltaAt: null,
        } as InvoiceProofResponse['windowSummary']),
      deltas: (data.deltas as InvoiceProofResponse['deltas']) ?? [],
      verification:
        (data.verification as InvoiceProofResponse['verification']) ??
        ({
          proofRoot: null,
          totalBalance: 0,
          periodBalance: 0,
        } as InvoiceProofResponse['verification']),
    };
  }

  private normalizeCheckpointResponse(
    data: Record<string, unknown>,
  ): CheckpointResponse {
    return {
      checkpointId: String(data.checkpointId ?? ''),
      period: String(data.period ?? ''),
      proofRoot: String(data.proofRoot ?? ''),
      scope: data.scope as CheckpointResponse['scope'],
      mode: data.mode as CheckpointResponse['mode'],
      deltaCount: Number(data.deltaCount ?? 0),
      selectedFingerprintCount:
        data.selectedFingerprintCount == null
          ? undefined
          : Number(data.selectedFingerprintCount),
      eligibleFingerprintCount:
        data.eligibleFingerprintCount == null
          ? undefined
          : Number(data.eligibleFingerprintCount),
      selectedFingerprints: Array.isArray(data.selectedFingerprints)
        ? data.selectedFingerprints.map((value) => String(value))
        : undefined,
      fromIndex: Number(data.fromIndex ?? 0),
      toIndex: Number(data.toIndex ?? 0),
      customerId: String(data.customerId ?? ''),
      status: toRecordStatus(data.status),
      message: String(data.message ?? ''),
    };
  }

  private normalizeListCheckpointsResponse(
    data: Record<string, unknown>,
  ): ListCheckpointsResponse {
    const checkpoints = Array.isArray(data.checkpoints)
      ? data.checkpoints.map((entry) => {
          const item = entry as Record<string, unknown>;
          return {
            checkpointId: String(item.checkpointId ?? ''),
            period: String(item.period ?? ''),
            proofRoot:
              item.proofRoot == null ? null : String(item.proofRoot),
            scope: item.scope as ListCheckpointsResponse['checkpoints'][number]['scope'],
            mode: item.mode as ListCheckpointsResponse['checkpoints'][number]['mode'],
            deltaCount: Number(item.deltaCount ?? 0),
            selectedFingerprintCount:
              item.selectedFingerprintCount == null
                ? undefined
                : Number(item.selectedFingerprintCount),
            eligibleFingerprintCount:
              item.eligibleFingerprintCount == null
                ? undefined
                : Number(item.eligibleFingerprintCount),
            customerId: String(item.customerId ?? ''),
            status: toRecordStatus(item.status),
            verificationReference:
              item.verificationReference == null
                ? null
                : String(item.verificationReference),
            verifiedAt: item.verifiedAt == null ? null : String(item.verifiedAt),
            receivedAt: String(item.receivedAt ?? ''),
          };
        })
      : [];

    const pagination = (data.pagination ?? {}) as Record<string, unknown>;
    return {
      checkpoints,
      pagination: {
        total: Number(pagination.total ?? checkpoints.length),
        limit: Number(pagination.limit ?? checkpoints.length),
        offset: Number(pagination.offset ?? 0),
      },
    };
  }

  private normalizeSequenceGapsResponse(
    data: Record<string, unknown>,
  ): SequenceGapsResponse {
    const gaps = Array.isArray(data.gaps)
      ? data.gaps.map((entry) => {
          const item = entry as Record<string, unknown>;
          return {
            startSequence: String(item.startSequence ?? ''),
            endSequence: String(item.endSequence ?? ''),
            missingCount: String(item.missingCount ?? '0'),
          };
        })
      : [];

    return {
      customerId: String(data.customerId ?? ''),
      customerReference: String(data.customerReference ?? ''),
      customerPartition: String(data.customerPartition ?? ''),
      nextSequence: String(data.nextSequence ?? '0'),
      rangeStart: String(data.rangeStart ?? '0'),
      rangeEnd: String(data.rangeEnd ?? '0'),
      gaps,
      hasGaps: Boolean(data.hasGaps),
      missingRanges: Number(data.missingRanges ?? gaps.length),
      missingCountInPage: String(data.missingCountInPage ?? '0'),
      truncated: Boolean(data.truncated),
    };
  }

  private normalizeListCustomersResponse(
    data: Record<string, unknown>,
  ): ListCustomersResponse {
    const customers = Array.isArray(data.customers)
      ? data.customers.map((entry) => {
          const item = entry as Record<string, unknown>;
          return {
            customerId: String(item.customerId ?? ''),
            customerReference: String(item.customerReference ?? ''),
            totalDeltas: Number(item.totalDeltas ?? 0),
            firstDeltaAt:
              item.firstDeltaAt == null ? null : String(item.firstDeltaAt),
            lastDeltaAt:
              item.lastDeltaAt == null ? null : String(item.lastDeltaAt),
          };
        })
      : [];

    const pagination = (data.pagination ?? {}) as Record<string, unknown>;
    return {
      customers,
      pagination: {
        total: Number(pagination.total ?? customers.length),
        page: Number(pagination.page ?? 1),
        limit: Number(pagination.limit ?? customers.length),
        totalPages: Number(pagination.totalPages ?? 1),
      },
    };
  }

  private normalizeCustomerDetailResponse(
    data: Record<string, unknown>,
  ): CustomerRecordDetail {
    const period = (data.period ?? null) as Record<string, unknown> | null;

    return {
      customerId: String(data.customerId ?? ''),
      customerReference: String(data.customerReference ?? ''),
      totalDeltas: Number(data.totalDeltas ?? 0),
      firstDeltaAt: data.firstDeltaAt == null ? null : String(data.firstDeltaAt),
      lastDeltaAt: data.lastDeltaAt == null ? null : String(data.lastDeltaAt),
      customerPartition: String(data.customerPartition ?? ''),
      computedBalance: Number(data.computedBalance ?? 0),
      period: period
        ? {
            id: String(period.id ?? ''),
            startDate: String(period.startDate ?? ''),
            endDateExclusive: String(period.endDateExclusive ?? ''),
            label: String(period.label ?? ''),
          }
        : undefined,
      mostRecentActivePeriod:
        data.mostRecentActivePeriod == null
          ? null
          : String(data.mostRecentActivePeriod),
      latestCheckpoint:
        data.latestCheckpoint == null ? null : String(data.latestCheckpoint),
      privacyNote: String(data.privacyNote ?? ''),
      recentActivity:
        (data.recentActivity as CustomerRecordDetail['recentActivity']) ??
        ({
          items: [],
          pagination: {
            total: 0,
            page: 1,
            limit: 20,
            totalPages: 1,
          },
        } as CustomerRecordDetail['recentActivity']),
    };
  }

  // -------------------------------------------------------------------------
  // Invoice Proof (deprecated — use receipt with period)
  // -------------------------------------------------------------------------

  /**
   * Generate an invoice-ready receipt for a customer's billing period.
   *
   * @deprecated Use `receipt(customerId, { period })` instead.
   * @param customerId - The customer to generate the receipt for.
   * @param options - Period selection and request overrides.
   * @returns Receipt with proof root, verifyUrl, and verification data.
   */
  async invoiceProof(
    customerId: string,
    options?: InvoiceProofOptions,
  ): Promise<InvoiceProofResponse> {
    return this.receiptForPeriod(customerId, options);
  }
}
