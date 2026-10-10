import { createHash } from 'crypto';
import { PacSpaceError } from '../errors';
import type {
  InternalBatchDelta,
  InternalBatchResponse,
} from './internal/batch-transport';
import type {
  CustomerUsageSummary,
  FlushSummariesOptions,
  QueuedUsageSummary,
  SubmissionAutomationOptions,
  SubmissionProfile,
  SubmissionQueueState,
  SummaryFlushFailure,
  SummaryFlushResult,
} from '../types/submission';

type SubmitBatchFn = (
  deltas: InternalBatchDelta[],
) => Promise<InternalBatchResponse>;

interface SubmissionCoordinatorConfig {
  submitBatch: SubmitBatchFn;
  options?: SubmissionAutomationOptions;
}

const PROFILE_DEFAULT_CADENCE_MS: Record<SubmissionProfile, number> = {
  daily: 86_400_000,
  sub_daily: 21_600_000, // DEFAULT UNVALIDATED (6h)
  immediate: 0,
};

const SHUTDOWN_SIGNALS = ['SIGINT', 'SIGTERM', 'beforeExit'] as const;

/**
 * Tenant-owned metering submission automation.
 *
 * This coordinator only submits tenant-produced summaries. It does not infer
 * or meter raw product usage events.
 */
export class SubmissionCoordinator {
  private static readonly trackedCoordinators = new Set<SubmissionCoordinator>();
  private static shutdownHooksRegistered = false;
  private static readonly shutdownHandlers: Record<
    (typeof SHUTDOWN_SIGNALS)[number],
    () => void
  > = {
    SIGINT: () => {
      void SubmissionCoordinator.flushTrackedCoordinators();
    },
    SIGTERM: () => {
      void SubmissionCoordinator.flushTrackedCoordinators();
    },
    beforeExit: () => {
      void SubmissionCoordinator.flushTrackedCoordinators();
    },
  };

  private readonly submitBatch: SubmitBatchFn;
  private readonly profile: SubmissionProfile;
  private readonly cadenceMs: number;
  private readonly enterprise: boolean;
  private readonly autoStart: boolean;
  private readonly autoFlushOnShutdown: boolean;
  private readonly maxDeltasPerRequest: number;
  private readonly maxRequestsPerMinute: number;
  private readonly defaultReason: string;

  private readonly queue = new Map<string, QueuedUsageSummary>();
  private shutdownTracked = false;

  private timer: ReturnType<typeof setTimeout> | null = null;
  private running = false;
  private nextFlushAt: number | null = null;
  private activeFlush: Promise<SummaryFlushResult> | null = null;
  private lastRequestAt = 0;

  constructor(config: SubmissionCoordinatorConfig) {
    this.submitBatch = config.submitBatch;

    const options = config.options ?? {};
    this.profile = options.profile ?? 'daily';
    this.enterprise = options.enterprise ?? false;
    this.autoStart = options.autoStart ?? true;
    this.autoFlushOnShutdown = options.autoFlushOnShutdown ?? true;
    this.defaultReason = options.defaultReason ?? 'usage_summary';

    const configuredCadenceMs =
      options.cadenceMs ?? PROFILE_DEFAULT_CADENCE_MS[this.profile];
    this.cadenceMs = Math.max(0, Math.floor(configuredCadenceMs));

    const configuredPerRequest = options.maxDeltasPerRequest ?? 100;
    this.maxDeltasPerRequest = Math.min(
      100,
      Math.max(1, Math.floor(configuredPerRequest)),
    );

    const configuredRpm = options.maxRequestsPerMinute ?? 10;
    this.maxRequestsPerMinute = Math.max(1, Math.floor(configuredRpm));

    this.assertProfileCompatibility();
  }

  /**
   * Enqueue one tenant-produced customer summary.
   */
  queueSummary(summary: CustomerUsageSummary): QueuedUsageSummary {
    const normalized = this.normalizeSummary(summary);
    this.queue.set(normalized.key, normalized);
    this.ensureShutdownHooks();

    if (this.profile === 'immediate') {
      void this.flushSummaries();
      return normalized;
    }

    if (this.autoStart && !this.running) {
      this.start();
    }

    return normalized;
  }

  /**
   * Enqueue multiple tenant-produced summaries.
   */
  queueSummaries(summaries: CustomerUsageSummary[]): QueuedUsageSummary[] {
    return summaries.map((summary) => this.queueSummary(summary));
  }

  /**
   * Returns queue and scheduler state.
   */
  getQueueState(): SubmissionQueueState {
    return {
      profile: this.profile,
      cadenceMs: this.cadenceMs,
      enterprise: this.enterprise,
      queuedCount: this.queue.size,
      isRunning: this.running,
      nextFlushAt:
        this.nextFlushAt !== null
          ? new Date(this.nextFlushAt).toISOString()
          : null,
    };
  }

  /**
   * Start scheduled flushes for non-immediate profiles.
   */
  start(): void {
    this.ensureShutdownHooks();
    if (this.profile === 'immediate') {
      this.running = true;
      this.nextFlushAt = null;
      return;
    }
    if (this.running) {
      return;
    }
    this.running = true;
    this.scheduleNextFlush(this.cadenceMs);
  }

  /**
   * Stop scheduled flushes.
   */
  stop(): void {
    this.running = false;
    this.nextFlushAt = null;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    if (this.queue.size === 0) {
      this.untrackShutdownHooks();
    }
  }

  /**
   * Flush queued summaries immediately.
   */
  async flushSummaries(
    options?: FlushSummariesOptions,
  ): Promise<SummaryFlushResult> {
    if (this.activeFlush) {
      return this.activeFlush;
    }

    this.activeFlush = this.performFlush(options);

    try {
      return await this.activeFlush;
    } finally {
      this.activeFlush = null;
    }
  }

  /**
   * Stop scheduler, flush pending work, and unregister shutdown hooks.
   */
  async shutdown(): Promise<void> {
    this.stop();
    if (this.queue.size > 0) {
      await this.flushSummaries();
    }
    this.untrackShutdownHooks();
  }

  private assertProfileCompatibility(): void {
    if (
      !this.enterprise &&
      (this.profile === 'sub_daily' || this.profile === 'immediate')
    ) {
      throw new PacSpaceError(
        `Submission profile "${this.profile}" is enterprise-only. Set enterprise: true to enable this profile.`,
        0,
        'INVALID_SUBMISSION_PROFILE',
      );
    }
    if (this.profile !== 'immediate' && this.cadenceMs <= 0) {
      throw new PacSpaceError(
        `Submission profile "${this.profile}" requires cadenceMs > 0.`,
        0,
        'INVALID_SUBMISSION_PROFILE',
      );
    }
  }

  private normalizeSummary(summary: CustomerUsageSummary): QueuedUsageSummary {
    const customerId = summary.customerId.trim();
    if (!customerId) {
      throw new PacSpaceError(
        'customerId is required for summary submission.',
        0,
        'INVALID_SUMMARY',
      );
    }

    if (!Number.isFinite(summary.delta) || summary.delta === 0) {
      throw new PacSpaceError(
        'delta must be a finite non-zero number for summary submission.',
        0,
        'INVALID_SUMMARY',
      );
    }

    const windowStart = this.normalizeIso(summary.windowStart, 'windowStart');
    const windowEnd = this.normalizeIso(summary.windowEnd, 'windowEnd');
    if (windowEnd <= windowStart) {
      throw new PacSpaceError(
        'windowEnd must be later than windowStart.',
        0,
        'INVALID_SUMMARY',
      );
    }

    const key = `${customerId}|${windowStart}|${windowEnd}`;
    const referenceId =
      summary.referenceId?.trim() || this.buildReferenceId(summary, windowStart, windowEnd);

    return {
      ...summary,
      customerId,
      windowStart,
      windowEnd,
      key,
      referenceId,
      queuedAt: new Date().toISOString(),
      reason: summary.reason?.trim() || this.defaultReason,
    };
  }

  private normalizeIso(value: string, field: string): string {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      throw new PacSpaceError(
        `${field} must be a valid ISO-8601 timestamp.`,
        0,
        'INVALID_SUMMARY',
      );
    }
    return parsed.toISOString();
  }

  private buildReferenceId(
    summary: CustomerUsageSummary,
    windowStart: string,
    windowEnd: string,
  ): string {
    const digest = createHash('sha256')
      .update(
        JSON.stringify({
          customerId: summary.customerId,
          delta: summary.delta,
          windowStart,
          windowEnd,
        }),
      )
      .digest('hex')
      .slice(0, 48);
    return `sum_${digest}`;
  }

  private async performFlush(
    options?: FlushSummariesOptions,
  ): Promise<SummaryFlushResult> {
    const startedAt = new Date().toISOString();
    const maxItems =
      options?.maxItems !== undefined
        ? Math.max(0, Math.floor(options.maxItems))
        : Number.POSITIVE_INFINITY;

    const selected = Array.from(this.queue.values()).slice(0, maxItems);
    const failures: SummaryFlushFailure[] = [];

    let submitted = 0;
    let replayed = 0;
    let requestCount = 0;
    const keysToDelete = new Set<string>();

    if (selected.length === 0) {
      return {
        profile: this.profile,
        startedAt,
        finishedAt: new Date().toISOString(),
        attempted: 0,
        submitted: 0,
        failed: 0,
        replayed: 0,
        requestCount: 0,
        queuedAfterFlush: this.queue.size,
        failures: [],
      };
    }

    const chunks = this.chunk(selected, this.maxDeltasPerRequest);
    for (const chunk of chunks) {
      const payload: InternalBatchDelta[] = chunk.map((item) => ({
        customerId: item.customerId,
        delta: item.delta,
        reason: item.reason ?? this.defaultReason,
        referenceId: item.referenceId,
        metadata: {
          summaryWindowStart: item.windowStart,
          summaryWindowEnd: item.windowEnd,
          summaryProfile: this.profile,
          submissionType: 'tenant_summary',
          ...(item.metadata ?? {}),
        },
      }));

      try {
        await this.paceRequests();
        requestCount++;
        const response = await this.submitBatch(payload);
        const indexedResults = new Map<number, (typeof response.results)[number]>();
        for (const result of response.results ?? []) {
          if (typeof result.index === 'number') {
            indexedResults.set(result.index, result);
          }
        }

        for (let index = 0; index < chunk.length; index++) {
          const item = chunk[index];
          const result = indexedResults.get(index);
          const status = String(result?.status ?? '').toUpperCase();
          const isFailed = status === 'FAILED';
          if (isFailed) {
            failures.push({
              customerId: item.customerId,
              referenceId: item.referenceId,
              error: String(result?.error ?? 'Summary submission failed'),
            });
            continue;
          }
          submitted += 1;
          if (result?.idempotent === true) {
            replayed += 1;
          }
          keysToDelete.add(item.key);
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        for (const item of chunk) {
          failures.push({
            customerId: item.customerId,
            referenceId: item.referenceId,
            error: message,
          });
        }
      }
    }

    for (const key of keysToDelete) {
      this.queue.delete(key);
    }

    const finishedAt = new Date().toISOString();
    if (this.queue.size === 0 && !this.running) {
      this.untrackShutdownHooks();
    }
    return {
      profile: this.profile,
      startedAt,
      finishedAt,
      attempted: selected.length,
      submitted,
      failed: failures.length,
      replayed,
      requestCount,
      queuedAfterFlush: this.queue.size,
      failures,
    };
  }

  private async paceRequests(): Promise<void> {
    const minIntervalMs = Math.ceil(60_000 / this.maxRequestsPerMinute);
    const now = Date.now();
    const waitMs = this.lastRequestAt + minIntervalMs - now;
    if (waitMs > 0) {
      await this.sleep(waitMs);
    }
    this.lastRequestAt = Date.now();
  }

  private chunk<T>(items: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let index = 0; index < items.length; index += size) {
      chunks.push(items.slice(index, index + size));
    }
    return chunks;
  }

  private scheduleNextFlush(delayMs: number): void {
    if (!this.running || this.profile === 'immediate') {
      return;
    }
    if (this.timer) {
      clearTimeout(this.timer);
    }
    const safeDelay = Math.max(1, delayMs);
    this.nextFlushAt = Date.now() + safeDelay;
    this.timer = setTimeout(() => {
      void this.onScheduledFlush();
    }, safeDelay);
    this.timer.unref?.();
  }

  private async onScheduledFlush(): Promise<void> {
    this.timer = null;
    if (!this.running || this.profile === 'immediate') {
      return;
    }
    this.nextFlushAt = null;

    try {
      await this.flushSummaries();
    } finally {
      if (this.running) {
        this.scheduleNextFlush(this.cadenceMs);
      }
    }
  }

  private ensureShutdownHooks(): void {
    if (!this.autoFlushOnShutdown) {
      return;
    }
    if (this.shutdownTracked) {
      return;
    }
    this.trackShutdownHooks();
  }

  private static async flushTrackedCoordinators(): Promise<void> {
    for (const coordinator of Array.from(
      SubmissionCoordinator.trackedCoordinators,
    )) {
      try {
        await coordinator.flushSummaries();
      } catch {
        // Best-effort shutdown flush. Errors are intentionally ignored.
      }
    }
  }

  private trackShutdownHooks(): void {
    if (typeof process === 'undefined' || typeof process.on !== 'function') {
      return;
    }

    if (!SubmissionCoordinator.shutdownHooksRegistered) {
      for (const signal of SHUTDOWN_SIGNALS) {
        process.on(signal, SubmissionCoordinator.shutdownHandlers[signal]);
      }
      SubmissionCoordinator.shutdownHooksRegistered = true;
    }
    SubmissionCoordinator.trackedCoordinators.add(this);
    this.shutdownTracked = true;
  }

  private untrackShutdownHooks(): void {
    SubmissionCoordinator.trackedCoordinators.delete(this);
    this.shutdownTracked = false;

    if (
      SubmissionCoordinator.trackedCoordinators.size > 0 ||
      !SubmissionCoordinator.shutdownHooksRegistered ||
      typeof process === 'undefined' ||
      typeof process.off !== 'function'
    ) {
      return;
    }

    for (const signal of SHUTDOWN_SIGNALS) {
      process.off(signal, SubmissionCoordinator.shutdownHandlers[signal]);
    }
    SubmissionCoordinator.shutdownHooksRegistered = false;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
