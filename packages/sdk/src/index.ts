import { HttpClient } from './client';
import { BalanceResource } from './resources/balance';
import { CustomersResource } from './resources/customers';
import { RecordsResource } from './resources/records';
import { Webhooks } from './webhooks/verify';
import type { PacSpaceConfig } from './types/config';
import type { VerifyResponse, VerifySource } from './types/balance';

/** Default production API base URL. */
const DEFAULT_PRODUCTION_URL = 'https://app.pacspace.io';

/**
 * Default sandbox API base URL: the same host. The API routes each request by
 * the environment of its key; `sandboxUrl` stays as a bring-your-own override.
 */
const DEFAULT_SANDBOX_URL = DEFAULT_PRODUCTION_URL;

/**
 * PacSpace SDK — the official TypeScript client for the PacSpace Balance API.
 *
 * @example
 * ```typescript
 * import { PacSpace } from '@pacspace-io/sdk';
 *
 * const pac = new PacSpace({ apiKey: process.env.PACSPACE_API_KEY! });
 *
 * // Record a delta
 * const delta = await pac.balance.emit('cust_123', -42.50, 'usage_charge');
 *
 * // Derive balance
 * const { computedBalance } = await pac.balance.derive('cust_123');
 *
 * // Compare against counterparty
 * const report = await pac.balance.compare('cust_123', {
 *   yours: 95000,
 *   theirs: 98000,
 * });
 *
 * // Period-end receipt (shareable verification proof)
 * const receipt = await pac.balance.receipt('cust_123', { period: '2026-02' });
 *
 * // Verify a proof root (public, no auth)
 * const verification = await pac.verify(receipt.proofRoot);
 * ```
 */
export class PacSpace {
  /**
   * Preferred SDK initializer for Phase 3 surface.
   */
  static init(
    apiKey: string,
    options: Omit<PacSpaceConfig, 'apiKey'> = {},
  ): PacSpace {
    return new PacSpace({ apiKey, ...options });
  }

  /** @internal */
  private readonly client: HttpClient;
  /** Base URL for API (used by verify, which requires no auth). */
  private readonly baseUrl: string;
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;

  /**
   * Balance API resource — emit deltas, derive balances, compare, receipt, checkpoint.
   */
  readonly balance: BalanceResource;

  /**
   * Dashboard customer helpers.
   */
  readonly customers: CustomersResource;

  /**
   * Records API resource — fingerprint a file, emit, read a receipt or history, check.
   */
  readonly records: RecordsResource;

  /**
   * Webhook verification helper.
   * Only available when a `webhookSecret` is provided.
   */
  readonly webhooks: Webhooks | undefined;

  /**
   * Create a new PacSpace SDK instance.
   *
   * @param config - SDK configuration.
   * @param config.apiKey - Your Balance API key (required).
   * @param config.baseUrl - API base URL (optional, overrides the key-based choice).
   * @param config.sandboxUrl - Custom sandbox URL (optional, used for `pk_test_*` keys; the default is the same host as production, where the key decides the environment).
   * @param config.productionUrl - Custom production URL (optional, used for `pk_live_*` keys).
   * @param config.chainId - Default chain ID (optional, auto-detected from key prefix).
   * @param config.maxRetries - Max retries on transient errors (default: 2).
   * @param config.timeout - Request timeout in ms (default: 30000).
   */
  constructor(config: PacSpaceConfig) {
    // HttpClient handles base URL auto-routing internally
    this.client = new HttpClient(config);
    this.fetchFn = config.fetch || globalThis.fetch;
    this.timeoutMs = config.timeout ?? 30_000;
    
    // For verify() method, we need to determine base URL ourselves
    // Use explicit baseUrl if provided, otherwise auto-route
    if (config.baseUrl) {
      this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    } else {
      const apiKey = config.apiKey;
      if (apiKey.startsWith('pk_test_')) {
        this.baseUrl = (config.sandboxUrl || DEFAULT_SANDBOX_URL).replace(/\/+$/, '');
      } else if (apiKey.startsWith('pk_live_')) {
        this.baseUrl = (config.productionUrl || DEFAULT_PRODUCTION_URL).replace(/\/+$/, '');
      } else {
        // Fallback to production
        this.baseUrl = (config.productionUrl || DEFAULT_PRODUCTION_URL).replace(/\/+$/, '');
      }
    }
    this.balance = new BalanceResource(this.client, config.submission);
    this.customers = new CustomersResource(this.client);
    this.records = new RecordsResource(this.client, config.records);

    if (config.webhookSecret) {
      this.webhooks = new Webhooks(config.webhookSecret);
    }
  }

  /**
   * Close the SDK client and reject buffered write requests.
   */
  close(reason?: string): void {
    this.balance.stopSummaryScheduler();
    this.client.close(reason);
  }

  /**
   * Graceful shutdown: flush summary queue and close the client.
   */
  async shutdown(reason = 'SDK shutdown'): Promise<void> {
    await this.balance.shutdownSummaryScheduler();
    this.client.close(reason);
  }

  /**
   * Verify a proof root via the verification endpoint.
   *
   * No API key required. Anyone with a proof root can confirm it
   * independently. The response contains proof-only facts: validity,
   * timestamps, and chain references. Record contents are never returned
   * here; fetch semantic receipts by their receipt identifier instead
   * (ADR 0008).
   *
   * @param proofRoot - The proof root from a receipt (hex string).
   * @param options - Optional source selection and abort signal.
   * @param options.source - Verification source (`db` | `chain` | `both`). Defaults to `db`.
   * @param options.signal - Optional abort signal.
   * @returns Proof-only verification facts.
   *
   * @example
   * ```typescript
   * const result = await pac.verify('0x7f3a9b2c1d4e5f6a...', { source: 'both' });
   * if (result.verified) {
   *   console.log(result.recordedAt);
   *   console.log(result.verification?.verificationExplorerUrl);
   * }
   * ```
   */
  async verify(
    proofRoot: string,
    options: { source?: VerifySource; signal?: AbortSignal } = {},
  ): Promise<VerifyResponse> {
    const source = options.source ?? 'db';
    if (!['db', 'chain', 'both'].includes(source)) {
      throw new Error(`Invalid verify source: ${source}`);
    }

    const params = new URLSearchParams();
    if (source !== 'db') {
      params.set('source', source);
    }
    const query = params.toString();
    const url =
      `${this.baseUrl}/api/v1/verify/${encodeURIComponent(proofRoot)}`
      + (query ? `?${query}` : '');

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);
    const onAbort = () => controller.abort();
    options.signal?.addEventListener('abort', onAbort);

    let response: Response;
    try {
      response = await this.fetchFn(url, {
        method: 'GET',
        signal: controller.signal,
      });
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error(
          `Verification request timed out after ${this.timeoutMs}ms`,
        );
      }
      throw error;
    } finally {
      options.signal?.removeEventListener('abort', onAbort);
      clearTimeout(timeoutId);
    }

    if (!response.ok) {
      const body = (await response.json().catch(() => ({}))) as {
        success?: boolean;
        error?: string;
        message?: string;
      };
      const msg = body.error ?? body.message ?? response.statusText;
      throw new Error(`Verification failed: ${msg}`);
    }

    const raw = (await response.json()) as {
      success?: boolean;
      data?: VerifyResponse;
    };
    if (raw.success && raw.data !== undefined) {
      return raw.data;
    }
    throw new Error('Verification failed: unexpected response format');
  }
}

// ---------------------------------------------------------------------------
// Re-export all public types for consumers
// ---------------------------------------------------------------------------

// Core
export type { PacSpaceConfig, RequestOptions } from './types/config';
export type { RecordStatus, CheckpointType } from './types/common';

// Balance API
export type {
  AdjustsRef,
  EmitOptions,
  EmitAndWaitOptions,
  EmitResponse,
  DeriveOptions,
  DeriveResponse,
  VerifiedDelta,
  WindowSummary,
  CompareOptions,
  CompareBalances,
  CompareResponse,
  DiscrepancyReport,
  ReceiptResponse,
  ReceiptDocument,
  ReceiptStatementRow,
  ReceiptDailyTotal,
  ReceiptListItem,
  ReceiptGetOptions,
  ReceiptListOptions,
  ReceiptGrantKind,
  ReceiptGrantScope,
  ReceiptGrantStatus,
  ReceiptAccessGrant,
  CreateReceiptGrantParams,
  CreateReceiptGrantResponse,
  CheckpointOptions,
  CheckpointResponse,
  CheckpointTimelinePoint,
  CheckpointTimelineGap,
  CheckpointTimelineResponse,
  ListCheckpointTimelineOptions,
  CheckpointDiffResponse,
  DeltaStatusResponse,
  WaitForVerifiedOptions,
  UsageResponse,
  SequenceGapsOptions,
  SequenceGapRange,
  SequenceGapsResponse,
  ListWebhookDeliveriesOptions,
  ListWebhookDeliveriesResponse,
  CustomerRecordSummary,
  CustomerRecordDetail,
  CustomerRecordActivity,
  ListCustomersOptions,
  ListCustomersResponse,
  GetCustomerOptions,
  InvoiceProofOptions,
  InvoiceProofResponse,
  InvoiceProofDelta,
  InvoiceProofWindowSummary,
  InvoiceProofVerification,
  VerifySource,
  VerifyResponse,
  VerifySummary,
  VerifyRecord,
  VerifyVerification,
} from './types/balance';
export type {
  CreateCustomerOptions,
  CreateCustomerResponse,
  CustomerEventCadence,
  CustomerSharingState,
} from './resources/customers';

export type {
  SubmissionProfile,
  SubmissionAutomationOptions,
  CustomerUsageSummary,
  QueuedUsageSummary,
  FlushSummariesOptions,
  SummaryFlushFailure,
  SummaryFlushResult,
  SubmissionQueueState,
} from './types/submission';

// Errors
export {
  PacSpaceError,
  InvalidApiKeyError,
  InsufficientCreditsError,
  NotFoundError,
  ContractNotDeployedError,
  CadenceLimitError,
  RateLimitError,
  ServiceUnavailableError,
  ValidationError,
  InvalidScopeCombinationError,
  ScopeTooWideError,
  ReceiptNotFoundError,
  ReceiptNotReadyError,
  TimeoutError,
  WebhookVerificationError,
} from './errors';

// Webhooks
export { Webhooks } from './webhooks/verify';
export type {
  VerifyOptions,
} from './webhooks/verify';
export type {
  KnownWebhookEventType,
  WebhookEventType,
  WebhookEvent,
  WebhookEventMap,
  WebhookHeaders,
  DeltaVerifiedPayload,
  DeltaFailedPayload,
  CustomerCreatedPayload,
  RecordCommittedPayload,
  RecordFailedPayload,
} from './webhooks/types';

export { fingerprint } from './fingerprint';
export type { FingerprintInput, FingerprintOptions, FingerprintResult, PayloadRef } from './fingerprint';
export { blindingFileText } from './blinding';
export type { Blinding } from './blinding';
export { readBlindingFile, writeBlindingFile } from './blinding-file';
export type {
  EntryNumber,
  RecordCheckEntryResult,
  RecordCheckExpect,
  RecordCheckFile,
  RecordCheckInput,
  RecordCheckSource,
  RecordDiscloseEntry,
  RecordDiscloseInput,
  RecordDisclosureFile,
  RecordEmitInput,
  RecordEmitResponse,
  RecordEntryRef,
  RecordEntryStatus,
  RecordHistory,
  RecordHistoryEntry,
  RecordHistoryCheck,
  RecordHistoryInput,
  RecordLifecycle,
  RecordReceiptInput,
  RecordReceiptResponse,
  RecordReadOptions,
  OpenedRecordEntry,
} from './types/records';
export { generateWorkspaceSecret, nextWorkspaceSecret } from './records-encryption/workspace-secret';
export { memoryPinStore } from './records-encryption/pin-store';
export { filePinStore } from './records-encryption/pin-store-file';
export type { RecordsPin, RecordsPinStore } from './records-encryption/pin-store';
export { RecordsEncryptionError, RECORDS_ENCRYPTION_WORDS } from './records-encryption/words';
export type { RecordsEncryptionCode } from './records-encryption/words';
export type {
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
  RecordsSecretSource,
  RecordsShareKeyWrapInput,
} from './types/records-encryption';
