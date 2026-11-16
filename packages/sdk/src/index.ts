import { HttpClient } from './client';
import { RecordsResource } from './resources/records';
import { Webhooks } from './webhooks/verify';
import type { PacSpaceConfig } from './types/config';
import type { VerifyResponse, VerifySource } from './types/verify';

/** Default production API base URL. */
const DEFAULT_PRODUCTION_URL = 'https://app.pacspace.io';

/**
 * Default sandbox API base URL: the same host. The API routes each request by
 * the environment of its key; `sandboxUrl` stays as a bring-your-own override.
 */
const DEFAULT_SANDBOX_URL = DEFAULT_PRODUCTION_URL;

/**
 * PacSpace SDK: the official TypeScript client for the PacSpace API.
 *
 * @example
 * ```typescript
 * import { PacSpace, fingerprint } from '@pacspace-io/sdk';
 *
 * const pac = new PacSpace({ apiKey: process.env.PACSPACE_API_KEY! });
 *
 * // Record an entry
 * const { ref, blinding } = await fingerprint(fileBytes);
 * const entry = await pac.records.emit({
 *   record: 'build-1',
 *   title: 'Handoff',
 *   occurredAt: '2026-09-14T10:02:00Z',
 *   actorId: 'ci',
 *   payloads: [ref],
 * });
 *
 * // Read the history and check it in your process
 * const history = await pac.records.history({ record: 'build-1' });
 * const check = await pac.records.check({
 *   history,
 *   expect: [{ entry: 1, files: [{ source: fileBytes, blinding }] }],
 * });
 *
 * // Verify a proof root (public, no auth)
 * const verification = await pac.verify('0x7f3a9b2c1d4e5f6a...');
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
   * @param config.apiKey - Your PacSpace API key (required).
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
    this.records = new RecordsResource(this.client, config.records);

    if (config.webhookSecret) {
      this.webhooks = new Webhooks(config.webhookSecret);
    }
  }

  /**
   * Close the SDK client and reject buffered write requests.
   */
  close(reason?: string): void {
    this.client.close(reason);
  }

  /**
   * Graceful shutdown: an async alias of `close()`.
   */
  async shutdown(reason = 'SDK shutdown'): Promise<void> {
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

// Verify
export type {
  VerifySource,
  VerifyResponse,
  VerifySummary,
  VerifyRecord,
  VerifyVerification,
} from './types/verify';

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
  RecordCommittedPayload,
  RecordFailedPayload,
  RecordClosedPayload,
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
  RecordLabels,
  RecordCloseOptions,
  RecordCloseResponse,
  RecordReceiptInput,
  RecordReceiptResponse,
  RecordReadOptions,
  OpenedRecordEntry,
} from './types/records';
export { generateWorkspaceSecret, nextWorkspaceSecret } from './records-encryption/workspace-secret';
export { readWorkspaceSecretFile, workspaceSecretFileName, type WorkspaceSecretEnvironment } from './workspace-secret-file';
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
