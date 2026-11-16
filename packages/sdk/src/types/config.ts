import type { RecordsEncryptionOptions } from './records-encryption';
import type { SubmissionAutomationOptions } from './submission';

/**
 * PacSpace SDK configuration options.
 */
export interface PacSpaceConfig {
  /**
   * Your Balance API key.
   * Format: `pk_live_PUBLIC.SECRET` (production) or `pk_test_PUBLIC.SECRET` (sandbox).
   */
  apiKey: string;

  /**
   * Optional webhook signing secret. When provided, `pac.webhooks` is enabled.
   */
  webhookSecret?: string;

  /**
   * Base URL for the Balance API.
   * If provided, this overrides the key-based choice.
   * If not provided, the SDK chooses by API key prefix:
   * - `pk_test_*` keys → `sandboxUrl` if set, else `https://app.pacspace.io`
   * - `pk_live_*` keys → `productionUrl` if set, else `https://app.pacspace.io`
   * One host serves both environments; the API reads the environment from
   * the key.
   */
  baseUrl?: string;

  /**
   * Custom sandbox API URL, for a private sandbox host.
   * Used for `pk_test_*` keys. The default is the production host, which
   * routes a sandbox key to the sandbox data plane.
   * Ignored if `baseUrl` is explicitly provided.
   */
  sandboxUrl?: string;

  /**
   * Custom production API URL.
   * Used when auto-routing `pk_live_*` keys.
   * Ignored if `baseUrl` is explicitly provided.
   */
  productionUrl?: string;

  /**
   * Default chain ID to use for all requests.
   * Auto-detected from API key prefix when not set:
   * - `pk_test_*` → 296 (Hedera Testnet)
   * - `pk_live_*` → 295 (Hedera Mainnet)
   */
  chainId?: number;

  /**
   * Default credit pool ID for all requests.
   */
  creditPoolId?: number;

  /**
   * Maximum number of automatic retries on transient errors (5xx, network).
   * @default 2
   */
  maxRetries?: number;

  /**
   * Request timeout in milliseconds.
   * @default 30000
   */
  timeout?: number;

  /**
   * Custom fetch implementation. Uses global `fetch` by default (Node 18+).
   */
  fetch?: typeof fetch;

  /**
   * Enable client-side buffering for write requests when the API is temporarily unavailable.
   * Buffered requests are retried in the background and resolved once drained.
   * @default true
   */
  bufferWrites?: boolean;

  /**
   * Maximum number of buffered write requests kept in memory.
   * @default 1000
   */
  bufferMaxItems?: number;

  /**
   * Maximum retry attempts per buffered write before rejecting it.
   * @default 100
   */
  bufferMaxAttempts?: number;

  /**
   * Base retry delay (ms) for buffered writes.
   * @default 1000
   */
  bufferBaseDelayMs?: number;

  /**
   * Maximum retry delay (ms) for buffered writes.
   * @default 60000
   */
  bufferMaxDelayMs?: number;

  /**
   * Submission automation profile for tenant-produced usage summaries.
   */
  submission?: SubmissionAutomationOptions;

  /**
   * Encrypted records: the workspace secret (`secret` or `secretProvider`)
   * and where confirmed codes are pinned. Without a secret, records are
   * written in plaintext.
   */
  records?: RecordsEncryptionOptions;
}

/**
 * Per-request options that can override defaults.
 */
export interface RequestOptions {
  /** Override the default chain ID for this request. */
  chainId?: number;
  /** Override the default credit pool ID for this request. */
  creditPoolId?: number;
  /** Idempotency key to prevent duplicate processing. */
  idempotencyKey?: string;
  /** Dashboard JWT used for dashboard-only helper methods. */
  dashboardToken?: string;
  /** AbortSignal for request cancellation. */
  signal?: AbortSignal;
}
