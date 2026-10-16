import type { PacSpaceConfig, RequestOptions } from './types/config';
import type { RawApiResponse } from './types/common';
import {
  CadenceLimitError,
  PacSpaceError,
  RateLimitError,
  ServiceUnavailableError,
  mapApiError,
} from './errors';

/**
 * Default production API base URL.
 */
const DEFAULT_PRODUCTION_URL = 'https://app.pacspace.io';

/**
 * Default sandbox API base URL.
 *
 * The same host as production: the API routes each request by the
 * environment of its key, so a `pk_test_` key on `app.pacspace.io` reads and
 * writes the sandbox data plane. `sandboxUrl` stays as a bring-your-own
 * override for a private sandbox host.
 */
const DEFAULT_SANDBOX_URL = DEFAULT_PRODUCTION_URL;

/**
 * Default request timeout in milliseconds.
 */
const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Default maximum number of retries on transient errors.
 */
const DEFAULT_MAX_RETRIES = 2;

/**
 * Enable client-side write buffering by default.
 */
const DEFAULT_BUFFER_WRITES = true;

/**
 * Maximum in-memory buffered write requests.
 */
const DEFAULT_BUFFER_MAX_ITEMS = 1000;

/**
 * Maximum retry attempts per buffered request.
 */
const DEFAULT_BUFFER_MAX_ATTEMPTS = 100;

/**
 * Base delay for buffered request retries.
 */
const DEFAULT_BUFFER_BASE_DELAY_MS = 1000;

/**
 * Max delay for buffered request retries.
 */
const DEFAULT_BUFFER_MAX_DELAY_MS = 60_000;

/**
 * HTTP status codes that are safe to retry.
 */
const RETRYABLE_STATUS_CODES = new Set([408, 429, 500, 502, 503, 504]);

interface BufferedRequest<T> {
  id: string;
  method: string;
  path: string;
  body: unknown;
  options?: RequestOptions;
  attempts: number;
  nextAttemptAt: number;
  resolve: (value: T) => void;
  reject: (error: Error) => void;
}

interface ParsedApiError {
  message: string;
  code?: string;
  retryAfterSeconds?: number;
  customerId?: string;
  body?: Record<string, unknown>;
}

/** Per-call options inside the SDK: extra headers ride beside the public ones. */
export interface ClientRequestOptions extends RequestOptions {
  headers?: Record<string, string>;
}

const API_ERROR_BODIES = new WeakMap<Error, Record<string, unknown>>();

/** The refusal's own fields (as `recordKid` on a version refusal), for the SDK's retry rules. @internal */
export function apiErrorBody(error: unknown): Record<string, unknown> | undefined {
  return error instanceof Error ? API_ERROR_BODIES.get(error) : undefined;
}

/** Keeps a refusal's own fields beside it, for a transport other than this client. @internal */
export function registerApiErrorBody(error: Error, body: Record<string, unknown>): void {
  API_ERROR_BODIES.set(error, body);
}

function withBody(error: PacSpaceError, parsed: ParsedApiError): PacSpaceError {
  if (parsed.body) API_ERROR_BODIES.set(error, parsed.body);
  return error;
}

/**
 * Low-level HTTP client for the Balance API.
 * Handles authentication, response unwrapping, retries, and error mapping.
 *
 * @internal — Use the PacSpace class instead of this directly.
 */
export class HttpClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly maxRetries: number;
  private readonly timeout: number;
  private readonly fetchFn: typeof fetch;
  private readonly bufferWrites: boolean;
  private readonly bufferMaxItems: number;
  private readonly bufferMaxAttempts: number;
  private readonly bufferBaseDelayMs: number;
  private readonly bufferMaxDelayMs: number;
  private readonly bufferedWrites: Array<BufferedRequest<unknown>> = [];
  private drainTimer: ReturnType<typeof setTimeout> | null = null;
  private drainInProgress = false;
  private closed = false;

  /** Default chain ID, auto-detected from API key prefix or explicit config. */
  readonly defaultChainId: number | undefined;
  /** Default credit pool ID. */
  readonly defaultCreditPoolId: number | undefined;

  constructor(config: PacSpaceConfig) {
    if (!config.apiKey) {
      throw new PacSpaceError(
        'API key is required. Pass it via new PacSpace({ apiKey: "pk_..." })',
        0,
        'MISSING_API_KEY',
      );
    }

    this.apiKey = config.apiKey;
    
    // Determine base URL: explicit baseUrl overrides everything, otherwise auto-route by API key prefix
    if (config.baseUrl) {
      this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    } else {
      this.baseUrl = this.detectBaseUrl(config.apiKey, config).replace(/\/+$/, '');
    }
    
    this.maxRetries = config.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
    this.fetchFn = config.fetch || globalThis.fetch;
    this.bufferWrites = config.bufferWrites ?? DEFAULT_BUFFER_WRITES;
    this.bufferMaxItems = config.bufferMaxItems ?? DEFAULT_BUFFER_MAX_ITEMS;
    this.bufferMaxAttempts = config.bufferMaxAttempts ?? DEFAULT_BUFFER_MAX_ATTEMPTS;
    this.bufferBaseDelayMs =
      config.bufferBaseDelayMs ?? DEFAULT_BUFFER_BASE_DELAY_MS;
    this.bufferMaxDelayMs = config.bufferMaxDelayMs ?? DEFAULT_BUFFER_MAX_DELAY_MS;

    // Auto-detect chain ID from API key prefix
    this.defaultChainId = config.chainId ?? this.detectChainId(config.apiKey);
    this.defaultCreditPoolId = config.creditPoolId;

    if (!this.fetchFn) {
      throw new PacSpaceError(
        'No global fetch found. Upgrade to Node 18+ or pass a custom fetch implementation via config.',
        0,
        'NO_FETCH',
      );
    }
  }

  /**
   * Returns the resolved API base URL used by this client.
   */
  getBaseUrl(): string {
    return this.baseUrl;
  }

  /**
   * Close the client and reject any buffered writes.
   */
  close(reason = 'Client closed'): void {
    this.closed = true;
    if (this.drainTimer) {
      clearTimeout(this.drainTimer);
      this.drainTimer = null;
    }
    const pending = this.bufferedWrites.splice(0, this.bufferedWrites.length);
    for (const item of pending) {
      item.reject(new PacSpaceError(reason, 0, 'CLIENT_CLOSED', item.path));
    }
  }

  /**
   * Make a GET request and return unwrapped data.
   */
  async get<T>(path: string, options?: ClientRequestOptions): Promise<T> {
    return this.request<T>('GET', path, undefined, options);
  }

  /** PUT, unwrapped; never buffered. */
  async put<T>(path: string, body: unknown, options?: ClientRequestOptions): Promise<T> {
    return this.request<T>('PUT', path, body, options, false);
  }

  /** DELETE, unwrapped; never buffered. */
  async delete<T>(path: string, options?: ClientRequestOptions): Promise<T> {
    return this.request<T>('DELETE', path, undefined, options, false);
  }

  /** POST, unwrapped, never buffered: a write whose refusal the caller acts on. */
  async postNow<T>(path: string, body: unknown, options?: ClientRequestOptions): Promise<T> {
    return this.request<T>('POST', path, body, options, false);
  }

  /**
   * A request to a link's public routes: no API key, no retries, the
   * response as it came. `init.headers` is the whole header set.
   */
  async fetchPublic(path: string, init: { method: string; headers: Record<string, string>; body?: string }): Promise<Response> {
    if (this.closed) {
      throw new PacSpaceError('Client closed', 0, 'CLIENT_CLOSED', path);
    }
    return this.fetchWithTimeout(`${this.baseUrl}${path}`, init);
  }

  /**
   * GET that returns the parsed body and response headers without requiring
   * the `{ success, data }` envelope (record history is the digested bundle).
   */
  async getRaw<T>(
    path: string,
    options?: ClientRequestOptions,
  ): Promise<{ body: T; headers: Headers; status: number }> {
    return this.requestRaw<T>('GET', path, undefined, options);
  }

  /**
   * Make a POST request and return unwrapped data.
   */
  async post<T>(
    path: string,
    body?: unknown,
    options?: ClientRequestOptions,
  ): Promise<T> {
    return this.request<T>('POST', path, body, options);
  }

  /**
   * Core request method with retry logic, auth injection, and response unwrapping.
   */
  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    options?: ClientRequestOptions,
    allowBuffering = true,
  ): Promise<T> {
    if (this.closed) {
      throw new PacSpaceError('Client closed', 0, 'CLIENT_CLOSED', path);
    }
    const url = `${this.baseUrl}${path}`;
    const headers = this.buildHeaders(options);

    const requestInit: RequestInit = {
      method,
      headers,
      signal: options?.signal,
    };

    if (body !== undefined) {
      requestInit.body = JSON.stringify(body);
    }

    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      // Wait before retrying (exponential backoff)
      if (attempt > 0) {
        const delayMs = this.getRetryDelay(attempt, lastError);
        await this.sleep(delayMs);
      }

      let response: Response;
      try {
        response = await this.fetchWithTimeout(url, requestInit);
      } catch (err) {
        // Network errors are retryable
        lastError =
          err instanceof Error
            ? err
            : new Error(String(err));

        if (attempt < this.maxRetries) {
          continue;
        }

        const networkError = new PacSpaceError(
          `Network error: ${lastError.message}`,
          0,
          'NETWORK_ERROR',
          path,
        );
        if (allowBuffering && this.shouldBufferRequest(method, networkError)) {
          return this.enqueueBufferedRequest<T>(
            method,
            path,
            body,
            options,
            networkError,
          );
        }
        throw networkError;
      }

      // Successful response — parse and unwrap
      if (response.ok) {
        const raw = (await response.json()) as RawApiResponse<T> & {
          code?: string;
          retryAfterSeconds?: number;
          schema?: string;
        };

        if (raw.success && raw.data !== undefined) {
          return raw.data;
        }

        const parsedError = this.extractApiError(
          raw as unknown as Record<string, unknown>,
          'Unknown error',
        );
        if (response.status === 202 && parsedError.code === 'IDEMPOTENCY_PENDING') {
          return {
            code: 'IDEMPOTENCY_PENDING',
            retryAfterSeconds: parsedError.retryAfterSeconds,
            message: parsedError.message,
          } as T;
        }
        if (raw.schema === 'record-history-bundle/v1') {
          return raw as T;
        }

        throw this.mapError(response, parsedError, path);
      }

      // Non-retryable error — throw immediately
      if (!RETRYABLE_STATUS_CODES.has(response.status)) {
        const errorBody = await this.safeParseJson(response);
        const parsedError = this.extractApiError(errorBody, response.statusText);
        throw this.mapError(response, parsedError, path);
      }

      // Retryable error — continue to next attempt
      const errorBody = await this.safeParseJson(response);
      const parsedError = this.extractApiError(errorBody, response.statusText);
      lastError = this.mapError(response, parsedError, path);
      if (lastError instanceof CadenceLimitError) {
        throw lastError;
      }
    }

    // All retries exhausted
    const finalError =
      lastError || new PacSpaceError('Request failed', 0, 'UNKNOWN', path);
    if (allowBuffering && this.shouldBufferRequest(method, finalError)) {
      return this.enqueueBufferedRequest<T>(
        method,
        path,
        body,
        options,
        finalError,
      );
    }
    throw finalError;
  }

  private async requestRaw<T>(
    method: string,
    path: string,
    body?: unknown,
    options?: ClientRequestOptions,
  ): Promise<{ body: T; headers: Headers; status: number }> {
    if (this.closed) {
      throw new PacSpaceError('Client closed', 0, 'CLIENT_CLOSED', path);
    }
    const url = `${this.baseUrl}${path}`;
    const headers = this.buildHeaders(options);
    const requestInit: RequestInit = {
      method,
      headers,
      signal: options?.signal,
    };
    if (body !== undefined) {
      requestInit.body = JSON.stringify(body);
    }
    const response = await this.fetchWithTimeout(url, requestInit);
    const parsed = (await this.safeParseJson(response)) as T;
    if (!response.ok) {
      const parsedError = this.extractApiError(
        parsed as unknown as Record<string, unknown> | null,
        response.statusText,
      );
      throw this.mapError(response, parsedError, path);
    }
    return { body: parsed, headers: response.headers, status: response.status };
  }

  /**
   * Build HTTP headers with auth and optional overrides.
   */
  private buildHeaders(options?: ClientRequestOptions): Record<string, string> {
    const headers: Record<string, string> = {
      'X-Api-Key': this.apiKey,
      'Content-Type': 'application/json',
      'User-Agent': '@pacspace-io/sdk/0.14.0',
    };

    if (options?.dashboardToken) {
      headers.Authorization = `Bearer ${options.dashboardToken}`;
    }

    const chainId = options?.chainId ?? this.defaultChainId;
    if (chainId !== undefined) {
      headers['X-Chain-Id'] = String(chainId);
    }

    const creditPoolId = options?.creditPoolId ?? this.defaultCreditPoolId;
    if (creditPoolId !== undefined) {
      headers['X-Credit-Pool-Id'] = String(creditPoolId);
    }

    if (options?.idempotencyKey) {
      headers['Idempotency-Key'] = options.idempotencyKey;
    }

    return { ...headers, ...(options?.headers ?? {}) };
  }

  /**
   * Fetch with an AbortController-based timeout.
   */
  private async fetchWithTimeout(
    url: string,
    init: RequestInit,
  ): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    // Merge external signal with timeout signal
    const externalSignal = init.signal;
    if (externalSignal) {
      externalSignal.addEventListener('abort', () => controller.abort());
    }

    try {
      return await this.fetchFn(url, {
        ...init,
        signal: controller.signal,
      });
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') {
        if (externalSignal?.aborted) {
          throw new PacSpaceError('Request cancelled', 0, 'CANCELLED', url);
        }
        throw new PacSpaceError(
          `Request timed out after ${this.timeout}ms`,
          0,
          'TIMEOUT',
          url,
        );
      }
      throw err;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Calculate retry delay with exponential backoff.
   * Respects Retry-After header for rate limit errors.
   */
  private getRetryDelay(attempt: number, lastError?: Error): number {
    // Respect rate limit retry-after
    if (lastError instanceof RateLimitError && lastError.retryAfter) {
      return lastError.retryAfter * 1000;
    }
    if (
      lastError instanceof ServiceUnavailableError &&
      lastError.retryAfter
    ) {
      return lastError.retryAfter * 1000;
    }

    // Exponential backoff: 500ms, 1500ms, 3500ms, ...
    const baseDelay = 500;
    const delay = baseDelay * Math.pow(2, attempt - 1);
    // Add jitter (0–25% of delay)
    const jitter = delay * 0.25 * Math.random();
    return delay + jitter;
  }

  /**
   * Safely parse JSON from a response, returning null on failure.
   */
  private async safeParseJson(
    response: Response,
  ): Promise<Record<string, unknown> | null> {
    try {
      return (await response.json()) as Record<string, unknown>;
    } catch {
      return null;
    }
  }

  private mapError(response: Response, parsedError: ParsedApiError, path: string): PacSpaceError {
    return withBody(mapApiError(response.status, parsedError.message, path, response.headers, parsedError), parsedError);
  }

  /**
   * Extract normalized API error fields from an error payload.
   */
  private extractApiError(
    errorBody: Record<string, unknown> | null,
    fallback: string,
  ): ParsedApiError {
    if (!errorBody) {
      return { message: fallback };
    }

    const nestedError = this.asRecord(errorBody.error);
    if (nestedError) {
      return {
        message:
          this.asMessage(nestedError.message) ??
          this.asMessage(errorBody.message) ??
          fallback,
        code:
          this.asString(nestedError.code) ??
          this.asString(errorBody.code),
        retryAfterSeconds: this.asNumber(nestedError.retryAfterSeconds),
        customerId: this.asString(nestedError.customerId),
        body: nestedError,
      };
    }

    return {
      message:
        this.asMessage(errorBody.message) ??
        this.asMessage(errorBody.error) ??
        fallback,
      code: this.asString(errorBody.code),
      retryAfterSeconds: this.asNumber(errorBody.retryAfterSeconds),
      customerId: this.asString(errorBody.customerId),
      body: errorBody,
    };
  }

  private asMessage(value: unknown): string | undefined {
    if (typeof value === 'string') {
      return value;
    }
    if (Array.isArray(value)) {
      const messages = value
        .filter((item): item is string => typeof item === 'string')
        .map((item) => item.trim())
        .filter((item) => item.length > 0);
      if (messages.length > 0) {
        return messages.join('; ');
      }
    }
    return undefined;
  }

  private asRecord(value: unknown): Record<string, unknown> | null {
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
    return null;
  }

  private asString(value: unknown): string | undefined {
    return typeof value === 'string' ? value : undefined;
  }

  private asNumber(value: unknown): number | undefined {
    if (typeof value === 'number' && Number.isFinite(value)) {
      return value;
    }
    if (typeof value === 'string') {
      const parsed = Number.parseFloat(value);
      if (Number.isFinite(parsed)) {
        return parsed;
      }
    }
    return undefined;
  }

  private shouldBufferRequest(method: string, error: Error): boolean {
    if (!this.bufferWrites) return false;
    const normalizedMethod = method.toUpperCase();
    if (
      normalizedMethod === 'GET' ||
      normalizedMethod === 'HEAD' ||
      normalizedMethod === 'OPTIONS'
    ) {
      return false;
    }

    if (error instanceof PacSpaceError) {
      if (
        error.code === 'CANCELLED' ||
        error.code === 'MISSING_API_KEY' ||
        error.code === 'INVALID_API_KEY' ||
        error.code === 'VALIDATION_ERROR' ||
        error.code === 'CADENCE_LIMIT'
      ) {
        return false;
      }
      return (
        RETRYABLE_STATUS_CODES.has(error.statusCode) || error.statusCode === 0
      );
    }

    return true;
  }

  private enqueueBufferedRequest<T>(
    method: string,
    path: string,
    body: unknown,
    options: RequestOptions | undefined,
    lastError: Error,
  ): Promise<T> {
    if (this.closed) {
      throw new PacSpaceError('Client closed', 0, 'CLIENT_CLOSED', path);
    }
    if (this.bufferedWrites.length >= this.bufferMaxItems) {
      throw new PacSpaceError(
        `Client write buffer is full (${this.bufferMaxItems} items)`,
        0,
        'WRITE_BUFFER_FULL',
        path,
      );
    }

    return new Promise<T>((resolve, reject) => {
      const requestId = `buf_${Date.now()}_${Math.random()
        .toString(16)
        .slice(2)}`;
      const rejectIfAborted = () => {
        this.removeBufferedRequest(requestId);
        reject(new PacSpaceError('Request cancelled', 0, 'CANCELLED', path));
      };

      if (options?.signal?.aborted) {
        rejectIfAborted();
        return;
      }
      options?.signal?.addEventListener('abort', rejectIfAborted, {
        once: true,
      });

      const delayMs = this.getBufferDelayMs(1, lastError);
      const buffered: BufferedRequest<T> = {
        id: requestId,
        method,
        path,
        body,
        options,
        attempts: 1,
        nextAttemptAt: Date.now() + delayMs,
        resolve: (value) => {
          options?.signal?.removeEventListener('abort', rejectIfAborted);
          resolve(value);
        },
        reject: (error) => {
          options?.signal?.removeEventListener('abort', rejectIfAborted);
          reject(error);
        },
      };

      this.bufferedWrites.push(buffered as BufferedRequest<unknown>);
      this.scheduleBufferDrain();
    });
  }

  private removeBufferedRequest(requestId: string): void {
    const index = this.bufferedWrites.findIndex((item) => item.id === requestId);
    if (index >= 0) {
      this.bufferedWrites.splice(index, 1);
    }
  }

  private scheduleBufferDrain(): void {
    if (this.closed) return;
    if (this.drainTimer || this.drainInProgress || this.bufferedWrites.length === 0) {
      return;
    }
    const nextAttemptAt = this.bufferedWrites.reduce(
      (min, item) => Math.min(min, item.nextAttemptAt),
      Number.POSITIVE_INFINITY,
    );
    const delayMs = Math.max(0, nextAttemptAt - Date.now());
    this.drainTimer = setTimeout(() => {
      this.drainTimer = null;
      void this.drainBufferedWrites();
    }, delayMs);
    this.drainTimer.unref?.();
  }

  private async drainBufferedWrites(): Promise<void> {
    if (this.closed) return;
    if (this.drainInProgress) return;
    this.drainInProgress = true;

    try {
      while (this.bufferedWrites.length > 0) {
        const current = this.bufferedWrites[0] as BufferedRequest<unknown>;
        if (current.nextAttemptAt > Date.now()) {
          break;
        }

        try {
          const result = await this.request<unknown>(
            current.method,
            current.path,
            current.body,
            current.options,
            false,
          );
          this.bufferedWrites.shift();
          current.resolve(result);
        } catch (error) {
          const err =
            error instanceof Error ? error : new Error(String(error));
          current.attempts += 1;
          if (current.attempts > this.bufferMaxAttempts) {
            this.bufferedWrites.shift();
            current.reject(err);
            continue;
          }
          current.nextAttemptAt =
            Date.now() + this.getBufferDelayMs(current.attempts, err);
          break;
        }
      }
    } finally {
      this.drainInProgress = false;
      this.scheduleBufferDrain();
    }
  }

  private getBufferDelayMs(attempt: number, error?: Error): number {
    if (error instanceof RateLimitError && error.retryAfter) {
      return error.retryAfter * 1000;
    }
    if (error instanceof ServiceUnavailableError && error.retryAfter) {
      return error.retryAfter * 1000;
    }
    const cappedAttempt = Math.min(Math.max(attempt, 1), 12);
    const delay = this.bufferBaseDelayMs * Math.pow(2, cappedAttempt - 1);
    return Math.min(delay, this.bufferMaxDelayMs);
  }

  /**
   * Base URL from the API key prefix.
   * - `pk_test_*` keys → `sandboxUrl`, or the default host
   * - `pk_live_*` keys → `productionUrl`, or the default host
   *
   * Both defaults are `https://app.pacspace.io`; the key decides the
   * environment there. The prefix only matters when a custom URL is set.
   */
  private detectBaseUrl(apiKey: string, config: PacSpaceConfig): string {
    if (apiKey.startsWith('pk_test_')) {
      return config.sandboxUrl || DEFAULT_SANDBOX_URL;
    }
    if (apiKey.startsWith('pk_live_')) {
      return config.productionUrl || DEFAULT_PRODUCTION_URL;
    }
    // Fallback to production if prefix doesn't match expected patterns
    return config.productionUrl || DEFAULT_PRODUCTION_URL;
  }

  /**
   * Auto-detect chain ID from API key prefix.
   */
  private detectChainId(apiKey: string): number | undefined {
    if (apiKey.startsWith('pk_test_')) {
      return 296; // Hedera Testnet
    }
    if (apiKey.startsWith('pk_live_')) {
      return 295; // Hedera Mainnet
    }
    return undefined;
  }

  /**
   * Promise-based sleep utility.
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
