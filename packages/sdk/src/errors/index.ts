/**
 * Base error class for all PacSpace SDK errors.
 * Extends native Error with structured API error data.
 */
export class PacSpaceError extends Error {
  /** HTTP status code from the API response. */
  readonly statusCode: number;
  /** Machine-readable error code (e.g., 'INSUFFICIENT_CREDITS'). */
  readonly code: string;
  /** The original API request path that triggered this error. */
  readonly requestPath?: string;

  constructor(
    message: string,
    statusCode: number,
    code: string,
    requestPath?: string,
  ) {
    super(message);
    this.name = 'PacSpaceError';
    this.statusCode = statusCode;
    this.code = code;
    this.requestPath = requestPath;

    // Ensure instanceof works correctly in TS
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when the API key is missing, invalid, or disabled (HTTP 401).
 */
export class InvalidApiKeyError extends PacSpaceError {
  constructor(message = 'Invalid or missing API key', requestPath?: string) {
    super(message, 401, 'INVALID_API_KEY', requestPath);
    this.name = 'InvalidApiKeyError';
  }
}

/**
 * Thrown when the tenant has insufficient credits for the operation (HTTP 402).
 */
export class InsufficientCreditsError extends PacSpaceError {
  constructor(
    message = 'Insufficient credits for this operation',
    requestPath?: string,
  ) {
    super(message, 402, 'INSUFFICIENT_CREDITS', requestPath);
    this.name = 'InsufficientCreditsError';
  }
}

/**
 * Thrown when the requested resource is not found (HTTP 404).
 */
export class NotFoundError extends PacSpaceError {
  constructor(message = 'Resource not found', requestPath?: string) {
    super(message, 404, 'NOT_FOUND', requestPath);
    this.name = 'NotFoundError';
  }
}

/**
 * Thrown when a receipt cannot be found (HTTP 404).
 */
export class ReceiptNotFoundError extends PacSpaceError {
  constructor(message = 'Receipt not found', requestPath?: string) {
    super(message, 404, 'RECEIPT_NOT_FOUND', requestPath);
    this.name = 'ReceiptNotFoundError';
  }
}

/**
 * Thrown when a receipt exists but is not ready yet (HTTP 409).
 */
export class ReceiptNotReadyError extends PacSpaceError {
  constructor(message = 'Receipt is not ready yet', requestPath?: string) {
    super(message, 409, 'RECEIPT_NOT_READY', requestPath);
    this.name = 'ReceiptNotReadyError';
  }
}

/**
 * Thrown when no contract is deployed for the tenant (HTTP 412).
 */
export class ContractNotDeployedError extends PacSpaceError {
  constructor(
    message = 'No contract deployed. Provision an environment first.',
    requestPath?: string,
  ) {
    super(message, 412, 'CONTRACT_NOT_DEPLOYED', requestPath);
    this.name = 'ContractNotDeployedError';
  }
}

/**
 * Thrown when the API rate limit is exceeded (HTTP 429).
 */
export class RateLimitError extends PacSpaceError {
  /** Seconds to wait before retrying, if provided by the API. */
  readonly retryAfter: number | null;

  constructor(
    message = 'Rate limit exceeded',
    retryAfter: number | null = null,
    requestPath?: string,
  ) {
    super(message, 429, 'RATE_LIMITED', requestPath);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

/**
 * Thrown when a customer's submission cadence window has not elapsed (HTTP 429).
 * This error is terminal for the current request and should not be auto-retried.
 */
export class CadenceLimitError extends PacSpaceError {
  /** Milliseconds remaining before the next allowed submission, if provided. */
  readonly retryAfterMs: number | null;
  /** Customer ID associated with the cadence block, when provided. */
  readonly customerId: string | null;

  constructor(
    message = 'Submission cadence limit reached',
    retryAfterSeconds: number | null = null,
    customerId: string | null = null,
    requestPath?: string,
  ) {
    super(message, 429, 'CADENCE_LIMIT', requestPath);
    this.name = 'CadenceLimitError';
    this.retryAfterMs =
      retryAfterSeconds && Number.isFinite(retryAfterSeconds)
        ? Math.max(0, Math.floor(retryAfterSeconds * 1000))
        : null;
    this.customerId = customerId;
  }
}

/**
 * Thrown when the API is temporarily unavailable (HTTP 503).
 */
export class ServiceUnavailableError extends PacSpaceError {
  /** Seconds to wait before retrying, if provided by the API. */
  readonly retryAfter: number | null;

  constructor(
    message = 'Service temporarily unavailable',
    retryAfter: number | null = null,
    requestPath?: string,
  ) {
    super(message, 503, 'SERVICE_UNAVAILABLE', requestPath);
    this.name = 'ServiceUnavailableError';
    this.retryAfter = retryAfter;
  }
}

/**
 * Thrown when the API returns a validation error (HTTP 400).
 */
export class ValidationError extends PacSpaceError {
  constructor(message = 'Invalid request data', requestPath?: string) {
    super(message, 400, 'VALIDATION_ERROR', requestPath);
    this.name = 'ValidationError';
  }
}

/**
 * Thrown when a request mixes mutually-exclusive scope fields (HTTP 400).
 */
export class InvalidScopeCombinationError extends PacSpaceError {
  constructor(
    message = 'Choose either a checkpoint or a time scope for this request.',
    requestPath?: string,
  ) {
    super(message, 400, 'INVALID_SCOPE_COMBINATION', requestPath);
    this.name = 'InvalidScopeCombinationError';
  }
}

/**
 * Thrown when the requested scope exceeds the maximum supported window (HTTP 400).
 */
export class ScopeTooWideError extends PacSpaceError {
  constructor(
    message = 'Scope window is too wide for a single request.',
    requestPath?: string,
  ) {
    super(message, 400, 'SCOPE_TOO_WIDE', requestPath);
    this.name = 'ScopeTooWideError';
  }
}

/**
 * Thrown when a polling operation exceeds the configured timeout.
 */
export class TimeoutError extends PacSpaceError {
  constructor(
    message = 'Operation timed out waiting for verification',
    requestPath?: string,
  ) {
    super(message, 0, 'TIMEOUT', requestPath);
    this.name = 'TimeoutError';
  }
}

/**
 * Thrown when the webhook signature is invalid.
 */
export class WebhookVerificationError extends PacSpaceError {
  constructor(message = 'Webhook signature verification failed') {
    super(message, 0, 'WEBHOOK_VERIFICATION_FAILED');
    this.name = 'WebhookVerificationError';
  }
}

/**
 * Map an HTTP status code + API response to the appropriate typed error.
 * @internal
 */
export function mapApiError(
  statusCode: number,
  message: string,
  requestPath?: string,
  headers?: Headers,
  apiError?: {
    code?: string;
    retryAfterSeconds?: number | null;
    customerId?: string | null;
  },
): PacSpaceError {
  const headerRetryAfter = headers?.get('retry-after');
  const parsedHeaderRetryAfter = headerRetryAfter
    ? Number.parseInt(headerRetryAfter, 10)
    : null;
  const retryAfterSeconds =
    apiError?.retryAfterSeconds ??
    (Number.isFinite(parsedHeaderRetryAfter)
      ? parsedHeaderRetryAfter
      : null);

  switch (statusCode) {
    case 400:
      if (apiError?.code === 'INVALID_SCOPE_COMBINATION') {
        return new InvalidScopeCombinationError(message, requestPath);
      }
      if (apiError?.code === 'SCOPE_TOO_WIDE') {
        return new ScopeTooWideError(message, requestPath);
      }
      if (apiError?.code) {
        return new PacSpaceError(message, statusCode, apiError.code, requestPath);
      }
      return new ValidationError(message, requestPath);
    case 401:
      return new InvalidApiKeyError(message, requestPath);
    case 402:
      return new InsufficientCreditsError(message, requestPath);
    case 404:
      if (apiError?.code === 'RECEIPT_NOT_FOUND') {
        return new ReceiptNotFoundError(message, requestPath);
      }
      return new NotFoundError(message, requestPath);
    case 409:
      if (apiError?.code === 'RECEIPT_NOT_READY') {
        return new ReceiptNotReadyError(message, requestPath);
      }
      return new PacSpaceError(message, statusCode, apiError?.code || 'CONFLICT', requestPath);
    case 412:
      return new ContractNotDeployedError(message, requestPath);
    case 429: {
      if (apiError?.code === 'CADENCE_LIMIT') {
        return new CadenceLimitError(
          message,
          retryAfterSeconds,
          apiError.customerId ?? null,
          requestPath,
        );
      }
      return new RateLimitError(
        message,
        retryAfterSeconds,
        requestPath,
      );
    }
    case 503: {
      return new ServiceUnavailableError(
        message,
        retryAfterSeconds,
        requestPath,
      );
    }
    default:
      return new PacSpaceError(
        message,
        statusCode,
        apiError?.code || 'API_ERROR',
        requestPath,
      );
  }
}
