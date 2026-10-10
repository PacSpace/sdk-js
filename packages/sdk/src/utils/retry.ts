/**
 * Utility for exponential backoff delay calculations.
 * @internal — Used by the HttpClient; exported for advanced use cases.
 */

/**
 * Calculate exponential backoff delay with jitter.
 *
 * @param attempt - The retry attempt number (1-indexed).
 * @param baseDelay - Base delay in milliseconds.
 * @param maxDelay - Maximum delay in milliseconds.
 * @returns Delay in milliseconds.
 */
export function exponentialBackoff(
  attempt: number,
  baseDelay = 500,
  maxDelay = 30_000,
): number {
  const delay = Math.min(baseDelay * Math.pow(2, attempt - 1), maxDelay);
  const jitter = delay * 0.25 * Math.random();
  return delay + jitter;
}
