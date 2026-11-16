import type { RecordStatus } from '../types/common';
import { TimeoutError } from '../errors';

/**
 * Terminal statuses — once a record reaches these, polling stops.
 */
const TERMINAL_STATUSES: Set<RecordStatus> = new Set(['VERIFIED', 'FAILED']);

/**
 * Options for the poll utility.
 */
export interface PollOptions {
  /**
   * Maximum time (ms) to wait before throwing a TimeoutError.
   * @default 60000
   */
  timeout?: number;
  /**
   * Interval (ms) between polls.
   * @default 2000
   */
  pollInterval?: number;
  /** AbortSignal for cancellation. */
  signal?: AbortSignal;
}

/**
 * Poll a status-returning function until a terminal status is reached.
 *
 * @param statusFn — Async function that returns the current status and full data.
 * @param options — Timeout and interval configuration.
 * @returns The full data object once a terminal status is reached.
 * @throws TimeoutError if the timeout is exceeded.
 *
 * @internal
 */
export async function pollUntilTerminal<T extends { status: RecordStatus }>(
  statusFn: () => Promise<T>,
  options?: PollOptions,
): Promise<T> {
  const timeout = options?.timeout ?? 60_000;
  const pollInterval = options?.pollInterval ?? 2_000;
  const signal = options?.signal;

  const deadline = Date.now() + timeout;

  while (Date.now() < deadline) {
    // Check cancellation
    if (signal?.aborted) {
      throw new TimeoutError('Polling cancelled');
    }

    const result = await statusFn();

    if (TERMINAL_STATUSES.has(result.status)) {
      return result;
    }

    // Wait before next poll, but respect the deadline
    const remaining = deadline - Date.now();
    const delay = Math.min(pollInterval, remaining);

    if (delay <= 0) break;

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(resolve, delay);

      // If cancelled during sleep, clean up and reject
      if (signal) {
        const onAbort = () => {
          clearTimeout(timer);
          reject(new TimeoutError('Polling cancelled'));
        };
        signal.addEventListener('abort', onAbort, { once: true });
      }
    });
  }

  throw new TimeoutError(
    `Operation did not reach a terminal status within ${timeout}ms`,
  );
}
