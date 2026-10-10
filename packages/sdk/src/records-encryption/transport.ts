import { registerApiErrorBody, type ClientRequestOptions } from '../client';
import { PacSpaceError } from '../errors';

/**
 * What encrypted records need from a transport (L2e design v2, D5).
 * `HttpClient` is one, sending the API key; a key page passes one that sends
 * the dashboard session to the dashboard's encrypted door instead. The paths
 * are always the SDK's own `/api/v1/records/...` paths.
 */
export interface RecordsTransport {
  get<T>(path: string, options?: ClientRequestOptions): Promise<T>;
  getRaw<T>(path: string, options?: ClientRequestOptions): Promise<{ body: T; headers: Headers; status: number }>;
  post<T>(path: string, body?: unknown, options?: ClientRequestOptions): Promise<T>;
  postNow<T>(path: string, body: unknown, options?: ClientRequestOptions): Promise<T>;
  put<T>(path: string, body: unknown, options?: ClientRequestOptions): Promise<T>;
  delete<T>(path: string, options?: ClientRequestOptions): Promise<T>;
}

/** A refusal from another transport, carrying its body for the SDK's retry rules (as `recordKid`). */
export function transportError(message: string, statusCode: number, code: string, body?: Record<string, unknown>): PacSpaceError {
  const error = new PacSpaceError(message, statusCode, code);
  if (body) registerApiErrorBody(error, body);
  return error;
}
