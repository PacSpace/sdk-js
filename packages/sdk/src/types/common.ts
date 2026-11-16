/**
 * Raw API response envelope returned by all PacSpace endpoints.
 * The SDK unwraps this automatically — users never see it.
 * @internal
 */
export interface RawApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
  statusCode?: number;
}

/**
 * Record verification lifecycle.
 */
export type RecordStatus =
  | 'QUEUED'
  | 'PROCESSING'
  | 'VERIFIED'
  | 'FAILED';

/**
 * Checkpoint type for balance derivation.
 */
export type CheckpointType = 'proofRoot' | 'recordId';
