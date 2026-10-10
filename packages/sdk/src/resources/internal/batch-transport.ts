import type { HttpClient } from '../../client';
import type { RequestOptions } from '../../types/config';
import type { ContentFingerprint } from '../../types/balance';

/**
 * @internal
 * Internal-only transport options for the tenant-summary submission path.
 * Not part of the public SDK surface.
 */
export interface InternalBatchOptions extends RequestOptions {
  referenceId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * @internal
 * Internal-only delta shape used by the tenant-summary submission coordinator.
 * Not part of the public SDK surface.
 */
export interface InternalBatchDelta {
  customerId: string;
  delta: number;
  reason: string;
  referenceId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * @internal
 * Internal-only per-item result for the tenant-summary submission coordinator.
 * Not part of the public SDK surface.
 */
export interface InternalBatchItemResult {
  index: number;
  customerId: string;
  delta: number;
  recordId?: string;
  itemHash?: ContentFingerprint;
  receiptId?: string;
  referenceId?: string;
  sequenceNumber?: string;
  idempotent?: boolean;
  status: string;
  error?: string;
}

/**
 * @internal
 * Internal-only response shape for the tenant-summary submission coordinator.
 * Not part of the public SDK surface.
 */
export interface InternalBatchResponse {
  totalQueued: number;
  totalFailed: number;
  results: InternalBatchItemResult[];
  _efficiency?: {
    uniqueCustomers: number;
    totalDeltas: number;
    estimatedSlots: number;
    message: string;
  };
}

/**
 * @internal
 * Internal transport used by the tenant-summary submission coordinator only.
 * This is not a public SDK method; do not reference from public code paths.
 */
export async function submitInternalBatch(
  client: HttpClient,
  deltas: InternalBatchDelta[],
  options?: InternalBatchOptions,
): Promise<InternalBatchResponse> {
  const { ...requestOptions } = options ?? {};
  const response = await client.post<Record<string, unknown>>(
    '/api/v1/balance/delta/batch',
    { deltas },
    requestOptions,
  );
  return normalizeInternalBatchResponse(response);
}

function normalizeInternalBatchResponse(
  data: Record<string, unknown>,
): InternalBatchResponse {
  const results = Array.isArray(data.results)
    ? data.results.map((entry) => {
        const item = entry as Record<string, unknown>;
        return {
          index: Number(item.index ?? 0),
          customerId: String(item.customerId ?? ''),
          delta: Number(item.delta ?? 0),
          recordId:
            item.recordId == null ? undefined : String(item.recordId),
          itemHash:
            item.itemHash == null ? undefined : String(item.itemHash),
          receiptId:
            item.receiptId == null ? undefined : String(item.receiptId),
          referenceId:
            item.referenceId == null ? undefined : String(item.referenceId),
          sequenceNumber:
            item.sequenceNumber == null
              ? undefined
              : String(item.sequenceNumber),
          idempotent:
            item.idempotent == null ? undefined : Boolean(item.idempotent),
          status: String(item.status ?? ''),
          error: item.error == null ? undefined : String(item.error),
        };
      })
    : [];

  return {
    totalQueued: Number(data.totalQueued ?? results.length),
    totalFailed: Number(data.totalFailed ?? 0),
    results,
    _efficiency: data._efficiency as InternalBatchResponse['_efficiency'],
  };
}
