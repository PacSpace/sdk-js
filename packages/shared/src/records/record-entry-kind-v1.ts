import type { LayoutDocumentV1 } from '../proof/layout-document-v1';
import { decodeStateV1 } from '../proof/layout-document-v1';
import { FLAG_DELIVERY_FAILED, FLAG_TRANSITION_NOT_APPLIED, splitWordV1 } from '../proof/slot-encoding-v1';

export type RecordEntryKindNameV1 = 'transition' | 'attempt' | 'failure';

/**
 * What kind of entry a committed word records, read from the word's flags
 * under its layout, never from content: `transition_not_applied` is an
 * attempt entry, `delivery_failed` a failure record, anything else a
 * transition. `lifecycle` is the lifecycle the word carries, which an
 * attempt or a failure record keeps unchanged.
 */
export function recordEntryKindV1(
  layout: LayoutDocumentV1,
  newWord: string | bigint,
): { kind: RecordEntryKindNameV1; lifecycle: string } {
  const state = decodeStateV1(layout, splitWordV1(newWord).state96);
  const flags = Array.isArray(state.flags) ? (state.flags as string[]) : [];
  const lifecycle = String(state[layout.lifecycle.field]);
  if (flags.includes(FLAG_TRANSITION_NOT_APPLIED)) return { kind: 'attempt', lifecycle };
  if (flags.includes(FLAG_DELIVERY_FAILED)) return { kind: 'failure', lifecycle };
  return { kind: 'transition', lifecycle };
}
