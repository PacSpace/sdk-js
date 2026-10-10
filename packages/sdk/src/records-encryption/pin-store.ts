/**
 * A workspace whose code the person confirmed outside PacSpace: the id of
 * the public key that made the code, and when. Wraps go only to a pinned key;
 * a later wrap that finds another key there is refused before anything is
 * wrapped. A pin holds no secret.
 */
export interface RecordsPin {
  publicKeyId: string;
  confirmedAt: string;
}

export interface RecordsPinStore {
  get(workspaceId: string): Promise<RecordsPin | null>;
  set(workspaceId: string, pin: RecordsPin): Promise<void>;
}

/** Pins held for this process only. */
export function memoryPinStore(): RecordsPinStore {
  const pins = new Map<string, RecordsPin>();
  return {
    async get(workspaceId) {
      const pin = pins.get(workspaceId);
      return pin ? { ...pin } : null;
    },
    async set(workspaceId, pin) {
      pins.set(workspaceId, { publicKeyId: pin.publicKeyId, confirmedAt: pin.confirmedAt });
    },
  };
}
