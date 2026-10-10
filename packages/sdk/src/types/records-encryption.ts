import type { RecordsPinStore } from '../records-encryption/pin-store';
import type { RecordCheckSource } from './records';

/** The workspace secret: a pacspace-workspace-secret/v1 file's text, or the file parsed. */
export type RecordsSecretSource = string | { schema: string; secrets: Array<{ version: number; secret: string }> };

export interface RecordsEncryptionOptions {
  /** The workspace secret. It is the customer's: it stays in this process and is never sent. */
  secret?: RecordsSecretSource;
  /** Called once per client for the workspace secret. */
  secretProvider?: () => RecordsSecretSource | Promise<RecordsSecretSource>;
  /** Where confirmed codes are pinned; a memory store by default. */
  pinStore?: RecordsPinStore;
}

/** A record by its own id (worked out to its wire id here) or, for another workspace's record, by its wire id. */
export interface RecordTarget {
  recordType?: string;
  record?: string;
  wireRecordId?: string;
  /** `false` names a plaintext record by its own id. */
  encrypted?: boolean;
}

export interface RecordsIdentityResult {
  xwingPublicId: string;
  /** The 40-digit code the other side confirms with you, outside PacSpace. */
  code: string;
  created: boolean;
}

export interface RecordsHolderAddInput {
  workspaceId: string;
  scope?: 'workspace' | 'record';
  required?: boolean;
  /** Record scope: the one record whose key is wrapped. */
  record?: RecordTarget;
  /** The code they read out to you, the first time; later wraps use the pin. */
  confirmedCode?: string;
}

export interface RecordsHolderAddResult {
  holderId: string;
  created: boolean;
  wraps: Array<{ version: number | null; state: string }>;
}

export interface RecordsHoldingResult {
  holderId: string;
  version: number | null;
  state: string;
  reason?: string;
}

export interface RecordsGrantCreateInput extends RecordTarget {
  kind: 'BEARER' | 'RECIPIENT_BOUND' | 'TENANT_BOUND';
  recipientEmail?: string;
  counterpartyWorkspaceId?: string;
  authorizes?: 'acknowledgment';
  ttlHours?: number;
  maxUses?: number;
  label?: string;
  /** For a grant to a named workspace on an encrypted record, the first time. */
  confirmedCode?: string;
}

export interface RecordsShareKeyWrapInput extends RecordTarget {
  handle: string;
  /** The link's key: its bytes, the link, or its `#dk=` part. */
  disclosureKey: Uint8Array | string;
  workspaceId: string;
  confirmedCode?: string;
}

export interface RecordCopyFile {
  schema: 'pacspace-record-copy/v1';
  bytes: Uint8Array;
}

export interface RecordOpenOptions {
  accessCode?: string;
  /** Where batch roots are read; the public mirror by default. */
  source?: RecordCheckSource;
}

export interface RecordOpenResult {
  handle: string;
  sealHistory: Record<string, unknown>;
  /** Null when the link reveals no fields. */
  disclosure: Record<string, unknown> | null;
  /**
   * The revealed entries, counted from 1, checked. `fields` holds each
   * revealed field by its JSON pointer; `content` is the whole entry when
   * nothing in it was withheld.
   */
  entries: Array<{ entry: number; fields: Array<{ pointer: string; value: unknown }>; content: Record<string, unknown> | null; withheld: number }>;
}

export interface RecordRotateResult {
  version: number;
  kid: string;
  holders: Array<{ holderId: string; workspaceId: string; wrapped: boolean; code?: string }>;
}

export interface RecordRekeyInput extends RecordTarget {
  toVersion: number;
}

export interface RecordRekeyResult {
  entries: Array<{ entry: number; state: 'swapped' | 'already' }>;
  grants: Array<{ grantId: string; wrapped: boolean; code?: string }>;
  holders: Array<{ holderId: string; wrapped: boolean; code?: string }>;
}
