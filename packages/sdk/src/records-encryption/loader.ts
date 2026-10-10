import type * as Shared from '@pacspace/shared';
import type * as Asymmetric from '@pacspace/shared/dist/records-crypto/asymmetric';

/** Resolved through the package's exports at run time; the SDK's own resolution reads its types from dist. */
const ASYMMETRIC = '@pacspace/shared/records-crypto/asymmetric';

/**
 * The key layer of encrypted records: records-crypto and its asymmetric
 * part, loaded once per process. Every key the SDK makes or opens comes from
 * this one module, because a key is only usable by the module that made it;
 * a record key crosses to the bundled verifier as bytes, in memory only.
 *
 * In the published package scripts/build.mjs replaces this file with a
 * require of the bundled `./records-crypto.js` subpath, which carries the
 * pinned libraries; the names below are exactly what that subpath exports.
 */
export type RecordsCrypto = Pick<
  typeof Shared,
  | 'RecordsKeyringV1'
  | 'localRecordsKeyProviderV1'
  | 'parseRecordsKeyringFileV1'
  | 'serializeRecordsKeyringFileV1'
  | 'generateWorkspaceSecretV1'
  | 'wireRecordIdV1'
  | 'wireReferenceIdV1'
  | 'contentTagV1'
  | 'recordKeyOfV1'
  | 'recordKeyFromBytesV1'
  | 'exportKeyBytesV1'
  | 'sealRecordEntryV1'
  | 'openRecordEntryEnvelopeV1'
  | 'recordEntryPlaintextV1'
  | 'checkEncryptedWriteSizeV1'
  | 'newSaltKeyV2'
  | 'commitRecordContentV2'
> &
  Pick<
    typeof Asymmetric,
    | 'workspaceSeedFromBytesV1'
    | 'sealSeedWrapV1'
    | 'openSeedWrapV1'
    | 'publicKeyIdV1'
    | 'holderKeyCodeV1'
    | 'wrapRecordsKeyV1'
    | 'wrapRecordKeyV1'
    | 'wrapDisclosureKeyV1'
    | 'unwrapRecordsKeyV1'
    | 'unwrapRecordKeyV1'
    | 'unwrapDisclosureKeyV1'
  >;

let loaded: Promise<RecordsCrypto> | null = null;

export function loadRecordsCrypto(): Promise<RecordsCrypto> {
  if (!loaded) {
    loaded = Promise.all([import('@pacspace/shared'), import(/* @vite-ignore */ ASYMMETRIC) as Promise<typeof Asymmetric>]).then(
      ([symmetric, asymmetric]) => ({ ...symmetric, ...asymmetric }) as RecordsCrypto,
    );
  }
  return loaded;
}
