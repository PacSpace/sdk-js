// The exact part of @pacspace/shared the SDK bundles: the shared verifier and
// the two public-source readers that `records.check` runs, records-crypto
// (the blinded fingerprint, its blinding file and the held-file rule) and
// payload-ref/v1's Rule B, which `emit` and `check` apply before anything is
// sent. The build aliases `@pacspace/shared` to this file, so nothing else in
// that package (server modules, email, passwords) can reach the published
// SDK; scripts/build.mjs refuses any input from outside these sources. The
// standalone checker (packages/check/scripts/shared-surface.ts) bundles the
// same verifier. `records.disclose` adds the seal history, the kept copy and
// each entry's kind (seals-first A) beside record hash v2's disclosure.
// Encrypted records (L2d) add the v3 history's opener and intake's admission
// check, which a client runs on the content before it encrypts.
export * from '../../shared/src/records/record-history-bundle-v1';
export * from '../../shared/src/records/record-history-bundle-v2';
export * from '../../shared/src/records/record-history-bundle-v3';
export { admitRecordEntryV1 } from '../../shared/src/records/record-admission-v1';
export { listPublishedLayouts } from '../../shared/src/records/layouts';
export * from '../../shared/src/records/record-seal-history-v1';
export * from '../../shared/src/records/record-link-copy-v1';
export { recordEntryKindV1 } from '../../shared/src/records/record-entry-kind-v1';
export { getPublishedLayoutRegistry } from '../../shared/src/records/layouts';
export { recordContentOfReceipt } from '../../shared/src/proof/semantic-receipt-v3';
export * from '../../shared/src/demo/independent-verify-records';
export * from '../../shared/src/demo/mirror-node-record-chain-reader';
export * from '../../shared/src/records-crypto';
export { assertNoBlindingMaterial } from '../../shared/src/proof/payload-ref-v1';
export { RecordIntakeError } from '../../shared/src/proof/layout-document-v1';
