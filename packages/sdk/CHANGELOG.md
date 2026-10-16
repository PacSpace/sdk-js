# Changelog

## 0.14.0 - 2026-10-16

### Changed

- **Encrypted records move to format 2. Update every server that writes or reads encrypted records. 0.13.0 can no longer write encrypted records or add an encryption version.**
- An encrypted write declares its record hash version. Encrypted records started after format 2 use record hash v3: each top-level field is sealed once, so a shown field has exactly one sealed value. Records that are not encrypted are unchanged.
- Wraps to a holder, a grant reader or a link are bound to the owning workspace. Opening an encrypted record through a grant needs `owner`, the owning workspace's id; a missing or malformed id is refused before anything is sent (RECORDS_OWNER_INVALID).
- records.shareKeyWrap() returns `fragment`. Add it to the link after `#`: a link opened through a wrap opens only the disclosure its fragment names.
- records.rotate() adds the new version and its holder wraps in one request, and seals the seed of each key this workspace holds under it.
- An encrypted write retried after its first attempt went under another version is sent again under the version the record uses.

### Added

- After this workspace's key is replaced on the key pages, reads and records.holdings.confirm() still open what was wrapped to its earlier keys.
- RECORDS_SECRET_FILE_OUTDATED: "This workspace replaced its key. Use its new secret file on this server."
- RECORDS_RETIRED_KEY_MISMATCH: "A retired key for this workspace doesn't match its listed code. Don't use it; contact PacSpace."
- The records-encryption entry point exports replaceKey() and setUpKey() for the key pages. They run only through the dashboard, with the person's password.

## 0.13.0 - 2026-10-09

### Added

- Added generateWorkspaceSecret() and nextWorkspaceSecret(), and the records.secret and records.secretProvider options.
- With a workspace secret set, records.emit() encrypts new records and returns both the record id and the wire record id; records.wireId() gives the wire id for a webhook handler.
- records.history(), records.receipt() and records.bundle() open encrypted records with the workspace secret, a holder wrap or a record key, and check each entry against its sealed record hash.
- Added records.keepCopy(), records.recordKey() and records.open(link, { accessCode }).
- Added records.identity, records.holders, records.holdings and records.grants, with a pin store: wraps go only to workspaces whose code you confirmed.
- Added records.rotate() and records.rekey().

## 0.12.0 - 2026-10-02

- **fingerprint() now blinds by default and returns { ref, blinding }. Pass .ref as the payload, and save .blinding with writeBlindingFile beside the file: a blinded entry can be checked only with it.**
- fingerprint(input) mixes a random 32-byte value into the fingerprint (alg hmac-sha-256), so it cannot be matched to a guessed file without the blinding file. The file's size is stored as before.
- For today's plain sha-256 fingerprint, pass { blind: false } or { alg: 'sha-256' } and use .ref.
- To check a file later, pass it with its blinding file: records.check({ ..., expect: [{ entry, files: [{ source, blinding }] }] }), or fingerprint(file, { blinding }). Fingerprinting the file again without its blinding file gives a different fingerprint, which does not match.
- records.emit and records.check refuse a blinding, a blinding file or a whole fingerprint result before sending anything (RECORD_BLINDING_INCLUDED).
- A Blinding shows no value. JSON.stringify throws on it, so a logger that serializes an object holding one throws too; log the ref instead.
- If a blinding file is lost, its entry can no longer be matched to the file. The entry's seal still verifies.
- Before: const ref = await fingerprint(file); ... payloads: [ref]
- After: const { ref, blinding } = await fingerprint(file); await writeBlindingFile(path, blinding); ... payloads: [ref]

### Added

- `records.check` reads the history of a record created with record hash v2: the file names itself `record-history-bundle/v2`, and its entries are `semantic-receipt/v3`. Each top-level field of such a record, and each item of a top-level list, is sealed on its own, with its own salt, so a copy can show some fields and still check against the seal on the ledger. Records created before v2 keep their `record-history-bundle/v1` files, byte for byte.
- Version 0.11.0 and earlier refuse a `record-history-bundle/v2` file by name ("Not a record-history-bundle/v1.") and report each expected entry as not found. Update to read a v2 record's history.
- `records.check` gives each entry a `kind`: `attempt`, `failure` or `transition`, read from the entry's verified word.
- `records.disclose({ record, entries, source })` builds a file that reveals the fields you choose of a record's entries, checked on your machine against their seals on the ledger at the `source` you pass. It uploads nothing and makes no link.
- `records.disclose` reads the record's seal history and its history in one call, `GET /api/v1/records/{recordType}/{record}/disclosure-source`, with your API key, and checks the file against the public ledger at the `source` you pass. A record with more than 5000 entries on the ledger answers 413 `RECORD_HISTORY_TOO_LARGE`, which `records.disclose` passes on.

## 0.11.0 - 2026-09-22

### Changed

- **Entries count from 1**, as every PacSpace page does. Through 0.10.0 the SDK took the wire's `seq` (counted from 0) under the name `entry`, so `amends: { entry: 1 }` named the second entry while the record page called that one "Entry 2"; the README's own example corrected the wrong entry. Now `entry` is the entry's number as the pages show it, and the SDK converts at its boundary (`seq = entry - 1`) in `records.emit` (`amends.entry`, `references[].entry`), `records.receipt` (`entry`), `records.history` (`fromEntry`, `toEntry`), and `records.check` (`expect[].entry`; each result's `entry` is now `seq + 1`). An `entry` below 1 throws `ValidationError` with the sentence that teaches the rule before anything is sent. The history file the SDK returns is the wire document the check verifies by its digest, so its `receipts[].seq` and `entries[].seq` stay the wire's numbers. **If your code passed 0-based numbers, add 1.**
- New exported types: `EntryNumber`, `RecordEntryRef`, `RecordHistoryEntry`, `RecordCheckEntryResult`.
- User-Agent header is `@pacspace-io/sdk/0.11.0`.

## 0.10.0 - 2026-09-22

### Fixed

- `records.check` verifies the history it is given. Through 0.9.0 the installed package did not: the verifier lived in `@pacspace/shared`, which is not published, and was named as an optional peer; installed from the registry the import failed, and the check fell back to "some entry is committed", answering `ok: true` on a history with a changed sealed field. The SDK is now bundled the way `@pacspace-io/check` is: the exact verifier modules are bundled in at build time (`scripts/build.mjs`, `scripts/shared-surface.ts`), and the build refuses any input from outside `packages/sdk` and `packages/shared/src`. `records.check` runs every seal, the chain between entries, the file's own digest, and the current word when `source` is given. A verifier that throws answers `ok: false` with `reason` "The check did not finish: ...". The test suite installs the packed tarball into an empty directory and runs the tampered-history case from the installed package.

### Changed

- `ethers` (`^6.13.4`) is the SDK's one runtime dependency; the verifier's hashing and the public-source readers use it. The `@pacspace/shared` peer dependency is gone.
- User-Agent header is `@pacspace-io/sdk/0.10.0`.

## 0.9.0 - 2026-09-21

### Changed

- The default sandbox URL is `https://app.pacspace.io`, the same host as production. The API routes each request by the environment of its key, so a `pk_test_` key on the default host reads and writes the sandbox data plane; a `pk_live_` key on a sandbox-only host is refused with `API_KEY_ENVIRONMENT_HOST_MISMATCH` (403). `sandboxUrl` stays as a bring-your-own override for a private sandbox host. The `api-sandbox` host keeps serving; nothing that names it breaks. Sandbox traffic on the default host shares the production host's throttle tiers.
- User-Agent header is `@pacspace-io/sdk/0.9.0`.

### Added

- Records: `records.emit({ record, title, occurredAt, actorId, payloads, kind?, amends?, references? })` writes an entry to a record (`machine-action-record` by default), `records.receipt({ record, entry })` reads one entry's receipt, `records.history({ record, fromEntry?, toEntry? })` reads the record's history file, and `records.check({ history, expect?, source? })` runs the check in your process, reading the public source when `source` is given (`@pacspace/shared` as an optional peer). `fingerprint(fileOrBytes)` computes the `PayloadRef` (`sha-256`, `digest`, `byteLength`) an entry carries for a file. Landed in the repository on 2026-09-16 (Slice C5) and first published here.

- `webhooks.verify` accepts an `X-PacSpace-Signature` header that carries more than one `v1=<hex>` value, comma separated. For 24 hours after a signing-secret rotation with overlap, PacSpace signs each delivery with the current secret and the previous one; the event is genuine when any one value matches the secret you hold, and each comparison is constant time. A single-value header verifies exactly as before.
- `balance.emit(..., { adjusts })` sends `adjusts` (`{ referenceId }` or `{ recordId }`) on `POST /api/v1/balance/delta`. `records.emit({ amends })` already maps `entry` to wire `seq`; the README now shows both.

## 0.8.0 - 2026-09-14

### Added

- Receipt access grants: `balance.receipts.createGrant(receiptId, params)`, `balance.receipts.listGrants(receiptId)`, and `balance.receipts.revokeGrant(receiptId, grantId, { reason })`, with the `ReceiptAccessGrant`, `ReceiptGrantKind` (`BEARER`, `RECIPIENT_BOUND`), `ReceiptGrantScope` (`SEMANTIC`, `CHAIN_BEARING`), `ReceiptGrantStatus`, `CreateReceiptGrantParams`, and `CreateReceiptGrantResponse` types. The grant token is returned once; only its hash is stored (ADR 0008 §5). Landed in the repository on 2026-08-04 and first published here.

### Changed

- Verify response types match what `GET /api/v1/verify/:proofRoot` returns since the move to proof-only verification (ADR 0008): `VerifyVerification.reference` is now `verificationReference`, and `batchId`, `chainId`, and `contractAddress` are carried. `VerifySummary` and `VerifyRecord` are marked `@deprecated`; the endpoint has not returned record contents since 0.5.x, and the types remain only for compile compatibility.
- User-Agent header bumped to `@pacspace-io/sdk/0.8.0`.

### Fixed

- `receiptId` and `proofRoot` are distinct identifiers and the SDK no longer substitutes one for the other. `balance.emit()`, `balance.derive()`, and the emit-then-status merge previously filled a missing `proofRoot` from `receiptId` (and once overwrote `proofRoot` with the status response's `receiptId`), which under the live API made a receipt identifier pose as a proof root. `receiptId` is the stable opaque receipt handle for `receipts.*`; `proofRoot` is the published root for verification. Type comments on `EmitResponse` and `VerifiedDelta` corrected to match (ADR 0008 §5, N-4 ruling 2026-08-28).

## 0.7.0 - 2026-05-28

### Changed

- Default production base URL is now `https://app.pacspace.io`, the single consolidated app/API origin (see ADR 0004). The previous `https://api.pacspace.io` host is being retired and is not maintained as a long-term default; pass `productionUrl` to target a custom host.
- User-Agent header bumped to `@pacspace-io/sdk/0.7.0`.

## 0.6.0 - 2026-05-27

### Added

- `InvoiceProofResponse.verificationApiUrl` now carries the machine verification endpoint for tools, agents, and auditors.
- `PacSpace.verify(proofRoot, { source })` supports `db`, `chain`, and `both` source selection.

### Deprecated

- `InvoiceProofResponse.verificationExplorerUrl` is retained for compatibility but deprecated. Use `verificationApiUrl` for machine verification and `verifyUrl` for human invoice links.

### Changed

- User-Agent header bumped to `@pacspace-io/sdk/0.6.0`.

## 0.5.1 - 2026-05-06

### Behavior changes

- When a tenant has Shared Record enabled and a customer handle exists, invoice bundle URL fields such as `verifyUrl` may resolve to the persistent customer permalink (`/c/{handle}`) instead of a period-specific receipt URL. Treat URL fields as opaque strings and use explicit receipt/checkpoint identifiers for period parsing.

### Added

- Shared Record invoice bundles may include additive fields such as `accessHint`, `customerLinkUrl`, and `customerLinkHost` when exposed by the API. Existing receipt URL fields remain strings.

## 0.4.0 - 2026-04-19

### Breaking changes

- `BalanceResource.emitBatch()` has been removed from the public SDK surface. PacSpace positions itself as neutral verification infrastructure for usage-based billing disputes, and the public API is single-emit only. Submit deltas one at a time with `balance.emit(...)`, or queue summaries through the `SubmissionCoordinator` (`balance.queueSummary(...)`, `balance.flushSummaries(...)`, etc.), which handles request sizing internally.
- The public types `BulkEmitOptions`, `BulkDelta`, `BulkDeltaResult`, and `BulkEmitResponse` have been removed from `@pacspace-io/sdk`.
- `SubmissionAutomationOptions.batchSize` has been renamed to `maxDeltasPerRequest`. Semantics are unchanged — the default remains `100` deltas per outbound submission request. Update any explicit overrides.

### Changed

- Package keywords no longer advertise `blockchain` or `smart-contract`; the package description now matches the billing-dispute verification wedge.
- User-Agent header bumped to `@pacspace-io/sdk/0.4.0`.

### Internal

- Multi-delta submission transport (used by `SubmissionCoordinator`) has been moved to `src/resources/internal/batch-transport.ts`. This module is private and its types (`InternalBatchDelta`, `InternalBatchResponse`, etc.) are not part of the published API.

### Migration guide

1. **If you called `balance.emitBatch(deltas)` directly**, loop over `balance.emit(customerId, delta, reason, options?)` instead, or use the submission coordinator (`queueSummary` / `flushSummaries` / `startSummaryScheduler`). The coordinator continues to chunk outbound requests internally — no user-facing change to throughput or idempotency.
2. **If you passed `{ batchSize: N }` to the submission scheduler options**, rename the field to `maxDeltasPerRequest: N`. No behavior change.
3. **If your code imported `BulkDelta`, `BulkEmitOptions`, `BulkDeltaResult`, or `BulkEmitResponse`**, remove those imports — they are no longer exported.

## 0.3.0 - 2026-04-16

### Breaking changes

- `balance.derive()` and `balance.compare()` now default to the current UTC month when no scope is provided.
- Checkpoint mode and scope mode are now mutually exclusive. Passing `startingCheckpoint` together with `period`, `timePreset`, `startDate`, or `endDate` is invalid.

### Added

- Scope-aware derive/compare support (`period`, `timePreset`, `startDate`, `endDate`).
- Multi-month rollup fields in derive/compare responses (`scope`, `monthlyBreakdown`, `cumulativeBalance`).
- Typed 400-class SDK errors:
  - `InvalidScopeCombinationError`
  - `ScopeTooWideError`
- Convenience derive helpers:
  - `balance.deriveCurrentMonth(customerId, options?)`
  - `balance.deriveForPeriod(customerId, period, options?)`
  - `balance.deriveMonthsBack(customerId, months, options?)`
- `balance.customer(customerId, { period })` support with period metadata in responses.

### Migration guide

1. **If you previously depended on all-time derive/compare defaults**, send an explicit multi-month scope in each call.
2. **If you used checkpoint-based incremental replay**, keep using `startingCheckpoint`, but do not send scope fields in the same request.
3. **If your app relies on customer detail balances**, pass `period` explicitly when you need a specific month.
