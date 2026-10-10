# @pacspace-io/sdk

Official TypeScript SDK for the [PacSpace Balance API](https://docs.pacspace.io). Zero dependencies, fully typed, built for Node.js 18+.

## Install

```bash
npm install @pacspace-io/sdk
```

## Quick Start

```typescript
import { PacSpace } from '@pacspace-io/sdk';

const pac = new PacSpace({ apiKey: process.env.PACSPACE_API_KEY! });

// Record a delta
const delta = await pac.balance.emit('cust_123', -42.50, 'usage_charge');
console.log(delta.receiptId); // Store for later verification

// Derive balance
const { computedBalance } = await pac.balance.derive('cust_123');

// Compare against counterparty
const report = await pac.balance.compare('cust_123', {
  yours: 95000,
  theirs: 98000,
});

// Period-end checkpoint
const checkpoint = await pac.balance.checkpoint('cust_123', {
  period: '2026-02',
});
```

## API Reference

### `new PacSpace(config)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | `string` | **required** | Your Balance API key (`pk_live_*` or `pk_test_*`) |
| `baseUrl` | `string` | `https://app.pacspace.io` | API base URL (overrides the key-based choice if provided) |
| `sandboxUrl` | `string` | `https://app.pacspace.io` | Custom sandbox URL for a private sandbox host (used for `pk_test_*` keys) |
| `productionUrl` | `string` | `https://app.pacspace.io` | Custom production URL (used for `pk_live_*` keys) |
| `chainId` | `number` | auto-detected | Default chain ID (296 for sandbox, 295 for production) |
| `maxRetries` | `number` | `2` | Max retries on transient errors |
| `timeout` | `number` | `30000` | Request timeout in ms |
| `webhookSecret` | `string` | — | Webhook signing secret (enables `pac.webhooks`) |

### Balance API

#### `pac.balance.emit(customerId, delta, reason, options?)`

Record a credit or debit delta. Returns immediately with `QUEUED` status.

```typescript
const delta = await pac.balance.emit('cust_123', -42.50, 'usage_charge', {
  referenceId: 'inv_001',
  metadata: { plan: 'growth' },
});

const adjustment = await pac.balance.emit('cust_123', -10, 'adjustment', {
  adjusts: { referenceId: 'inv_001' },
});
```

`adjusts` names the committed entry this delta adjusts, by that entry's `referenceId` or `recordId`. The original stays visible. The API refuses the write when the named entry is missing, pending, or out of scope.

#### `pac.records.emit({ record, title, occurredAt, actorId, payloads, amends? })`

Record a records entry. `amends` names a committed entry by `recordKey` and `entry`. The SDK counts entries from 1, as every PacSpace page does: `entry: 1` is the first entry of the record, the one the record page calls "Entry 1". The HTTP API and the history file carry the same position as `seq`, counted from 0; the SDK converts at its boundary (`seq = entry - 1`), so you never send or read a `seq`. An `entry` below 1 is refused before anything is sent.

```typescript
const entry = await pac.records.emit({
  record: 'build-1',
  title: 'Handoff restated',
  occurredAt: '2026-09-14T10:02:00Z',
  actorId: 'ci',
  payloads: [{ alg: 'sha-256', digest: 'bb'.repeat(32), byteLength: '1' }],
  amends: { recordKey: '0xab', entry: 1 }, // corrects the first entry
  note: 'handoff restated',
  lifecycle: 'amended',
});
```

`pac.records.receipt({ record, entry })`, `pac.records.history({ record, fromEntry?, toEntry? })`, and `check`'s `expect[].entry` count the same way. The history file itself is the wire document the check verifies by its digest, so its `receipts[].seq` and `entries[].seq` stay the wire's numbers; `check` reports each result as `entry` (`seq + 1`).

`pac.records.history({ record })` returns the record's history file and `pac.records.check({ history, expect?, source? })` runs the check in your process: every seal, the chain between entries, the file's own digest, and the current word when `source` names the public source. The verifier is bundled into the SDK (0.10.0 and later); `ethers` is its one runtime dependency. Someone who holds only that file and the fingerprint printed on a statement, with no PacSpace account and no SDK, runs the same check with the standalone checker: `npx @pacspace-io/check history.json --fingerprint 0x...` ([`@pacspace-io/check`](https://www.npmjs.com/package/@pacspace-io/check)). It reads the public source and never calls PacSpace.

#### `fingerprint(input, options?)`

fingerprint() blinds by default: it mixes a random 32-byte value into the fingerprint, so the fingerprint cannot be matched to a guessed file without the file's blinding file.

It returns { ref, blinding }. Send ref as the payload. Save blinding beside the file with writeBlindingFile(path, blinding); anyone checking the file later needs it.

To check a file later, pass it with its blinding file: in records.check, expect: [{ entry, files: [{ source, blinding }] }], or fingerprint(file, { blinding }). A blinding belongs to one file; another file is refused.

The blinding file is as private as the file: whoever holds both can confirm the file is in the record. The file's size is stored as before.

blind: false, or alg: 'sha-256', gives today's plain sha-256 fingerprint as { ref, blinding: null }. It is not blinded.

On Windows the blinding file's permissions are not restricted to you; keep it somewhere only you can read.

#### `pac.balance.emitAndWait(customerId, delta, reason, options?)`

Record a delta and poll until it reaches a terminal status (`VERIFIED` or `FAILED`).

```typescript
const verified = await pac.balance.emitAndWait('cust_123', -42.50, 'usage', {
  timeout: 30_000,
  pollInterval: 1000,
});
```

#### `pac.balance.derive(customerId, options?)`

Derive a customer's balance from all verified deltas.

```typescript
const result = await pac.balance.derive('cust_123');
console.log(result.computedBalance);

// With checkpointing for efficiency:
const next = await pac.balance.derive('cust_123', {
  startingBalance: result.computedBalance,
  startingCheckpoint: result.latestReceiptId!,
});
```

#### `pac.balance.compare(customerId, balances, options?)`

Compare balances against neutral truth for dispute resolution.

```typescript
const report = await pac.balance.compare('cust_123', {
  yours: 95000,
  theirs: 98000,
});

if (report.matchesYours) {
  console.log('Your balance is correct');
}
```

#### `pac.balance.receipt(customerId, options?)`

Generate a verifiable receipt. With `options.period` (YYYY-MM), returns a period-specific receipt with `proofRoot`, `verifyUrl`, and `verificationReference`. Treat `verifyUrl` as an opaque invoice link; when Shared Record is enabled it may point at a persistent `/c/{handle}` customer record instead of a proof-root URL.

```typescript
// Period receipt (shareable proof for invoices)
const receipt = await pac.balance.receipt('cust_123', { period: '2026-02' });
console.log(receipt.proofRoot);   // Proof root for verification
console.log(receipt.verifyUrl);   // Share this opaque URL on invoices
console.log(receipt.verificationApiUrl); // Machine endpoint for tools and auditors
console.log(receipt.finalBalance);

// Full record receipt (all verified deltas)
const full = await pac.balance.receipt('cust_123');
console.log(full.finalBalance);
console.log(full.verification.itemHashes);
```

#### `pac.verify(proofRoot, options?)`

Verify a proof root via the verification endpoint. No API key required. The response contains proof-only facts (validity, timestamps, and chain references); record contents are never returned here.

```typescript
const result = await pac.verify(receipt.proofRoot);
if (result.verified) {
  console.log(result.recordedAt);
  console.log(result.verification?.verificationExplorerUrl);
}
```

Use `options.source` to select the verification source:

```typescript
await pac.verify(receipt.proofRoot, { source: 'both' }); // 'db' (default), 'chain', or 'both'
```

Use `receipt.verifyUrl` for human invoice links. Use
`receipt.verificationApiUrl` when a tool, agent, or auditor needs to call the
machine verification endpoint. `receipt.verificationExplorerUrl` is a deprecated
legacy compatibility field and will be retained until a future major version.

#### `pac.balance.checkpoint(customerId?, options?)`

Commit a period-end checkpoint. The proof root is recorded on the proof layer for independent verification.

```typescript
const checkpoint = await pac.balance.checkpoint('cust_123', {
  period: '2026-02',
});
console.log(checkpoint.proofRoot); // Include in your invoice
```

#### Receipt access grants

Issue separately revocable, optionally expiring authorizations for receipt
retrieval. The grant token is returned once and only its hash is stored —
share `grantUrl` with the counterparty and revoke the grant at any time to
cut off later retrieval.

```typescript
// Issue a recipient-bound grant for an auditor, valid for 30 days
const { grantUrl, grant } = await pac.balance.receipts.createGrant('chk_abc123', {
  kind: 'RECIPIENT_BOUND',
  recipientEmail: 'auditor@counterparty.com',
  ttlHours: 24 * 30,
  label: 'Q3 audit',
});
// Deliver grantUrl to the auditor; they confirm their email on retrieval.

// List every path to a receipt (grants plus Shared Record step-up)
const grants = await pac.balance.receipts.listGrants('chk_abc123');

// Revoke when the engagement ends
await pac.balance.receipts.revokeGrant('chk_abc123', grant.grantId, {
  reason: 'engagement ended',
});
```

Grant scopes control what the retrieved receipt carries: `SEMANTIC` (default)
serves record contents with chain-correlation fields stripped, while
`CHAIN_BEARING` produces a self-contained receipt that also carries the proof
root and chain reference for independent verification (ADR 0008 §5).

### Webhooks

Verify webhook signatures and process events with type safety.

```typescript
const pac = new PacSpace({
  apiKey: process.env.PACSPACE_API_KEY!,
  webhookSecret: process.env.PACSPACE_WEBHOOK_SECRET!,
});

// Express middleware
app.use('/webhooks', express.json({
  verify: (req, _res, buf) => { (req as any).rawBody = buf.toString(); }
}));

app.post('/webhooks/pacspace', pac.webhooks!.middleware(), (req, res) => {
  const event = (req as any).pacspaceEvent;

  if (event.event === 'delta.verified') {
    console.log('Delta verified:', event.data.receiptId);
  }

  res.status(200).json({ received: true });
});

// Manual verification
const event = pac.webhooks!.verify(signature, timestamp, rawBody);
```

### Error Handling

All errors extend `PacSpaceError` with structured data:

```typescript
import { PacSpace, InsufficientCreditsError, RateLimitError } from '@pacspace-io/sdk';

try {
  await pac.balance.emit('cust_123', -1000, 'charge');
} catch (err) {
  if (err instanceof InsufficientCreditsError) {
    console.log('Buy more credits');
  } else if (err instanceof RateLimitError) {
    console.log(`Retry after ${err.retryAfter}s`);
  }
}
```

| Error Class | Status | When |
|-------------|--------|------|
| `ValidationError` | 400 | Invalid request data |
| `InvalidApiKeyError` | 401 | Bad or missing API key |
| `InsufficientCreditsError` | 402 | Not enough credits |
| `NotFoundError` | 404 | Resource not found |
| `ContractNotDeployedError` | 412 | No contract provisioned |
| `RateLimitError` | 429 | Rate limit exceeded |
| `TimeoutError` | — | Polling timeout exceeded |

## Environment Detection

One host serves both environments. The API reads the environment from your key: a `pk_test_*` key on `https://app.pacspace.io` reads and writes the sandbox data plane, a `pk_live_*` key the production one. The SDK sends every request to that host unless you set a URL:

- `pk_test_*` → `sandboxUrl` when configured, else `https://app.pacspace.io`
- `pk_live_*` → `productionUrl` when configured, else `https://app.pacspace.io`

The key prefix also picks the default `chainId` (296 for sandbox, 295 for production).

### Examples

**Sandbox (automatic):**
```typescript
const pac = new PacSpace({ apiKey: 'pk_test_...' });
// Sends to https://app.pacspace.io; the key selects the sandbox environment.
```

**Production (automatic):**
```typescript
const pac = new PacSpace({ apiKey: 'pk_live_...' });
// Automatically uses production API URL
```

**Custom URLs:**
```typescript
// A private sandbox host (bring your own)
const pac = new PacSpace({
  apiKey: 'pk_test_...',
  sandboxUrl: 'https://custom-sandbox.example.com',
});

// Override production URL
const pac = new PacSpace({
  apiKey: 'pk_live_...',
  productionUrl: 'https://custom-production.example.com',
});

// Override with explicit baseUrl (disables auto-routing)
const pac = new PacSpace({
  apiKey: 'pk_test_...',
  baseUrl: 'https://custom-api.example.com',
});
```

## Requirements

- Node.js 18+ (uses native `fetch`)
- TypeScript 5+ (for full type inference)
