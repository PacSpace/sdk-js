# @pacspace-io/sdk

Official TypeScript SDK for the [PacSpace API](https://docs.pacspace.io). Zero dependencies, fully typed, built for Node.js 18+.

## Install

```bash
npm install @pacspace-io/sdk
```

## Quick Start

```typescript
import { PacSpace, fingerprint } from '@pacspace-io/sdk';

const pac = new PacSpace({ apiKey: process.env.PACSPACE_API_KEY! });

// Fingerprint a file and record an entry
const { ref, blinding } = await fingerprint(fileBytes);
const entry = await pac.records.emit({
  record: 'build-1',
  title: 'Handoff',
  occurredAt: '2026-09-14T10:02:00Z',
  actorId: 'ci',
  payloads: [ref],
});

// Read the history and check it in your process
const history = await pac.records.history({ record: 'build-1' });
const check = await pac.records.check({
  history,
  expect: [{ entry: 1, files: [{ source: fileBytes, blinding }] }],
});
```

## API Reference

### `new PacSpace(config)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | `string` | **required** | Your PacSpace API key (`pk_live_*` or `pk_test_*`) |
| `baseUrl` | `string` | `https://app.pacspace.io` | API base URL (overrides the key-based choice if provided) |
| `sandboxUrl` | `string` | `https://app.pacspace.io` | Custom sandbox URL for a private sandbox host (used for `pk_test_*` keys) |
| `productionUrl` | `string` | `https://app.pacspace.io` | Custom production URL (used for `pk_live_*` keys) |
| `chainId` | `number` | auto-detected | Default chain ID (296 for sandbox, 295 for production) |
| `maxRetries` | `number` | `2` | Max retries on transient errors |
| `timeout` | `number` | `30000` | Request timeout in ms |
| `webhookSecret` | `string` | — | Webhook signing secret (enables `pac.webhooks`) |

### Records

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

The answer's `entry` is the number this entry will have in its record, counted from 1.

`labels` puts up to 10 `name=value` pairs on the record, as an object (`{ model: 'm-0926' }`) or a string (`'model=m-0926, site=press-line-4'`, split on commas, semicolons or new lines, names lowercased). Labels go on the record, never in an entry, and are never committed. Names are lowercase letters, digits, `_`, `.` and `-`, up to 32 characters; values are letters, digits and `._:/-`, up to 64. Labels outside those limits are refused with `RECORD_LABELS_INVALID` before anything is sent. With a workspace secret set, each label is blinded under your workspace's key before it is sent: PacSpace can tell which records share a label, never what the label says.

#### `pac.records.close(record, { recordType?, lastEntry? })`

Closes a record. A close is a fact about the record, not an entry: nothing is written into the record. The close names the record's last entry, counted from 1. Left out, `lastEntry` is the last entry this process wrote to the record, or the record's own last entry, read from PacSpace. A close made while entries are still on their way is refused with `RECORD_CLOSE_SEQ_MISMATCH`; a write to a closed record is refused with `RECORD_CLOSED`. Closing again after the same entry returns `idempotent: true`. With a workspace secret set, the record is closed by its wire id; `encrypted: false` closes a plaintext record.

```typescript
await pac.records.emit({ record: 'session-12', title: 'Session 12', occurredAt, actorId: 'agent-7', payloads: [ref], labels: { model: 'm-0926' } });
const closed = await pac.records.close('session-12');
// closed.lastEntry, closed.closedAt, closed.lastSeal
```

`pac.records.receipt({ record, entry })`, `pac.records.history({ record, fromEntry?, toEntry? })`, and `check`'s `expect[].entry` count the same way. The history file itself is the wire document the check verifies by its digest, so its `receipts[].seq` and `entries[].seq` stay the wire's numbers; `check` reports each result as `entry` (`seq + 1`).

`pac.records.history({ record })` returns the record's history file and `pac.records.check({ history, expect?, source? })` runs the check in your process: every seal, the chain between entries, the file's own digest, and the current word when `source` names the public source. On an encrypted record it first opens each entry with the record's key: the workspace secret's, or the one `grant` and `owner`, `recordKey` or `holderFor` name, as `history` takes them. The verifier is bundled into the SDK (0.10.0 and later); `ethers` is its one runtime dependency. Someone who holds only that file and the fingerprint printed on a statement, with no PacSpace account and no SDK, runs the same check with the standalone checker: `npx @pacspace-io/check history.json --fingerprint 0x...` ([`@pacspace-io/check`](https://www.npmjs.com/package/@pacspace-io/check)). It reads the public source and never calls PacSpace.

#### `fingerprint(input, options?)`

fingerprint() blinds by default: it mixes a random 32-byte value into the fingerprint, so the fingerprint cannot be matched to a guessed file without the file's blinding file.

It returns { ref, blinding }. Send ref as the payload. Save blinding beside the file with writeBlindingFile(path, blinding); anyone checking the file later needs it.

To check a file later, pass it with its blinding file: in records.check, expect: [{ entry, files: [{ source, blinding }] }], or fingerprint(file, { blinding }). A blinding belongs to one file; another file is refused.

The blinding file is as private as the file: whoever holds both can confirm the file is in the record. The file's size is stored as before.

blind: false, or alg: 'sha-256', gives today's plain sha-256 fingerprint as { ref, blinding: null }. It is not blinded.

On Windows the blinding file's permissions are not restricted to you; keep it somewhere only you can read.

#### `readWorkspaceSecretFile(path)`

readWorkspaceSecretFile() reads a workspace secret file and returns its text, for `records: { secret }`. Node only.

```typescript
import { PacSpace, readWorkspaceSecretFile } from '@pacspace-io/sdk';

const pac = PacSpace.init(process.env.PACSPACE_API_KEY!, {
  records: { secret: await readWorkspaceSecretFile('./pacspace-workspace-secret-sandbox-v1.json') },
});
```

It reads the file under either name: Sandbox's `pacspace-workspace-secret-sandbox-v1.json`, or `pacspace-workspace-secret-v1.json`. A file that isn't a workspace secret is refused with RECORDS_SECRET_INVALID. workspaceSecretFileName(version, environment) gives the name the dashboard downloads it under.

#### `pac.verify(proofRoot, options?)`

Verify a proof root via the verification endpoint. No API key required. The response contains proof-only facts (validity, timestamps, and chain references); record contents are never returned here.

```typescript
const result = await pac.verify('0x7f3a9b2c1d4e5f6a...');
if (result.verified) {
  console.log(result.recordedAt);
  console.log(result.verification?.verificationExplorerUrl);
}
```

Use `options.source` to select the verification source:

```typescript
await pac.verify('0x7f3a9b2c1d4e5f6a...', { source: 'both' }); // 'db' (default), 'chain', or 'both'
```

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

  if (event.event === 'record.committed') {
    console.log('Record committed:', event.data.receiptId);
  }

  res.status(200).json({ received: true });
});

// Manual verification
const event = pac.webhooks!.verify(signature, timestamp, rawBody);
```

`record.closed` arrives when a record is closed, by your code or by PacSpace after the source's timeout: `{ recordType, entityId, closedBy, lastSeq, lastSeal, closedOn }`, where `closedBy` is `code` or `timeout` and `lastSeq` counts from 0, as the wire does.

### Error Handling

All errors extend `PacSpaceError` with structured data:

```typescript
import { PacSpace, InsufficientCreditsError, RateLimitError } from '@pacspace-io/sdk';

try {
  await pac.records.emit(input);
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
