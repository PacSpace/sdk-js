# @pacspace-io/check

Checks a PacSpace record history file against the public source. It runs
without PacSpace: the file and the public source are enough.

A printed statement from a PacSpace Shared Record names this checker. With
the history file the statement's reader downloaded and the fingerprint
printed on the statement, the check the statement describes can be run
again at any time, by anyone, without the link and without asking PacSpace
or the recording side.

## Run it

```
npx @pacspace-io/check history.json
```

With the fingerprint printed on the statement, so the checker also says
whether that statement was printed over this exact file:

```
npx @pacspace-io/check history.json --fingerprint 0x7079b0ac...
```

The output is a few labeled facts and then plain sentences:

```
Reference                    0x7777...7777
Fingerprint of this history  0x7079...820d
Exported                     2026-09-12T01:00:00.000Z (UTC)
Public source                <the public source the record names>

This record has 3 entries. All 3 are here, and all 3 match what was committed.
Compared with the public source for this record: it matches.
Daily statement of 12 September 2026 (UTC): matches.
The fingerprint you gave names this file.
The check shows the record is unchanged since it was committed. It does not show that what was recorded was true.
```

## What it checks

1. The file against its own fingerprint. A history file carries the
   fingerprint of its contents; a file that was changed after it was
   exported no longer produces it, and the checker says so and stops.
2. Every entry against what was committed. Each entry carries the material
   that lets the checker recompute what was committed for it and compare.
3. Completeness. The record's own count says how many entries it has; the
   checker names any entry the file does not carry.
4. The record against the public source. Unless `--offline`, the checker
   reads the record's current state and the batches its entries were
   committed in from the public source and compares the file with them.
5. The daily statement. A history file carries the daily statement that
   covered it at export. When that statement is still the current one the
   file alone proves it; otherwise `--full` reads every daily statement the
   public source carries and compares.

The last sentence is always the same, because it is the boundary of the
check: the check shows the record is unchanged since it was committed; it
does not show that what was recorded was true.

A seal history, saved from a Shared Record link, and a kept copy from its Keep a copy, are checked the same way. The check confirms the seals, their order and that all of them are here, and each revealed field against its entry's seal; --held-file checks a file against the fingerprints among the revealed fields.

--held-file checks whether a verified entry names a file you hold. For a blinded entry, add --blinding with the file's blinding file. Both files are read on this machine, as bytes.

## Open a link

npx @pacspace-io/check open asks for a Shared Record link, reads the record from the link's host, checks it against the public source and shows the fields the link reveals. If the link has an access code, it asks for that too. --copy saves a kept copy and --html saves the report as a page.

An encrypted record's history is checked with its record key: npx @pacspace-io/check history.json --key record-key.txt. A copy made with keepCopy carries its key and is checked like any history file.

npx @pacspace-io/check release checks the key pages a host serves against the release record on the ledger.

release reads each file three ways, as the host sends it, and checks each answer and its headers against the production release record pinned in the checker. It proves what the host served to this run, not what it serves anyone else.

--release-record <key>,<chain>,<contract> checks a staging release record instead. Such a run never passes.

## Options

```
--fingerprint <0x...>  the fingerprint printed on a statement
--held-file <path>     check whether a verified entry names a file you hold
--blinding <path>      the blinding file for the file you hold, when its entry is blinded
--history <path>       the seal history or kept copy a disclosure is checked against
--key <path>           the record key for an encrypted history, read from this file (- for stdin)
--link-file <path>     open: read the link from this file instead of asking
--access-code-file <path>  open: read the access code from this file instead of asking
--copy <path>          open: save a kept copy of what the link shows to a new file
--html <path>          open: save the report as a page that opens without a network connection
--release-record <key>,<chain>,<contract>  release: checks a staging release record; such a run never passes
--offline              check the file alone; do not read the public source
--source <url>         read the public source from this mirror
--rpc <url>            read the public source over JSON-RPC at this URL
--full                 also read the complete chain of daily statements
--timeout <ms>         network timeout per read (default 10000)
--json                 print the report as JSON
```

Exit codes: 0 the check passed as asked; 1 it did not, or the file you hold is not in it; 2 the history file, the link, a key, the file you hold, its blinding file or the arguments could not be used; 3 the public source or the link's host could not be reached. When more than one applies, 2 comes before 3, and 3 before 1.

## From code

```ts
import { readFile } from 'node:fs/promises';
import { checkHistory, parseHistoryFile, renderReport } from '@pacspace-io/check';

const bundle = parseHistoryFile(await readFile('history.json', 'utf8'));
const report = await checkHistory(bundle, { statementFingerprint: '0x7079b0ac...' });
console.log(renderReport(report));
if (report.exitCode !== 0) process.exitCode = report.exitCode;
```

`report` is a `pacspace-check-report/v1` document: the record's count and
the entries that matched, were missing, or did not match; whether the file
is intact; what the public source said; the daily statement's outcome; the
fingerprint comparison; and the sentences printed above.

## What it needs

Node.js 18 or later and the network, for the public source. open reads the record from the link's host, and release reads the key pages from the host it checks. Checking a file sends nothing to PacSpace. The public source for a record is named inside the history
file; `--source` and `--rpc` point the checker at a mirror or endpoint of
your own.

## License

MIT
