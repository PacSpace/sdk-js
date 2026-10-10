# Changelog

## 0.3.0 - 2026-10-09

### Added

- open: opens a Shared Record link on this machine, checks it against the public source, and shows the fields it reveals. --copy saves a kept copy, --html a report page.
- --key <path> checks an encrypted record's history (record-history-bundle/v3) with its record key; a copy made with keepCopy (pacspace-record-copy/v1) is checked with the key it carries.
- release: checks the key pages a host serves against the release record on the ledger.

## 0.2.0 - 2026-10-02

### Added

- --held-file <path> checks whether a verified entry names a file you hold; for a blinded entry, add --blinding <path>. Both files are read on this machine, as bytes. The report gains an optional heldFile field. Exit codes keep their meanings.
- Reads a record's seal history (record-seal-history/v1), a kept copy (record-link-copy/v1), a disclosure (record-disclosure/v1) and v2 history files: every seal, their order, that all of them are here, each revealed field against its seal, and the current seal against the public source.

## 0.1.1 - 2026-09-22

### Changed

- The counted sentence says what the check confirms and no more. "This record has 3 entries. All 3 are here, and all 3 match what was committed." replaces "All 3 match what was committed. Nothing is missing." (one entry: "It is here, and it matches what was committed."). The check confirms that every entry the record says it has is present and matches; it cannot confirm that nothing which should have been recorded is absent, and the old sentence read as that claim. The `--json` report's `sentences` change with it; the counts and the exit codes do not.

## 0.1.0 - 2026-09-18

### Added

- `pacspace-check <history.json>`: checks a PacSpace record history file on its own (fingerprint, layout against the published documents, every entry, completeness, the daily statement it carries) and against the public source (the record's current state and the batches its entries were committed in). `--fingerprint` compares the fingerprint printed on a statement with the file. `--offline` checks the file alone. `--full` reads every daily statement the public source carries so a daily statement that later statements have moved past can still be compared. `--json` prints the `pacspace-check-report/v1` document. Exit codes `0`, `1`, `2`, `3`.
- Library entry: `parseHistoryFile`, `checkHistory`, `renderReport`, and the report's sentence builders.
- The checker is the shared verifier the PacSpace Shared Record runs in the browser, bundled with `ethers` as its only dependency. It is the checker a printed statement names (records buyer posture plan, DfD-39 (A)).
