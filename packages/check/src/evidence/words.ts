/**
 * The sentences `pacspace-check evidence` and `pacspace-check sample` print, one per check, in the product's words:
 * "matches its seal" and "committed", never "verified". Each is new with R7 and listed for David's approval in the
 * slice's report; their verbs are the Shared Record page's ("Matches its seal", "Does not match its seal",
 * "committed", "Checked").
 */
const entriesWord = (n: number) => (n === 1 ? 'entry' : 'entries');
const list = (items: ReadonlyArray<string | number>) =>
  items.length === 1 ? String(items[0]) : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;

export const EVIDENCE_WORDS = {
  notEvidence: 'This is not an evidence record this version reads.',
  tooLarge: 'This file is too large to be an evidence record.',
  edition: (edition: string) => (edition === 'full' ? 'The full evidence record.' : 'The evidence record for reviewers. Checks that need a revealed field are not in it.'),
  notSigned: 'The file is not signed by a device on the link.',
  signed: (code: string) => `Signed by device ${code}, a confirmed device on this link. Both signatures match the file.`,
  signatureDiffers: 'The file was changed after it was signed, or one of its two signatures does not match.',
  signerNotOnLink: (code: string) => `Signed by device ${code}, which is not a confirmed device on this link.`,
  numbered: (n: number) => (n === 1 ? 'Record 1 is here.' : `Records 1 to ${n} are all here, none missing.`),
  numberMissing: (missing: number[]) => `Record ${list(missing)} ${missing.length === 1 ? 'is' : 'are'} missing from the file.`,
  recordMatches: (record: number, entries: number) => `Record ${record}: ${entries === 1 ? 'its entry matches its seal' : `all ${entries} entries match their seals`}, and the record is as committed.`,
  recordDiffers: (record: number) => `Record ${record}: its seals do not match what was committed.`,
  recordOffline: (record: number) => `Record ${record}: its seals are in order. Not compared with the proof layer (--offline).`,
  closeMatches: (records: number) => `Each record's close matches its last entry's seal (${records} ${records === 1 ? 'record' : 'records'}).`,
  closeDiffers: (record: number) => `Record ${record}: its close does not match its last entry's seal.`,
  revealedMatch: (record: number, entries: number) => `Record ${record}: the ${entriesWord(entries)} revealed on the link ${entries === 1 ? 'matches its seal' : 'match their seals'}.`,
  revealedDiffer: (record: number) => `Record ${record}: a revealed field does not match its seal.`,
  answerMatches: (request: string, entries: number) => `${request}: the ${entries === 1 ? 'entry shown matches its seal' : `${entries} entries shown match their seals`}.`,
  answerDiffers: (request: string) => `${request}: an entry shown does not match its seal.`,
  answerSeals: (n: number) => (n === 1 ? 'The entry answered carries its committed seal.' : `The ${n} entries answered carry their committed seals.`),
  answerSealsDiffer: (request: string) => `${request}: an entry answered does not carry its committed seal.`,
  notCheckedOffline: 'Revealed and answered fields are checked against the proof layer, so they were not checked (--offline).',
  ackSigned: (ref: string) => `${ref}: signed by a confirmed device on this link. Both signatures match.`,
  ackDiffers: (ref: string) => `${ref}: one of its two signatures does not match, or it names another link.`,
  ackNamesOther: (ref: string) => `${ref}: it names records or disclosures other than the ones in this file.`,
  ackNotHeld: (refs: string[]) => `${list(refs)}: sent from another device of the team, so ${refs.length === 1 ? 'its signatures are' : 'their signatures are'} not in this file.`,
  indexMatches: (records: number) => `The index record commits each record's join and close: all ${records} match.`,
  indexDiffers: (record: number) => `Record ${record}: its join or close is not what the index record committed.`,
  indexNotHeld: "The index record's seals are not in this file, so each join was checked against the record's own seals only.",
  readerMatches: (acks: number) => `The link's own record commits ${acks === 1 ? 'the acknowledgment' : `each of the ${acks} acknowledgments`} in this file.`,
  readerDiffers: (ref: string) => `${ref}: not what the link's own record committed.`,
  readerNotHeld: "The link's own record is not in this file, so its entries were not checked against it.",
  systemOffline: "The index record and the link's own record are checked against the proof layer, so they were not checked (--offline).",
  systemDiffers: (which: 'index' | 'reader') => `${which === 'index' ? "The index record's" : "The link's own record's"} seals do not match what was committed.`,
  unreachable: 'The proof layer could not be reached. Check again to try once more.',
  boundary: 'The check shows what was committed and that it is unchanged. It does not show that what was recorded was true.',
} as const;

export const SAMPLE_WORDS = {
  none: 'No request in this file was drawn at random.',
  matches: (request: string, n: number) => `${request}: the ${n === 1 ? 'entry drawn at random follows' : `${n} entries drawn at random follow`} from the sample's seed.`,
  differs: (request: string) => `${request}: the picks do not follow from the sample's seed.`,
  poolDiffers: (request: string) => `${request}: the sample's pool is not the one its request committed.`,
} as const;
