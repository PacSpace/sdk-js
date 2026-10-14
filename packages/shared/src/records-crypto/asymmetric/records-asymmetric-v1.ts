import { MLDSA65_PUBLIC_KEY_BYTES, MLDSA65_SIGNATURE_BYTES } from '../../records/signed-acknowledgment-v2';
import { toBase64Url } from '../base64url';
import { concatBytes, platformCrypto, randomBytes, sha256, utf8 } from '../platform-crypto';
import {
  RecordKeyV1,
  RecordsEncryptionError,
  RecordsKeyV1,
  RecordsKeyringV1,
  RecordsWrapKeyV1,
  exportKeyBytesV1,
  recordKeyFromBytesV1,
  recordsKeyFromBytesV1,
  type RecordsRefusalV1,
} from '../records-encryption-v1';
import {
  KEY_WRAP_CT_BYTES_V1,
  KEY_WRAP_ENC_BYTES_V1,
  KEY_WRAP_SUITE_V1,
  PUBLIC_KEY_ID_LABEL_V1,
  SEED_WRAP_CT_BYTES_V1,
  WORKSPACE_PUBLIC_KEY_BYTES_V1,
  readKeyWrapShapeV1,
  readSeedWrapShapeV1,
  workspacePublicKeyIdV1,
} from '../wrap-shapes-v1';

export {
  KEY_WRAP_CT_BYTES_V1,
  KEY_WRAP_ENC_BYTES_V1,
  KEY_WRAP_SUITE_V1,
  SEED_WRAP_CT_BYTES_V1,
  WORKSPACE_PUBLIC_KEY_BYTES_V1,
  readKeyWrapShapeV1,
  readSeedWrapShapeV1,
};

/**
 * Level 2's asymmetric layer (ADR 0015 sections 4, 5 and 11; formats note N3,
 * N9 and N12): the workspace keypair from a 32-byte seed our code draws, the
 * seed's wrap under `W_v`, the public key id and the holder key code, wraps
 * to a holder under the suite `hpke-1`, and ML-DSA-65 signing.
 *
 * This file is reached only through the `records-crypto/asymmetric` subpath,
 * which shared's index does not re-export, and it loads `hpke`,
 * `@panva/hpke-noble` and `@noble/post-quantum` by dynamic import on first
 * use, so the API, worker and indexer load none of them.
 *
 * No seed or private key is ever printed: those types keep their bytes in a
 * module WeakMap. Refusals carry a code and no sentence; nothing here logs.
 */
export const RECORDS_ASYMMETRIC_LABELS_V1 = {
  publicKeyId: PUBLIC_KEY_ID_LABEL_V1,
  holderKeyCode: 'pacspace:holder-key-code:v1',
  seedWrap: 'pacspace:seed-wrap:v1',
  wrap: 'pacspace:wrap:v1',
} as const;

/** The one wrap suite: HPKE base mode, MLKEM768-X25519 as draft-ietf-hpke-pq-05 fixes it, HKDF-SHA256, AES-256-GCM. */
export const KEY_WRAP_SUITES_V1 = {
  'hpke-1': { kem: 0x647a, kdf: 0x0001, aead: 0x0002, draft: 'draft-ietf-hpke-pq-05' },
} as const;
export const WORKSPACE_SEED_BYTES_V1 = 32;
export const MLDSA65_SEED_BYTES_V1 = 32;
export const HOLDER_KEY_CODE_DIGITS_V1 = 40;

export type KeyWrapPurposeV1 = 'records-key' | 'record-key' | 'disclosure-key';

export type RecordsAsymmetricCodeV1 =
  | 'WORKSPACE_SEED_INVALID'
  | 'WORKSPACE_PUBLIC_KEY_INVALID'
  | 'SEED_WRAP_MALFORMED'
  | 'SEED_WRAP_WRONG_KEY'
  | 'SEED_WRAP_AUTH_FAILED'
  | 'KEY_WRAP_MALFORMED'
  | 'KEY_WRAP_SUITE'
  | 'KEY_WRAP_WRONG_HOLDER'
  | 'KEY_WRAP_AUTH_FAILED'
  | 'KEY_WRAP_KEY_MISMATCH'
  | 'KEY_WRAP_BINDING_INVALID'
  | 'MLDSA_KEY_INVALID';

/** Thrown by the writing side only; its message is the code. */
export class RecordsAsymmetricError extends Error {
  constructor(readonly code: RecordsAsymmetricCodeV1) {
    super(code);
    this.name = 'RecordsAsymmetricError';
  }
}

const refuse = <C extends string>(code: C): RecordsRefusalV1<C> => ({ ok: false, code });

const SEP = new Uint8Array([0]);
const HEX64 = /^[0-9a-f]{64}$/;
const WIRE_ID = /^[A-Za-z0-9_-]{22}$/;
const IV_BYTES = 12;
const INSPECT = Symbol.for('nodejs.util.inspect.custom');
const L = RECORDS_ASYMMETRIC_LABELS_V1;
const SUITE = KEY_WRAP_SUITES_V1[KEY_WRAP_SUITE_V1];

const unhex = (text: string) => Uint8Array.from(text.match(/../g) ?? [], (h) => parseInt(h, 16));

// ------------------------------------------------------------------ the pinned libraries, loaded on first use

type Libraries = {
  hpke: typeof import('hpke');
  noble: typeof import('@panva/hpke-noble');
  hybrid: typeof import('@noble/post-quantum/hybrid.js');
  mldsa: typeof import('@noble/post-quantum/ml-dsa.js');
};

let libraries: Promise<Libraries> | null = null;

function load(): Promise<Libraries> {
  libraries ??= Promise.all([
    import('hpke'),
    import('@panva/hpke-noble'),
    import('@noble/post-quantum/hybrid.js'),
    import('@noble/post-quantum/ml-dsa.js'),
  ]).then(([hpke, noble, hybrid, mldsa]) => ({ hpke, noble, hybrid, mldsa }));
  return libraries;
}

/** @internal The pinned libraries, for the draft's vectors; untyped so no declaration names them. */
export function loadRecordsAsymmetricLibrariesV1(): Promise<unknown> {
  return load();
}

/** @internal The wrap suite's KDF and AEAD factories: hpke's, which run on the platform's WebCrypto. */
export async function keyWrapSuiteFactoriesV1(): Promise<unknown> {
  const { hpke } = await load();
  return { kdf: hpke.KDF_HKDF_SHA256, aead: hpke.AEAD_AES_256_GCM };
}

async function wrapSuite(ikmE?: Uint8Array) {
  const { hpke, noble, hybrid } = await load();
  const kem = ikmE
    ? () => {
        const base = noble.KEM_MLKEM768_X25519();
        return {
          ...base,
          DeriveKeyPair: base.DeriveKeyPair.bind(base),
          GenerateKeyPair: base.GenerateKeyPair.bind(base),
          SerializePublicKey: base.SerializePublicKey.bind(base),
          DeserializePublicKey: base.DeserializePublicKey.bind(base),
          SerializePrivateKey: base.SerializePrivateKey.bind(base),
          DeserializePrivateKey: base.DeserializePrivateKey.bind(base),
          Decap: base.Decap.bind(base),
          async Encap(pkR: Parameters<typeof base.Encap>[0]) {
            const { cipherText, sharedSecret } = hybrid.ml_kem768_x25519.encapsulate(await base.SerializePublicKey(pkR), ikmE);
            return { shared_secret: sharedSecret, enc: cipherText };
          },
        };
      }
    : noble.KEM_MLKEM768_X25519;
  const suite = new hpke.CipherSuite(kem, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_256_GCM);
  if (suite.KEM.id !== SUITE.kem || suite.KDF.id !== SUITE.kdf || suite.AEAD.id !== SUITE.aead) {
    throw new RecordsAsymmetricError('KEY_WRAP_SUITE');
  }
  return suite;
}

// ------------------------------------------------------------------ hidden key types

const HELD = new WeakMap<object, Uint8Array>();

abstract class HiddenKey {
  protected constructor(bytes: Uint8Array) {
    HELD.set(this, Uint8Array.from(bytes));
  }
  protected abstract describe(): string;
  toString(): string {
    return this.describe();
  }
  toJSON(): string {
    return this.describe();
  }
  [INSPECT](): string {
    return this.describe();
  }
}

function heldBytes(key: HiddenKey, code: RecordsAsymmetricCodeV1): Uint8Array {
  const bytes = HELD.get(key);
  if (!bytes) throw new RecordsAsymmetricError(code);
  return bytes;
}

/** The workspace's private seed, with the X-Wing public key it makes. */
export class WorkspaceSeedV1 extends HiddenKey {
  readonly #publicKey: Uint8Array;
  /** @internal */
  constructor(seed: Uint8Array, publicKey: Uint8Array, readonly publicKeyId: string) {
    super(seed);
    this.#publicKey = Uint8Array.from(publicKey);
  }
  /** The encoded public key (1,216 bytes): the ML-KEM-768 key, then the X25519 key. */
  get publicKey(): Uint8Array {
    return Uint8Array.from(this.#publicKey);
  }
  protected describe(): string {
    return `[workspace seed ${this.publicKeyId.slice(0, 8)}]`;
  }
}

/** An ML-DSA-65 signing key, made from a 32-byte seed. */
export class MldsaSigningKeyV1 extends HiddenKey {
  readonly #publicKey: Uint8Array;
  /** @internal */
  constructor(seed: Uint8Array, publicKey: Uint8Array) {
    super(seed);
    this.#publicKey = Uint8Array.from(publicKey);
  }
  get publicKey(): Uint8Array {
    return Uint8Array.from(this.#publicKey);
  }
  protected describe(): string {
    return '[ML-DSA-65 signing key]';
  }
}

/**
 * The seed's 32 bytes, for the two places they may leave the key layer: the
 * seed wrap and the published vectors.
 */
export function exportWorkspaceSeedBytesV1(seed: WorkspaceSeedV1): Uint8Array {
  return Uint8Array.from(heldBytes(seed, 'WORKSPACE_SEED_INVALID'));
}

// ------------------------------------------------------------------ the workspace keypair, its id and code (N3, section 7)

function assertPublicKey(publicKey: Uint8Array): void {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== WORKSPACE_PUBLIC_KEY_BYTES_V1) {
    throw new RecordsAsymmetricError('WORKSPACE_PUBLIC_KEY_INVALID');
  }
}

/** `SHA-256("pacspace:public-key-id:v1" || 0x00 || encoded public key)`, 64 lowercase hex. */
export async function publicKeyIdV1(publicKey: Uint8Array): Promise<string> {
  assertPublicKey(publicKey);
  return (await workspacePublicKeyIdV1(publicKey))!;
}

/**
 * The holder key code: the first 17 bytes of `SHA-256("pacspace:holder-key-code:v1"
 * || 0x00 || encoded public key)` as an unsigned big-endian integer, modulo
 * 10^40, 40 digits with leading zeros in eight groups of five.
 */
export async function holderKeyCodeV1(publicKey: Uint8Array): Promise<string> {
  assertPublicKey(publicKey);
  const digest = await sha256(concatBytes(utf8(L.holderKeyCode), SEP, publicKey));
  let n = 0n;
  for (const byte of digest.subarray(0, 17)) n = (n << 8n) | BigInt(byte);
  const digits = (n % 10n ** 40n).toString().padStart(HOLDER_KEY_CODE_DIGITS_V1, '0');
  return digits.match(/.{5}/g)!.join(' ');
}

/** The keypair the 32-byte seed makes, as draft-ietf-hpke-pq-05's MLKEM768-X25519 derives it. */
export async function workspaceSeedFromBytesV1(seed: Uint8Array): Promise<WorkspaceSeedV1> {
  if (!(seed instanceof Uint8Array) || seed.length !== WORKSPACE_SEED_BYTES_V1) throw new RecordsAsymmetricError('WORKSPACE_SEED_INVALID');
  const { hybrid } = await load();
  const { publicKey } = hybrid.ml_kem768_x25519.keygen(Uint8Array.from(seed));
  return new WorkspaceSeedV1(seed, publicKey, await publicKeyIdV1(publicKey));
}

/** A new workspace keypair from 32 random bytes this code draws (not the library's key generation). */
export async function generateWorkspaceSeedV1(): Promise<WorkspaceSeedV1> {
  return workspaceSeedFromBytesV1(randomBytes(WORKSPACE_SEED_BYTES_V1));
}

// ------------------------------------------------------------------ the seed wrap under W_v (N9)

export interface SeedWrapV1 {
  v: 1;
  alg: 'A256GCM';
  kid: string;
  iv: string;
  ct: string;
}

const seedWrapAad = (publicKeyId: string) => concatBytes(utf8(L.seedWrap), SEP, unhex(publicKeyId)) as BufferSource;

async function aesKey(key: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  const { subtle } = await platformCrypto();
  return subtle.importKey('raw', Uint8Array.from(key), { name: 'AES-GCM' }, false, [usage]);
}

/** @internal Seals the seed under a given IV; vectors and the seal below only. */
export async function sealSeedWrapWithIvV1(wrapKey: RecordsWrapKeyV1, seed: WorkspaceSeedV1, iv: Uint8Array): Promise<SeedWrapV1> {
  if (!(wrapKey instanceof RecordsWrapKeyV1) || !(seed instanceof WorkspaceSeedV1) || !(iv instanceof Uint8Array) || iv.length !== IV_BYTES) {
    throw new RecordsAsymmetricError('WORKSPACE_SEED_INVALID');
  }
  const { subtle } = await platformCrypto();
  const ct = new Uint8Array(
    await subtle.encrypt(
      { name: 'AES-GCM', iv: Uint8Array.from(iv), additionalData: seedWrapAad(seed.publicKeyId), tagLength: 128 },
      await aesKey(exportKeyBytesV1(wrapKey), 'encrypt'),
      Uint8Array.from(heldBytes(seed, 'WORKSPACE_SEED_INVALID')),
    ),
  );
  return { v: 1, alg: 'A256GCM', kid: wrapKey.id, iv: toBase64Url(iv), ct: toBase64Url(ct) };
}

/** The seed, sealed for storage at PacSpace under `W_v` with a fresh IV. */
export async function sealSeedWrapV1(wrapKey: RecordsWrapKeyV1, seed: WorkspaceSeedV1): Promise<SeedWrapV1> {
  return sealSeedWrapWithIvV1(wrapKey, seed, randomBytes(IV_BYTES));
}

/**
 * Opens a seed wrap with `W_v`, or with a keyring (whose `W_v` named by
 * `kid` opens it), for the public key id it was stored under. Never throws.
 */
export async function openSeedWrapV1(input: {
  wrap: unknown;
  publicKeyId: string;
  wrapKey?: RecordsWrapKeyV1;
  keyring?: RecordsKeyringV1;
}): Promise<{ ok: true; seed: WorkspaceSeedV1 } | RecordsRefusalV1<'SEED_WRAP_MALFORMED' | 'SEED_WRAP_WRONG_KEY' | 'SEED_WRAP_AUTH_FAILED'>> {
  try {
    const shape = readSeedWrapShapeV1(input?.wrap);
    if (!shape.ok) return shape;
    if (typeof input.publicKeyId !== 'string' || !HEX64.test(input.publicKeyId)) return refuse('SEED_WRAP_MALFORMED');
    let key = input.wrapKey;
    if (input.keyring) key = input.keyring.versions.map((v) => input.keyring!.wrapKey(v)).find((k) => k?.id === shape.kid) ?? undefined;
    if (!(key instanceof RecordsWrapKeyV1) || key.id !== shape.kid) return refuse('SEED_WRAP_WRONG_KEY');
    let seed: Uint8Array;
    try {
      const { subtle } = await platformCrypto();
      seed = new Uint8Array(
        await subtle.decrypt(
          { name: 'AES-GCM', iv: Uint8Array.from(shape.iv), additionalData: seedWrapAad(input.publicKeyId), tagLength: 128 },
          await aesKey(exportKeyBytesV1(key), 'decrypt'),
          Uint8Array.from(shape.ct),
        ),
      );
    } catch {
      return refuse('SEED_WRAP_AUTH_FAILED');
    }
    const made = await workspaceSeedFromBytesV1(seed);
    if (made.publicKeyId !== input.publicKeyId) return refuse('SEED_WRAP_AUTH_FAILED');
    return { ok: true, seed: made };
  } catch {
    return refuse('SEED_WRAP_AUTH_FAILED');
  }
}

// ------------------------------------------------------------------ wraps to a holder (N9)

export interface KeyWrapV1 {
  v: 1;
  suite: typeof KEY_WRAP_SUITE_V1;
  to: string;
  enc: string;
  ct: string;
}

/** The binding each purpose hashes into `info`. */
export type KeyWrapBindingV1 =
  | { purpose: 'records-key'; recordsKeyId: string }
  | { purpose: 'record-key'; recordType: string; wireRecordId: string }
  | { purpose: 'disclosure-key'; handle: string };

const PRINTABLE_ASCII = /^[\x21-\x7e]+$/;

function bindingBytes(binding: KeyWrapBindingV1): Uint8Array {
  switch (binding?.purpose) {
    case 'records-key':
      if (typeof binding.recordsKeyId === 'string' && HEX64.test(binding.recordsKeyId)) return unhex(binding.recordsKeyId);
      break;
    case 'record-key':
      if (typeof binding.recordType === 'string' && PRINTABLE_ASCII.test(binding.recordType) && typeof binding.wireRecordId === 'string' && WIRE_ID.test(binding.wireRecordId)) {
        return concatBytes(utf8(binding.recordType), SEP, utf8(binding.wireRecordId));
      }
      break;
    case 'disclosure-key':
      if (typeof binding.handle === 'string' && PRINTABLE_ASCII.test(binding.handle)) return utf8(binding.handle);
      break;
  }
  throw new RecordsAsymmetricError('KEY_WRAP_BINDING_INVALID');
}

/** `"pacspace:wrap:v1" || 0x00 || purpose || 0x00 || SHA-256(binding)`, at most 64 bytes. */
export async function keyWrapInfoV1(binding: KeyWrapBindingV1): Promise<Uint8Array> {
  const bytes = bindingBytes(binding);
  return concatBytes(utf8(L.wrap), SEP, utf8(binding.purpose), SEP, await sha256(bytes));
}

/** @internal Seals 32 key bytes to a public key; `ikmE` fixes the encapsulation for vectors only. */
export async function sealKeyWrapV1(input: {
  publicKey: Uint8Array;
  binding: KeyWrapBindingV1;
  keyBytes: Uint8Array;
  ikmE?: Uint8Array;
}): Promise<KeyWrapV1> {
  assertPublicKey(input.publicKey);
  if (!(input.keyBytes instanceof Uint8Array) || input.keyBytes.length !== 32) throw new RecordsAsymmetricError('KEY_WRAP_BINDING_INVALID');
  const info = await keyWrapInfoV1(input.binding);
  const suite = await wrapSuite(input.ikmE);
  const pk = await suite.DeserializePublicKey(Uint8Array.from(input.publicKey));
  const { encapsulatedSecret, ciphertext } = await suite.Seal(pk, Uint8Array.from(input.keyBytes), { info });
  return { v: 1, suite: KEY_WRAP_SUITE_V1, to: await publicKeyIdV1(input.publicKey), enc: toBase64Url(encapsulatedSecret), ct: toBase64Url(ciphertext) };
}

/** `K_v`, wrapped to a workspace-scope holder's confirmed public key. */
export async function wrapRecordsKeyV1(publicKey: Uint8Array, recordsKey: RecordsKeyV1): Promise<KeyWrapV1> {
  if (!(recordsKey instanceof RecordsKeyV1)) throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
  return sealKeyWrapV1({ publicKey, binding: { purpose: 'records-key', recordsKeyId: recordsKey.id }, keyBytes: exportKeyBytesV1(recordsKey) });
}

/** One record's `RK`, wrapped to a record-scope holder or a counterparty. */
export async function wrapRecordKeyV1(
  publicKey: Uint8Array,
  recordKey: RecordKeyV1,
  record: { recordType: string; wireRecordId: string },
): Promise<KeyWrapV1> {
  if (!(recordKey instanceof RecordKeyV1)) throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
  return sealKeyWrapV1({
    publicKey,
    binding: { purpose: 'record-key', recordType: record?.recordType, wireRecordId: record?.wireRecordId },
    keyBytes: exportKeyBytesV1(recordKey),
  });
}

/** A disclosure key, wrapped to a reader's confirmed public key. */
export async function wrapDisclosureKeyV1(publicKey: Uint8Array, disclosureKey: Uint8Array, handle: string): Promise<KeyWrapV1> {
  return sealKeyWrapV1({ publicKey, binding: { purpose: 'disclosure-key', handle }, keyBytes: disclosureKey });
}

type UnwrapRefusal = RecordsRefusalV1<'KEY_WRAP_MALFORMED' | 'KEY_WRAP_SUITE' | 'KEY_WRAP_WRONG_HOLDER' | 'KEY_WRAP_AUTH_FAILED' | 'KEY_WRAP_BINDING_INVALID'>;

async function openKeyWrap(seed: WorkspaceSeedV1, wrap: unknown, binding: KeyWrapBindingV1): Promise<{ ok: true; keyBytes: Uint8Array } | UnwrapRefusal> {
  const shape = readKeyWrapShapeV1(wrap);
  if (!shape.ok) return shape;
  if (!(seed instanceof WorkspaceSeedV1)) return refuse('KEY_WRAP_WRONG_HOLDER');
  if (shape.to !== seed.publicKeyId) return refuse('KEY_WRAP_WRONG_HOLDER');
  let info: Uint8Array;
  try {
    info = await keyWrapInfoV1(binding);
  } catch {
    return refuse('KEY_WRAP_BINDING_INVALID');
  }
  try {
    const suite = await wrapSuite();
    const privateKey = await suite.DeserializePrivateKey(Uint8Array.from(heldBytes(seed, 'WORKSPACE_SEED_INVALID')), false);
    const publicKey = await suite.DeserializePublicKey(seed.publicKey);
    const keyBytes = await suite.Open({ privateKey, publicKey }, shape.enc, shape.ct, { info });
    if (keyBytes.length !== 32) return refuse('KEY_WRAP_AUTH_FAILED');
    return { ok: true, keyBytes };
  } catch {
    return refuse('KEY_WRAP_AUTH_FAILED');
  }
}

/**
 * `K_v` from a wrap. The expected id comes from the wrap's stored key
 * version; it is recomputed from the unwrapped bytes before use. Never throws.
 */
export async function unwrapRecordsKeyV1(input: {
  seed: WorkspaceSeedV1;
  wrap: unknown;
  version: number;
  recordsKeyId: string;
}): Promise<{ ok: true; recordsKey: RecordsKeyV1 } | UnwrapRefusal | RecordsRefusalV1<'KEY_WRAP_KEY_MISMATCH'>> {
  try {
    if (!Number.isSafeInteger(input?.version) || input.version < 1) return refuse('KEY_WRAP_BINDING_INVALID');
    const opened = await openKeyWrap(input.seed, input.wrap, { purpose: 'records-key', recordsKeyId: input.recordsKeyId });
    if (!opened.ok) return opened;
    const recordsKey = await recordsKeyFromBytesV1(opened.keyBytes, input.version);
    if (recordsKey.id !== input.recordsKeyId) return refuse('KEY_WRAP_KEY_MISMATCH');
    return { ok: true, recordsKey };
  } catch {
    return refuse('KEY_WRAP_AUTH_FAILED');
  }
}

/** One record's `RK` from a wrap. Never throws. */
export async function unwrapRecordKeyV1(input: {
  seed: WorkspaceSeedV1;
  wrap: unknown;
  recordType: string;
  wireRecordId: string;
}): Promise<{ ok: true; recordKey: RecordKeyV1 } | UnwrapRefusal> {
  try {
    const opened = await openKeyWrap(input.seed, input.wrap, { purpose: 'record-key', recordType: input?.recordType, wireRecordId: input?.wireRecordId });
    if (!opened.ok) return opened;
    return { ok: true, recordKey: await recordKeyFromBytesV1(opened.keyBytes) };
  } catch {
    return refuse('KEY_WRAP_AUTH_FAILED');
  }
}

/** A disclosure key from a wrap. Never throws. */
export async function unwrapDisclosureKeyV1(input: {
  seed: WorkspaceSeedV1;
  wrap: unknown;
  handle: string;
}): Promise<{ ok: true; disclosureKey: Uint8Array } | UnwrapRefusal> {
  try {
    const opened = await openKeyWrap(input.seed, input.wrap, { purpose: 'disclosure-key', handle: input?.handle });
    if (!opened.ok) return opened;
    return { ok: true, disclosureKey: opened.keyBytes };
  } catch {
    return refuse('KEY_WRAP_AUTH_FAILED');
  }
}

// ------------------------------------------------------------------ ML-DSA-65 (question C)

/** The signing key a 32-byte seed makes (FIPS 204 ML-DSA.KeyGen_internal). */
export async function mldsaSigningKeyFromSeedV1(seed: Uint8Array): Promise<MldsaSigningKeyV1> {
  if (!(seed instanceof Uint8Array) || seed.length !== MLDSA65_SEED_BYTES_V1) throw new RecordsAsymmetricError('MLDSA_KEY_INVALID');
  const { mldsa } = await load();
  const { publicKey } = mldsa.ml_dsa65.keygen(Uint8Array.from(seed));
  return new MldsaSigningKeyV1(seed, publicKey);
}

/** A new signing key from 32 random bytes this code draws. */
export async function generateMldsaSigningKeyV1(): Promise<MldsaSigningKeyV1> {
  return mldsaSigningKeyFromSeedV1(randomBytes(MLDSA65_SEED_BYTES_V1));
}

/** The seed's 32 bytes, for storage on the key-page origin and the published vectors. */
export function exportMldsaSeedBytesV1(key: MldsaSigningKeyV1): Uint8Array {
  return Uint8Array.from(heldBytes(key, 'MLDSA_KEY_INVALID'));
}

/** @internal `deterministic` signs with no added randomness; vectors only. */
export async function signMldsa65WithV1(key: MldsaSigningKeyV1, message: Uint8Array, deterministic: boolean): Promise<Uint8Array> {
  if (!(key instanceof MldsaSigningKeyV1) || !(message instanceof Uint8Array)) throw new RecordsAsymmetricError('MLDSA_KEY_INVALID');
  const { mldsa } = await load();
  const { secretKey } = mldsa.ml_dsa65.keygen(Uint8Array.from(heldBytes(key, 'MLDSA_KEY_INVALID')));
  try {
    return mldsa.ml_dsa65.sign(Uint8Array.from(message), secretKey, deterministic ? { extraEntropy: false } : {});
  } finally {
    secretKey.fill(0);
  }
}

/** ML-DSA-65 over the message, hedged (FIPS 204's default), empty context. */
export async function signMldsa65V1(key: MldsaSigningKeyV1, message: Uint8Array): Promise<Uint8Array> {
  return signMldsa65WithV1(key, message, false);
}

/** Sizes first, then the signature. Never throws. */
export async function verifyMldsa65V1(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== MLDSA65_PUBLIC_KEY_BYTES) return false;
    if (!(signature instanceof Uint8Array) || signature.length !== MLDSA65_SIGNATURE_BYTES || !(message instanceof Uint8Array)) return false;
    const { mldsa } = await load();
    return mldsa.ml_dsa65.verify(Uint8Array.from(signature), Uint8Array.from(message), Uint8Array.from(publicKey));
  } catch {
    return false;
  }
}
