/**
 * `reader-crypto-v1`'s wraps (ADR 0019; records prototype build, R6, D-1, D-16): a trail link's device keys, and the
 * link, answer and note keys wrapped to them with BF's `wrapDisclosureKeyV1` under a typed binding, never a bare
 * handle. The keyless half is `records/reader-crypto-v1.ts`. Reached only through the asymmetric subpath, as BF's
 * layer is, so the libraries it loads stay out of everything shared's index reaches.
 *
 * Wraps are `KeyWrapV1`: each binding names the link's handle, which is unique across every workspace, so a wrap
 * made for one link, epoch, request or note opens for no other.
 */
import { platformCrypto, utf8 } from '../platform-crypto';
import { fromBase64Url, toBase64Url } from '../base64url';
import {
  approvalMessageV1,
  answerKeyBindingV1,
  deviceCodeV1,
  deviceIdV1,
  linkKeyBindingV1,
  noteKeyBindingV1,
  type NoteNameV1,
} from '../../records/reader-crypto-v1';
import type { SigningPublicKeyJwkV1 } from '../../records/signed-acknowledgment-v1';
import {
  MldsaSigningKeyV1,
  WorkspaceSeedV1,
  mldsaSigningKeyFromSeedV1,
  signMldsa65V1,
  verifyMldsa65V1,
  unwrapDisclosureKeyV1,
  workspaceSeedFromBytesV1,
  wrapDisclosureKeyV1,
  type KeyWrapV1,
} from './records-asymmetric-v1';

/** A device's keys: the X-Wing pair from its 32-byte seed, the ML-DSA-65 key from its own seed, and the browser's P-256 public key. */
export interface DeviceKeysV1 {
  xwing: WorkspaceSeedV1;
  mldsa: MldsaSigningKeyV1;
  p256Jwk: SigningPublicKeyJwkV1;
  deviceId: string;
  code: string;
}

/**
 * Makes a device's keys from its two 32-byte seeds (the X-Wing pair through `workspaceSeedFromBytesV1`, the ML-DSA-65
 * key through `mldsaSigningKeyFromSeedV1`) and the P-256 public key `browser-key-v2.ts` holds, with its id and code.
 */
export async function makeDeviceKeysV1(input: { xwingSeed: Uint8Array; mldsaSeed: Uint8Array; p256Jwk: SigningPublicKeyJwkV1 }): Promise<DeviceKeysV1> {
  const xwing = await workspaceSeedFromBytesV1(input.xwingSeed);
  const mldsa = await mldsaSigningKeyFromSeedV1(input.mldsaSeed);
  const deviceId = await deviceIdV1({ xwingPublicKey: xwing.publicKey, p256Jwk: input.p256Jwk, mldsaPublicKey: mldsa.publicKey });
  return { xwing, mldsa, p256Jwk: input.p256Jwk, deviceId, code: deviceCodeV1(deviceId) };
}

/** What a device registers with: its three public keys, the X-Wing and ML-DSA-65 keys in base64url. */
export function devicePublicV1(keys: DeviceKeysV1): { xwingPublicKey: string; p256Jwk: SigningPublicKeyJwkV1; mldsaPublicKey: string } {
  return { xwingPublicKey: toBase64Url(keys.xwing.publicKey), p256Jwk: keys.p256Jwk, mldsaPublicKey: toBase64Url(keys.mldsa.publicKey) };
}

/** The link key for one epoch, wrapped to a confirmed device's or the workspace identity's X-Wing public key. */
export function wrapLinkKeyV1(publicKey: Uint8Array, linkKey: Uint8Array, handle: string, epoch: number): Promise<KeyWrapV1> {
  return wrapDisclosureKeyV1(publicKey, linkKey, linkKeyBindingV1(handle, epoch));
}

export function unwrapLinkKeyV1(input: { seed: WorkspaceSeedV1; wrap: unknown; handle: string; epoch: number }) {
  return unwrapDisclosureKeyV1({ seed: input.seed, wrap: input.wrap, handle: linkKeyBindingV1(input.handle, input.epoch) });
}

/** An answer's key, wrapped to one confirmed device. */
export function wrapAnswerKeyV1(publicKey: Uint8Array, answerKey: Uint8Array, handle: string, requestRef: string): Promise<KeyWrapV1> {
  return wrapDisclosureKeyV1(publicKey, answerKey, answerKeyBindingV1(handle, requestRef));
}

export function unwrapAnswerKeyV1(input: { seed: WorkspaceSeedV1; wrap: unknown; handle: string; requestRef: string }) {
  return unwrapDisclosureKeyV1({ seed: input.seed, wrap: input.wrap, handle: answerKeyBindingV1(input.handle, input.requestRef) });
}

/** A sealed note's key, wrapped to a confirmed device or, for a rule's label text, to the workspace identity. */
export function wrapNoteKeyV1(publicKey: Uint8Array, noteKey: Uint8Array, name: NoteNameV1): Promise<KeyWrapV1> {
  return wrapDisclosureKeyV1(publicKey, noteKey, noteKeyBindingV1(name));
}

export function unwrapNoteKeyV1(input: { seed: WorkspaceSeedV1; wrap: unknown; name: NoteNameV1 }) {
  return unwrapDisclosureKeyV1({ seed: input.seed, wrap: input.wrap, handle: noteKeyBindingV1(input.name) });
}

/**
 * A confirmed device's approval of a later device: ES256 (WebCrypto, IEEE P1363) and ML-DSA-65 over the UTF-8 of
 * `approvalMessageV1`, both required, in the members BF's v2 envelope names them. The API checks both with the
 * verifier it already runs for v2 acknowledgments.
 */
export function signApprovalV1(input: {
  p256PrivateKey: CryptoKey;
  mldsa: MldsaSigningKeyV1;
  handle: string;
  epoch: number;
  newDeviceId: string;
}): Promise<{ signature: string; mldsaSignature: string }> {
  return signDeviceMessageV1({ p256PrivateKey: input.p256PrivateKey, mldsa: input.mldsa, message: approvalMessageV1(input.handle, input.epoch, input.newDeviceId) });
}

/**
 * A device's v2 pair over one message (R7: an approval, an acknowledgment, an evidence file): ES256 (WebCrypto, IEEE
 * P1363) and ML-DSA-65 over its UTF-8, both required, as base64url.
 */
export async function signDeviceMessageV1(input: { p256PrivateKey: CryptoKey; mldsa: MldsaSigningKeyV1; message: string }): Promise<{ signature: string; mldsaSignature: string }> {
  const message = new Uint8Array(utf8(input.message));
  const { subtle } = await platformCrypto();
  const es256 = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, input.p256PrivateKey, message as BufferSource));
  const mldsa = await signMldsa65V1(input.mldsa, message);
  return { signature: toBase64Url(es256), mldsaSignature: toBase64Url(mldsa) };
}

/**
 * Both of a device's signatures over one message, checked against its P-256 JWK and ML-DSA-65 public key: true only
 * when both verify. Shapes first; never throws.
 */
export async function verifyDeviceMessageV1(input: {
  p256Jwk: SigningPublicKeyJwkV1;
  mldsaPublicKey: Uint8Array;
  message: string;
  signature: unknown;
  mldsaSignature: unknown;
}): Promise<boolean> {
  try {
    if (typeof input.signature !== 'string' || typeof input.mldsaSignature !== 'string') return false;
    const es256 = fromBase64Url(input.signature);
    const mldsa = fromBase64Url(input.mldsaSignature);
    const jwk = input.p256Jwk;
    if (!es256 || es256.length !== 64 || !mldsa || !jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256') return false;
    const message = new Uint8Array(utf8(input.message));
    const { subtle } = await platformCrypto();
    const key = await subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const first = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, es256 as BufferSource, message as BufferSource);
    return first && (await verifyMldsa65V1(input.mldsaPublicKey, message, mldsa));
  } catch {
    return false;
  }
}
