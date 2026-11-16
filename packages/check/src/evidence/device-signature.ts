import type * as Asymmetric from '@pacspace/shared/dist/records-crypto/asymmetric';

/** Resolved through the package's exports at run time; the checker's own resolution reads its types from dist. */
const ASYMMETRIC = '@pacspace/shared/records-crypto/asymmetric';

/**
 * A device's v2 pair over one message, checked by the asymmetric layer (ML-DSA-65 needs its pinned library), loaded
 * once per process and only by the `evidence` command. In the published package scripts/build.mjs replaces this file
 * with a require of the bundled `./records-crypto.js` subpath, which carries the pinned libraries, so `cli.js` and
 * `index.js` bundle none of them.
 */
export type DeviceSignature = Pick<typeof Asymmetric, 'verifyDeviceMessageV1'>;

let loaded: Promise<DeviceSignature> | null = null;

export function loadDeviceSignature(): Promise<DeviceSignature> {
  if (!loaded) loaded = import(/* @vite-ignore */ ASYMMETRIC) as Promise<DeviceSignature>;
  return loaded;
}
