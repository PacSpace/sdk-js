// The libraries level 2's asymmetric layer runs on, at the exact install
// paths and versions the lockfile resolves (ADR 0015, formats note N12).
// The SDK's and the checker's builds bundle these and nothing else from
// node_modules; the specs read the same list.
export const RECORDS_CRYPTO_PINS = [
  { path: 'node_modules/hpke', name: 'hpke', version: '1.1.7' },
  { path: 'node_modules/@panva/hpke-noble', name: '@panva/hpke-noble', version: '1.1.7' },
  { path: 'node_modules/@panva/hpke-noble/node_modules/@noble/curves', name: '@noble/curves', version: '2.4.0' },
  { path: 'node_modules/@panva/hpke-noble/node_modules/@noble/hashes', name: '@noble/hashes', version: '2.4.0' },
  { path: 'node_modules/@noble/ciphers', name: '@noble/ciphers', version: '2.4.0' },
  { path: 'node_modules/@noble/post-quantum', name: '@noble/post-quantum', version: '0.7.1' },
  { path: 'node_modules/@noble/post-quantum/node_modules/@noble/curves', name: '@noble/curves', version: '2.4.0' },
  { path: 'node_modules/@noble/post-quantum/node_modules/@noble/hashes', name: '@noble/hashes', version: '2.4.0' },
];

// Dependencies resolved before level 2 that the pinned set must not move.
export const RECORDS_CRYPTO_UNMOVED = [
  { path: 'node_modules/@noble/curves', version: '1.2.0' },
  { path: 'node_modules/@noble/curves/node_modules/@noble/hashes', version: '1.3.2' },
  { path: 'node_modules/ethers/node_modules/@noble/hashes', version: '1.3.2' },
  { path: 'node_modules/@otplib/plugin-crypto-noble/node_modules/@noble/hashes', version: '2.0.1' },
];

/**
 * The pin a bundled node_modules file belongs to, or null. `file` is
 * relative to the repository root; the longest matching path wins, so a
 * nested copy is never mistaken for the top-level one.
 */
export function pinOf(file) {
  const normalized = file.split('\\').join('/');
  let best = null;
  for (const pin of RECORDS_CRYPTO_PINS) {
    if (normalized.startsWith(`${pin.path}/`) && (!best || pin.path.length > best.path.length)) best = pin;
  }
  if (!best) return null;
  const rest = normalized.slice(best.path.length + 1);
  return rest.startsWith('node_modules/') ? null : best;
}
