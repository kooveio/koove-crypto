/**
 * Cryptographically secure random bytes, portable across Node and React Native.
 *
 * - Node / browsers / RN with a WebCrypto polyfill: use `crypto.getRandomValues`.
 * - Bare React Native (Hermes): fall back to Expo's hardware-backed CSPRNG.
 *   `expo-crypto` is required lazily so Node/Jest never tries to load the
 *   native module.
 */
export function randomBytes(length: number): Uint8Array {
  const globalCrypto = (globalThis as { crypto?: Crypto }).crypto;
  if (globalCrypto && typeof globalCrypto.getRandomValues === 'function') {
    const bytes = new Uint8Array(length);
    globalCrypto.getRandomValues(bytes);
    return bytes;
  }

  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const ExpoCrypto = require('expo-crypto') as {
    getRandomBytes(byteCount: number): Uint8Array;
  };
  return ExpoCrypto.getRandomBytes(length);
}
