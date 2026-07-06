/**
 * Recovery identity — break-glass read access derived from a one-time code.
 *
 * Every secret's recipient set includes a per-app "recovery" public key
 * (alongside the attested devices and the controller). The matching secret key
 * is NEVER stored anywhere: it is re-derived on demand from a recovery code
 * that the developer saw exactly once, at `app create` time.
 *
 *   code (24-word BIP39 mnemonic, 256-bit entropy)
 *     -> entropy[32 raw bytes]                      (checksum-validated decode)
 *     -> HKDF-SHA256(entropy, info="koove-recovery-v1")
 *     -> X25519 secret key -> IdentityKeyPair
 *
 * The code is full-entropy, so no slow/password KDF is needed — HKDF is used
 * only for domain separation, so the mnemonic's entropy can never be reused as
 * key material by another protocol. Derivation is from the decoded ENTROPY,
 * not the mnemonic string, so wording normalization can never change the key.
 *
 * Losing the code is unrecoverable by design (zero-knowledge: Koove cannot
 * read, so Koove cannot reset). Holding the code alone is not enough to read a
 * secret — fetching envelopes still requires the app token (see task6 §6).
 */
import { entropyToMnemonic, mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { x25519 } from '@noble/curves/ed25519.js';

import { randomBytes } from './random';
import { bytesToBase64 } from './encoding';
import type { IdentityKeyPair } from './envelope';

const RECOVERY_ENTROPY_BYTES = 32; // 256-bit -> 24 words
const HKDF_INFO = new TextEncoder().encode('koove-recovery-v1');

/** Number of words in a Koove recovery code. */
export const RECOVERY_CODE_WORDS = 24;

/**
 * Canonicalize user input of a recovery code: trim, lowercase, collapse any
 * whitespace runs (spaces, newlines, tabs) to single spaces. Applied before
 * validation so re-typed codes survive formatting differences.
 */
export function normalizeRecoveryCode(code: string): string {
  return code.trim().toLowerCase().split(/\s+/).join(' ');
}

/**
 * Generate a fresh recovery code: 32 bytes from the platform CSPRNG, encoded
 * as a 24-word English BIP39 mnemonic (with checksum). Show it to the user
 * once and never persist it.
 */
export function generateRecoveryCode(): string {
  return entropyToMnemonic(randomBytes(RECOVERY_ENTROPY_BYTES), wordlist);
}

/**
 * Re-derive the recovery identity from a recovery code. Deterministic: the
 * same code always yields the same X25519 key pair.
 *
 * @throws if the mnemonic has an invalid word, a bad checksum, or is not the
 *         24-word (256-bit) form.
 */
export function deriveRecoveryIdentity(recoveryCode: string): IdentityKeyPair {
  const mnemonic = normalizeRecoveryCode(recoveryCode);
  // Decodes and verifies the checksum; throws on any invalid mnemonic.
  const entropy = mnemonicToEntropy(mnemonic, wordlist);
  if (entropy.length !== RECOVERY_ENTROPY_BYTES) {
    throw new Error(
      `recovery code must be a ${RECOVERY_CODE_WORDS}-word (256-bit) mnemonic, ` +
        `got ${entropy.length * 8}-bit`,
    );
  }
  const secretKey = hkdf(sha256, entropy, undefined, HKDF_INFO, 32);
  const publicKey = x25519.getPublicKey(secretKey);
  return {
    publicKey: bytesToBase64(publicKey),
    secretKey: bytesToBase64(secretKey),
  };
}
