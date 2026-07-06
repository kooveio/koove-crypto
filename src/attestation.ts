/**
 * Attestation binding — the single shared construction that commits an
 * attestation challenge to a device's X25519 public key.
 *
 * This one function is used identically by every surface, so the binding can
 * never diverge across platforms:
 *   - iOS SDK       -> result is passed as the App Attest `clientDataHash`
 *   - Android SDK   -> result is passed as the Play Integrity request nonce
 *   - control plane -> recomputed during verification to confirm which public
 *                      key a genuine attestation actually vouched for
 *
 *   binding = SHA256( "koove-attest-v1" || nonce[32 raw bytes] || x25519PublicKey[32 raw bytes] )
 *
 * Both inputs are base64 and are decoded to raw bytes BEFORE hashing (we never
 * hash the base64 strings), so the construction is encoding-independent. The
 * domain tag is versioned to prevent cross-protocol reuse, and every field is
 * fixed-length, so the concatenation is unambiguous without separators.
 *
 * Native wrappers MUST pass this result through verbatim — they never recompute
 * the hash — or the single-implementation guarantee is lost.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { base64ToBytes } from './encoding';

const ATTESTATION_DOMAIN = new TextEncoder().encode('koove-attest-v1');
const NONCE_BYTES = 32; // server-issued challenge nonce
const PUBLIC_KEY_BYTES = 32; // X25519 public key

/**
 * Compute the attestation binding for a challenge nonce and an X25519 public
 * key (both base64). Returns the raw 32-byte SHA-256 digest.
 *
 * @throws if the decoded nonce or public key is not exactly 32 bytes.
 */
export function computeAttestationBinding(
  challengeNonceB64: string,
  x25519PublicKeyB64: string,
): Uint8Array {
  const nonce = base64ToBytes(challengeNonceB64);
  if (nonce.length !== NONCE_BYTES) {
    throw new Error(
      `attestation challenge nonce must be ${NONCE_BYTES} bytes, got ${nonce.length}`,
    );
  }
  const publicKey = base64ToBytes(x25519PublicKeyB64);
  if (publicKey.length !== PUBLIC_KEY_BYTES) {
    throw new Error(
      `X25519 public key must be ${PUBLIC_KEY_BYTES} bytes, got ${publicKey.length}`,
    );
  }

  const buf = new Uint8Array(
    ATTESTATION_DOMAIN.length + NONCE_BYTES + PUBLIC_KEY_BYTES,
  );
  buf.set(ATTESTATION_DOMAIN, 0);
  buf.set(nonce, ATTESTATION_DOMAIN.length);
  buf.set(publicKey, ATTESTATION_DOMAIN.length + NONCE_BYTES);
  return sha256(buf);
}
