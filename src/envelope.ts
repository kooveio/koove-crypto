/**
 * Envelope encryption — the cryptographic core of Koove's zero-knowledge model.
 *
 * Each secret is encrypted once with a random per-secret Data Encryption Key
 * (DEK) using AES-256-GCM. The DEK is then "wrapped" (sealed) independently for
 * every authorized consumer using X25519 ECDH -> HKDF-SHA256 -> AES-256-GCM
 * (a sealed-box construction).
 *
 * The server only ever stores ciphertext and wrapped DEKs; it never sees the
 * plaintext secret nor the DEK. Authorizing a new consumer means an already
 * authorized party unwraps the DEK and re-wraps it for the new public key — the
 * server just moves bytes. This also makes key rotation a re-wrap, not a
 * re-encryption of the secret.
 *
 * Primitives: @noble/curves (X25519) + @noble/ciphers (AES-256-GCM) +
 * @noble/hashes (HKDF-SHA256). Pure JS, audited, no native linking.
 */
import { x25519 } from '@noble/curves/ed25519.js';
import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { randomBytes } from './random';
import { bytesToBase64, base64ToBytes } from './encoding';

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

const DEK_BYTES = 32; // AES-256
const KEY_BYTES = 32; // X25519 scalar / public key
const NONCE_BYTES = 12; // AES-GCM standard nonce
const HKDF_INFO = TEXT_ENCODER.encode('koove-envelope-v1');

/** An X25519 key pair identifying a single consumer (device, service, user). */
export interface IdentityKeyPair {
  /** base64-encoded X25519 public key (32 bytes). Acts as the consumer id. */
  publicKey: string;
  /** base64-encoded X25519 secret key (32 bytes). Never leaves the consumer. */
  secretKey: string;
}

/** A DEK sealed to one recipient's public key. */
export interface SealedKey {
  /** Ephemeral X25519 public key (base64). */
  epk: string;
  /** AES-GCM nonce used to wrap the DEK (base64). */
  nonce: string;
  /** Wrapped DEK + GCM tag (base64). */
  ct: string;
}

/** A secret encrypted once, with the DEK sealed per authorized recipient. */
export interface SecretEnvelope {
  v: 1;
  /** AES-GCM nonce for the secret data (base64). */
  nonce: string;
  /** Secret ciphertext + GCM tag (base64). */
  ct: string;
  /** Map of recipient public key (base64) -> sealed DEK. */
  wraps: Record<string, SealedKey>;
}

/**
 * Generate a fresh consumer identity. 32 random bytes are a valid X25519
 * scalar (clamping is handled internally by the curve).
 */
export function generateIdentityKeyPair(): IdentityKeyPair {
  const secretKey = randomBytes(KEY_BYTES);
  const publicKey = x25519.getPublicKey(secretKey);
  return {
    publicKey: bytesToBase64(publicKey),
    secretKey: bytesToBase64(secretKey),
  };
}

/**
 * Derive the AES key that wraps the DEK. The HKDF salt binds the derived key to
 * both the ephemeral and recipient public keys, giving per-message domain
 * separation (same spirit as libsodium's crypto_box_seal).
 */
function deriveWrapKey(
  shared: Uint8Array,
  ephemeralPublic: Uint8Array,
  recipientPublic: Uint8Array,
): Uint8Array {
  const salt = new Uint8Array(ephemeralPublic.length + recipientPublic.length);
  salt.set(ephemeralPublic, 0);
  salt.set(recipientPublic, ephemeralPublic.length);
  return hkdf(sha256, shared, salt, HKDF_INFO, 32);
}

/** Seal (wrap) a DEK so that only the holder of `recipientPublicKey` can open it. */
export function sealKey(recipientPublicKeyB64: string, dek: Uint8Array): SealedKey {
  const recipientPublic = base64ToBytes(recipientPublicKeyB64);
  const ephemeralSecret = randomBytes(KEY_BYTES);
  const ephemeralPublic = x25519.getPublicKey(ephemeralSecret);
  const shared = x25519.getSharedSecret(ephemeralSecret, recipientPublic);
  const wrapKey = deriveWrapKey(shared, ephemeralPublic, recipientPublic);
  const nonce = randomBytes(NONCE_BYTES);
  const ct = gcm(wrapKey, nonce).encrypt(dek);
  return {
    epk: bytesToBase64(ephemeralPublic),
    nonce: bytesToBase64(nonce),
    ct: bytesToBase64(ct),
  };
}

/** Open (unwrap) a sealed DEK using the recipient's secret key. */
export function openKey(recipientSecretKeyB64: string, sealed: SealedKey): Uint8Array {
  const recipientSecret = base64ToBytes(recipientSecretKeyB64);
  const recipientPublic = x25519.getPublicKey(recipientSecret);
  const ephemeralPublic = base64ToBytes(sealed.epk);
  const shared = x25519.getSharedSecret(recipientSecret, ephemeralPublic);
  const wrapKey = deriveWrapKey(shared, ephemeralPublic, recipientPublic);
  const nonce = base64ToBytes(sealed.nonce);
  const ct = base64ToBytes(sealed.ct);
  // Throws if the tag is invalid (tampering / wrong recipient).
  return gcm(wrapKey, nonce).decrypt(ct);
}

/**
 * Encrypt a secret for one or more authorized consumers. The plaintext is
 * encrypted once; the DEK is sealed separately for each recipient.
 */
export function encryptSecret(
  recipientPublicKeysB64: string[],
  plaintext: string,
): SecretEnvelope {
  if (recipientPublicKeysB64.length === 0) {
    throw new Error('encryptSecret requires at least one recipient public key');
  }
  const dek = randomBytes(DEK_BYTES);
  const nonce = randomBytes(NONCE_BYTES);
  const data = TEXT_ENCODER.encode(plaintext);
  const ct = gcm(dek, nonce).encrypt(data);

  const wraps: Record<string, SealedKey> = {};
  for (const recipient of recipientPublicKeysB64) {
    wraps[recipient] = sealKey(recipient, dek);
  }

  return {
    v: 1,
    nonce: bytesToBase64(nonce),
    ct: bytesToBase64(ct),
    wraps,
  };
}

/** Decrypt a secret envelope using the consumer's identity. */
export function decryptSecret(
  identity: IdentityKeyPair,
  envelope: SecretEnvelope,
): string {
  const sealed = envelope.wraps[identity.publicKey];
  if (!sealed) {
    throw new Error('This identity is not an authorized recipient of the secret');
  }
  const dek = openKey(identity.secretKey, sealed);
  const nonce = base64ToBytes(envelope.nonce);
  const ct = base64ToBytes(envelope.ct);
  const data = gcm(dek, nonce).decrypt(ct);
  return TEXT_DECODER.decode(data);
}

/**
 * Authorize a new recipient for an existing envelope, without re-encrypting the
 * secret. An already-authorized identity unwraps the DEK and re-seals it for the
 * new public key. This is how multi-device, team sharing, and key rotation work.
 */
export function addRecipient(
  authorizedIdentity: IdentityKeyPair,
  envelope: SecretEnvelope,
  newRecipientPublicKeyB64: string,
): SecretEnvelope {
  const sealed = envelope.wraps[authorizedIdentity.publicKey];
  if (!sealed) {
    throw new Error('The authorizing identity is not a recipient of this secret');
  }
  const dek = openKey(authorizedIdentity.secretKey, sealed);
  return {
    ...envelope,
    wraps: {
      ...envelope.wraps,
      [newRecipientPublicKeyB64]: sealKey(newRecipientPublicKeyB64, dek),
    },
  };
}
