/**
 * Tests for the attestation binding construction.
 *
 * The binding is the single shared commitment used by the iOS SDK, the Android
 * SDK and the control plane. These tests pin its EXACT byte layout so the three
 * surfaces can never diverge.
 *
 * Uses node:assert + node:crypto (independent SHA-256) so it runs under plain
 * tsc, like envelope.test.ts.
 */
import assert from 'node:assert';
import { createHash } from 'node:crypto';
import {
  generateIdentityKeyPair,
  computeAttestationBinding,
  bytesToBase64,
  base64ToBytes,
} from '../index';

function test(name: string, fn: () => void): void {
  fn();
  console.log('  ✓', name);
}

/** Deterministic 32-byte nonce (base64) for reproducible assertions. */
function makeNonce(seed: number): string {
  const n = new Uint8Array(32);
  for (let i = 0; i < 32; i++) n[i] = (seed + i * 7) & 0xff;
  return bytesToBase64(n);
}

/** Independent reference implementation of the canonical layout. */
function reference(nonceB64: string, pubKeyB64: string): Buffer {
  return createHash('sha256')
    .update(
      Buffer.concat([
        Buffer.from('koove-attest-v1', 'utf8'),
        Buffer.from(base64ToBytes(nonceB64)),
        Buffer.from(base64ToBytes(pubKeyB64)),
      ]),
    )
    .digest();
}

console.log('attestation binding');

test('output is a 32-byte SHA-256 digest', () => {
  const dev = generateIdentityKeyPair();
  const out = computeAttestationBinding(makeNonce(1), dev.publicKey);
  assert.strictEqual(out.length, 32);
});

test('matches the exact canonical layout: SHA256(domain || nonce || pubkey)', () => {
  const dev = generateIdentityKeyPair();
  const nonceB64 = makeNonce(2);
  const got = Buffer.from(computeAttestationBinding(nonceB64, dev.publicKey));
  assert.ok(
    got.equals(reference(nonceB64, dev.publicKey)),
    'binding must equal SHA256(domain || nonce || pubkey)',
  );
});

test('deterministic for identical inputs', () => {
  const dev = generateIdentityKeyPair();
  const nonceB64 = makeNonce(3);
  const a = Buffer.from(computeAttestationBinding(nonceB64, dev.publicKey));
  const b = Buffer.from(computeAttestationBinding(nonceB64, dev.publicKey));
  assert.ok(a.equals(b));
});

test('a different nonce changes the binding (freshness)', () => {
  const dev = generateIdentityKeyPair();
  const a = Buffer.from(computeAttestationBinding(makeNonce(4), dev.publicKey));
  const b = Buffer.from(computeAttestationBinding(makeNonce(5), dev.publicKey));
  assert.ok(!a.equals(b));
});

test('a different public key changes the binding (commits to the key)', () => {
  const nonceB64 = makeNonce(6);
  const a = Buffer.from(computeAttestationBinding(nonceB64, generateIdentityKeyPair().publicKey));
  const b = Buffer.from(computeAttestationBinding(nonceB64, generateIdentityKeyPair().publicKey));
  assert.ok(!a.equals(b));
});

test('the versioned domain tag prevents cross-protocol reuse', () => {
  const dev = generateIdentityKeyPair();
  const nonceB64 = makeNonce(7);
  const untagged = createHash('sha256')
    .update(
      Buffer.concat([
        Buffer.from(base64ToBytes(nonceB64)),
        Buffer.from(base64ToBytes(dev.publicKey)),
      ]),
    )
    .digest();
  const got = Buffer.from(computeAttestationBinding(nonceB64, dev.publicKey));
  assert.ok(!got.equals(untagged), 'must differ from an untagged concat');
});

test('rejects a nonce that is not 32 bytes', () => {
  const dev = generateIdentityKeyPair();
  assert.throws(
    () => computeAttestationBinding(bytesToBase64(new Uint8Array(16)), dev.publicKey),
    /nonce must be 32 bytes/,
  );
});

test('rejects a public key that is not 32 bytes', () => {
  assert.throws(
    () => computeAttestationBinding(makeNonce(8), bytesToBase64(new Uint8Array(31))),
    /public key must be 32 bytes/,
  );
});

console.log('\nAll attestation binding tests passed.');
