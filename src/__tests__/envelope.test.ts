/**
 * Crypto correctness tests for the envelope encryption core.
 *
 * Uses node:assert so it runs without a heavy jest/babel toolchain (the SDK
 * builds with plain tsc). Run with `npm test`.
 */
import assert from 'node:assert';
import {
  generateIdentityKeyPair,
  encryptSecret,
  decryptSecret,
  addRecipient,
} from '../envelope';

const SECRET = 'sk_live_51HxRtZ_super_secret_API_key_🔐_áéíóú';

function test(name: string, fn: () => void): void {
  fn();
  console.log('  ✓', name);
}

console.log('envelope encryption');

test('single-recipient roundtrip preserves the value (incl. unicode)', () => {
  const device = generateIdentityKeyPair();
  const env = encryptSecret([device.publicKey], SECRET);
  assert.strictEqual(env.v, 1);
  assert.ok(!env.ct.includes('super_secret'), 'ciphertext must not leak plaintext');
  assert.strictEqual(decryptSecret(device, env), SECRET);
});

test('multi-recipient: device and backend service both decrypt', () => {
  const device = generateIdentityKeyPair();
  const service = generateIdentityKeyPair();
  const env = encryptSecret([device.publicKey, service.publicKey], SECRET);
  assert.strictEqual(Object.keys(env.wraps).length, 2);
  assert.strictEqual(decryptSecret(device, env), SECRET);
  assert.strictEqual(decryptSecret(service, env), SECRET);
});

test('unauthorized identity is rejected', () => {
  const device = generateIdentityKeyPair();
  const attacker = generateIdentityKeyPair();
  const env = encryptSecret([device.publicKey], SECRET);
  assert.throws(() => decryptSecret(attacker, env), /not an authorized recipient/);
});

test('tampered ciphertext is rejected by the GCM auth tag', () => {
  const device = generateIdentityKeyPair();
  const env = encryptSecret([device.publicKey], SECRET);
  const tampered = JSON.parse(JSON.stringify(env));
  const buf = Buffer.from(tampered.ct, 'base64');
  buf[0] ^= 0xff;
  tampered.ct = buf.toString('base64');
  assert.throws(() => decryptSecret(device, tampered));
});

test('addRecipient authorizes a new device without re-encrypting the secret', () => {
  const device = generateIdentityKeyPair();
  const newDevice = generateIdentityKeyPair();
  const env = encryptSecret([device.publicKey], SECRET);
  const env2 = addRecipient(device, env, newDevice.publicKey);
  assert.strictEqual(env2.ct, env.ct, 'data ciphertext must be unchanged');
  assert.strictEqual(decryptSecret(newDevice, env2), SECRET);
  assert.strictEqual(decryptSecret(device, env2), SECRET);
});

test('each encryption uses a fresh DEK and nonce', () => {
  const device = generateIdentityKeyPair();
  const a = encryptSecret([device.publicKey], 'same');
  const b = encryptSecret([device.publicKey], 'same');
  assert.notStrictEqual(a.ct, b.ct);
  assert.notStrictEqual(a.nonce, b.nonce);
});

console.log('\nAll envelope encryption tests passed.');
