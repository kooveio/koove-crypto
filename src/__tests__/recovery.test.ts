/**
 * Tests for the recovery-code derivation.
 *
 * The derivation (mnemonic -> entropy -> HKDF-SHA256 -> X25519) is the ONLY
 * path back to a lost app's secrets, so these tests pin its exact layout with
 * an independent HKDF (node:crypto) and a fixed BIP39 test vector — if the
 * construction ever drifts, previously issued recovery codes stop working.
 *
 * Uses node:assert + node:crypto so it runs under plain tsc, like the other
 * suites.
 */
import assert from 'node:assert';
import { hkdfSync } from 'node:crypto';
import {
  generateRecoveryCode,
  deriveRecoveryIdentity,
  normalizeRecoveryCode,
  generateIdentityKeyPair,
  encryptSecret,
  decryptSecret,
  base64ToBytes,
  RECOVERY_CODE_WORDS,
} from '../index';

function test(name: string, fn: () => void): void {
  fn();
  console.log('  ✓', name);
}

/**
 * Official BIP39 vector for 256-bit all-zero entropy. Fixed input so the
 * pinned-layout assertions are reproducible.
 */
const ZERO_ENTROPY_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon art';

console.log('recovery derivation');

test('generates a 24-word mnemonic', () => {
  const code = generateRecoveryCode();
  assert.strictEqual(code.split(' ').length, RECOVERY_CODE_WORDS);
});

test('every generated code round-trips to a valid identity', () => {
  const code = generateRecoveryCode();
  const id = deriveRecoveryIdentity(code);
  assert.strictEqual(base64ToBytes(id.publicKey).length, 32);
  assert.strictEqual(base64ToBytes(id.secretKey).length, 32);
});

test('derivation is deterministic: same code, same key pair', () => {
  const code = generateRecoveryCode();
  const a = deriveRecoveryIdentity(code);
  const b = deriveRecoveryIdentity(code);
  assert.strictEqual(a.publicKey, b.publicKey);
  assert.strictEqual(a.secretKey, b.secretKey);
});

test('two codes derive two different identities', () => {
  const a = deriveRecoveryIdentity(generateRecoveryCode());
  const b = deriveRecoveryIdentity(generateRecoveryCode());
  assert.notStrictEqual(a.publicKey, b.publicKey);
});

test('pins the exact layout: HKDF-SHA256(entropy, info="koove-recovery-v1")', () => {
  const got = deriveRecoveryIdentity(ZERO_ENTROPY_MNEMONIC);
  const expectedSecret = Buffer.from(
    hkdfSync(
      'sha256',
      Buffer.alloc(32), // the vector's entropy: 32 zero bytes
      Buffer.alloc(0), // no salt (RFC 5869: treated as HashLen zeros)
      Buffer.from('koove-recovery-v1', 'utf8'),
      32,
    ),
  );
  assert.ok(
    Buffer.from(base64ToBytes(got.secretKey)).equals(expectedSecret),
    'secret key must equal an independent HKDF of the mnemonic entropy',
  );
});

test('derives from entropy, not the mnemonic string (formatting-proof)', () => {
  const canonical = deriveRecoveryIdentity(ZERO_ENTROPY_MNEMONIC);
  const messy = deriveRecoveryIdentity(
    '  ' + ZERO_ENTROPY_MNEMONIC.toUpperCase().split(' ').join('\n  ') + '  ',
  );
  assert.strictEqual(messy.publicKey, canonical.publicKey);
  assert.strictEqual(messy.secretKey, canonical.secretKey);
});

test('normalizeRecoveryCode collapses case and whitespace', () => {
  assert.strictEqual(
    normalizeRecoveryCode('  Abandon\tABANDON \n art '),
    'abandon abandon art',
  );
});

test('the recovery identity works as an envelope recipient (break-glass read)', () => {
  const code = generateRecoveryCode();
  const recovery = deriveRecoveryIdentity(code);
  const device = generateIdentityKeyPair();
  const envelope = encryptSecret([device.publicKey, recovery.publicKey], 'db-password');
  // Re-derive from the code alone, as in a real recovery.
  const rederived = deriveRecoveryIdentity(code);
  assert.strictEqual(decryptSecret(rederived, envelope), 'db-password');
});

test('rejects a mnemonic with a bad checksum', () => {
  // Swap the checksum-bearing last word for another valid wordlist word.
  const bad = ZERO_ENTROPY_MNEMONIC.replace(/ art$/, ' zoo');
  assert.throws(() => deriveRecoveryIdentity(bad));
});

test('rejects words outside the wordlist', () => {
  const bad = ZERO_ENTROPY_MNEMONIC.replace(/^abandon/, 'koove');
  assert.throws(() => deriveRecoveryIdentity(bad));
});

test('rejects a valid but non-24-word mnemonic (wrong entropy size)', () => {
  // Official 12-word vector (128-bit zero entropy) — valid BIP39, wrong size.
  const twelve =
    'abandon abandon abandon abandon abandon abandon ' +
    'abandon abandon abandon abandon abandon about';
  assert.throws(() => deriveRecoveryIdentity(twelve), /24-word/);
});

console.log('\nAll recovery derivation tests passed.');
