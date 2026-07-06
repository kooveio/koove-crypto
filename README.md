# @koove/crypto

Zero-knowledge envelope-encryption primitives for [Koove](https://koove.io) — the
zero-knowledge secrets manager for developers. Pure JavaScript, auditable, no native
linking. Shared by the Koove SDK, CLI and control plane.

**This package is open source on purpose: it is the auditable proof of Koove's
zero-knowledge model.** The construction here is exactly what encrypts your secrets, so
anyone can verify that the server never has what it needs to read them.

## What it does

- **Envelope encryption.** Each secret is encrypted once with a random Data Encryption
  Key (DEK) using **AES-256-GCM**. The DEK is sealed per recipient public key using
  **X25519 (ECDH) + HKDF-SHA256** (a sealed-box construction). Adding a recipient or
  rotating keys is a re-seal of the DEK — never a re-encryption of the secret.
- **Attestation binding** (`computeAttestationBinding`): the single shared commitment
  that binds an attestation challenge to a device's X25519 public key, identical on iOS,
  Android and the server.
- **Recovery codes** (`generateRecoveryCode` / `deriveRecoveryIdentity`): BIP39 256-bit
  mnemonic → HKDF-SHA256 → X25519 identity, for break-glass recovery.

Primitives: [@noble/curves](https://github.com/paulmillr/noble-curves) (X25519),
[@noble/ciphers](https://github.com/paulmillr/noble-ciphers) (AES-256-GCM),
[@noble/hashes](https://github.com/paulmillr/noble-hashes) (HKDF-SHA256) and
[@scure/bip39](https://github.com/paulmillr/scure-bip39).

## Install

```bash
npm install @koove/crypto
```

## Usage

```ts
import {
  generateIdentityKeyPair,
  encryptSecret,
  decryptSecret,
  addRecipient,
} from '@koove/crypto';

// Each consumer (device / service) has an X25519 identity.
const device = generateIdentityKeyPair();

// Encrypt once, sealed for one or more recipients. The server only ever stores this.
const envelope = encryptSecret([device.publicKey], 'my-secret-value');

// Only a holder of the matching secret key can decrypt.
const value = decryptSecret(device, envelope); // 'my-secret-value'

// Authorize a new device without re-encrypting the secret (this is how the
// server never needs to see the plaintext — an authorized party re-seals the DEK).
const newDevice = generateIdentityKeyPair();
const updated = addRecipient(device, envelope, newDevice.publicKey);
```

## Tests

The test suite pins the exact byte layout of every construction against independent
reference implementations (`node:crypto`) and official BIP39 vectors, so the format can
never silently drift.

```bash
npm test
```

## License

MIT © Koove. See [LICENSE](./LICENSE).

Part of Koove — https://koove.io · https://github.com/kooveio
