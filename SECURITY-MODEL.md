# Koove — Security model & threat model (public)

> The public threat model for [Koove](https://koove.io), a zero-knowledge
> secrets manager. This document is a sanitized synthesis of our internal
> architecture decision records — it states what we guarantee, how, and (just
> as importantly) what we do **not** guarantee. If a claim isn't here, we
> don't make it. Security contact: [security.txt](https://koove.io/.well-known/security.txt).

## Trust boundary

- **The server is not trusted with plaintext.** It stores only ciphertext and
  sealed keys, holds no recipient private key, and therefore cannot read a
  secret's plaintext — by construction, not by policy. "Zero-knowledge" here
  means *the service* cannot read your secrets.
- **The client is not trusted either.** Any client can be rooted, hooked or
  repackaged. So trust does not live in the client: it lives in the
  cryptography and in the server's gate over *who is an eligible recipient*.
- What the promise does **not** mean: it does not mean nobody can read your
  secrets. You (via your controller identity), your verified devices, and
  whoever holds your recovery code can. The promise is made against Koove — and
  it's verifiable because the client-side code is open source.

## Cryptographic construction

- **Envelope encryption.** Each secret is encrypted once with a random Data
  Encryption Key (DEK) using **AES-256-GCM**. The DEK is sealed per recipient
  public key with **X25519 (ECDH) + HKDF-SHA256** (a sealed-box construction).
  Adding a device, revoking one, or rotating keys is a **re-seal** of the DEK,
  never a re-encryption of the secret.
- **Audited primitives, no hand-rolled crypto.** Built on the
  [`@noble`](https://github.com/paulmillr/noble-hashes) audited libraries. This
  package (`@koove/crypto`) is the auditable core; its tests pin the byte
  layout against independent vectors so the format cannot silently drift.
- **Attestation binding.** A single shared function commits an attestation
  challenge to a device's X25519 public key, computed identically on iOS,
  Android and the server, so the binding can never diverge across platforms.

## Attestation (who may decrypt)

A mobile device becomes an eligible recipient **only** after passing real,
cryptographically verified attestation. Verification is server-side.

- **iOS — Apple App Attest.** The server verifies the attestation object by
  composing vetted primitives (CBOR, X.509/ASN.1, `node:crypto`) following
  Apple's documented steps: chain to the **pinned** Apple App Attestation Root
  CA, the nonce check against Apple's extension OID, the keyId/rpIdHash/counter/
  aaguid/credentialId checks. We do not depend on an unmaintained third-party
  App Attest library, and we never hand-roll CBOR/ASN.1/X.509 parsing. The
  development-environment aaguid is accepted **only** in non-production.
- **Android — Google Play Integrity.** Verdicts are checked via Google's
  official server-side token decoding: nonce binding, package name, freshness,
  app-recognized and device-integrity verdicts.
- **Fail-closed.** Both verifiers reject with a named reason when unconfigured;
  they never fall through to "accept" and never turn a misconfiguration into a
  silent pass.
- **Local decryption is biometric-gated** (Face ID / fingerprint), and the
  private key never leaves the device's hardware-backed storage.

## Transport hardening

Certificate pinning is **declarative and OS-level** (iOS ATS pinned domains,
Android Network Security Config), not a JavaScript dependency. Pins are
**root-CA SPKI SHA-256** values with a backup CA, because leaf certificates
rotate frequently and dual-CA pinning survives an issuer change. Android
carries a documented fail-open expiration so an unmaintained build degrades to
normal TLS rather than bricking.

## Defense in depth (server-side, uncircumventable by a compromised client)

- **Anomaly detection** over the audit trail: reads from a never-seen IP,
  abnormal read velocity, repeated failed attestations.
- **Canary / honeytokens:** decoy secrets a legitimate consumer never fetches;
  any read is a confirmed-breach signal.
- **Recipient-set consistency check:** the server verifies (using public keys
  only, never the DEK) that an uploaded envelope is sealed for exactly the
  recipients on record — catching a stale set that still names a revoked device.

## Recovery & revocation — with honest limits

- Two always-present recipients per app: a **controller identity** (private key
  in the developer's tooling/KMS, never on the server) for add-device and kill,
  and a **recovery identity** derived from a one-time 24-word BIP39 code, shown
  once and never stored, for break-glass after total device loss.
- **Revocation is soft-immediate, hard via re-wrap:** a revoked device drops
  from discovery at once and the cryptographic kill removes its wrap from every
  envelope.
- **The honest limit we never hide:** no system can "un-deliver" a plaintext a
  device already decrypted and cached. For a total kill you must rotate the
  secret's *value*. We say this in the product, the CLI and the docs — distrust
  anyone who promises instant revocation of already-delivered secrets.
- If you lose every device **and** the recovery code, the secrets are
  unrecoverable. That is the cost of real zero-knowledge, and we'd rather tell
  you than pretend otherwise.

## Verification status (honest)

- **iOS App Attest: verified end-to-end on physical hardware** (real
  attestation, chain to Apple's pinned root, biometric-gated decryption, no dev
  bypass), including the negative case: a non-recipient device cannot decrypt.
- **Android Play Integrity: implemented and unit-tested; live hardware run
  pending** Play Console setup. We label it exactly that everywhere — never
  "works on both".
- **Supply chain:** npm packages are published via OIDC trusted publishing with
  **SLSA provenance attestations**, and run **no install-time scripts**.
- **Independent cryptographic audit:** on the roadmap (target H2 2026); the
  report will be published in full. Until then the claim is "auditable", not
  "audited".

## Scope not covered / out of scope

- Payment data (handled by Stripe, PCI-DSS Level 1 — Koove never sees a card).
- A fully compromised (rooted/jailbroken) device can read what the running app
  can read; client hardening raises cost, it is not the control. The controls
  that matter are server-side.
- Denial-of-service and physical attacks on an already-compromised device.

---

*Found something? See [security.txt](https://koove.io/.well-known/security.txt)
and our [disclosure policy](https://koove.io/en/security/disclosure). Good-faith
research is welcome and protected by a safe harbor.*
