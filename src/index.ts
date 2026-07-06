export {
  generateIdentityKeyPair,
  sealKey,
  openKey,
  encryptSecret,
  decryptSecret,
  addRecipient,
} from './envelope';
export type { IdentityKeyPair, SealedKey, SecretEnvelope } from './envelope';
export { computeAttestationBinding } from './attestation';
export {
  generateRecoveryCode,
  deriveRecoveryIdentity,
  normalizeRecoveryCode,
  RECOVERY_CODE_WORDS,
} from './recovery';
export { bytesToBase64, base64ToBytes } from './encoding';
