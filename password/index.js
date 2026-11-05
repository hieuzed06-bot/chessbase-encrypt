/**
 * password/index.js
 * Public API for the password subsystem.
 * Consumers import from here — internal layout can change
 * without breaking call sites.
 */
export {
  validateEncryptionPassword,
  MIN_PASSWORD_CODE_POINTS,
  MAX_PASSWORD_BYTES,
} from './validate.js';
