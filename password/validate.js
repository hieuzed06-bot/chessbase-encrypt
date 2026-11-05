/**
 * password/validate.js
 * Single source of truth for all password validation rules.
 * Import this in both the crypto layer and the UI layer
 * so the rules never diverge.
 */

const TE = new TextEncoder();

export const MIN_PASSWORD_CODE_POINTS = 16;
export const MAX_PASSWORD_BYTES = 1024;

/**
 * Validate a passphrase before encryption.
 * Returns null when the password is acceptable,
 * or a human-readable error string when it is not.
 *
 * Decryption deliberately skips this check for
 * backward-compatibility with older files.
 *
 * @param {string} password
 * @returns {string|null}
 */
export function validateEncryptionPassword(password) {
  if (typeof password !== 'string') return 'Password is required.';
  if (Array.from(password).length < MIN_PASSWORD_CODE_POINTS) {
    return `Use a password or passphrase of at least ${MIN_PASSWORD_CODE_POINTS} characters.`;
  }
  if (TE.encode(password).length > MAX_PASSWORD_BYTES) {
    return `Password must not exceed ${MAX_PASSWORD_BYTES.toLocaleString()} UTF-8 bytes.`;
  }
  if (!password.trim()) return 'Password cannot contain only whitespace.';
  return null;
}
