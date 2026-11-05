/**
 * password/test/password.test.js
 * Tests for all password validation rules.
 * Relocated from test/crypto-password.test.js and extended.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validateEncryptionPassword,
  MIN_PASSWORD_CODE_POINTS,
  MAX_PASSWORD_BYTES,
} from '../validate.js';

test('requires a passphrase of at least MIN_PASSWORD_CODE_POINTS Unicode characters', () => {
  assert.match(validateEncryptionPassword('short'), /at least 16/);
  assert.equal(validateEncryptionPassword('correct horse battery'), null);
});

test('counts Unicode code points rather than UTF-16 code units', () => {
  assert.equal(validateEncryptionPassword('\u{1F600}'.repeat(MIN_PASSWORD_CODE_POINTS)), null);
  assert.match(validateEncryptionPassword('\u{1F600}'.repeat(MIN_PASSWORD_CODE_POINTS - 1)), /at least 16/);
});

test('rejects whitespace-only passwords', () => {
  assert.match(validateEncryptionPassword(' '.repeat(MIN_PASSWORD_CODE_POINTS)), /whitespace/);
});

test('rejects passwords exceeding MAX_PASSWORD_BYTES UTF-8 bytes', () => {
  assert.match(validateEncryptionPassword('a'.repeat(MAX_PASSWORD_BYTES + 1)), /1,024/);
});

test('does not accept non-string password values', () => {
  assert.match(validateEncryptionPassword(null), /required/);
  assert.match(validateEncryptionPassword(undefined), /required/);
  assert.match(validateEncryptionPassword(123), /required/);
});

test('accepts a password exactly at the minimum length', () => {
  assert.equal(validateEncryptionPassword('a'.repeat(MIN_PASSWORD_CODE_POINTS)), null);
});

test('accepts a password exactly at the maximum byte length', () => {
  assert.equal(validateEncryptionPassword('a'.repeat(MAX_PASSWORD_BYTES)), null);
});
