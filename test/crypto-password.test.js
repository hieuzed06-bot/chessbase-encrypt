import test from 'node:test';
import assert from 'node:assert/strict';
import { validateEncryptionPassword } from '../crypto-v3.js';

test('requires a passphrase of at least 16 Unicode characters', () => {
  assert.match(validateEncryptionPassword('short'), /at least 16/);
  assert.equal(validateEncryptionPassword('correct horse battery'), null);
});

test('counts Unicode code points rather than UTF-16 code units', () => {
  assert.equal(validateEncryptionPassword('😀'.repeat(16)), null);
  assert.match(validateEncryptionPassword('😀'.repeat(15)), /at least 16/);
});

test('rejects whitespace-only and oversized passwords', () => {
  assert.match(validateEncryptionPassword(' '.repeat(16)), /whitespace/);
  assert.match(validateEncryptionPassword('a'.repeat(1025)), /1,024/);
});

test('does not accept non-string password values', () => {
  assert.match(validateEncryptionPassword(null), /required/);
});
