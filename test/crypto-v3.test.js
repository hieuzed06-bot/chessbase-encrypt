import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { encryptBytes, decryptBytes } from '../crypto-v3.js';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

test('CCX v3 round-trips UTF-8 and uses fresh randomized envelopes', async () => {
  const source = 'const secret = "Xin chào ♟️";\nconsole.log(secret);';
  const a = await encryptBytes(source, 'correct horse battery staple');
  const b = await encryptBytes(source, 'correct horse battery staple');
  assert.equal(new TextDecoder().decode(a.subarray(0, 4)), 'CCX3');
  assert.notDeepEqual(a, b);
  assert.equal(await decryptBytes(a, 'correct horse battery staple'), source);
});

test('CCX v3 rejects a wrong password and modified ciphertext', async () => {
  const encrypted = await encryptBytes('tamper test', 'a sufficiently long password');
  await assert.rejects(() => decryptBytes(encrypted, 'wrong password'));
  const changed = encrypted.slice();
  changed[changed.length - 1] ^= 1;
  await assert.rejects(() => decryptBytes(changed, 'a sufficiently long password'));
});

test('CCX v3 supports empty plaintext', async () => {
  const encrypted = await encryptBytes('', 'empty input password');
  assert.equal(await decryptBytes(encrypted, 'empty input password'), '');
});
