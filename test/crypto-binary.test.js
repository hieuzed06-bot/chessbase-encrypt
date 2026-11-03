import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { encryptRawBytes, decryptRawBytes, encryptBytes, decryptBytes } from '../crypto-v3.js';

globalThis.crypto ??= webcrypto;
const password = 'correct horse battery staple';

test('binary encryption round-trips arbitrary bytes without UTF-8 conversion', async () => {
  const original = new Uint8Array([0, 255, 1, 128, 13, 10, 0, 42, 254]);
  const encrypted = await encryptRawBytes(original, password);
  const decrypted = await decryptRawBytes(encrypted, password);
  assert.deepEqual(decrypted, original);
});

test('text encryption API remains backward compatible', async () => {
  const original = 'Lua/Luau 🧩\nprint("hello")';
  const encrypted = await encryptBytes(original, password);
  assert.equal(await decryptBytes(encrypted, password), original);
});

test('binary decrypt rejects a wrong password', async () => {
  const encrypted = await encryptRawBytes(new Uint8Array([0, 255, 17]), password);
  await assert.rejects(() => decryptRawBytes(encrypted, 'incorrect password'), /decrypt|operation|authentication/i);
});
