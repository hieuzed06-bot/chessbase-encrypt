import test from 'node:test';
import assert from 'node:assert/strict';
import { packMatePayload, unpackMatePayload } from '../mate-payload.js';

test('mate content round-trips inside the encrypted payload wrapper', () => {
  const payload = Uint8Array.of(0, 1, 2, 255);
  const packed = packMatePayload(payload, 'second secret 🔐');
  const unpacked = unpackMatePayload(packed);
  assert.equal(unpacked.mate, 'second secret 🔐');
  assert.deepEqual(unpacked.payload, payload);
});

test('empty mate leaves the legacy payload format unchanged', () => {
  const payload = Uint8Array.of(1, 2, 3);
  assert.equal(packMatePayload(payload, ''), payload);
  const unpacked = unpackMatePayload(payload);
  assert.equal(unpacked.mate, '');
  assert.equal(unpacked.payload, payload);
});

test('rejects oversized mate content and malformed wrappers', () => {
  assert.throws(() => packMatePayload(Uint8Array.of(1), 'x'.repeat(4097)), /4 KiB/);
  const malformed = Uint8Array.of(67, 67, 88, 77, 1, 0, 0, 0, 8, 65);
  assert.throws(() => unpackMatePayload(malformed), /Invalid encrypted mate/);
});
