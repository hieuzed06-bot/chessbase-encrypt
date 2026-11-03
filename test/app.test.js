import test from 'node:test';
import assert from 'node:assert/strict';
import { buildProtectedPage, packFilePayload, parseFilePayload } from '../app.js';

test('file payloads preserve bytes and remove local path components', () => {
  const file = {
    name: `folder${String.fromCharCode(92)}private.js`,
    type: 'text/javascript',
  };
  const source = new Uint8Array([0, 1, 127, 128, 255]);
  const payload = packFilePayload(file, source);
  const restored = parseFilePayload(payload);

  assert.equal(restored.name, 'private.js');
  assert.equal(restored.type, 'text/javascript');
  assert.deepEqual(restored.bytes, source);
});

test('file payloads reject unsupported extensions and oversized metadata payloads', () => {
  assert.throws(
    () => packFilePayload({ name: 'payload.exe', type: 'application/octet-stream' }, new Uint8Array([1])),
    /Unsupported file extension/,
  );
  assert.throws(
    () => packFilePayload({ name: 'large.txt', type: 'text/plain' }, new Uint8Array(1024 * 1024)),
    /1 MiB encrypted payload limit/,
  );
});

test('protected HTML binds its decryptor to the page nonce', () => {
  const pgn = '[Event "Secret"]\n\n1. a1 *';
  const html = buildProtectedPage(pgn);
  const cspNonce = html.match(/script-src 'nonce-([^']+)'/)?.[1];
  const scriptNonce = html.match(/<script nonce="([^"]+)">/)?.[1];
  const script = html.match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/)?.[1];

  assert.ok(cspNonce);
  assert.equal(scriptNonce, cspNonce);
  assert.ok(script);
  assert.ok(script.includes(`const PGN=\`${pgn}\`;`));
  assert.doesNotThrow(() => new Function(script));
});
