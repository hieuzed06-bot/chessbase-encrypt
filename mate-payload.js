import { MAX_SOURCE_BYTES } from './codec.js';

const MAGIC = new Uint8Array([67, 67, 88, 77, 1]); // CCXM v1
const MAX_MATE_BYTES = 4096;
const decoder = new TextDecoder('utf-8', { fatal: true });

export function packMatePayload(payload, mate = '') {
  if (!(payload instanceof Uint8Array)) throw new TypeError('Expected payload bytes.');
  if (typeof mate !== 'string') throw new TypeError('Mate must be text.');
  const secret = new TextEncoder().encode(mate);
  if (secret.length > MAX_MATE_BYTES) throw new Error('Mate content exceeds the 4 KiB limit.');
  if (secret.length === 0) return payload;
  const total = MAGIC.length + 4 + secret.length + payload.length;
  if (total > MAX_SOURCE_BYTES) throw new Error('Payload plus mate content exceeds the 1 MiB limit.');
  const packed = new Uint8Array(total);
  packed.set(MAGIC, 0);
  new DataView(packed.buffer).setUint32(MAGIC.length, secret.length, false);
  packed.set(secret, MAGIC.length + 4);
  packed.set(payload, MAGIC.length + 4 + secret.length);
  return packed;
}

export function unpackMatePayload(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('Expected decrypted bytes.');
  const hasMagic = bytes.length >= MAGIC.length + 4 && MAGIC.every((value, index) => bytes[index] === value);
  if (!hasMagic) return { mate: '', payload: bytes };
  const length = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(MAGIC.length, false);
  if (length < 1 || length > MAX_MATE_BYTES || MAGIC.length + 4 + length > bytes.length) {
    throw new Error('Invalid encrypted mate metadata.');
  }
  const start = MAGIC.length + 4;
  const mate = decoder.decode(bytes.subarray(start, start + length));
  return { mate, payload: bytes.slice(start + length) };
}
