// CCX v3 cryptographic envelope.
// Web Crypto is used throughout; chess notation remains an encoding layer only.
export { validateEncryptionPassword } from './password/validate.js';
import { validateEncryptionPassword } from './password/validate.js';

const TE = new TextEncoder();
const TD = new TextDecoder('utf-8', { fatal: true });
const MAGIC = TE.encode('CCX3');
const ITERATIONS = 1_000_000;
const AAD = TE.encode('CodeLocker|CCX|3|PBKDF2-SHA256|1000000|AES-256-GCM|MOVE-CODEC-1');
const MAX_SOURCE_BYTES = 1024 * 1024;
const MAX_PADDED_BYTES = 2 * 1024 * 1024;

function randomBytes(length) {
  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 65536) {
    crypto.getRandomValues(out.subarray(offset, Math.min(offset + 65536, length)));
  }
  return out;
}

async function deriveV3Key(password, salt, usage) {
  const passwordKey = await crypto.subtle.importKey(
    'raw', TE.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const master = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    passwordKey, 256
  );
  const hkdfKey = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: TE.encode('CCX v3 AES-256-GCM') },
    hkdfKey, { name: 'AES-GCM', length: 256 }, false, [usage]
  );
}

function packWithRandomPadding(plain) {
  if (plain.length > MAX_SOURCE_BYTES) throw new Error('Source exceeds the 1 MiB limit.');
  const needed = plain.length + 4;
  let size = 256;
  while (size < needed) size *= 2;
  if (size > MAX_PADDED_BYTES) throw new Error('Padded data exceeds the size limit.');
  const packed = randomBytes(size);
  new DataView(packed.buffer).setUint32(0, plain.length, false);
  packed.set(plain, 4);
  return packed;
}

function unpackAndValidate(packed) {
  if (packed.length < 256 || packed.length > MAX_PADDED_BYTES ||
      (packed.length & (packed.length - 1)) !== 0) {
    throw new Error('Invalid CCX v3 padded payload.');
  }
  const length = new DataView(packed.buffer, packed.byteOffset, packed.byteLength).getUint32(0, false);
  if (length > MAX_SOURCE_BYTES || length > packed.length - 4) {
    throw new Error('Invalid CCX v3 plaintext length.');
  }
  return packed.slice(4, 4 + length);
}

export async function encryptRawBytes(plain, password) {
  const passwordError = validateEncryptionPassword(password);
  if (passwordError) throw new Error(passwordError);
  if (!(plain instanceof Uint8Array)) throw new TypeError('Expected plaintext bytes.');
  if (plain.length > MAX_SOURCE_BYTES) throw new Error('Source exceeds the 1 MiB limit.');
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveV3Key(password, salt, 'encrypt');
  const packed = packWithRandomPadding(plain);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: AAD, tagLength: 128 }, key, packed
  ));
  const envelope = new Uint8Array(32 + ciphertext.length);
  envelope.set(MAGIC, 0);
  envelope.set(salt, 4);
  envelope.set(iv, 20);
  envelope.set(ciphertext, 32);
  return envelope;
}

async function decryptV3(buffer, password) {
  if (buffer.length < 32 + 256 + 16) throw new Error('CCX v3 data is truncated.');
  const salt = buffer.subarray(4, 20);
  const iv = buffer.subarray(20, 32);
  const key = await deriveV3Key(password, salt, 'decrypt');
  const packed = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: AAD, tagLength: 128 },
    key, buffer.subarray(32)
  ));
  return unpackAndValidate(packed);
}

async function decryptLegacy(buffer, password) {
  if (buffer.length < 45) throw new Error('Data too short — corrupted or invalid PGN.');
  // Both legacy work-factor attempts run in parallel via Promise.allSettled so
  // neither attempt reveals which work factor matched through a timing signal,
  // while also being faster than sequential attempts.
  const salt = buffer.subarray(0, 16);
  const iv   = buffer.subarray(16, 28);
  const ct   = buffer.subarray(28);
  const rawKey = TE.encode(password);

  async function attempt(iterations) {
    const base = await crypto.subtle.importKey('raw', rawKey, 'PBKDF2', false, ['deriveKey']);
    const key  = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
  }

  const [r600k, r100k] = await Promise.allSettled([attempt(600000), attempt(100000)]);
  if (r600k.status === 'fulfilled') return r600k.value;
  if (r100k.status === 'fulfilled') return r100k.value;
  throw new Error('Decryption failed — wrong password or data was tampered with.');
}

export async function decryptRawBytes(buffer, password) {
  if (!(buffer instanceof Uint8Array)) throw new TypeError('Expected encrypted bytes.');
  if (typeof password !== 'string' || !password.length) throw new Error('Password is required.');
  const isV3 = buffer.length >= 4 && MAGIC.every((byte, i) => buffer[i] === byte);
  return isV3 ? decryptV3(buffer, password) : decryptLegacy(buffer, password);
}

export async function encryptBytes(text, password) {
  if (typeof text !== 'string') throw new TypeError('Expected text.');
  return encryptRawBytes(TE.encode(text), password);
}

export async function decryptBytes(buffer, password) {
  return TD.decode(await decryptRawBytes(buffer, password));
}

export const CCX_V3_ITERATIONS = ITERATIONS;
