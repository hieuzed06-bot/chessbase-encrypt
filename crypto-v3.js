// CCX v3 cryptographic envelope.
// Web Crypto is used throughout; chess notation remains an encoding layer only.
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
  return TD.decode(packed.subarray(4, 4 + length));
}

export async function encryptBytes(text, password) {
  if (typeof password !== 'string' || !password.length) throw new Error('Password is required.');
  const plain = TE.encode(text);
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
  for (const iterations of [600000, 100000]) {
    try {
      const base = await crypto.subtle.importKey('raw', TE.encode(password), 'PBKDF2', false, ['deriveKey']);
      const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: buffer.subarray(0, 16), iterations, hash: 'SHA-256' },
        base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
      );
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: buffer.subarray(16, 28) }, key, buffer.subarray(28)
      );
      return TD.decode(plain);
    } catch {}
  }
  throw new Error('Decryption failed — wrong password or data was tampered with.');
}

export async function decryptBytes(buffer, password) {
  if (!(buffer instanceof Uint8Array)) throw new TypeError('Expected encrypted bytes.');
  if (typeof password !== 'string' || !password.length) throw new Error('Password is required.');
  const isV3 = buffer.length >= 4 && MAGIC.every((byte, i) => buffer[i] === byte);
  return isV3 ? decryptV3(buffer, password) : decryptLegacy(buffer, password);
}

export const CCX_V3_ITERATIONS = ITERATIONS;
