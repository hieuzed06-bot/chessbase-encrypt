import { MAX_SOURCE_BYTES } from './codec.js';

const FILE_PREFIX = new Uint8Array([67, 67, 88, 70]);
const ALLOWED_EXTENSIONS = new Set([
  'pdf', 'xls', 'xlsx', 'xlsm', 'doc', 'docx', 'docm', 'lua', 'luau', 'txt',
  'js', 'mjs', 'cjs', 'sh', 'bash', 'zsh', 'command', 'cs', 'bat', 'cmd',
  'ps1', 'psm1', 'py', 'json', 'csv', 'xml', 'html', 'css', 'sql', 'md',
]);

export const MAX_CIPHER_BYTES = 2 * 1024 * 1024 + 48;

function cleanFileName(value) {
  return String(value)
    .replaceAll(String.fromCharCode(92), '/')
    .split('/')
    .pop()
    .split('')
    .filter((character) => {
      const code = character.charCodeAt(0);
      return code >= 32 && code !== 127;
    })
    .join('')
    .slice(0, 180);
}

function isValidMimeType(value) {
  const parts = typeof value === 'string' ? value.split('/') : [];
  return parts.length === 2 && parts.every((part) => /^[a-z0-9.+-]+$/i.test(part));
}

export function formatBytes(bytes) {
  return bytes < 1024 ? `${bytes} B` : `${Math.round((bytes / 1024) * 10) / 10} KB`;
}

export function packFilePayload(file, bytes) {
  const name = cleanFileName(file.name);
  const extension = (name.split('.').pop() || '').toLowerCase();

  if (!ALLOWED_EXTENSIONS.has(extension)) {
    throw new Error('Unsupported file extension. Supported: PDF, Excel, Word, Lua/Luau, TXT, JS, SH, C# and terminal scripts.');
  }

  const type = isValidMimeType(file.type) ? file.type : 'application/octet-stream';
  const metadata = new TextEncoder().encode(JSON.stringify({ name, type }));
  const payload = new Uint8Array(8 + metadata.length + bytes.length);

  payload.set(FILE_PREFIX, 0);
  new DataView(payload.buffer).setUint32(4, metadata.length, false);
  payload.set(metadata, 8);
  payload.set(bytes, 8 + metadata.length);

  if (payload.length > MAX_SOURCE_BYTES) {
    throw new Error('File or source exceeds the 1 MiB encrypted payload limit.');
  }

  return payload;
}

export function parseFilePayload(bytes) {
  if (bytes.length < 8 || !FILE_PREFIX.every((byte, index) => bytes[index] === byte)) {
    return null;
  }

  const metadataLength = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(4, false);
  if (metadataLength < 2 || metadataLength > 1024 || 8 + metadataLength > bytes.length) {
    throw new Error('Invalid encrypted file metadata.');
  }

  const metadata = JSON.parse(
    new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(8, 8 + metadataLength)),
  );
  const name = cleanFileName(metadata.name || 'download.bin') || 'download.bin';
  const type = isValidMimeType(metadata.type) ? metadata.type : 'application/octet-stream';

  return { name, type, bytes: bytes.slice(8 + metadataLength) };
}

export function downloadBytes(bytes, name, type = 'application/octet-stream') {
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name;
  anchor.rel = 'noopener';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export function buildProtectedPage(pgn) {
  const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = btoa(String.fromCharCode(...nonceBytes));

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>Protected Code — Chess Cipher</title>
<style>
*{box-sizing:border-box}body{margin:0;padding:28px 14px;background:#0d1117;color:#e6edf3;font:14px system-ui;display:grid;place-items:center;min-height:100vh}.card{width:100%;max-width:680px}h1{font-size:21px}p,.meta{color:#8b949e;font-size:12px;line-height:1.5}input,button,pre{width:100%;box-sizing:border-box;border-radius:8px;padding:11px;margin:6px 0;background:#161b22;color:#e6edf3;border:1px solid #30363d}button{background:#769656;border:0;font-weight:700;cursor:pointer}button:disabled{opacity:.5}pre{white-space:pre-wrap;overflow:auto;max-height:65vh}#out{display:none}.err{color:#f85149;min-height:18px}
</style></head><body><main class="card"><h1>Protected Code</h1><p>CCX v3 · PBKDF2-SHA256 · HKDF · AES-256-GCM · Chess notation</p>
<label for="pw">Password</label><input id="pw" type="password" autocomplete="current-password" placeholder="Enter password">
<button id="btn">Unlock</button><div id="err" class="err" role="status" aria-live="polite"></div><section id="out"><p>Decrypted source code</p><pre id="code"></pre><button id="copy">Copy code</button><div id="meta" class="meta"></div></section></main>
<script nonce="${nonce}">
'use strict';
const PGN=\`${pgn}\`;
const enc=new TextEncoder(), dec=new TextDecoder('utf-8',{fatal:true});
const AAD=enc.encode('CodeLocker|CCX|3|PBKDF2-SHA256|1000000|AES-256-GCM|MOVE-CODEC-1');
const P=['','N','B','R'],F='abcdefgh',R='12345678';
function parse(pgn){
 if(enc.encode(pgn).length>8*1024*1024)throw Error('PGN exceeds 8 MiB.');
 const body=pgn.split(/\\r?\\n/).filter(l=>!/^\\s*\\[[A-Za-z][A-Za-z0-9_]*\\s+"[^"\\r\\n]*"\\]\\s*$/.test(l)).join(' ');
 const tokens=body.trim().split(/\\s+/).filter(Boolean),out=[];
 for(const t of tokens){if(/^\\d+\\.(?:\\.\\.)?$/.test(t)||['*','1-0','0-1','1/2-1/2'].includes(t))continue;
  if(!/^(?:[NBR])?[a-h][1-8]$/.test(t))throw Error('Invalid chess-cipher token.');
  const p=t.length===3?P.indexOf(t[0]):0, f=F.indexOf(t[t.length-2]), r=R.indexOf(t[t.length-1]);
  if(p<0||f<0||r<0)throw Error('Invalid move token.');out.push((p<<6)|(f<<3)|r);
  if(out.length>2*1024*1024+48)throw Error('Too many encrypted moves.');
 }
 if(!out.length)throw Error('No encrypted moves found.');
 return new Uint8Array(out);
}
async function deriveV3(password,salt){
 const base=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);
 const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:1000000,hash:'SHA-256'},base,256);
 const hk=await crypto.subtle.importKey('raw',bits,'HKDF',false,['deriveKey']);
 return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt,info:enc.encode('CCX v3 AES-256-GCM')},hk,{name:'AES-GCM',length:256},false,['decrypt']);
}
async function decrypt(bytes,password){
 const isV3=bytes.length>=4&&bytes[0]===67&&bytes[1]===67&&bytes[2]===88&&bytes[3]===51;
 if(isV3){
  if(bytes.length<304)throw Error('CCX v3 data is truncated.');
  const key=await deriveV3(password,bytes.subarray(4,20));
  const packed=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.subarray(20,32),additionalData:AAD,tagLength:128},key,bytes.subarray(32)));
  if(packed.length<256||packed.length>2*1024*1024||(packed.length&(packed.length-1))!==0)throw Error('Invalid padded payload.');
  const n=new DataView(packed.buffer,packed.byteOffset,packed.byteLength).getUint32(0,false);
  if(n>1024*1024||n>packed.length-4)throw Error('Invalid plaintext length.');
  return packed.slice(4,4+n);
 }
 if(bytes.length<45)throw Error('Legacy data is truncated.');
 let recovered=null;
 for(const iterations of [600000,100000]){
  try{const base=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveKey']);
   const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:bytes.subarray(0,16),iterations,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
   const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.subarray(16,28)},key,bytes.subarray(28));
   if(recovered===null)recovered=new Uint8Array(plain);
  }catch{}
 }
 if(recovered!==null)return recovered;
 throw Error('Wrong password or damaged data.');
}
function cleanName(value){
 return String(value||'download.bin').replaceAll(String.fromCharCode(92),'/').split('/').pop().split('').filter(character=>{const code=character.charCodeAt(0);return code>=32&&code!==127}).join('').slice(0,180)||'download.bin';
}
function validType(value){
 const parts=typeof value==='string'?value.split('/') : [];
 return parts.length===2&&parts.every(part=>/^[a-z0-9.+-]+$/i.test(part));
}
async function unlock(){
 const button=document.getElementById('btn'),error=document.getElementById('err'),password=document.getElementById('pw').value;
 error.textContent='';if(!password){error.textContent='Password is required.';return;}
 button.disabled=true;button.textContent='Decrypting…';
 try{
  const plain=await decrypt(parse(PGN),password);
  if(plain.length>=8&&plain[0]===67&&plain[1]===67&&plain[2]===88&&plain[3]===70){
   const n=new DataView(plain.buffer,plain.byteOffset,plain.byteLength).getUint32(4,false);
   if(n<2||n>1024||8+n>plain.length)throw Error('Invalid file metadata');
   const meta=JSON.parse(dec.decode(plain.subarray(8,8+n)));
   const name=cleanName(meta.name);
   const type=validType(meta.type)?meta.type:'application/octet-stream';
   const url=URL.createObjectURL(new Blob([plain.slice(8+n)],{type}));
   const anchor=document.createElement('a');anchor.href=url;anchor.download=name;anchor.click();setTimeout(()=>URL.revokeObjectURL(url),10000);
   document.getElementById('meta').textContent='File downloaded: '+name;document.getElementById('out').style.display='block';
  }else{
   const code=dec.decode(plain);document.getElementById('code').textContent=code;document.getElementById('out').style.display='block';
   document.getElementById('meta').textContent=code.split('\\n').length+' lines · '+code.length+' characters';
  }
  button.textContent='Unlocked';
 }catch{
  error.textContent='Wrong password, corrupted data, or unsupported file.';button.disabled=false;button.textContent='Unlock';
 }
}
document.getElementById('btn').addEventListener('click',unlock);
document.getElementById('pw').addEventListener('keydown',event=>{if(event.key==='Enter')unlock();});
document.getElementById('copy').addEventListener('click',()=>navigator.clipboard.writeText(document.getElementById('code').textContent));
<\/script></body></html>`;
}
