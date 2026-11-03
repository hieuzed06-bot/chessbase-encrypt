import { toPGN, fromPGN, MAX_SOURCE_BYTES, MAX_PGN_BYTES } from './codec.js';
import { encryptBytes, decryptBytes, encryptRawBytes, decryptRawBytes } from './crypto-v3.js';

// ── Self-decrypt page template ─────────────────────────
function buildProtectedPage(pgn){
  const nonceBytes=crypto.getRandomValues(new Uint8Array(16));
  const nonce=btoa(String.fromCharCode(...nonceBytes));
  // Cipher PGN alphabet cannot contain a backtick, so it is safe in this template literal.
  return`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>Protected Code — Chess Cipher</title>
<style>
*{box-sizing:border-box}body{margin:0;padding:28px 14px;background:#0d1117;color:#e6edf3;font:14px system-ui;display:grid;place-items:center;min-height:100vh}.card{width:100%;max-width:680px}h1{font-size:21px}p,.meta{color:#8b949e;font-size:12px;line-height:1.5}input,button,pre{width:100%;box-sizing:border-box;border-radius:8px;padding:11px;margin:6px 0;background:#161b22;color:#e6edf3;border:1px solid #30363d}button{background:#769656;border:0;font-weight:700;cursor:pointer}button:disabled{opacity:.5}pre{white-space:pre-wrap;overflow:auto;max-height:65vh}#out{display:none}.err{color:#f85149;min-height:18px}
</style></head><body><main class="card"><h1>🔐 Protected Code</h1><p>CCX v3 · PBKDF2-SHA256 · HKDF · AES-256-GCM · Chess notation</p>
<label for="pw">Password</label><input id="pw" type="password" autocomplete="current-password" placeholder="Enter password">
<button id="btn">🔓 Unlock</button><div id="err" class="err"></div><section id="out"><p>Decrypted source code</p><pre id="code"></pre><button id="copy">Copy code</button><div id="meta" class="meta"></div></section></main>
<script nonce="\${nonce}">
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
async function unlock(){
 const btn=document.getElementById('btn'),err=document.getElementById('err'),pw=document.getElementById('pw').value;
 err.textContent='';if(!pw){err.textContent='Password is required.';return;}
 btn.disabled=true;btn.textContent='Decrypting…';
 try{const plain=await decrypt(parse(PGN),pw);if(plain.length>=8&&plain[0]===67&&plain[1]===67&&plain[2]===88&&plain[3]===70){const n=new DataView(plain.buffer,plain.byteOffset,plain.byteLength).getUint32(4,false);if(n<2||n>1024||8+n>plain.length)throw Error('Invalid file metadata');const meta=JSON.parse(dec.decode(plain.subarray(8,8+n)));const name=String(meta.name||'download.bin').split(/[\\\\/]/).pop().replace(/[\\u0000-\\u001f\\u007f]/g,'').slice(0,180)||'download.bin';const type=typeof meta.type==='string'&&/^[a-z0-9.+-]+\\/[a-z0-9.+-]+$/i.test(meta.type)?meta.type:'application/octet-stream';const url=URL.createObjectURL(new Blob([plain.slice(8+n)],{type}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),10000);document.getElementById('meta').textContent='File downloaded: '+name;document.getElementById('out').style.display='block';}else{const code=dec.decode(plain);document.getElementById('code').textContent=code;document.getElementById('out').style.display='block';document.getElementById('meta').textContent=code.split('\\n').length+' lines · '+code.length+' characters';}btn.textContent='✓ Unlocked';}
 catch(e){err.textContent='Wrong password, corrupted data, or unsupported file.';btn.disabled=false;btn.textContent='🔓 Unlock';}
}
document.getElementById('btn').addEventListener('click',unlock);
document.getElementById('pw').addEventListener('keydown',e=>{if(e.key==='Enter')unlock();});
document.getElementById('copy').addEventListener('click',()=>navigator.clipboard.writeText(document.getElementById('code').textContent));
<\/script></body></html>`;
}

// ── UI state ────────────────────────────────────────────
let mode='protect', lastPGN='', lastEncrypted=null, selectedFile=null, selectedCipherFile=null;

function setMode(m){
  mode=m;
  document.getElementById('tab-protect').className='tab'+(m==='protect'?' active':'');
  document.getElementById('tab-unlock').className='tab'+(m==='unlock'?' active':'');
  document.getElementById('panel-protect').style.display=m==='protect'?'':'none';
  document.getElementById('panel-unlock').style.display=m==='unlock'?'':'none';
}

function setBusy(id, busy, label){
  const btn=document.getElementById(id);
  btn.disabled=busy;
  btn.innerHTML=busy
    ?'<div class="spin"></div><span>Working…</span>'
    :`<span id="${id==='enc-btn'?'enc-label':'dec-label'}">${label}</span>`;
}

// ── Protect ─────────────────────────────────────────────
function updateSrcInfo(){
  const v=document.getElementById('src').value;
  const lines=v?v.split('\n').length:0;
  const bytes=new TextEncoder().encode(v).length;
  document.getElementById('src-info').textContent=lines+' lines · '+fmt(bytes);
}

async function doEncrypt(){
  const src=document.getElementById('src').value;
  const pw=document.getElementById('pass-enc').value;
  const confirmPw=document.getElementById('pass-confirm').value;
  showMsg('enc-err','','');
  if(pw!==confirmPw){showMsg('enc-err','Passwords do not match.','err');showToast('Passwords do not match.','error');return;}
  if(Array.from(pw).length<16){showMsg('enc-err','Use a password or passphrase of at least 16 characters.','err');showToast('Password must be at least 16 characters.','error');return;}
  if(new TextEncoder().encode(pw).length>1024){showMsg('enc-err','Password must not exceed 1,024 UTF-8 bytes.','err');showToast('Password is too long.','error');return;}
  if(!pw.trim()){showMsg('enc-err','Password cannot contain only whitespace.','err');showToast('Password cannot contain only whitespace.','error');return;}
  if(!selectedFile&&!src.trim()){showMsg('enc-err','Choose a file or enter source text.','err');showToast('Choose a file or enter source text first.','error');return;}
  setBusy('enc-btn',true,'');
  try{
    const sourceBytes=selectedFile?new Uint8Array(await selectedFile.arrayBuffer()):new TextEncoder().encode(src);
    const payload=selectedFile?packFilePayload(selectedFile,sourceBytes):sourceBytes;
    if(payload.length>MAX_SOURCE_BYTES)throw new Error('File or source exceeds the 1 MiB encrypted payload limit.');
    const buf=await encryptRawBytes(payload,pw);
    lastEncrypted=buf;
    lastPGN=toPGN(buf);
    document.getElementById('pgn-out').value=lastPGN;
    document.getElementById('pgn-meta').textContent=buf.length+' moves · '+fmt(buf.length);
    document.getElementById('enc-result').style.display='block';
    showMsg('enc-msg','Encryption complete. Download the .ccx file, copy the PGN, or save the protected HTML page.','ok');showToast('Encryption completed successfully.');
  }catch(e){showMsg('enc-err',e.message,'err');showToast(e.message,'error');}
  finally{setBusy('enc-btn',false,'🔐 Encrypt');}
}

function copyPGN(){
  navigator.clipboard.writeText(lastPGN).then(()=>{showToast('Encrypted PGN copied to clipboard.');
    const t=document.getElementById('pgn-copy');
    t.textContent='Copied!';setTimeout(()=>t.textContent='Copy',1800);
  }).catch(()=>showToast('Could not access the clipboard.','error'));
}

function downloadEncrypted(){
  if(!lastEncrypted)return;
  downloadBytes(lastEncrypted,'protected-file.ccx','application/octet-stream');showToast('Encrypted .ccx file download started.');
}

function downloadPage(){
  if(!lastPGN) return;
  const html=buildProtectedPage(lastPGN);
  const blob=new Blob([html],{type:'text/html'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='protected-code.html';
  a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href),5000);
  showToast('Protected HTML page download started.');
}

function clearEnc(){
  document.getElementById('src').value='';
  document.getElementById('file-input').value='';selectedFile=null;
  document.getElementById('file-info').textContent='No file selected';
  document.getElementById('pass-enc').value='';
  document.getElementById('pass-confirm').value='';
  document.getElementById('pgn-out').value='';
  document.getElementById('enc-result').style.display='none';
  document.getElementById('src-info').textContent='0 lines · 0 B';
  showMsg('enc-err','','');showMsg('enc-msg','','');
  lastPGN='';lastEncrypted=null;
  showToast('Workspace cleared.');
}

// ── Unlock ───────────────────────────────────────────────
async function doDecrypt(){
  let pgn=document.getElementById('pgn-in').value.trim();
  const pw=document.getElementById('pass-dec').value;
  showMsg('dec-msg','','');
  if(!pw){showMsg('dec-msg','Password is required.','err');showToast('Enter your password to continue.','error');return;}
  if(!pgn&&!selectedCipherFile){showMsg('dec-msg','Choose a .ccx file or paste PGN to unlock.','err');showToast('Choose an encrypted file or paste PGN first.','error');return;}
  if(pgn&&new TextEncoder().encode(pgn).length>MAX_PGN_BYTES){showMsg('dec-msg','PGN exceeds the 8 MiB limit.','err');showToast('PGN exceeds the 8 MiB limit.','error');return;}
  // Accept protected HTML — extract PGN from template literal
  if(pgn.startsWith('<!DOCTYPE')||pgn.startsWith('<html')){
    const m=pgn.match(/const PGN=`([\s\S]*?)`;/);
    if(!m){showMsg('dec-msg','Could not extract PGN from HTML file.','err');showToast('Could not read encrypted data from this HTML file.','error');return;}
    pgn=m[1].replace(/\\`/g,'`').replace(/\\\\/g,'\\');
  }
  setBusy('dec-btn',true,'');
  try{
    const buf=selectedCipherFile?new Uint8Array(await selectedCipherFile.arrayBuffer()):fromPGN(pgn);
    const plain=await decryptRawBytes(buf,pw);
    const file=parseFilePayload(plain);
    if(file){downloadBytes(file.bytes,file.name,file.type);document.getElementById('dec-result').style.display='none';showMsg('dec-msg','File decrypted. Download started: '+file.name,'ok');showToast('File decrypted successfully. Download started.');}
    else{const code=new TextDecoder('utf-8',{fatal:true}).decode(plain);document.getElementById('code-out').value=code;document.getElementById('dec-result').style.display='block';const lines=code.split('\n').length;document.getElementById('dec-meta').textContent=lines+' lines · '+code.length+' chars';showMsg('dec-msg','Decryption complete. Authentication verified.','ok');showToast('Decryption completed successfully.');}
  }catch(e){
    document.getElementById('dec-result').style.display='none';
    showMsg('dec-msg',e.message,'err');showToast(e.message,'error');
  }
  finally{setBusy('dec-btn',false,'🔓 Decrypt');}
}

function copyDecCode(){
  navigator.clipboard.writeText(document.getElementById('code-out').value).then(()=>{showToast('Decrypted text copied to clipboard.');
    const t=document.getElementById('dec-copy');
    t.textContent='Copied!';setTimeout(()=>t.textContent='Copy',1800);
  }).catch(()=>showToast('Could not access the clipboard.','error'));
}

function clearDecMsg(){showMsg('dec-msg','','');}


const FILE_PREFIX=new Uint8Array([67,67,88,70]);
const ALLOWED_EXTENSIONS=new Set(['pdf','xls','xlsx','xlsm','doc','docx','docm','lua','luau','txt','js','mjs','cjs','sh','bash','zsh','command','cs','bat','cmd','ps1','psm1','py','json','csv','xml','html','css','sql','md']);
function packFilePayload(file,bytes){
  const name=file.name.split(/[\\/]/).pop().replace(/[\u0000-\u001f\u007f]/g,'').slice(0,180);
  const ext=(name.split('.').pop()||'').toLowerCase();
  if(!ALLOWED_EXTENSIONS.has(ext))throw new Error('Unsupported file extension. Supported: PDF, Excel, Word, Lua/Luau, TXT, JS, SH, C# and terminal scripts.');
  const type=/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(file.type)?file.type:'application/octet-stream';
  const meta=new TextEncoder().encode(JSON.stringify({name,type}));
  const out=new Uint8Array(8+meta.length+bytes.length);
  out.set(FILE_PREFIX,0);new DataView(out.buffer).setUint32(4,meta.length,false);out.set(meta,8);out.set(bytes,8+meta.length);
  return out;
}
function parseFilePayload(bytes){
  if(bytes.length<8||!FILE_PREFIX.every((b,i)=>bytes[i]===b))return null;
  const n=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getUint32(4,false);
  if(n<2||n>1024||8+n>bytes.length)throw new Error('Invalid encrypted file metadata.');
  const meta=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(8,8+n)));
  const name=String(meta.name||'download.bin').split(/[\\/]/).pop().replace(/[\u0000-\u001f\u007f]/g,'').slice(0,180)||'download.bin';
  const type=typeof meta.type==='string'&&/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(meta.type)?meta.type:'application/octet-stream';
  return {name,type,bytes:bytes.slice(8+n)};
}
function downloadBytes(bytes,name,type){
  const url=URL.createObjectURL(new Blob([bytes],{type:type||'application/octet-stream'})),a=document.createElement('a');
  a.href=url;a.download=name;a.rel='noopener';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),10000);
}
async function handleFileSelection(){
  const file=document.getElementById('file-input').files[0];selectedFile=file||null;
  document.getElementById('file-info').textContent=file?file.name+' · '+fmt(file.size):'No file selected';
  if(file)document.getElementById('src').value='';
  updateSrcInfo();
  if(file)showToast('File selected: '+file.name);
}

async function handleCipherFileSelection(){
  const file=document.getElementById('pgn-file').files[0];
  const info=document.getElementById('pgn-file-info');
  selectedCipherFile=null;
  document.getElementById('pgn-in').value='';
  if(!file){info.textContent='Supports .ccx, .pgn, .txt, and protected HTML';return;}
  info.textContent=file.name+' · '+fmt(file.size);
  showToast('Selected: '+file.name);
  const ext=(file.name.split('.').pop()||'').toLowerCase();
  if(ext==='ccx'){
    selectedCipherFile=file;
  }else{
    if(file.size>MAX_PGN_BYTES){info.textContent='File is too large (8 MiB maximum)';showMsg('dec-msg','PGN/HTML exceeds the 8 MiB limit.','err');return;}
    document.getElementById('pgn-in').value=await file.text();
    selectedCipherFile=null;
  }
  clearDecMsg();
}

let toastTimer=null;
function showToast(message,type='success'){
  const toast=document.getElementById('toast');
  const text=document.getElementById('toast-text');
  const icon=document.getElementById('toast-icon');
  if(!toast||!text||!icon)return;
  text.textContent=String(message);
  toast.classList.toggle('error',type==='error');
  icon.textContent=type==='error'?'!':'✓';
  toast.classList.add('show');
  if(toastTimer)clearTimeout(toastTimer);
  toastTimer=setTimeout(()=>toast.classList.remove('show'),3200);
}

// ── Utils ────────────────────────────────────────────────
function showMsg(id,text,cls){
  const el=document.getElementById(id);
  if(el){el.textContent=text;el.className='msg'+(cls?' '+cls:'');}
}
function fmt(b){ return b<1024?b+' B':Math.round(b/1024*10)/10+' KB'; }

// Bind controls without inline event-handler attributes.
document.getElementById('tab-protect').addEventListener('click',()=>setMode('protect'));
document.getElementById('tab-unlock').addEventListener('click',()=>setMode('unlock'));
document.getElementById('src').addEventListener('input',()=>{selectedFile=null;document.getElementById('file-input').value='';document.getElementById('file-info').textContent='No file selected';updateSrcInfo();});
document.getElementById('file-input').addEventListener('change',handleFileSelection);
document.getElementById('enc-btn').addEventListener('click',doEncrypt);
document.getElementById('pgn-copy-btn').addEventListener('click',copyPGN);
document.getElementById('dl-btn').addEventListener('click',downloadPage);
document.getElementById('dl-ccx-btn').addEventListener('click',downloadEncrypted);
document.getElementById('clear-enc-btn').addEventListener('click',clearEnc);
document.getElementById('pgn-in').addEventListener('input',()=>{selectedCipherFile=null;document.getElementById('pgn-file').value='';document.getElementById('pgn-file-info').textContent='Hỗ trợ .ccx, .pgn, .txt và HTML đã bảo vệ';clearDecMsg();});
document.getElementById('pgn-file').addEventListener('change',handleCipherFileSelection);
document.getElementById('dec-btn').addEventListener('click',doDecrypt);
document.getElementById('dec-copy-btn').addEventListener('click',copyDecCode);
