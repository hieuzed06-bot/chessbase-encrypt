import { toPGN, fromPGN, MAX_SOURCE_BYTES, MAX_PGN_BYTES } from './codec.js';
import { encryptBytes, decryptBytes } from './crypto-v3.js';

// ── Self-decrypt page template ─────────────────────────
function buildProtectedPage(pgn){
  const nonceBytes=crypto.getRandomValues(new Uint8Array(16));
  const nonce=btoa(String.fromCharCode(...nonceBytes));
  // Cipher PGN alphabet cannot contain a backtick, so it is safe in this template literal.
  return`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'nonce-\${nonce}'; style-src 'unsafe-inline'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>Protected Code — Chess Cipher</title>
<style>
*{box-sizing:border-box}body{margin:0;padding:28px 14px;background:#0d1117;color:#e6edf3;font:14px system-ui;display:grid;place-items:center;min-height:100vh}.card{width:100%;max-width:680px}h1{font-size:21px}p,.meta{color:#8b949e;font-size:12px;line-height:1.5}input,button,pre{width:100%;box-sizing:border-box;border-radius:8px;padding:11px;margin:6px 0;background:#161b22;color:#e6edf3;border:1px solid #30363d}button{background:#769656;border:0;font-weight:700;cursor:pointer}button:disabled{opacity:.5}pre{white-space:pre-wrap;overflow:auto;max-height:65vh}#out{display:none}.err{color:#f85149;min-height:18px}
</style></head><body><main class="card"><h1>🔐 Protected Code</h1><p>CCX v3 · PBKDF2-SHA256 · HKDF · AES-256-GCM · Chess notation</p>
<label for="pw">Password</label><input id="pw" type="password" autocomplete="current-password" placeholder="Enter password">
<button id="btn">🔓 Unlock</button><div id="err" class="err"></div><section id="out"><p>Decrypted source code</p><pre id="code"></pre><button id="copy">Copy code</button><div id="meta" class="meta"></div></section></main>
<script nonce="\${nonce}">
'use strict';
const PGN=\`\${pgn}\`;
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
  return dec.decode(packed.subarray(4,4+n));
 }
 if(bytes.length<45)throw Error('Legacy data is truncated.');
 for(const iterations of [600000,100000]){
  try{const base=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveKey']);
   const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:bytes.subarray(0,16),iterations,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
   return dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.subarray(16,28)},key,bytes.subarray(28)));
  }catch{}
 }
 throw Error('Wrong password or damaged data.');
}
async function unlock(){
 const btn=document.getElementById('btn'),err=document.getElementById('err'),pw=document.getElementById('pw').value;
 err.textContent='';if(!pw){err.textContent='Password is required.';return;}
 btn.disabled=true;btn.textContent='Decrypting…';
 try{const code=await decrypt(parse(PGN),pw);document.getElementById('code').textContent=code;document.getElementById('out').style.display='block';document.getElementById('meta').textContent=code.split('\\n').length+' lines · '+code.length+' characters';btn.textContent='✓ Unlocked';}
 catch(e){err.textContent='Wrong password, corrupted data, or unsupported file.';btn.disabled=false;btn.textContent='🔓 Unlock';}
}
document.getElementById('btn').addEventListener('click',unlock);
document.getElementById('pw').addEventListener('keydown',e=>{if(e.key==='Enter')unlock();});
document.getElementById('copy').addEventListener('click',()=>navigator.clipboard.writeText(document.getElementById('code').textContent));
<\/script></body></html>\`;
}

// ── UI state ────────────────────────────────────────────
let mode='protect', lastPGN='';

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
  showMsg('enc-err','','');
  if(!pw){showMsg('enc-err','Password is required — encryption refused without a password.','err');return;}
  if(!src.trim()){showMsg('enc-err','No code to encrypt.','err');return;}
  if(new TextEncoder().encode(src).length>MAX_SOURCE_BYTES){showMsg('enc-err','Source exceeds the 1 MiB limit.','err');return;}
  setBusy('enc-btn',true,'');
  try{
    const buf=await encryptBytes(src,pw);
    lastPGN=toPGN(buf);
    document.getElementById('pgn-out').value=lastPGN;
    document.getElementById('pgn-meta').textContent=buf.length+' moves · '+fmt(buf.length);
    document.getElementById('enc-result').style.display='block';
    showMsg('enc-msg','✓ Encrypted. Copy PGN or download a self-decrypting page.','ok');
  }catch(e){showMsg('enc-err',e.message,'err');}
  finally{setBusy('enc-btn',false,'🔐 Encrypt');}
}

function copyPGN(){
  navigator.clipboard.writeText(lastPGN).then(()=>{
    const t=document.getElementById('pgn-copy');
    t.textContent='Copied!';setTimeout(()=>t.textContent='Copy',1800);
  });
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
}

function clearEnc(){
  document.getElementById('src').value='';
  document.getElementById('pass-enc').value='';
  document.getElementById('pgn-out').value='';
  document.getElementById('enc-result').style.display='none';
  document.getElementById('src-info').textContent='0 lines · 0 B';
  showMsg('enc-err','','');showMsg('enc-msg','','');
  lastPGN='';
}

// ── Unlock ───────────────────────────────────────────────
async function doDecrypt(){
  let pgn=document.getElementById('pgn-in').value.trim();
  const pw=document.getElementById('pass-dec').value;
  showMsg('dec-msg','','');
  if(!pw){showMsg('dec-msg','Password is required.','err');return;}
  if(!pgn){showMsg('dec-msg','Paste PGN to unlock.','err');return;}
  if(new TextEncoder().encode(pgn).length>MAX_PGN_BYTES){showMsg('dec-msg','PGN exceeds the 2 MiB limit.','err');return;}
  // Accept protected HTML — extract PGN from template literal
  if(pgn.startsWith('<!DOCTYPE')||pgn.startsWith('<html')){
    const m=pgn.match(/const PGN=`([\s\S]*?)`;/);
    if(!m){showMsg('dec-msg','Could not extract PGN from HTML file.','err');return;}
    pgn=m[1].replace(/\\`/g,'`').replace(/\\\\/g,'\\');
  }
  setBusy('dec-btn',true,'');
  try{
    const buf=fromPGN(pgn);
    const code=await decryptBytes(buf,pw);
    document.getElementById('code-out').value=code;
    document.getElementById('dec-result').style.display='block';
    const lines=code.split('\n').length;
    document.getElementById('dec-meta').textContent=lines+' lines · '+code.length+' chars';
    showMsg('dec-msg','✓ Decrypted — auth tag verified, data is intact.','ok');
  }catch(e){
    document.getElementById('dec-result').style.display='none';
    showMsg('dec-msg',e.message,'err');
  }
  finally{setBusy('dec-btn',false,'🔓 Decrypt');}
}

function copyDecCode(){
  navigator.clipboard.writeText(document.getElementById('code-out').value).then(()=>{
    const t=document.getElementById('dec-copy');
    t.textContent='Copied!';setTimeout(()=>t.textContent='Copy',1800);
  });
}

function clearDecMsg(){showMsg('dec-msg','','');}

// ── Utils ────────────────────────────────────────────────
function showMsg(id,text,cls){
  const el=document.getElementById(id);
  if(el){el.textContent=text;el.className='msg'+(cls?' '+cls:'');}
}
function fmt(b){ return b<1024?b+' B':Math.round(b/1024*10)/10+' KB'; }

// Bind controls without inline event-handler attributes.
document.getElementById('tab-protect').addEventListener('click',()=>setMode('protect'));
document.getElementById('tab-unlock').addEventListener('click',()=>setMode('unlock'));
document.getElementById('src').addEventListener('input',updateSrcInfo);
document.getElementById('enc-btn').addEventListener('click',doEncrypt);
document.getElementById('pgn-copy-btn').addEventListener('click',copyPGN);
document.getElementById('dl-btn').addEventListener('click',downloadPage);
document.getElementById('clear-enc-btn').addEventListener('click',clearEnc);
document.getElementById('pgn-in').addEventListener('input',clearDecMsg);
document.getElementById('dec-btn').addEventListener('click',doDecrypt);
document.getElementById('dec-copy-btn').addEventListener('click',copyDecCode);
