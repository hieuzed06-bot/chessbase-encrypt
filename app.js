import { toPGN, fromPGN, MAX_SOURCE_BYTES, MAX_PGN_BYTES } from './codec.js';

// ── Crypto ─────────────────────────────────────────────
const TE=new TextEncoder(), TD=new TextDecoder();

async function deriveKey(pw, salt, usage, iterations=600000){
  const base=await crypto.subtle.importKey('raw',TE.encode(pw),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2',salt,iterations,hash:'SHA-256'},
    base,{name:'AES-GCM',length:256},false,[usage]
  );
}

async function encryptBytes(text, pw){
  const pt=TE.encode(text);
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await deriveKey(pw,salt,'encrypt');
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,pt));
  const buf=new Uint8Array(28+ct.byteLength);
  buf.set(salt,0); buf.set(iv,16); buf.set(ct,28);
  return buf;
}

async function decryptBytes(buf, pw){
  if(buf.length<45) throw new Error('Data too short — corrupted or invalid PGN.');
  // Try the current work factor first, then retain compatibility with older 100k files.
  for(const iterations of [600000,100000]){
    try{
      const key=await deriveKey(pw,buf.slice(0,16),'decrypt',iterations);
      const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:buf.slice(16,28)},key,buf.slice(28));
      return TD.decode(pt);
    }catch{}
  }
  throw new Error('Decryption failed — wrong password or data was tampered with.');
}

// ── Self-decrypt page template ─────────────────────────
function buildProtectedPage(pgn){
  const nonceBytes=crypto.getRandomValues(new Uint8Array(16));
  const nonce=btoa(String.fromCharCode(...nonceBytes));
  const esc=pgn.replace(/\\/g,'\\\\').replace(/`/g,'\\`');
  return`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>🔐 Protected Code</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--text:#e6edf3;--text2:#8b949e;--border:#30363d;--green:#769656;--green2:#5a7a3a;--danger:#f85149;--mono:'Courier New',monospace;--r:8px}
body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem 1rem}
.card{width:100%;max-width:640px}
h1{font-size:20px;font-weight:700;margin-bottom:6px}
p{font-size:13px;color:var(--text2);margin-bottom:1.5rem;line-height:1.5}
label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--text2);display:block;margin-bottom:5px}
input{width:100%;padding:10px 14px;border-radius:var(--r);border:1px solid var(--border);background:var(--bg2);color:var(--text);font-size:14px;outline:none;margin-bottom:10px}
input:focus{border-color:#444c56}
input:disabled{opacity:.5}
button{width:100%;padding:10px;border-radius:var(--r);background:var(--green);color:#fff;border:none;font-size:14px;font-weight:600;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px;transition:.15s}
button:hover:not(:disabled){background:var(--green2)}
button:disabled{opacity:.5;cursor:not-allowed}
.spin{width:14px;height:14px;border:2px solid rgba(255,255,255,.25);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.err{color:var(--danger);font-size:12px;margin-top:8px;min-height:16px}
.out{margin-top:1.5rem;display:none}
pre{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);padding:1rem;overflow:auto;font-family:var(--mono);font-size:12.5px;line-height:1.65;color:var(--text);white-space:pre-wrap;word-break:break-word;max-height:65vh}
.meta{font-size:11px;color:var(--text2);margin-top:8px}
.copy-btn{width:auto;padding:6px 14px;font-size:12px;margin-top:8px;background:transparent;border:1px solid var(--border);color:var(--text2)}
.copy-btn:hover{border-color:var(--green);color:var(--green);background:transparent}
</style>
</head>
<body>
<div class="card">
  <h1>🔐 Protected Code</h1>
  <p>Encrypted with AES-256-GCM + Chess Cipher. Enter the password to reveal the source code.</p>
  <label>Password</label>
  <input type="password" id="pw" placeholder="Enter password..." >
  <button id="btn" >🔓 Unlock</button>
  <div class="err" id="err"></div>
  <div class="out" id="out">
    <label>Source code</label>
    <pre id="code"></pre>
    <button class="copy-btn" >Copy code</button>
    <div class="meta" id="meta"></div>
  </div>
</div>
<script nonce="${nonce}">
const PGN=\`${esc}\`;
const P=['','N','B','R'],F='abcdefgh',R='12345678';
function m2b(m){
  m=m.trim();let pi,fi,ri;
  if(m.length===3&&'NBR'.includes(m[0])){pi=P.indexOf(m[0]);fi=F.indexOf(m[1]);ri=R.indexOf(m[2]);}
  else if(m.length===2){pi=0;fi=F.indexOf(m[0]);ri=R.indexOf(m[1]);}
  else throw 0;
  return(pi<<6)|(fi<<3)|ri;
}
function parse(pgn){
  if(new TextEncoder().encode(pgn).length>2*1024*1024) throw new Error('PGN exceeds the 2 MiB limit.');
  const body=pgn.split('\\n').filter(l=>!/^\\s*\\[[A-Za-z][A-Za-z0-9_]*\\s+\"[^\"\\r\\n]*\"\\]\\s*$/.test(l)).join(' ');
  const tokens=body.trim().split(/\\s+/).filter(Boolean), bytes=[];
  for(const token of tokens){
    if(/^\\d+\\.(?:\\.\\.)?$/.test(token)||['*','1-0','0-1','1/2-1/2'].includes(token)) continue;
    if(!/^(?:[NBR])?[a-h][1-8]$/.test(token)) throw new Error('Invalid chess-cipher token.');
    bytes.push(m2b(token));
  }
  if(!bytes.length) throw new Error('No encrypted moves found.');
  return new Uint8Array(bytes);
}
async function dec(){
  const pw=document.getElementById('pw').value;
  const btn=document.getElementById('btn');
  const err=document.getElementById('err');
  err.textContent='';btn.disabled=true;
  btn.innerHTML='<div class="spin"></div><span>Decrypting…</span>';
  try{
    const buf=parse(PGN);
    const salt=buf.slice(0,16),iv=buf.slice(16,28),ct=buf.slice(28);
    if(!pw){err.textContent='Password is required.';btn.disabled=false;btn.innerHTML='🔓 Unlock';return;}
    const base=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
    let pt=null;
    for(const iterations of [600000,100000]){
      try{
        const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
        pt=await crypto.subtle.decrypt({name:'AES-GCM',iv},key,ct);
        break;
      }catch{}
    }
    if(!pt) throw new Error('Decryption failed');
    const code=new TextDecoder().decode(pt);
    document.getElementById('code').textContent=code;
    document.getElementById('out').style.display='block';
    document.getElementById('meta').textContent=code.split('\\n').length+' lines · '+code.length+' chars';
    btn.innerHTML='✓ Unlocked';
    document.getElementById('pw').disabled=true;
  }catch(e){
    err.textContent='Wrong password or data has been tampered with.';
    btn.disabled=false;btn.innerHTML='🔓 Unlock';
  }
}
function copyCode(){
  navigator.clipboard.writeText(document.getElementById('code').textContent);
}
document.getElementById('btn').addEventListener('click',dec);
document.getElementById('pw').addEventListener('keydown',event=>{if(event.key==='Enter')dec();});
document.getElementById('copy-btn').addEventListener('click',copyCode);
<\/script>
</body>
</html>`;
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
