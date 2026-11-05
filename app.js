import { toPGN, fromPGN, MAX_SOURCE_BYTES, MAX_PGN_BYTES } from './codec.js';
import { encryptBytes, decryptBytes, encryptRawBytes, decryptRawBytes } from './crypto-v3.js';
import { packMatePayload, unpackMatePayload } from './mate-payload.js';

// ── UI state ────────────────────────────────────────────
let mode='protect', lastPGN='', selectedFile=null, selectedCipherFile=null;

function setMode(m){
  mode=m;
  document.getElementById('pass-enc').value='';
  document.getElementById('pass-confirm').value='';
  document.getElementById('pass-dec').value='';
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
  const passwordInput=document.getElementById('pass-enc');
  const confirmInput=document.getElementById('pass-confirm');
  const pw=passwordInput.value;
  const confirmPw=confirmInput.value;
  passwordInput.value='';
  confirmInput.value='';
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
    const mate=document.getElementById('mate-enc').value;
    const encryptedPayload=packMatePayload(payload,mate);
    const buf=await encryptRawBytes(encryptedPayload,pw);
    lastPGN=toPGN(buf);
    document.getElementById('pgn-out').value=lastPGN;
    document.getElementById('pgn-meta').textContent=buf.length+' moves · '+fmt(buf.length);
    document.getElementById('enc-result').style.display='block';
    showMsg('enc-msg','Encryption complete. Download the PGN as a .txt file or copy it.','ok');showToast('Encryption completed successfully.');
  }catch(e){showMsg('enc-err',e.message,'err');showToast(e.message,'error');}
  finally{setBusy('enc-btn',false,'🔐 Encrypt');}
}

function copyPGN(){
  navigator.clipboard.writeText(lastPGN).then(()=>{showToast('Encrypted PGN copied to clipboard.');
    const t=document.getElementById('pgn-copy');
    t.textContent='Copied!';setTimeout(()=>t.textContent='Copy',1800);
  }).catch(()=>showToast('Could not access the clipboard.','error'));
}

function downloadPGNText(){
  if(!lastPGN)return;
  downloadBytes(new TextEncoder().encode(lastPGN),'chesscrypt-encrypted.txt','text/plain;charset=utf-8');
  showToast('Encrypted PGN .txt download started.');
}

function downloadDecryptedText(){
  const code=document.getElementById('code-out').value;
  downloadBytes(new TextEncoder().encode(code),'chesscrypt-decrypted.txt','text/plain;charset=utf-8');
  showToast('Decrypted .txt download started.');
}

function clearEnc(){
  document.getElementById('src').value='';
  document.getElementById('mate-enc').value='';
  document.getElementById('file-input').value='';selectedFile=null;
  document.getElementById('file-info').textContent='No file selected';
  document.getElementById('pass-enc').value='';
  document.getElementById('pass-confirm').value='';
  document.getElementById('pgn-out').value='';
  document.getElementById('enc-result').style.display='none';
  document.getElementById('src-info').textContent='0 lines · 0 B';
  showMsg('enc-err','','');showMsg('enc-msg','','');
  lastPGN='';
  showToast('Workspace cleared.');
}

// ── Unlock ───────────────────────────────────────────────
async function doDecrypt(){
  clearSensitiveOutputs();
  let pgn=document.getElementById('pgn-in').value.trim();
  const passwordInput=document.getElementById('pass-dec');
  const pw=passwordInput.value;
  passwordInput.value='';
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
    const decrypted=await decryptRawBytes(buf,pw);
    const unpacked=unpackMatePayload(decrypted);
    const plain=unpacked.payload;
    const mateOutput=document.getElementById('mate-out');
    const mateResult=document.getElementById('mate-result');
    mateOutput.value=unpacked.mate;
    mateResult.style.display=unpacked.mate?'block':'none';
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

function clearSensitiveOutputs(){
  document.getElementById('mate-out').value='';
  document.getElementById('mate-result').style.display='none';
}


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
document.getElementById('dl-txt-btn').addEventListener('click',downloadPGNText);
document.getElementById('dec-download-txt-btn').addEventListener('click',downloadDecryptedText);
document.getElementById('clear-enc-btn').addEventListener('click',clearEnc);
document.getElementById('pgn-in').addEventListener('input',()=>{selectedCipherFile=null;document.getElementById('pgn-file').value='';document.getElementById('pgn-file-info').textContent='Supports .ccx, .pgn, .txt, and protected HTML';clearDecMsg();});
document.getElementById('pgn-file').addEventListener('change',handleCipherFileSelection);
document.getElementById('dec-btn').addEventListener('click',doDecrypt);
document.getElementById('dec-copy-btn').addEventListener('click',copyDecCode);
window.addEventListener('pagehide',()=>{
  document.getElementById('pass-enc').value='';
  document.getElementById('pass-confirm').value='';
  document.getElementById('pass-dec').value='';
  clearSensitiveOutputs();
});
