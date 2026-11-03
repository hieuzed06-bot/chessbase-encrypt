const translations = {
  en: {
    brandSub:"Private code vault", theme:"Light", headline:"Keep your code on the board. Keep it private.", intro:"Protect code and documents, encode the encrypted data as chess notation, and unlock it whenever you need.",
    protectTab:"♟ Protect", unlockTab:"♙ Unlock", fileOptional:"Choose a file or paste source code", dropTitle:"Drop a file here", dropHint:"or browse your device · up to 1 MiB", browseFiles:"Browse files", noFile:"No file selected",
    sourceLabel:"Or paste text / source code", sourcePlaceholder:"Paste code or text here...", password:"Password", passwordPlaceholder:"Enter a strong password", passwordHelp:"Use at least 16 characters. A long passphrase is recommended.",
    confirmPassword:"Confirm password", confirmPlaceholder:"Re-enter your password", encrypt:"♜ Encrypt", encrypting:"Encrypting securely…", encryptedPgn:"Encrypted chess notation (PGN)", copy:"Copy", downloadCcx:"Download .ccx", downloadHtml:"Download protected HTML", clear:"Clear",
    encryptedFile:"Choose an encrypted file", dropEncrypted:"Drop a .ccx, .pgn or protected HTML file", orBrowse:"or browse your device", supportedEncrypted:"Supports .ccx, .pgn, .txt and protected HTML",
    pastePgn:"Or paste encrypted PGN", pgnPlaceholder:"Paste chess notation here...", decryptPassword:"Enter decryption password", decrypt:"♙ Decrypt", decrypting:"Decrypting and verifying…", decryptedCode:"Decrypted code"
  },
  vi: {
    brandSub:"Kho mã riêng tư", theme:"Sáng", headline:"Giữ mã nguồn trên bàn cờ. Giữ dữ liệu riêng tư.", intro:"Mã hoá mã nguồn và tài liệu thành ký hiệu cờ vua, sau đó giải mã bất cứ khi nào bạn cần.",
    protectTab:"♟ Mã hoá", unlockTab:"♙ Giải mã", fileOptional:"Chọn tệp hoặc dán mã nguồn", dropTitle:"Thả tệp vào đây", dropHint:"hoặc duyệt thiết bị · tối đa 1 MiB", browseFiles:"Chọn tệp", noFile:"Chưa chọn tệp",
    sourceLabel:"Hoặc dán văn bản / mã nguồn", sourcePlaceholder:"Dán mã nguồn hoặc văn bản tại đây...", password:"Mật khẩu", passwordPlaceholder:"Nhập mật khẩu mạnh", passwordHelp:"Sử dụng ít nhất 16 ký tự. Nên dùng một cụm mật khẩu dài.",
    confirmPassword:"Xác nhận mật khẩu", confirmPlaceholder:"Nhập lại mật khẩu", encrypt:"♜ Mã hoá", encrypting:"Đang mã hoá an toàn…", encryptedPgn:"Ký hiệu cờ vua đã mã hoá (PGN)", copy:"Sao chép", downloadCcx:"Tải .ccx", downloadHtml:"Tải HTML bảo vệ", clear:"Xoá",
    encryptedFile:"Chọn tệp đã mã hoá", dropEncrypted:"Thả tệp .ccx, .pgn hoặc HTML bảo vệ vào đây", orBrowse:"hoặc duyệt thiết bị", supportedEncrypted:"Hỗ trợ .ccx, .pgn, .txt và HTML bảo vệ",
    pastePgn:"Hoặc dán PGN đã mã hoá", pgnPlaceholder:"Dán ký hiệu cờ vua tại đây...", decryptPassword:"Nhập mật khẩu giải mã", decrypt:"♙ Giải mã", decrypting:"Đang giải mã và xác thực…", decryptedCode:"Mã nguồn đã giải mã"
  }
};
const messages = {
  "Passwords do not match.":"Mật khẩu xác nhận không khớp.",
  "Encryption complete. Download the .ccx file, copy the PGN, or save the protected HTML page.":"Mã hoá hoàn tất. Hãy tải tệp .ccx, sao chép PGN hoặc lưu trang HTML bảo vệ.",
  "Decryption complete. Authentication verified.":"Giải mã hoàn tất. Xác thực thành công.",
  "File is too large (8 MiB maximum)":"Tệp quá lớn (tối đa 8 MiB).",
  "Could not read encrypted data from this HTML file.":"Không thể đọc dữ liệu đã mã hoá từ tệp HTML này.",
  "Protected HTML page download started.":"Đã bắt đầu tải trang HTML bảo vệ.",
  "Password must be at least 16 characters.":"Mật khẩu phải có ít nhất 16 ký tự.",
  "Password is too long.":"Mật khẩu quá dài.",
  "Password cannot contain only whitespace.":"Mật khẩu không được chỉ chứa khoảng trắng.",
  "Choose a file or enter source text first.":"Hãy chọn tệp hoặc nhập mã nguồn trước.",
  "Encryption completed successfully.":"Mã hoá thành công.",
  "Decryption completed successfully.":"Giải mã thành công.",
  "Enter your password to continue.":"Hãy nhập mật khẩu để tiếp tục.",
  "Choose an encrypted file or paste PGN first.":"Hãy chọn tệp đã mã hoá hoặc dán PGN trước.",
  "Could not access the clipboard.":"Không thể truy cập bộ nhớ tạm.",
  "Workspace cleared.":"Đã xoá nội dung làm việc.",
  "Encrypted PGN copied to clipboard.":"Đã sao chép PGN đã mã hoá.",
  "Decrypted text copied to clipboard.":"Đã sao chép văn bản đã giải mã.",
  "File decrypted successfully. Download started.":"Đã giải mã tệp thành công. Bắt đầu tải xuống.",
  "Protected HTML page download started.":"Đã bắt đầu tải trang HTML bảo vệ.",
  "Encrypted .ccx file download started.":"Đã bắt đầu tải tệp .ccx đã mã hoá.",
  "Password is required.":"Yêu cầu nhập mật khẩu.",
  "No file selected":"Chưa chọn tệp",
  "Working…":"Đang xử lý…"
};
let language="en";
const $=(id)=>document.getElementById(id);
function applyLanguage(){
  document.documentElement.lang=language==="vi"?"vi":"en";
  document.querySelectorAll("[data-i18n]").forEach(el=>{
    const key=el.dataset.i18n, value=translations[language][key];
    if(value)el.textContent=value;
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach(el=>{
    const value=translations[language][el.dataset.i18nPlaceholder];
    if(value)el.placeholder=value;
  });
  $("language-toggle").textContent=language==="en"?"VI":"EN";
  $("theme-toggle").querySelector("[data-i18n]").textContent=translations[language].theme;
}
function translateDynamicText(root){
  const walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);
  const nodes=[];while(walker.nextNode())nodes.push(walker.currentNode);
  for(const node of nodes){const original=node.nodeValue.trim();if(messages[original])node.nodeValue=node.nodeValue.replace(original,messages[original]);}
}
function setupTheme(){
  const root=document.documentElement;
  $("theme-toggle").addEventListener("click",()=>{
    const next=root.dataset.theme==="dark"?"light":"dark";
    root.dataset.theme=next;
    $("theme-icon").textContent=next==="dark"?"☾":"☼";
    $("theme-toggle").setAttribute("aria-label",next==="dark"?"Switch to light theme":"Switch to dark theme");
  });
}
function setupLanguage(){
  $("language-toggle").addEventListener("click",()=>{language=language==="en"?"vi":"en";applyLanguage();});
}
function setupDropzones(){
  for(const zone of document.querySelectorAll("[data-drop-input]")){
    const input=$(zone.dataset.dropInput);
    zone.addEventListener("dragover",event=>{event.preventDefault();zone.classList.add("is-over");});
    zone.addEventListener("dragleave",event=>{if(!zone.contains(event.relatedTarget))zone.classList.remove("is-over");});
    zone.addEventListener("drop",event=>{
      event.preventDefault();zone.classList.remove("is-over");
      const files=event.dataTransfer?.files;
      if(!files?.length)return;
      const transfer=new DataTransfer();
      for(const file of files)transfer.items.add(file);
      input.files=transfer.files;
      input.dispatchEvent(new Event("change",{bubbles:true}));
    });
  }
}
function setupProgress(){
  const pairs=[["enc-btn","enc-progress"],["dec-btn","dec-progress"]];
  const sync=()=>{
    for(const [buttonId,progressId] of pairs){
      const button=$(buttonId),progress=$(progressId),busy=button.disabled;
      progress.classList.toggle("visible",busy);
      button.setAttribute("aria-busy",String(busy));
    }
  };
  const observer=new MutationObserver(sync);
  for(const [buttonId] of pairs)observer.observe($(buttonId),{attributes:true,attributeFilter:["disabled"]});
  sync();
}
function setupDynamicTranslations(){
  const observer=new MutationObserver(records=>{
    for(const record of records){
      if(record.target.nodeType===Node.TEXT_NODE){
        const value=record.target.nodeValue.trim();
        if(messages[value])record.target.nodeValue=record.target.nodeValue.replace(value,messages[value]);
      }else if(record.target.nodeType===Node.ELEMENT_NODE)translateDynamicText(record.target);
    }
  });
  for(const id of ["toast-text","enc-msg","enc-err","dec-msg","file-info","pgn-file-info"])observer.observe($(id),{childList:true,characterData:true,subtree:true});
}
setupTheme();setupLanguage();applyLanguage();setupDropzones();setupProgress();setupDynamicTranslations();
