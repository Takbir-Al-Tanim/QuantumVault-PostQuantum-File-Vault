const csrf = document.querySelector('meta[name="csrf-token"]').content;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const escapeHtml = value => String(value ?? '').replace(/[&<>'"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#039;','"':'&quot;'}[ch]));

// ---------- Drawer ----------
const cryptoDrawer = document.getElementById('cryptoDrawer');
const cryptoDrawerBackdrop = document.getElementById('cryptoDrawerBackdrop');
const closeCryptoDrawer = document.getElementById('closeCryptoDrawer');
const globalCryptoDemoBtn = document.getElementById('globalCryptoDemoBtn');
const replayDemoBtn = document.getElementById('replayDemoBtn');
const lastDemoHint = document.getElementById('lastDemoHint');
const placeholder = document.getElementById('visualizerPlaceholder');
const traceHeader = document.getElementById('traceHeader');
const traceList = document.getElementById('traceList');
const traceCounter = document.getElementById('traceCounter');
const traceTotal = document.getElementById('traceTotal');
const traceOperationLabel = document.getElementById('traceOperationLabel');
const traceOperationTitle = document.getElementById('traceOperationTitle');
let demoPlaying = false;

function openCryptoDrawer(){ cryptoDrawer?.classList.add('open'); cryptoDrawerBackdrop?.classList.remove('hidden'); }
function hideCryptoDrawer(){ cryptoDrawer?.classList.remove('open'); cryptoDrawerBackdrop?.classList.add('hidden'); }
globalCryptoDemoBtn?.addEventListener('click', openCryptoDrawer);
closeCryptoDrawer?.addEventListener('click', hideCryptoDrawer);
cryptoDrawerBackdrop?.addEventListener('click', hideCryptoDrawer);

const fallbackTeaching = {
  'ML-KEM-768': {summary:'Creates a post-quantum shared secret.', input:'Public key or KEM ciphertext + secret key', output:'Matching hidden shared secret', why:'Establishes key material without exposing the secret.'},
  'HKDF-SHA256': {summary:'Turns secret material into the exact file key.', input:'Shared secret + salt + file context', output:'256-bit file key', why:'Produces a clean, file-specific encryption key.'},
  'ChaCha20-Poly1305': {summary:'Encrypts the data and adds a tamper seal.', input:'File bytes + key + nonce', output:'Ciphertext + authentication tag', why:'Keeps content private and detects modification.'},
  'Access control': {summary:'Checks who is allowed to open the file.', input:'Signed-in user + ownership/share record', output:'Allow or deny', why:'Encryption still needs permission checks.'},
  'Application': {summary:'Prepares the file operation.', input:'User action + file', output:'Validated data', why:'Invalid input is rejected before cryptography.'},
  'Secure storage': {summary:'Stores only the encrypted result.', input:'Ciphertext + recovery metadata', output:'Encrypted vault item', why:'Readable plaintext is not kept at rest.'}
};

function teachingFor(step){
  const f = fallbackTeaching[step.algorithm] || {};
  return {
    summary: step.summary || f.summary || 'Step completed.',
    input: step.input_label || f.input || 'Input',
    output: step.output_label || f.output || 'Output',
    why: step.why || f.why || 'Part of the secure workflow.'
  };
}

function buildStep(step, index){
  const t = teachingFor(step);
  const el = document.createElement('article');
  el.className = 'trace-step active';
  el.innerHTML = `
    <div class="trace-step-head">
      <div class="trace-index">${index + 1}</div>
      <div class="trace-title"><strong>${escapeHtml(step.name)}</strong><span>${escapeHtml(step.algorithm)}</span></div>
      <span class="trace-time">${Number(step.time_ms || 0).toFixed(4)} ms</span>
    </div>
    <div class="trace-simple">
      <p>${escapeHtml(t.summary)}</p>
      <div class="io-grid"><div class="io-box"><b>IN</b>${escapeHtml(t.input)}</div><div class="io-arrow">→</div><div class="io-box"><b>OUT</b>${escapeHtml(t.output)}</div></div>
      <div class="why-box">${escapeHtml(t.why)}</div>
    </div>
    <pre class="trace-technical">${escapeHtml(step.detail || 'No extra technical detail.')}</pre>`;
  return el;
}

async function visualizeTrace(trace, kind, saveTrace = true){
  if (!trace?.length || demoPlaying) return;
  demoPlaying = true;
  if (saveTrace) localStorage.setItem('quantumVaultLastDemo', JSON.stringify({trace, kind}));
  openCryptoDrawer();
  placeholder.classList.add('hidden');
  traceHeader.classList.remove('hidden');
  traceList.classList.remove('hidden');
  traceTotal.classList.remove('hidden');
  traceList.innerHTML = '';
  traceTotal.textContent = '';

  const download = kind === 'download';
  traceOperationLabel.textContent = download ? 'DECRYPTION' : 'ENCRYPTION';
  traceOperationTitle.textContent = download ? 'Recovering the original file' : 'Protecting the file';
  replayDemoBtn.disabled = true;
  replayDemoBtn.textContent = 'Playing…';

  let total = 0;
  for (let i = 0; i < trace.length; i++) {
    const step = trace[i];
    total += Number(step.time_ms || 0);
    traceCounter.textContent = `${i + 1}/${trace.length}`;
    const el = buildStep(step, i);
    traceList.appendChild(el);
    el.scrollIntoView({behavior:'smooth', block:'nearest'});
    await sleep(900);
    el.classList.remove('active');
    el.classList.add('complete');
  }
  traceCounter.textContent = `${trace.length}/${trace.length}`;
  traceTotal.textContent = `✓ Complete · measured crypto stages ${total.toFixed(4)} ms`;
  demoPlaying = false;
  replayDemoBtn.disabled = false;
  replayDemoBtn.textContent = '↻ Replay last demo';
  lastDemoHint.textContent = download ? 'Last demo: secure download' : 'Last demo: encryption';
}

function refreshReplay(){
  const saved = localStorage.getItem('quantumVaultLastDemo');
  if (!replayDemoBtn) return;
  replayDemoBtn.disabled = !saved;
  if (saved) {
    try { const d = JSON.parse(saved); lastDemoHint.textContent = d.kind === 'download' ? 'Last demo: secure download' : 'Last demo: encryption'; } catch (_) {}
  }
}
refreshReplay();
replayDemoBtn?.addEventListener('click', async () => {
  const saved = localStorage.getItem('quantumVaultLastDemo');
  if (!saved) return;
  try { const demo = JSON.parse(saved); await visualizeTrace(demo.trace, demo.kind, false); }
  catch (_) { localStorage.removeItem('quantumVaultLastDemo'); refreshReplay(); }
});

document.querySelectorAll('#cryptoDrawer .mode-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#cryptoDrawer .mode-btn').forEach(x => x.classList.remove('active'));
    btn.classList.add('active');
    cryptoDrawer.classList.toggle('technical-mode', btn.dataset.mode === 'technical');
  });
});

// ---------- Generic modals ----------
function openModal(id){ document.getElementById(id)?.classList.remove('hidden'); }
function closeModal(el){ el?.closest('.modal-backdrop')?.classList.add('hidden'); }
document.querySelectorAll('.modal-close').forEach(btn => btn.addEventListener('click', () => closeModal(btn)));
document.querySelectorAll('.modal-backdrop').forEach(back => back.addEventListener('click', e => { if (e.target === back) back.classList.add('hidden'); }));

const uploadModalOpen = () => openModal('uploadModal');
const folderModalOpen = () => { openModal('folderModal'); setTimeout(() => document.getElementById('folderName')?.focus(), 80); };
const textModalOpen = () => { openModal('textModal'); setTimeout(() => document.getElementById('textFileName')?.focus(), 80); };

document.getElementById('toolbarUploadBtn')?.addEventListener('click', uploadModalOpen);
document.getElementById('emptyUploadBtn')?.addEventListener('click', uploadModalOpen);
document.getElementById('toolbarFolderBtn')?.addEventListener('click', folderModalOpen);
document.getElementById('toolbarTextBtn')?.addEventListener('click', textModalOpen);

// ---------- New menu ----------
const sidebarNewBtn = document.getElementById('sidebarNewBtn');
const newMenu = document.getElementById('newMenu');
sidebarNewBtn?.addEventListener('click', e => {
  e.stopPropagation();
  newMenu.classList.toggle('hidden');
  const r = sidebarNewBtn.getBoundingClientRect();
  newMenu.style.left = `${Math.min(r.left, window.innerWidth - 250)}px`;
  newMenu.style.top = `${r.bottom + 8}px`;
});
newMenu?.querySelectorAll('button').forEach(btn => btn.addEventListener('click', () => {
  newMenu.classList.add('hidden');
  if (btn.dataset.action === 'upload') uploadModalOpen();
  if (btn.dataset.action === 'folder') folderModalOpen();
  if (btn.dataset.action === 'text') textModalOpen();
}));
document.addEventListener('click', e => { if (newMenu && !newMenu.contains(e.target) && e.target !== sidebarNewBtn) newMenu.classList.add('hidden'); });

// ---------- Upload ----------
const uploadForm = document.getElementById('uploadForm');
const fileInput = document.getElementById('fileInput');
const dropZone = document.getElementById('dropZone');
const fileChoiceTitle = document.getElementById('fileChoiceTitle');
const fileChoiceMeta = document.getElementById('fileChoiceMeta');
const uploadBtn = document.getElementById('uploadBtn');
const uploadMessage = document.getElementById('uploadMessage');
const humanSize = bytes => bytes < 1024 ? `${bytes} B` : bytes < 1048576 ? `${(bytes/1024).toFixed(1)} KB` : `${(bytes/1048576).toFixed(2)} MB`;
function updateFileChoice(file){
  uploadBtn.disabled = !file;
  fileChoiceTitle.textContent = file ? file.name : 'Choose a file or drop it here';
  fileChoiceMeta.textContent = file ? `${humanSize(file.size)} · ready to encrypt` : 'TXT · PDF · JPG/PNG · CSV · ZIP';
}
fileInput?.addEventListener('change', () => updateFileChoice(fileInput.files[0]));
['dragenter','dragover'].forEach(name => dropZone?.addEventListener(name, e => { e.preventDefault(); dropZone.classList.add('dragover'); }));
['dragleave','drop'].forEach(name => dropZone?.addEventListener(name, e => { e.preventDefault(); dropZone.classList.remove('dragover'); }));
dropZone?.addEventListener('drop', e => {
  if (!e.dataTransfer.files.length) return;
  const dt = new DataTransfer(); dt.items.add(e.dataTransfer.files[0]); fileInput.files = dt.files; updateFileChoice(fileInput.files[0]);
});
uploadForm?.addEventListener('submit', async e => {
  e.preventDefault(); uploadBtn.disabled = true; uploadMessage.textContent = 'Encrypting…';
  try {
    const res = await fetch('/api/upload', {method:'POST', body:new FormData(uploadForm), headers:{'X-CSRFToken':csrf}});
    const data = await res.json(); if (!res.ok || !data.ok) throw new Error(data.error || 'Upload failed');
    uploadMessage.textContent = 'Encrypted and stored.';
    await visualizeTrace(data.trace, 'upload', true);
    setTimeout(() => window.location.reload(), 700);
  } catch (err) { uploadMessage.textContent = err.message; uploadBtn.disabled = false; }
});

// ---------- Create folder ----------
document.getElementById('folderForm')?.addEventListener('submit', async e => {
  e.preventDefault(); const form = e.currentTarget; const msg = document.getElementById('folderMessage');
  const body = Object.fromEntries(new FormData(form).entries()); msg.textContent = 'Creating…';
  try {
    const res = await fetch('/api/folders', {method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':csrf}, body:JSON.stringify(body)});
    const data = await res.json(); if (!res.ok || !data.ok) throw new Error(data.error || 'Could not create folder');
    window.location.reload();
  } catch (err) { msg.textContent = err.message; }
});

// ---------- Create encrypted text file ----------
document.getElementById('textFileForm')?.addEventListener('submit', async e => {
  e.preventDefault(); const btn = document.getElementById('createTextBtn'); const msg = document.getElementById('textFileMessage');
  btn.disabled = true; msg.textContent = 'Encrypting…';
  const body = {name:document.getElementById('textFileName').value, content:document.getElementById('textFileContent').value, folder_id:document.getElementById('textFolderId').value};
  try {
    const res = await fetch('/api/text-files', {method:'POST', headers:{'Content-Type':'application/json','X-CSRFToken':csrf}, body:JSON.stringify(body)});
    const data = await res.json(); if (!res.ok || !data.ok) throw new Error(data.error || 'Could not create file');
    msg.textContent = 'Created securely.';
    await visualizeTrace(data.trace, 'upload', true);
    setTimeout(() => window.location.reload(), 700);
  } catch (err) { msg.textContent = err.message; btn.disabled = false; }
});

// ---------- Folder actions ----------
document.querySelectorAll('.folder-delete-btn').forEach(btn => btn.addEventListener('click', async () => {
  if (!confirm(`Delete folder “${btn.dataset.name}”? It must be empty.`)) return;
  try {
    const res = await fetch(`/api/folders/${btn.dataset.id}/delete`, {method:'POST', headers:{'X-CSRFToken':csrf}});
    const data = await res.json(); if (!res.ok || !data.ok) throw new Error(data.error || 'Delete failed'); window.location.reload();
  } catch (err) { alert(err.message); }
}));

// ---------- Rename ----------
const renameModal = document.getElementById('renameModal');
function openRename(kind, id, name){
  document.getElementById('renameKind').value = kind; document.getElementById('renameId').value = id;
  document.getElementById('renameName').value = name; document.getElementById('renameTitle').textContent = kind === 'folder' ? 'Rename folder' : 'Rename file';
  document.getElementById('renameMessage').textContent = ''; openModal('renameModal'); setTimeout(() => document.getElementById('renameName').select(), 80);
}
document.querySelectorAll('.folder-rename-btn').forEach(btn => btn.addEventListener('click', () => openRename('folder', btn.dataset.id, btn.dataset.name)));
document.querySelectorAll('.rename-file-btn').forEach(btn => btn.addEventListener('click', () => openRename('file', btn.dataset.id, btn.dataset.name)));
document.getElementById('renameForm')?.addEventListener('submit', async e => {
  e.preventDefault(); const kind = document.getElementById('renameKind').value; const id = document.getElementById('renameId').value; const name = document.getElementById('renameName').value; const msg = document.getElementById('renameMessage');
  const url = kind === 'folder' ? `/api/folders/${id}/rename` : `/api/files/${id}/rename`; msg.textContent = 'Saving…';
  try { const res = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':csrf},body:JSON.stringify({name})}); const data=await res.json(); if(!res.ok||!data.ok) throw new Error(data.error||'Rename failed'); window.location.reload(); }
  catch(err){ msg.textContent=err.message; }
});

// ---------- Move ----------
function openMove(kind,id,name){
  document.getElementById('moveKind').value=kind;
  document.getElementById('moveFileId').value=id;
  document.getElementById('moveFileLabel').textContent=name;
  document.getElementById('moveTitle').textContent=kind==='folder'?'Move folder':'Move file';
  document.getElementById('moveMessage').textContent='';
  openModal('moveModal');
}
document.querySelectorAll('.move-file-btn').forEach(btn => btn.addEventListener('click', () => openMove('file',btn.dataset.id,btn.dataset.name)));
document.querySelectorAll('.folder-move-btn').forEach(btn => btn.addEventListener('click', () => openMove('folder',btn.dataset.id,btn.dataset.name)));
document.getElementById('moveForm')?.addEventListener('submit', async e => {
  e.preventDefault();
  const kind=document.getElementById('moveKind').value;
  const id=document.getElementById('moveFileId').value;
  const folder_id=document.getElementById('moveFolderSelect').value;
  const msg=document.getElementById('moveMessage'); msg.textContent='Moving…';
  const url=kind==='folder'?`/api/folders/${id}/move`:`/api/files/${id}/move`;
  try { const res=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':csrf},body:JSON.stringify({folder_id})}); const data=await res.json(); if(!res.ok||!data.ok) throw new Error(data.error||'Move failed'); window.location.reload(); }
  catch(err){ msg.textContent=err.message; }
});

// ---------- Download ----------
function decodeTrace(encoded){
  if (!encoded) return [];
  let normalized = encoded.replace(/-/g,'+').replace(/_/g,'/');
  while (normalized.length % 4) normalized += '=';
  return JSON.parse(atob(normalized));
}
async function downloadFile(id, name, button){
  const old = button?.textContent; if (button) { button.disabled = true; button.textContent = '…'; }
  try {
    const res = await fetch(`/api/files/${id}/download`);
    if (!res.ok) { let m='Download failed'; try{m=(await res.json()).error||m;}catch(_){} throw new Error(m); }
    const trace = decodeTrace(res.headers.get('X-Crypto-Trace'));
    const blob = await res.blob();
    await visualizeTrace(trace, 'download', true);
    const url = URL.createObjectURL(blob); const a=document.createElement('a'); a.href=url; a.download=name; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  } catch (err) { alert(err.message); }
  finally { if (button) { button.disabled=false; button.textContent=old; } }
}
document.querySelectorAll('.download-btn,.download-menu-btn').forEach(btn => btn.addEventListener('click', () => downloadFile(btn.dataset.id, btn.dataset.name, btn)));

// ---------- View toggle ----------
const fileView = document.getElementById('fileView');
const listBtn = document.getElementById('listViewBtn');
const gridBtn = document.getElementById('gridViewBtn');
function setView(mode){
  if (!fileView) return; fileView.classList.toggle('grid-mode', mode==='grid'); fileView.classList.toggle('list-mode', mode!=='grid');
  listBtn?.classList.toggle('active', mode!=='grid'); gridBtn?.classList.toggle('active', mode==='grid'); localStorage.setItem('qvFileView', mode);
}
listBtn?.addEventListener('click',()=>setView('list')); gridBtn?.addEventListener('click',()=>setView('grid')); setView(localStorage.getItem('qvFileView') || 'list');
