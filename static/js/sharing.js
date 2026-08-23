const shareCsrf = document.querySelector('meta[name="csrf-token"]').content;
const sharePanel = document.getElementById('shareCryptoPanel');
const shareBackdrop = document.getElementById('shareDrawerBackdrop');
const shareClose = document.getElementById('closeShareDrawer');
const globalDemo = document.getElementById('globalCryptoDemoBtn');
const sharePlaceholder = document.getElementById('shareVisualizerPlaceholder');
const shareTraceList = document.getElementById('shareTraceList');
const shareTraceHeader = document.getElementById('shareTraceHeader');
const shareTraceCounter = document.getElementById('shareTraceCounter');
const shareTraceTotal = document.getElementById('shareTraceTotal');
const shareTraceOperationLabel = document.getElementById('shareTraceOperationLabel');
const shareTraceOperationTitle = document.getElementById('shareTraceOperationTitle');
const replayBtn = document.getElementById('shareReplayBtn');
const replayHint = document.getElementById('shareReplayHint');
let playing = false;
const wait = ms => new Promise(r=>setTimeout(r,ms));
const esc = v => String(v??'').replace(/[&<>'"]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#039;','"':'&quot;'}[ch]));
function openDrawer(){sharePanel.classList.add('open');shareBackdrop.classList.remove('hidden')}
function closeDrawer(){sharePanel.classList.remove('open');shareBackdrop.classList.add('hidden')}
globalDemo?.addEventListener('click',openDrawer);shareClose?.addEventListener('click',closeDrawer);shareBackdrop?.addEventListener('click',closeDrawer);

const fallback={
 'ML-KEM-768':{summary:'Creates recipient-specific shared key material.',input:'Recipient public key or KEM ciphertext',output:'Matching share secret',why:'Only the intended recipient can reproduce it.'},
 'HKDF-SHA256':{summary:'Derives a key used only for the share envelope.',input:'Share secret + salt',output:'256-bit wrapping key',why:'File encryption and key sharing stay separate.'},
 'ChaCha20-Poly1305':{summary:'Wraps or unwraps the hidden file key.',input:'File key + wrapping key + nonce',output:'Authenticated key envelope',why:'The file key is protected and tamper-checked.'},
 'Access control':{summary:'Checks owner or recipient permission.',input:'Account + share record',output:'Allow or deny',why:'Revocation can block future access.'},
 'Secure storage':{summary:'Stores only the small share envelope.',input:'Encrypted key envelope',output:'Revocable permission',why:'The encrypted file itself is not duplicated.'},
 'Application':{summary:'Returns the file after checks pass.',input:'Verified plaintext',output:'Browser download',why:'No permanent plaintext copy is needed.'}
};
function stepCard(step,i){const f=fallback[step.algorithm]||{};const el=document.createElement('article');el.className='trace-step active';el.innerHTML=`<div class="trace-step-head"><div class="trace-index">${i+1}</div><div class="trace-title"><strong>${esc(step.name)}</strong><span>${esc(step.algorithm)}</span></div><span class="trace-time">${Number(step.time_ms||0).toFixed(4)} ms</span></div><div class="trace-simple"><p>${esc(step.summary||f.summary||'Step completed.')}</p><div class="io-grid"><div class="io-box"><b>IN</b>${esc(step.input_label||f.input||'Input')}</div><div class="io-arrow">→</div><div class="io-box"><b>OUT</b>${esc(step.output_label||f.output||'Output')}</div></div><div class="why-box">${esc(step.why||f.why||'Part of secure sharing.')}</div></div><pre class="trace-technical">${esc(step.detail||'No extra technical detail.')}</pre>`;return el}
async function showTrace(trace,kind,save=true){if(!trace?.length||playing)return;playing=true;if(save)localStorage.setItem('qvLastShareDemo',JSON.stringify({trace,kind}));openDrawer();sharePlaceholder.classList.add('hidden');shareTraceHeader.classList.remove('hidden');shareTraceList.classList.remove('hidden');shareTraceTotal.classList.remove('hidden');shareTraceList.innerHTML='';const opening=kind==='shared-download';shareTraceOperationLabel.textContent=opening?'SHARED DOWNLOAD':'CREATE SHARE';shareTraceOperationTitle.textContent=opening?'Opening recipient key envelope':'Wrapping the file key';replayBtn.disabled=true;replayBtn.textContent='Playing…';let total=0;for(let i=0;i<trace.length;i++){total+=Number(trace[i].time_ms||0);shareTraceCounter.textContent=`${i+1}/${trace.length}`;const el=stepCard(trace[i],i);shareTraceList.appendChild(el);el.scrollIntoView({behavior:'smooth',block:'nearest'});await wait(850);el.classList.remove('active');el.classList.add('complete')}shareTraceTotal.textContent=`✓ Complete · ${total.toFixed(4)} ms measured crypto stages`;shareTraceCounter.textContent=`${trace.length}/${trace.length}`;playing=false;replayBtn.disabled=false;replayBtn.textContent='↻ Replay last share demo';replayHint.textContent=opening?'Last demo: shared download':'Last demo: share creation'}
function refresh(){const s=localStorage.getItem('qvLastShareDemo');replayBtn.disabled=!s;if(s){try{const d=JSON.parse(s);replayHint.textContent=d.kind==='shared-download'?'Last demo: shared download':'Last demo: share creation'}catch(_){}}}refresh();
replayBtn?.addEventListener('click',async()=>{const s=localStorage.getItem('qvLastShareDemo');if(!s)return;try{const d=JSON.parse(s);await showTrace(d.trace,d.kind,false)}catch(_){localStorage.removeItem('qvLastShareDemo');refresh()}});
document.querySelectorAll('#shareCryptoPanel .mode-btn').forEach(btn=>btn.addEventListener('click',()=>{document.querySelectorAll('#shareCryptoPanel .mode-btn').forEach(x=>x.classList.remove('active'));btn.classList.add('active');sharePanel.classList.toggle('technical-mode',btn.dataset.mode==='technical')}));

const shareForm=document.getElementById('shareForm');
shareForm?.addEventListener('submit',async e=>{e.preventDefault();const btn=document.getElementById('shareBtn'),msg=document.getElementById('shareMessage');btn.disabled=true;msg.textContent='Creating secure access…';try{const body={file_id:document.getElementById('shareFileId').value,recipient_email:document.getElementById('recipientEmail').value};const res=await fetch('/api/shares',{method:'POST',headers:{'Content-Type':'application/json','X-CSRFToken':shareCsrf},body:JSON.stringify(body)});const data=await res.json();if(!res.ok||!data.ok)throw new Error(data.error||'Sharing failed');msg.textContent='Access created.';await showTrace(data.trace,'share',true);setTimeout(()=>location.reload(),700)}catch(err){msg.textContent=err.message;btn.disabled=false}});
function decode(encoded){if(!encoded)return[];let n=encoded.replace(/-/g,'+').replace(/_/g,'/');while(n.length%4)n+='=';return JSON.parse(atob(n))}
document.querySelectorAll('.shared-download-btn').forEach(btn=>btn.addEventListener('click',async()=>{const old=btn.textContent;btn.disabled=true;btn.textContent='…';try{const res=await fetch(`/api/shares/${btn.dataset.shareId}/download`);if(!res.ok){let m='Download failed';try{m=(await res.json()).error||m}catch(_){}throw new Error(m)}const trace=decode(res.headers.get('X-Crypto-Trace'));const blob=await res.blob();await showTrace(trace,'shared-download',true);const u=URL.createObjectURL(blob),a=document.createElement('a');a.href=u;a.download=btn.dataset.name;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(u)}catch(err){alert(err.message)}finally{btn.disabled=false;btn.textContent=old}}));
