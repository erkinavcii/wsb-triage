const SAFEBOX_TOKEN = (document.querySelector('meta[name="safebox-token"]') || {}).content || "";
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
let activeJobId = null, activeJob = null, pollTimer = null, renderedStaticKey = '', caps = {}, vtModalOpen = false, recentJobs = [];
let previewCtx = { jobId: null, filePath: '', mode: 'text' };

async function api(url, opts = {}) {
  opts.headers = opts.headers || {};
  if (SAFEBOX_TOKEN && !opts.headers['X-SafeBox-Token']) {
    opts.headers['X-SafeBox-Token'] = SAFEBOX_TOKEN;
  }
  const r = await fetch(url, opts);
  let d = null; try { d = await r.json(); } catch (e) {}
  if (!r.ok) throw new Error((d && d.detail) || ('HTTP ' + r.status));
  return d;
}
const post = (url, body) => api(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-SafeBox-Token': SAFEBOX_TOKEN }, body: JSON.stringify(body || {}) });
const showModal = id => { $(id).classList.remove('hidden'); $(id).classList.add('flex'); };
const hideModal = id => { $(id).classList.add('hidden'); $(id).classList.remove('flex'); };
const badge = (text, color) => `<span class="text-xs px-3 py-1.5 rounded-xl bg-${color}-500/15 text-${color}-300 border border-${color}-500/30 font-medium">${text}</span>`;
const fmtMB = b => (b / 1048576).toFixed(1) + ' MB';

async function loadVboxSnapshots(vmName, selectEl) {
  if (!selectEl) return;
  selectEl.innerHTML = '<option value="">Son SafeBox_Temiz snapshot</option>';
  if (!vmName) return;
  try {
    const d = await api('/api/vbox/snapshots/' + encodeURIComponent(vmName));
    (d.snapshots || []).forEach(s => {
      const opt = document.createElement('option');
      opt.value = s; opt.textContent = s;
      selectEl.appendChild(opt);
    });
  } catch (e) {}
}

// ---------------------------------------------------------------- system status
async function loadSystemStatus() {
  try {
    caps = await api('/api/system-status');
    $('vtStatusDot').className = 'w-2 h-2 rounded-full ' + (caps.vt_api_configured ? 'bg-emerald-400' : 'bg-amber-400');
    $('vtStatusText').textContent = caps.vt_api_configured ? `VT API aktif (${caps.vt_api_masked})` : 'VT API: anahtar girilmedi';
    if ($('mbEnabledInput') && !vtModalOpen) $('mbEnabledInput').checked = !!caps.mb_enabled;
    $('sysSubText').textContent = caps.os;
    let h = '';
    h += caps.windows_sandbox_enabled ? badge('✅ Windows Sandbox hazır', 'emerald')
      : badge('⚠️ Windows Sandbox kapalı', 'amber') + `<button id="btnEnableWsb" class="text-xs px-3 py-1.5 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 font-medium">🔧 Etkinleştir (yönetici onayı)</button>`;
    h += caps.seven_zip ? badge('✅ 7-Zip', 'emerald') : `<a href="https://www.7-zip.org" target="_blank" rel="noopener">${badge('⚠️ 7-Zip yok (RAR/7z için gerekli) ↗', 'amber')}</a>`;
    h += caps.tshark ? badge('✅ Wireshark / tshark', 'emerald') : `<a href="https://www.wireshark.org/download.html" target="_blank" rel="noopener">${badge('ℹ️ Wireshark yok (ağ özeti için) ↗', 'slate')}</a>`;
    h += caps.procmon ? badge('✅ Procmon', 'emerald') : '';
    if (caps.yara) {
      const y = caps.yara, probs = asArr(y.problems);
      const tip = esc([y.hint, ...probs].filter(Boolean).join('\n'));
      const n = asNum(y.rules_count);
      const yColor = (y.engine === 'yara-python' && !probs.length) ? 'emerald' : 'amber';
      const yTxt = `${yColor === 'emerald' ? '✅' : '⚠️'} YARA (${n} kural${probs.length ? `, ${probs.length} atlandı` : ''}${y.engine !== 'yara-python' ? ', yerleşik motor' : ''})`;
      h += `<button id="btnYaraModal" title="${tip}" class="text-xs px-3 py-1.5 rounded-xl bg-${yColor}-500/15 hover:bg-${yColor}-500/30 text-${yColor}-300 border border-${yColor}-500/30 font-medium">${yTxt}</button>`;
    }
    h += caps.context_menu
      ? `<button id="btnCtxMenu" class="text-xs px-3 py-1.5 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/30 font-medium" title="Dosya Gezgini sağ tık menüsünü kaldır">✅ Sağ tık menüsü aktif</button>`
      : `<button id="btnCtxMenu" class="text-xs px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 font-medium" title="Dosya/klasör sağ tık menüsüne 'SafeBox ile analiz et' ekler">🖱 Sağ tık menüsü ekle</button>`;
    if (caps.virtualbox_installed && caps.virtualbox_vms.length) {
      h += `<select id="vmSelect" class="text-xs bg-slate-900 border border-slate-700 rounded-xl px-2 py-1.5">${caps.virtualbox_vms.map(v => `<option>${esc(v.name)}</option>`).join('')}</select>
            <button id="btnHarden" class="text-xs px-3 py-1.5 rounded-xl bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/40">🛡️ VM'i izole et + snapshot</button>`;
      const vmHtml = caps.virtualbox_vms.map(v => `<option value="${esc(v.name)}">${esc(v.name)}</option>`).join('');
      if ($('vboxVmInput') && $('vboxVmInput').innerHTML !== vmHtml) {
        $('vboxVmInput').innerHTML = vmHtml;
        loadVboxSnapshots($('vboxVmInput').value, $('vboxSnapInput'));
      }
      if ($('sbModalVm')) $('sbModalVm').innerHTML = vmHtml;
    } else {
      if ($('vboxVmInput')) $('vboxVmInput').innerHTML = '<option value="">VirtualBox VM yok</option>';
      if ($('sbModalVm')) $('sbModalVm').innerHTML = '<option value="">VirtualBox VM yok</option>';
    }
    $('sysCapsBadges').innerHTML = h;
    if ($('btnEnableWsb')) $('btnEnableWsb').onclick = async () => alert((await post('/api/sandbox/enable')).message);
    if ($('btnHarden')) $('btnHarden').onclick = hardenVm;
    if ($('btnYaraModal')) $('btnYaraModal').onclick = openYaraModal;
    if ($('btnCtxMenu')) $('btnCtxMenu').onclick = async () => {
      try { const d = await post('/api/context-menu', { enabled: !caps.context_menu }); alert(d.message); loadSystemStatus(); }
      catch (e) { alert(e.message); }
    };
  } catch (e) { $('sysSubText').textContent = 'Sunucuya ulaşılamadı: ' + e.message; }
}

async function hardenVm() {
  const vm = $('vmSelect').value;
  if (!confirm(`'${vm}' sanal makinesinin TÜM ağ kartları, pano paylaşımı ve sürükle-bırak kalıcı olarak kapatılacak ve snapshot alınacak.\n\nVM kapalı olmalı. Bu VM'i başka işler için kullanıyorsanız (ör. hesap oturumları) zararlı testi için ayrı bir VM kullanmanız daha güvenli.\n\nDevam edilsin mi?`)) return;
  try { const d = await post('/api/vbox/harden', { vm_name: vm }); alert(d.message + (d.steps ? '\n\n• ' + d.steps.join('\n• ') : '')); }
  catch (e) { alert(e.message); }
}

// ---------------------------------------------------------------- start analysis
if ($('backendInput')) {
  $('backendInput').onchange = () => {
    const isVbox = $('backendInput').value === 'vbox';
    $('vboxOpts').classList.toggle('hidden', !isVbox);
    if (isVbox && $('vboxVmInput').value) loadVboxSnapshots($('vboxVmInput').value, $('vboxSnapInput'));
  };
}
if ($('vboxVmInput')) $('vboxVmInput').onchange = () => loadVboxSnapshots($('vboxVmInput').value, $('vboxSnapInput'));

function options() {
  return {
    password: $('pwInput').value,
    target: $('targetInput').value.trim(),
    target_args: $('targetArgsInput') ? $('targetArgsInput').value.trim() : '',
    dll_export: $('dllExportInput') ? $('dllExportInput').value.trim() : '',
    duration_min: parseInt($('durationInput').value, 10),
    memory_mb: parseInt($('memoryInput').value, 10) || 4096,
    network: $('optNetwork').checked,
    vt_upload: $('optUpload').checked,
    run_sandbox: $('optSandbox').checked,
    keep_sandbox_open: $('optKeepOpen').checked,
    simulate_user: $('optSimUser').checked,
    run_as_standard_user: $('optStdUser') ? $('optStdUser').checked : false,
    seed_honeyfiles: $('optHoneyfiles') ? $('optHoneyfiles').checked : true,
    notify: $('optNotify') ? $('optNotify').checked : true,
    sandbox_backend: $('backendInput') ? $('backendInput').value : 'wsb',
    vbox_vm: $('vboxVmInput') ? $('vboxVmInput').value : '',
    vbox_snapshot: $('vboxSnapInput') ? $('vboxSnapInput').value : '',
    vbox_user: $('vboxUserInput') ? $('vboxUserInput').value.trim() : '',
    vbox_password: $('vboxPassInput') ? $('vboxPassInput').value : '',
  };
}
async function startAnalysis(path, extra = {}) {
  if (!path) { alert('Önce bir dosya, klasör veya arşiv seçin.'); return; }
  try {
    const d = await post('/api/jobs', Object.assign({ path }, options(), extra));
    openJob(d.id);
    loadJobs();
  } catch (e) { alert('Başlatılamadı: ' + e.message); }
}
$('btnStart').onclick = () => startAnalysis($('pathInput').value.trim());
$('btnDemo').onclick = async () => {
  const d = await post('/api/demo');
  $('pathInput').value = d.path; $('targetInput').value = d.target;
  startAnalysis(d.path, { target: d.target, network: false });
};
document.querySelectorAll('[data-browse]').forEach(b => b.onclick = async () => {
  const d = await api('/api/browse-dialog?mode=' + b.dataset.browse);
  if (d.selected_path) $('pathInput').value = d.selected_path;
});

const MAX_UPLOAD = 4 * 1024 ** 3;
async function uploadAndStart(file) {
  if (!file) return;
  if (file.size > MAX_UPLOAD) {
    alert(`"${file.name}" ${(file.size / 1024 ** 3).toFixed(1)} GB. Panele bırakma sınırı 4 GB.\n\nBüyük dosyaları sağdaki 'Dosya' / 'Klasör' butonuyla seçin; kopyalanmadan analiz edilir.`);
    return;
  }
  const dz = $('dropZone'); const old = dz.innerHTML;
  dz.innerHTML = `<div class="text-sm text-cyan-300 animate-pulse">"${esc(file.name)}" alınıyor (${fmtMB(file.size)})...</div>`;
  try {
    const fd = new FormData(); fd.append('file', file);
    const d = await api('/api/upload', { method: 'POST', body: fd });
    $('pathInput').value = d.path;
    await startAnalysis(d.path);
  } catch (e) { alert('Yükleme hatası: ' + e.message); }
  finally { dz.innerHTML = old; bindDropZone(); }
}
function bindDropZone() {
  const dz = $('dropZone');
  dz.onclick = () => $('fileInput').click();
  $('fileInput').onchange = e => uploadAndStart(e.target.files[0]);
}
const dz = $('dropZone');
['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('drop-active'); }));
['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('drop-active'); }));
dz.addEventListener('drop', e => { if (e.dataTransfer.files.length) uploadAndStart(e.dataTransfer.files[0]); });
bindDropZone();

// ---------------------------------------------------------------- watcher
let watchInit = false;
async function loadWatch() {
  try {
    const w = await api('/api/watch');
    if (!watchInit) { $('watchFolder').value = w.folder; $('watchEnabled').checked = w.enabled; $('watchAuto').checked = w.auto_start; watchInit = true; }
    $('watchList').innerHTML = w.found.length ? w.found.slice().reverse().map((f, i) => `
      <div class="flex items-center justify-between gap-2 p-2 rounded-lg bg-slate-900 border border-slate-800">
        <div class="min-w-0"><div class="text-slate-200 truncate">${esc(f.name)}</div><div class="text-slate-500">${esc(f.time)} • ${fmtMB(f.size)}${f.later_part ? ' • arşiv parçası' : ''}</div></div>
        ${f.job ? `<button class="px-2 py-1 rounded bg-slate-800 text-cyan-300" data-open-job="${esc(f.job)}">Analizi aç</button>`
                : f.later_part ? '' : `<button class="px-2 py-1 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40" data-analyze="${esc(f.path)}">Analiz et</button>`}
      </div>`).join('') : (w.enabled ? 'İzleniyor — yeni indirme bekleniyor.' : 'Kapalı.');
  } catch (e) {}
}
async function saveWatch() {
  try { await post('/api/watch', { folder: $('watchFolder').value.trim(), enabled: $('watchEnabled').checked, auto_start: $('watchAuto').checked }); loadWatch(); }
  catch (e) { alert(e.message); }
}
$('btnWatchSave').onclick = saveWatch; $('watchEnabled').onchange = saveWatch; $('watchAuto').onchange = saveWatch;

// ---------------------------------------------------------------- jobs list
const levelBadge = {
  red: '<span class="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300">KIRMIZI</span>',
  yellow: '<span class="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300">İNCELE</span>',
  green: '<span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300">bayrak yok</span>',
  pending: '<span class="px-2 py-0.5 rounded bg-slate-700 text-slate-300">...</span>',
};
const statusTr = { running: 'çalışıyor', done: 'bitti', error: 'hata', waiting_sandbox: 'sandbox bekliyor', interrupted: 'yarıda kaldı', cancelled: 'iptal edildi' };
async function loadJobs() {
  try {
    const jobs = await api('/api/jobs');
    recentJobs = jobs || [];
    $('jobsList').innerHTML = jobs.length ? jobs.map(j => `
      <button data-open-job="${esc(j.id)}" class="w-full text-left flex items-center justify-between gap-2 p-2 rounded-lg ${j.id === activeJobId ? 'bg-slate-800 border-cyan-500/50' : 'bg-slate-900 border-slate-800'} border hover:border-slate-600">
        <div class="min-w-0"><div class="text-slate-200 truncate">${esc(j.sample.split(/[\\/]/).pop())}</div><div class="text-slate-500">${esc(j.created)} • ${esc(statusTr[j.status] || j.status)}</div></div>
        ${levelBadge[j.verdict] || ''}
      </button>`).join('') : 'Henüz analiz yok.';
  } catch (e) {}
}

$('btnCleanup').onclick = async () => {
  if (!confirm('30 günden eski, bitmiş bütün analizlerin klasörleri kalıcı olarak silinecek. Devam?')) return;
  try { const d = await post('/api/jobs-cleanup', { days: 30 }); alert(`${d.deleted.length} analiz silindi.`); loadJobs(); }
  catch (e) { alert(e.message); }
};

document.addEventListener('click', e => {
  const t = e.target.closest('[data-open-job],[data-analyze],[data-close],[data-vt-query],[data-vt-upload],[data-intel-query],[data-preview],[data-preview-mode],[data-yara-file]');
  if (!t) return;
  if (t.dataset.openJob) openJob(t.dataset.openJob);
  else if (t.dataset.analyze) { $('pathInput').value = t.dataset.analyze; startAnalysis(t.dataset.analyze); }
  else if (t.dataset.close) { if (t.dataset.close === 'vtModal') vtModalOpen = false; hideModal(t.dataset.close); }
  else if (t.dataset.vtQuery) manualVtQuery(parseInt(t.dataset.vtQuery, 10));
  else if (t.dataset.vtUpload) manualVtUpload(parseInt(t.dataset.vtUpload, 10));
  else if (t.dataset.intelQuery) manualIntelQuery(parseInt(t.dataset.intelQuery, 10));
  else if (t.dataset.preview !== undefined) openPreviewModal(parseInt(t.dataset.preview, 10));
  else if (t.dataset.previewMode) loadPreviewContent(t.dataset.previewMode);
  else if (t.dataset.yaraFile) selectYaraFile(t.dataset.yaraFile);
});

// ---------------------------------------------------------------- active job
function openJob(id) {
  activeJobId = id; renderedStaticKey = '';
  $('jobSection').classList.remove('hidden');
  clearTimeout(pollTimer);
  pollJob();
  loadJobs();
  setTimeout(() => $('jobSection').scrollIntoView({ behavior: 'smooth', block: 'start' }), 150);
}

async function pollJob() {
  if (!activeJobId) return;
  const id = activeJobId;
  try {
    const st = await api('/api/jobs/' + encodeURIComponent(id));
    if (id !== activeJobId) return;
    activeJob = st;
    renderJob(st);
    if (st.status === 'running') { pollTimer = setTimeout(pollJob, 2000); return; }
    loadJobs();
  } catch (e) { $('jobMeta').textContent = 'Durum alınamadı: ' + e.message; pollTimer = setTimeout(pollJob, 5000); }
}

const stageIcon = {
  pending: '<span class="text-slate-500">○</span>',
  running: '<span class="inline-block w-3.5 h-3.5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin"></span>',
  done: '<span class="text-emerald-400">✓</span>', skipped: '<span class="text-slate-400">⤼</span>',
  waiting: '<span class="text-amber-300">⏸</span>', queued: '<span class="text-sky-300">⏳</span>', unavailable: '<span class="text-amber-300">⚠</span>', error: '<span class="text-rose-400">✗</span>',
};

function renderJob(st) {
  $('jobSample').textContent = st.sample;
  const o = st.options;
  $('jobMeta').textContent = `${st.created} • ${statusTr[st.status] || st.status} • ${(o.sandbox_backend === 'vbox' ? 'VirtualBox' : 'Sandbox')} • internet ${o.network ? 'açık' : 'kapalı'} • ${o.duration_min} dk • klasör: ${st.case_dir}`;

  // buttons
  const sbStatus = st.stages.sandbox.status;
  let btn = `<button class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200" id="bOpenFolder">📂 Klasörü aç</button>`;
  if (st.has_report) {
    btn += `<button class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200" id="bReport">📄 Raporu göster</button>`;
    btn += `<a href="/api/jobs/${encodeURIComponent(st.id)}/report?format=html" target="_blank" rel="noopener noreferrer" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-cyan-300">🌐 HTML Rapor</a>`;
    btn += `<a href="/api/jobs/${encodeURIComponent(st.id)}/report?format=json" target="_blank" rel="noopener noreferrer" download="report_${encodeURIComponent(st.id)}.json" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-emerald-300">📦 JSON İndir</a>`;
    btn += `<a href="/api/jobs/${encodeURIComponent(st.id)}/iocs?format=csv" download="iocs_${encodeURIComponent(st.id)}.csv" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-amber-300">🧾 IOC (CSV)</a>`;
    btn += `<a href="/api/jobs/${encodeURIComponent(st.id)}/iocs?format=stix" download="iocs_${encodeURIComponent(st.id)}.stix.json" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-purple-300">🛡 IOC (STIX 2.1)</a>`;
  }
  if (st.has_pcap) btn += `<button class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200" id="bPcap" ${caps.tshark ? '' : 'disabled title="Wireshark kurulu değil"'}>🦈 Wireshark'ta aç</button>`;
  if (st.has_procmon) btn += `<button class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200" id="bProcmon">🔬 Procmon'da aç</button>`;
  if (sbStatus === 'running') btn += `<button class="px-3 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-xs text-rose-200 border border-rose-500/40" id="bStop">⏹ İzlemeyi şimdi bitir</button>`;
  else if (st.status !== 'running' && ['waiting', 'unavailable', 'error', 'done'].includes(sbStatus))
    btn += `<button class="px-3 py-1.5 rounded-lg bg-gradient-to-r from-indigo-500 to-purple-600 text-xs font-semibold text-white" id="bSandbox">🚀 ${sbStatus === 'done' ? "Sandbox'ta tekrar çalıştır" : "Sandbox'ta çalıştır"}</button>`;
  if (st.status === 'running' && sbStatus !== 'running')
    btn += `<button class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-rose-200 border border-rose-500/30" id="bCancel">✖ İptal et</button>`;
  if (st.status !== 'running')
    btn += `<button class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-rose-900/60 text-xs text-slate-300" id="bDelete" title="Analiz klasörünü siler. Seçtiğin orijinal dosya/klasöre dokunulmaz.">🗑 Sil</button>`;
  $('jobButtons').innerHTML = btn;
  const id = st.id, enc = encodeURIComponent(id);
  $('bOpenFolder').onclick = () => post(`/api/jobs/${enc}/open?what=folder`);
  if ($('bReport')) $('bReport').onclick = async () => { try { const r = await fetch(`/api/jobs/${enc}/report`, { headers: SAFEBOX_TOKEN ? { 'X-SafeBox-Token': SAFEBOX_TOKEN } : {} }); if (!r.ok) throw new Error('HTTP ' + r.status); $('reportText').textContent = await r.text(); showModal('reportModal'); } catch (e) { alert('Rapor alınamadı: ' + e.message); } };
  if ($('bPcap')) $('bPcap').onclick = () => post(`/api/jobs/${enc}/open?what=pcap`).catch(e => alert(e.message));
  if ($('bProcmon')) $('bProcmon').onclick = () => post(`/api/jobs/${enc}/open?what=procmon`).catch(e => alert(e.message));
  if ($('bStop')) $('bStop').onclick = () => post(`/api/jobs/${enc}/stop`);
  if ($('bCancel')) $('bCancel').onclick = async () => {
    if (!confirm('Analiz iptal edilsin mi? Çalışan adım güvenli bir noktada durur.')) return;
    try { await post(`/api/jobs/${enc}/cancel`); } catch (e) { alert(e.message); }
  };
  if ($('bDelete')) $('bDelete').onclick = async () => {
    if (!confirm("Bu analizin klasörü (açılmış dosyalar, ağ kaydı, rapor) kalıcı olarak silinecek. Orijinal dosyana dokunulmaz.\n\nSilinsin mi?")) return;
    try {
      await api(`/api/jobs/${enc}`, { method: 'DELETE' });
      activeJobId = null; $('jobSection').classList.add('hidden'); loadJobs();
    } catch (e) { alert(e.message); }
  };
  if ($('bSandbox')) $('bSandbox').onclick = () => openSandboxModal(st);

  // verdict
  const v = st.verdict || { level: 'pending', red: [], notes: [] };
  const vColor = { red: 'rose', yellow: 'amber', green: 'emerald', pending: 'slate' }[v.level];
  const vTitle = { red: '🚨 Ciddi bulgular var — ana bilgisayarda çalıştırmayın', yellow: '⚠️ İncelenmesi gereken bulgular var', green: '✅ Otomatik kontroller kırmızı bayrak bulmadı (bu, temiz olduğunu kanıtlamaz)', pending: '⏳ Analiz sürüyor...' }[v.level];
  $('verdictBox').innerHTML = `<div class="p-4 rounded-xl bg-${vColor}-950/40 border border-${vColor}-500/50 space-y-1.5">
      <div class="font-semibold text-sm text-${vColor}-200">${vTitle}</div>
      ${v.red.map(x => `<div class="text-xs text-rose-200">• <b>KIRMIZI:</b> ${esc(x)}</div>`).join('')}
      ${v.notes.map(x => `<div class="text-xs text-amber-200">• ${esc(x)}</div>`).join('')}
    </div>`;

  // stages
  $('stageList').innerHTML = Object.entries(st.stages).map(([k, s], i) => `
    <li class="p-3 rounded-xl bg-slate-900/80 border ${s.status === 'running' ? 'border-cyan-500/50' : s.status === 'error' ? 'border-rose-500/50' : 'border-slate-800'}">
      <div class="flex items-center gap-2 text-xs font-semibold text-slate-200">${stageIcon[s.status] || ''} ${i + 1}. ${esc(s.label)}</div>
      <div class="text-[11px] text-slate-400 mt-1 break-words">${esc(s.msg || ({ pending: 'Sırada', skipped: 'Atlandı' }[s.status] || ''))}</div>
    </li>`).join('');

  renderVt(st); renderSandbox(st); renderNetwork(st); renderStatic(st);
  $('jobLog').innerHTML = (st.log || []).slice().reverse().map(l => `<div><span class="text-slate-600">${esc(l.t)}</span> ${esc(l.msg)}</div>`).join('');
}

function vtCell(r) {
  if (!r) return '<span class="text-slate-500">—</span>';
  const m = r.stats.malicious, c = m >= 3 ? 'text-rose-300' : m > 0 ? 'text-amber-300' : 'text-emerald-300';
  return `<span class="${c} font-semibold">${m} / ${r.stats.total}</span>`;
}
function renderVt(st) {
  const rows = st.vt || [];
  $('vtSection').classList.toggle('hidden', !rows.length);
  if (!rows.length) return;
  $('vtTable').innerHTML = `<tr><th>Dosya</th><th>Durum</th><th>Zararlı</th><th>Etiket / motorlar</th><th></th></tr>` + rows.map(e => {
    const r = e.result;
    const intelTxt = e.intel && e.intel.summary ? `<div class="text-rose-300 font-semibold">${esc(e.intel.summary)}</div>` : '';
    const fam = r && r.has_dangerous_malware_family ? '<span class="px-1.5 py-0.5 rounded bg-rose-600/40 text-rose-100 font-bold mr-1">ZARARLI AİLE</span>' : '';
    const engines = r ? r.flagged_engines.slice(0, 4).map(x => `${esc(x.engine)}: ${esc(x.result)}`).join(' | ') : '';
    return `<tr><td class="mono break-all">${esc(e.rel)}</td><td class="text-slate-400">${esc(e.status)}</td><td>${vtCell(r)}</td>
      <td>${fam}${r ? esc(r.suggested_threat_label) : ''}${intelTxt}<div class="text-slate-500">${engines}</div></td>
      <td><a class="text-cyan-400 underline whitespace-nowrap" target="_blank" rel="noopener" href="${esc(e.gui_url)}">VT ↗</a></td></tr>`;
  }).join('');
}

// Everything under b / live comes from inside the sandbox and must be treated as attacker-controlled.
const asArr = x => Array.isArray(x) ? x : [];
const asNum = x => Number.isFinite(Number(x)) ? Number(x) : 0;
function listBox(title, items, color) {
  items = asArr(items);
  return `<div class="p-3 rounded-lg bg-slate-900 border ${items.length ? `border-${color}-500/40` : 'border-slate-800'}">
    <div class="text-xs font-semibold text-${color}-300 mb-1">${esc(title)} (${items.length})</div>
    <div class="text-[11px] mono text-slate-300 space-y-1 max-h-36 overflow-y-auto">${items.length ? items.slice(0, 60).map(x => `<div class="break-all">${esc(x)}</div>`).join('') : '<span class="text-slate-500">yok</span>'}</div></div>`;
}

function renderSandbox(st) {
  const s = st.stages.sandbox, live = (st.sandbox || {}).live, b = st.behavior;
  const shots = asArr(st.screenshots || (st.sandbox || {}).screenshots);
  const show = s.status === 'running' || live || b || shots.length > 0;
  $('sbSection').classList.toggle('hidden', !show);
  if (!show) return;
  $('sbPulse').className = 'w-2.5 h-2.5 rounded-full ' + (s.status === 'running' ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500');
  $('sbStatusText').textContent = (st.sandbox || {}).status_text || s.msg || '';
  const procs = asArr(b ? b.Processes : (live || {}).Processes).filter(p => p && typeof p === 'object');
  const conns = asArr(b ? (b.Network || {}).Connections : (live || {}).Connections).filter(c => c && typeof c === 'object');
  const susp = procs.filter(p => p.Suspicious).length, fromSample = procs.filter(p => p.InTree).length;
  const counter = (label, val, warn) => `<div class="p-3 rounded-xl bg-slate-900 border border-slate-800 text-center"><div class="text-[11px] text-slate-400">${label}</div><div class="text-lg font-bold ${warn ? 'text-rose-300' : 'text-white'}">${esc(val)}</div></div>`;
  $('sbCounters').innerHTML = counter('Kalan süre', live && s.status === 'running' ? asNum(live.SecondsLeft) + ' sn' : (b ? 'bitti' : '—'))
    + counter('Yeni işlem (örnekten)', `${procs.length} (${fromSample})`) + counter('Şüpheli komut', susp, susp > 0) + counter('TCP bağlantısı', conns.length);
  const src = b || live || {}, lan = src.LanBlock || {};
  const lanText = lan.Tampered ? `<span class="text-rose-300 font-semibold">🚨 Yerel ağ engeli kaldırılmaya çalışıldı (yeniden uygulandı): ${esc(asArr(lan.Details).join(', '))}</span>`
    : lan.Applied ? `<span class="text-emerald-300">🔒 Ev ağı / ana bilgisayar engelli — sadece internet + DNS (53) açık</span>`
    : lan.Requested ? `<span class="text-amber-300">⚠️ Yerel ağ engeli uygulanamadı: ${esc(lan.Status)}</span>` : `<span class="text-slate-400">İnternet kapalı</span>`;
  $('sbCounters').innerHTML += `<div class="col-span-2 md:col-span-4 text-[11px] flex flex-wrap gap-x-6 gap-y-1">${lanText}
    ${src.RunMode ? `<span class="text-slate-400">Örnek: ${esc(src.RunMode === 'copied' ? 'sandbox diskine kopyalanıp çalıştırıldı' : 'kopyalanmadan, salt okunur klasörden çalıştırıldı (büyük kurulum)')}</span>` : ''}</div>`;

  let pers;
  if (b) {
    const P = b.Persistence || {}, D = b.Defender || {};
    const advPers = asArr(P.WmiSubscriptions).concat(asArr(P.AppInitDlls), asArr(P.BitsJobs), asArr(P.PsProfiles), asArr(P.ComHijacks), asArr(P.ActiveSetup));
    pers = listBox('🍯 Yem dosya (honeyfile) uyarıları', b.HoneyfileAlerts, 'rose')
      + listBox('🛑 Defender değişiklikleri', D.Added, 'rose') + listBox('🛑 Defender tespitleri', D.ThreatsDetected, 'rose')
      + listBox('⚙️ Yeni servisler', P.Services, 'rose') + listBox('🧩 Yeni sürücüler', P.Drivers, 'rose')
      + listBox('⏰ Zamanlanmış görevler', P.Tasks, 'amber') + listBox('📌 Otomatik başlatma (Run/IFEO)', asArr(P.RunKeys).concat(asArr(P.Startup)), 'amber')
      + listBox('🕵️ Gelişmiş kalıcılık (WMI/COM/AppInit/BITS/PS)', advPers, advPers.length ? 'rose' : 'slate')
      + listBox('📝 hosts (eklenen / silinen)', asArr((b.Hosts || {}).Added).concat(asArr((b.Hosts || {}).Removed).map(x => `[-] ${x}`)), 'amber')
      + listBox('🧱 Güvenlik duvarı kuralları', (b.Firewall || {}).Added, 'amber')
      + listBox('🔌 Yeni dinleyici portlar (TCP)', (b.Network || {}).NewListening, 'rose')
      + listBox(`📂 Yeni çalıştırılabilirler (toplam ${asNum((b.Files || {}).NewCount)} yeni)`, (b.Files || {}).NewExecutables, 'purple')
      + listBox('✏️ Değiştirilen çalıştırılabilirler', (b.Files || {}).ModifiedExecutables, 'rose');
    const pmEvents = asArr((st.procmon_summary || {}).SensitiveEvents);
    if (pmEvents.length) pers += listBox('🔬 Procmon hassas erişimler', pmEvents, 'rose');
  } else {
    const q = (live && live.Quick) || {};
    pers = listBox('🛑 Defender değişiklikleri', q.Defender, 'rose') + listBox('⚙️ Yeni servisler', q.Services, 'rose')
      + listBox('⏰ Zamanlanmış görevler', q.Tasks, 'amber') + listBox('📌 Otomatik başlatma', asArr(q.RunKeys).concat(asArr(q.Startup)), 'amber')
      + listBox('📝 hosts değişiklikleri', q.Hosts, 'amber')
      + `<div class="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-400">Dosya sistemi, sürücü, yem dosya ve güvenlik duvarı karşılaştırması izleme bitince yapılır. Bu kutular 30 sn'de bir güncellenir.</div>`;
  }
  $('sbPersistence').innerHTML = pers;
  $('sbProcs').innerHTML = `<tr><th>Saat</th><th>İşlem</th><th>Üst</th><th>Komut satırı</th></tr>` + procs.slice(0, 200).map(p => `
    <tr class="${p.Suspicious ? 'bg-rose-950/40' : p.InTree ? 'bg-cyan-950/30' : ''}"><td>${esc(p.FirstSeen)}</td>
    <td class="whitespace-nowrap">${p.Suspicious ? '🚨 ' : ''}${p.InTree ? '🎯 ' : ''}${esc(p.Name)} <span class="text-slate-500">(${esc(p.Pid)})</span></td>
    <td class="text-slate-400">${esc(p.ParentName)}</td><td class="mono break-all text-slate-300">${esc((p.CommandLine || p.Path || '').slice(0, 400))}</td></tr>`).join('');
  $('sbConns').innerHTML = `<tr><th>Saat</th><th>İşlem</th><th>Hedef</th><th>Durum</th></tr>` + conns.slice(0, 200).map(c => `
    <tr class="${c.FromSample ? 'bg-cyan-950/30' : ''}"><td>${esc(c.FirstSeen)}</td><td>${c.FromSample ? '🎯 ' : ''}${esc(c.Process)}</td>
    <td class="mono">${esc(c.Remote)}:${esc(c.Port)}</td><td class="text-slate-400">${esc(c.State)}</td></tr>`).join('');
  $('sbScreenshotsWrap').classList.toggle('hidden', !shots.length);
  if (shots.length) {
    $('sbShotCount').textContent = String(shots.length);
    const encId = encodeURIComponent(st.id);
    $('sbScreenshots').innerHTML = shots.map(name => {
      const url = `/api/jobs/${encId}/screenshots/${encodeURIComponent(name)}`;
      return `<a href="${url}" target="_blank" rel="noopener noreferrer" class="block space-y-1">
        <img src="${url}" alt="${esc(name)}" class="sb-thumb" loading="lazy" />
        <div class="text-[11px] mono text-slate-400 text-center">${esc(name)}</div>
      </a>`;
    }).join('');
  }
}

const classRank = c => c.startsWith('KÖTÜYE') ? 0 : c.startsWith('BİLİNMEYEN') ? 1 : c.startsWith('Paylaşımlı') ? 2 : 3;
const classColor = c => c.startsWith('KÖTÜYE') ? 'text-rose-200 font-bold bg-rose-900/40' : c.startsWith('BİLİNMEYEN') ? 'text-rose-300 font-semibold'
  : c.startsWith('Paylaşımlı') ? 'text-amber-300' : c === 'Adobe' ? 'text-sky-300' : 'text-slate-500';
function procBadge(row) {
  const ps = asArr(row && row.processes);
  if (!ps.length) return '<span class="text-slate-500">—</span>';
  const cls = row.from_sample ? 'text-cyan-300 font-semibold' : 'text-slate-400';
  return `<span class="${cls}">${row.from_sample ? '🎯 ' : ''}${esc(ps.slice(0, 3).join(', '))}</span>`;
}
function domainTable(title, rows) {
  rows = rows || [];
  const sorted = rows.slice().sort((a, b) => classRank(a.class) - classRank(b.class) || b.count - a.count);
  return `<div><div class="text-xs font-semibold text-slate-300 mb-1">${title} (${rows.length})</div>
    <div class="overflow-auto max-h-72 rounded-lg border border-slate-800"><table class="tbl w-full text-[11px]"><tr><th>Ad</th><th>İşlem</th><th>Adet</th><th>Sınıf</th></tr>
    ${sorted.slice(0, 200).map(d => `<tr><td class="mono break-all">${esc(d.name)}</td><td>${procBadge(d)}</td><td>${d.count}</td>
      <td class="${classColor(d.class)}">${esc(d.class)}</td></tr>`).join('')}</table></div></div>`;
}
function renderNetwork(st) {
  const n = st.network;
  $('netSection').classList.toggle('hidden', !n && !st.has_pcap);
  if (!n && !st.has_pcap) return;
  if (!n) { $('netBody').innerHTML = `<div class="text-xs text-slate-400">Ağ kaydı (capture.pcapng) hazır. Otomatik özet için Wireshark'ı kurun, ardından analizi tekrar açın veya kaydı Wireshark'ta açın.</div>`; return; }
  const dohBanner = asArr(n.doh_domains).length
    ? `<div class="lg:col-span-2 p-2.5 rounded-xl bg-amber-950/40 border border-amber-500/40 text-xs text-amber-200">⚠️ DNS-over-HTTPS (DoH) sunucuları tespit edildi: <span class="mono">${asArr(n.doh_domains).map(esc).join(', ')}</span></div>`
    : '';
  const udpBox = `<div><div class="text-xs font-semibold text-slate-300 mb-1">UDP hedefleri (${asArr(n.udp_targets).length})</div><div class="text-[11px] mono text-slate-300 max-h-48 overflow-auto">
    ${asArr(n.udp_targets).map(u => `<div>${esc(u.target)} ×${u.count} ${(u.processes && u.processes.length) ? `← ${procBadge(u)}` : ''}</div>`).join('') || '<span class="text-slate-500">yok</span>'}</div></div>`;
  $('netBody').innerHTML = dohBanner + domainTable('DNS sorguları', n.dns) + domainTable('TLS / QUIC sunucu adları (SNI)', n.sni)
    + `<div><div class="text-xs font-semibold text-slate-300 mb-1">Şifresiz HTTP istekleri (${n.http.length})</div><div class="text-[11px] mono text-slate-300 max-h-48 overflow-auto space-y-0.5">
      ${n.http.map(h => `<div class="break-all ${classColor(h.class)}">${esc(h.method)} http://${esc(h.host)}${esc(h.uri)} ${(h.processes && h.processes.length) ? `← ${procBadge(h)}` : ''}</div>`).join('') || '<span class="text-slate-500">yok</span>'}</div></div>`
    + `<div><div class="text-xs font-semibold text-slate-300 mb-1">TCP bağlantı denemeleri</div><div class="text-[11px] mono text-slate-300 max-h-48 overflow-auto">
      ${n.tcp_targets.map(t => `<div>${esc(t.target)} ×${t.count} ${(t.processes && t.processes.length) ? `← ${procBadge(t)}` : ''}</div>`).join('') || '<span class="text-slate-500">yok</span>'}</div></div>`
    + udpBox;
}

// ---------------------------------------------------------------- static cards (SafeBox renderer)
function riskClass(s) { return s >= 65 ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' : s >= 35 ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'; }
function sigBadge(sig) {
  const s = (sig || {}).status || 'Unknown';
  if (s === 'Valid') return `<span class="px-2.5 py-0.5 rounded-full text-xs bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">✅ İmzalı (${esc(((sig.signer || '').split(',')[0] || '').replace('CN=', ''))})</span>`;
  if (s === 'HashMismatch') return `<span class="px-2.5 py-0.5 rounded-full text-xs bg-rose-500/25 text-rose-300 border border-rose-500/50 font-bold">🚨 İMZA BOZUK (sonradan değiştirilmiş)</span>`;
  return `<span class="px-2.5 py-0.5 rounded-full text-xs bg-amber-500/15 text-amber-300 border border-amber-500/30">⚠️ İmza yok (${esc(s)})</span>`;
}
function renderStatic(st) {
  const files = st.static || [];
  const vtSig = (st.vt || []).map(e => `${e.sha256}:${e.status}:${e.result ? e.result.stats.malicious : ''}:${(e.intel || {}).summary || ''}`).join('|');
  const key = st.id + ':' + files.length + ':' + vtSig;
  $('staticSection').classList.toggle('hidden', !files.length);
  if (key === renderedStaticKey) return;
  renderedStaticKey = key;
  const vtBySha = {}; (st.vt || []).forEach(e => vtBySha[e.sha256] = e);
  $('filesContainer').innerHTML = files.map((f, idx) => {
    const sha = f.hashes.sha256, vt = vtBySha[sha], pe = f.pe_info || {};
    const apis = Object.entries(pe.suspicious_imports || {});
    const apisHtml = apis.length ? apis.map(([c, l]) => `<div class="text-xs bg-slate-900/90 p-2 rounded-lg border border-slate-800"><span class="font-semibold text-amber-300">${esc(c)}:</span> <span class="mono text-slate-300">${esc(l.join(', '))}</span></div>`).join('')
      : '<div class="text-xs text-slate-500">Şüpheli API çağrısı yok.</div>';
    const strs = (f.string_findings || []).length ? f.string_findings.map(s => `<div class="p-2.5 rounded-lg border ${s.severity === 'critical' ? 'bg-rose-950/30 border-rose-500/40 text-rose-200' : 'bg-amber-950/30 border-amber-500/40 text-amber-200'} text-xs">
        <div class="font-bold">🚨 ${esc(s.category)}</div><div class="text-slate-300 text-[11px]">${esc(s.description)}</div><div class="mono text-[11px] text-cyan-300">${esc(s.matches.join(' | '))}</div></div>`).join('')
      : '<div class="text-xs text-slate-500">Bilinen stealer / RAT / anti-VM izi yok.</div>';
    const yaras = (f.yara_matches || []).length ? f.yara_matches.map(y => `<div class="p-2.5 rounded-lg border ${y.severity === 'critical' ? 'bg-rose-950/30 border-rose-500/40 text-rose-200' : 'bg-amber-950/30 border-amber-500/40 text-amber-200'} text-xs">
        <div class="font-bold">🎯 YARA: ${esc(y.rule)}</div><div class="text-slate-300 text-[11px]">${esc(y.description)}</div>${y.strings && y.strings.length ? `<div class="mono text-[11px] text-cyan-300">${esc(y.strings.join(' | '))}</div>` : ''}</div>`).join('')
      : '';
    const spoofs = asArr(f.spoof_flags).map(sf => `<div class="p-2.5 rounded-lg border bg-rose-950/40 border-rose-500/50 text-rose-200 text-xs font-semibold">🎭 ${esc(sf.reason)}</div>`).join('');
    const fmts = asArr(f.format_findings).map(ff => `<div class="p-2.5 rounded-lg border ${ff.severity === 'high' || ff.severity === 'critical' ? 'bg-rose-950/30 border-rose-500/40 text-rose-200' : 'bg-amber-950/30 border-amber-500/40 text-amber-200'} text-xs">
        <div class="font-bold">📎 ${esc(ff.category)}</div><div class="text-[11px] text-slate-300">${esc(ff.description)}</div></div>`).join('');
    const dotnet = asArr(pe.dotnet_indicators).map(di => `<div class="p-2 rounded-lg border bg-indigo-950/30 border-indigo-500/40 text-indigo-200 text-xs">🟣 .NET: ${esc(di.description)}</div>`).join('');
    const deobf = asArr(f.deobfuscated_snippets).length
      ? `<details class="bg-slate-900/90 p-2 rounded-lg border border-cyan-500/30 text-xs"><summary class="cursor-pointer text-cyan-300 font-semibold">🔓 Çözülen gizli komutlar (${f.deobfuscated_snippets.length})</summary><pre class="mt-2 text-[11px] mono text-slate-300 whitespace-pre-wrap break-all max-h-36 overflow-y-auto">${f.deobfuscated_snippets.map(d => `[${esc(d.kind)}]\n${esc(d.decoded)}`).join('\n---\n')}</pre></details>`
      : '';
    const urls = (f.interesting_urls || []).length ? `<div class="text-[11px] mono text-slate-400 break-all">URL'ler: ${f.interesting_urls.map(esc).join(' • ')}</div>` : '';
    const ips = asArr(f.interesting_ips).length ? `<div class="text-[11px] mono text-rose-300 break-all">IPv4 izleri: ${f.interesting_ips.map(esc).join(' • ')}</div>` : '';
    let peMeta = '';
    if (pe.is_pe) {
      const ovTxt = pe.overlay ? ` • Overlay: ${fmtMB(pe.overlay.size)} (ent ${pe.overlay.entropy}${pe.overlay.packer_hint ? ', ' + pe.overlay.packer_hint : ''})` : '';
      const secRows = asArr(pe.sections).map(sc => `<tr class="${sc.rwx ? 'bg-rose-950/40' : ''}"><td>${esc(sc.name)}</td><td>${sc.entropy}</td><td>${sc.virtual_size}</td><td>${sc.raw_size}</td><td>${sc.rwx ? '🚨 RWX' : sc.executable ? 'X' : ''}</td></tr>`).join('');
      peMeta = `<div class="text-[11px] text-slate-400 flex flex-wrap gap-x-3 gap-y-1">
        <span>Mimari: <b class="text-slate-200">${esc(pe.architecture)}</b></span>
        ${pe.compile_time ? `<span>Derleme: <b class="text-slate-200">${esc(pe.compile_time)}</b></span>` : ''}
        <span>İmport: <b class="text-slate-200">${asNum(pe.total_imports)}</b></span>
        ${pe.imphash ? `<span>imphash: <code class="mono text-cyan-300">${esc(pe.imphash)}</code></span>` : ''}
        ${pe.is_dotnet ? '<span class="text-indigo-300 font-semibold">.NET (CLR)</span>' : ''}
        ${pe.has_tls_callbacks ? '<span class="text-rose-300 font-semibold">TLS Callback</span>' : ''}
        ${ovTxt ? `<span>${esc(ovTxt.slice(3))}</span>` : ''}
      </div>
      ${secRows ? `<details class="text-[11px]"><summary class="cursor-pointer text-slate-400">PE bölümleri (${asArr(pe.sections).length})</summary><div class="overflow-x-auto mt-1"><table class="tbl w-full"><tr><th>Bölüm</th><th>Entropi</th><th>VSize</th><th>RSize</th><th>Bayrak</th></tr>${secRows}</table></div></details>` : ''}`;
    }
    return `<div class="glass-card rounded-2xl p-5 space-y-3">
      <div class="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div class="space-y-1 min-w-0">
          <div class="flex flex-wrap items-center gap-2"><span class="text-sm font-bold text-white mono break-all">${esc(f.rel)}</span>${sigBadge(f.signature)}
            <span class="text-xs text-slate-400">(${f.file_size_mb} MB • entropi ${f.entropy}/8)</span></div>
          <div class="text-[11px] text-slate-500 mono">SHA-256: <span class="text-slate-300 select-all">${esc(sha)}</span></div>
          ${peMeta}
        </div>
        <div class="px-3 py-1.5 rounded-xl border font-bold text-xs ${riskClass(f.risk_score)}">Statik risk ${f.risk_score}/100</div>
      </div>
      <ul class="list-disc list-inside text-xs text-slate-300 space-y-0.5">${f.risk_reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul>
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-3"><div class="space-y-2">${spoofs}${fmts}${yaras}${dotnet}${deobf}${strs}${ips}${urls}</div><div class="space-y-2">${apisHtml}</div></div>
      <div class="pt-2 border-t border-slate-800/80 flex flex-wrap items-center gap-2 text-xs">
        <button data-preview="${idx}" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-200 border border-slate-700 font-semibold">👁️ İçeriği incele</button>
        ${vt ? `<span>VirusTotal: ${vtCell(vt.result)} <span class="text-slate-500">${esc(vt.status)}</span></span>` : `<button data-vt-query="${idx}" class="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 font-semibold">🛡️ VirusTotal ile sorgula</button>`}
        <button data-intel-query="${idx}" class="px-3 py-1.5 rounded-lg bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/40 font-semibold">🔍 MB / HA Sor</button>
        <a href="https://www.virustotal.com/gui/file/${esc(sha)}" target="_blank" rel="noopener" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200">VT ↗</a>
        <a href="https://www.hybrid-analysis.com/search?query=${esc(sha)}" target="_blank" rel="noopener" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200">Hybrid Analysis ↗</a>
        <a href="https://app.any.run/submissions/#filehash:${esc(sha)}" target="_blank" rel="noopener" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200">ANY.RUN ↗</a>
        <a href="https://tria.ge/s?q=${esc(sha)}" target="_blank" rel="noopener" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200">Triage ↗</a>
      </div>
      <div id="vtBox_${idx}" class="hidden p-3 rounded-xl bg-slate-900 border border-slate-700 text-xs"></div>
    </div>`;
  }).join('');
}

async function manualVtQuery(idx) {
  const f = activeJob.static[idx], box = $('vtBox_' + idx);
  box.classList.remove('hidden'); box.innerHTML = '<div class="text-cyan-300 animate-pulse">Sorgulanıyor (ücretsiz API kotası nedeniyle 15 sn sürebilir)...</div>';
  const d = await api('/api/vt/query/' + f.hashes.sha256);
  if (d.status === 'not_found') { box.innerHTML = `${esc(d.message)} <button data-vt-upload="${idx}" class="ml-2 px-2 py-1 rounded bg-cyan-500/20 text-cyan-200 border border-cyan-500/40">⬆️ Yükle ve tara</button>`; return; }
  if (d.status !== 'found') { box.innerHTML = `<span class="text-rose-300">${esc(d.message)}</span>`; return; }
  box.innerHTML = `<div class="font-semibold">${vtCell(d)} motor zararlı dedi — ${esc(d.suggested_threat_label)} ${d.has_dangerous_malware_family ? '<b class="text-rose-300">(ZARARLI AİLE)</b>' : ''}</div>
    <div class="text-slate-400 mt-1">${d.flagged_engines.map(x => `${esc(x.engine)}: ${esc(x.result)}`).join(' | ')}</div>`;
}
async function manualVtUpload(idx) {
  const f = activeJob.static[idx], box = $('vtBox_' + idx);
  box.innerHTML = '<div class="text-cyan-300 animate-pulse">Yükleniyor...</div>';
  try { const d = await post('/api/vt/upload', { file_path: f.file_path }); box.innerHTML = esc(d.message); }
  catch (e) { box.innerHTML = `<span class="text-rose-300">${esc(e.message)}</span>`; }
}

async function manualIntelQuery(idx) {
  const f = activeJob.static[idx], box = $('vtBox_' + idx);
  box.classList.remove('hidden'); box.innerHTML = '<div class="text-indigo-300 animate-pulse">MalwareBazaar & Hybrid Analysis sorgulanıyor (yalnızca hash)...</div>';
  try {
    const d = await api('/api/intel/query/' + f.hashes.sha256);
    const lines = [];
    if (d.malwarebazaar) {
      const m = d.malwarebazaar;
      lines.push(m.found
        ? `<div><b class="text-rose-300">MalwareBazaar:</b> Zararlı kayıtlı (${esc(m.family || 'etiketsiz')}) — <a class="text-cyan-400 underline" href="${esc(m.gui_url)}" target="_blank" rel="noopener">detay ↗</a></div>`
        : `<div><b class="text-slate-300">MalwareBazaar:</b> ${esc(m.message || 'kayıt bulunamadı')}</div>`);
    }
    if (d.hybrid_analysis) {
      const h = d.hybrid_analysis;
      lines.push(h.found
        ? `<div><b class="${h.verdict === 'malicious' ? 'text-rose-300' : 'text-amber-300'}">Hybrid Analysis:</b> ${esc(h.verdict)} (skor ${esc(h.threat_score)}/100${h.family ? ', ' + esc(h.family) : ''}) — <a class="text-cyan-400 underline" href="${esc(h.gui_url)}" target="_blank" rel="noopener">detay ↗</a></div>`
        : `<div><b class="text-slate-300">Hybrid Analysis:</b> ${esc(h.message || 'kayıt bulunamadı')}</div>`);
    }
    box.innerHTML = lines.join('');
  } catch (e) { box.innerHTML = `<span class="text-rose-300">${esc(e.message)}</span>`; }
}

// ---------------------------------------------------------------- Sandbox launch modal (E9)
function openSandboxModal(st) {
  const o = st.options || {};
  const targets = asArr(st.runnable_targets);
  let tOpts = '<option value="">Otomatik seç</option>';
  targets.forEach(t => { tOpts += `<option value="${esc(t)}"${o.target === t ? ' selected' : ''}>${esc(t)}</option>`; });
  $('sbModalTarget').innerHTML = tOpts;
  $('sbModalTargetCustom').value = (o.target && !targets.includes(o.target)) ? o.target : '';
  $('sbModalArgs').value = o.target_args || '';
  $('sbModalDllExport').value = o.dll_export || '';
  $('sbModalDuration').value = String(o.duration_min || 10);
  $('sbModalMemory').value = String(o.memory_mb || 4096);
  $('sbModalBackend').value = o.sandbox_backend === 'vbox' ? 'vbox' : 'wsb';
  $('sbModalNet').checked = o.network !== false;
  $('sbModalKeepOpen').checked = !!o.keep_sandbox_open;
  $('sbModalSimUser').checked = o.simulate_user !== false;
  $('sbModalStdUser').checked = !!o.run_as_standard_user;
  $('sbModalHoney').checked = o.seed_honeyfiles !== false;
  $('sbModalUser').value = o.vbox_user || '';
  $('sbModalPass').value = '';
  const syncVbox = () => {
    const isVbox = $('sbModalBackend').value === 'vbox';
    $('sbModalVboxOpts').classList.toggle('hidden', !isVbox);
    if (isVbox && $('sbModalVm').value) loadVboxSnapshots($('sbModalVm').value, $('sbModalSnap'));
  };
  $('sbModalBackend').onchange = syncVbox;
  $('sbModalVm').onchange = () => loadVboxSnapshots($('sbModalVm').value, $('sbModalSnap'));
  if (o.vbox_vm && $('sbModalVm')) $('sbModalVm').value = o.vbox_vm;
  syncVbox();
  showModal('sandboxModal');
}
if ($('btnSbModalStart')) {
  $('btnSbModalStart').onclick = async () => {
    if (!activeJob) return;
    const targetVal = $('sbModalTargetCustom').value.trim() || $('sbModalTarget').value;
    const payload = {
      target: targetVal,
      target_args: $('sbModalArgs').value.trim(),
      dll_export: $('sbModalDllExport').value.trim(),
      duration_min: parseInt($('sbModalDuration').value, 10) || 10,
      memory_mb: parseInt($('sbModalMemory').value, 10) || 4096,
      network: $('sbModalNet').checked,
      keep_sandbox_open: $('sbModalKeepOpen').checked,
      simulate_user: $('sbModalSimUser').checked,
      run_as_standard_user: $('sbModalStdUser').checked,
      seed_honeyfiles: $('sbModalHoney').checked,
      sandbox_backend: $('sbModalBackend').value,
      vbox_vm: $('sbModalVm').value || '',
      vbox_snapshot: $('sbModalSnap').value || '',
      vbox_user: $('sbModalUser').value.trim(),
      vbox_password: $('sbModalPass').value || '',
    };
    try {
      await post(`/api/jobs/${encodeURIComponent(activeJob.id)}/sandbox`, payload);
      hideModal('sandboxModal');
      setTimeout(pollJob, 600);
    } catch (e) { alert(e.message); }
  };
}

// ---------------------------------------------------------------- Safe file preview modal (E15)
function openPreviewModal(idx) {
  if (!activeJob || !activeJob.static || !activeJob.static[idx]) return;
  const f = activeJob.static[idx];
  previewCtx = { jobId: activeJob.id, filePath: f.file_path, mode: 'text' };
  $('previewTitle').textContent = f.rel || f.file_name;
  showModal('previewModal');
  loadPreviewContent('text');
}
async function loadPreviewContent(mode) {
  previewCtx.mode = mode;
  $('previewText').textContent = 'Yükleniyor...';
  try {
    const d = await api(`/api/jobs/${encodeURIComponent(previewCtx.jobId)}/preview?file_path=${encodeURIComponent(previewCtx.filePath)}&mode=${encodeURIComponent(mode)}`);
    $('previewMeta').textContent = `${d.mode.toUpperCase()} • ${fmtMB(d.size)}${d.truncated ? ' (ilk kısım gösteriliyor)' : ''}`;
    $('previewText').textContent = d.content || '(boş)';
  } catch (e) { $('previewText').textContent = 'Hata: ' + e.message; }
}

// ---------------------------------------------------------------- YARA rules manager modal (E17)
async function openYaraModal() {
  $('yaraErr').classList.add('hidden');
  showModal('yaraModal');
  await refreshYaraModal();
}
async function refreshYaraModal() {
  try {
    const d = await api('/api/yara/rules');
    const st = d.status || {};
    $('yaraEngineInfo').textContent = `Motor: ${st.engine} • Toplam: ${st.rules_count} kural` + (st.hint ? ` • ${st.hint}` : '');
    const files = asArr(d.files);
    $('yaraFilesList').innerHTML = files.map(f => `
      <button data-yara-file="${esc(f.name)}" class="w-full text-left p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-500/40">
        <div class="text-slate-200 mono truncate">${esc(f.name)}</div>
        <div class="text-[11px] text-slate-400">${f.rules_count} kural${f.builtin ? ' • yerleşik (salt okunur)' : ''}${asArr(f.problems).length ? ' • ⚠️ sorunlu' : ''}</div>
      </button>`).join('');
    if (files.length && !$('yaraFileName').value) selectYaraFile(files[0].name);
  } catch (e) { $('yaraErr').textContent = e.message; $('yaraErr').classList.remove('hidden'); }
}
async function selectYaraFile(name) {
  $('yaraErr').classList.add('hidden');
  try {
    const d = await api('/api/yara/rules/' + encodeURIComponent(name));
    $('yaraFileName').value = d.name;
    $('yaraFileContent').value = d.content;
    const isBuiltin = d.name.toLowerCase() === 'safebox_builtin.yar';
    $('yaraFileName').readOnly = isBuiltin;
    $('yaraFileContent').readOnly = isBuiltin;
    $('btnYaraSave').classList.toggle('hidden', isBuiltin);
    $('btnYaraDelete').classList.toggle('hidden', isBuiltin);
  } catch (e) { $('yaraErr').textContent = e.message; $('yaraErr').classList.remove('hidden'); }
}
if ($('btnYaraNew')) {
  $('btnYaraNew').onclick = () => {
    $('yaraErr').classList.add('hidden');
    $('yaraFileName').readOnly = false;
    $('yaraFileContent').readOnly = false;
    $('yaraFileName').value = 'custom_rules.yar';
    $('yaraFileContent').value = 'rule Custom_Sample_Rule\n{\n    meta:\n        description = "Ozel kural"\n        severity = "high"\n        score = 25\n    strings:\n        $a = "suspicious_marker" ascii wide nocase\n    condition:\n        $a\n}\n';
    $('btnYaraSave').classList.remove('hidden');
    $('btnYaraDelete').classList.add('hidden');
  };
}
if ($('btnYaraSave')) {
  $('btnYaraSave').onclick = async () => {
    $('yaraErr').classList.add('hidden');
    try {
      await post('/api/yara/rules', { name: $('yaraFileName').value.trim(), content: $('yaraFileContent').value });
      await refreshYaraModal();
      loadSystemStatus();
    } catch (e) { $('yaraErr').textContent = e.message; $('yaraErr').classList.remove('hidden'); }
  };
}
if ($('btnYaraDelete')) {
  $('btnYaraDelete').onclick = async () => {
    const name = $('yaraFileName').value.trim();
    if (!name || !confirm(`'${name}' kural dosyası silinsin mi?`)) return;
    try {
      await api('/api/yara/rules/' + encodeURIComponent(name), { method: 'DELETE' });
      $('yaraFileName').value = ''; $('yaraFileContent').value = '';
      await refreshYaraModal();
      loadSystemStatus();
    } catch (e) { $('yaraErr').textContent = e.message; $('yaraErr').classList.remove('hidden'); }
  };
}

// ---------------------------------------------------------------- Compare two jobs
if ($('btnCompareModal')) {
  $('btnCompareModal').onclick = async () => {
    await loadJobs();
    const optsHtml = recentJobs.map(j => `<option value="${esc(j.id)}">${esc(j.sample.split(/[\\/]/).pop())} (${esc(j.created)})</option>`).join('');
    $('cmpBase').innerHTML = optsHtml;
    $('cmpTarget').innerHTML = optsHtml;
    if (recentJobs.length >= 2) { $('cmpBase').selectedIndex = 1; $('cmpTarget').selectedIndex = 0; }
    $('compareResult').innerHTML = recentJobs.length < 2 ? '<div class="text-amber-300">Karşılaştırma için en az 2 analiz gereklidir.</div>' : '';
    showModal('compareModal');
  };
}
if ($('btnRunCompare')) {
  $('btnRunCompare').onclick = async () => {
    const baseId = $('cmpBase').value, targetId = $('cmpTarget').value;
    if (!baseId || !targetId) return;
    $('compareResult').innerHTML = '<div class="text-cyan-300 animate-pulse">Farklar hesaplanıyor...</div>';
    try {
      const d = await api(`/api/compare?base=${encodeURIComponent(baseId)}&target=${encodeURIComponent(targetId)}`);
      const hi = d.highlights.length
        ? `<div class="p-3 rounded-xl bg-amber-950/30 border border-amber-500/40 space-y-1">${d.highlights.map(x => `<div class="text-amber-200">• ${esc(x)}</div>`).join('')}</div>`
        : `<div class="p-3 rounded-xl bg-slate-900 border border-slate-800 text-slate-400">Belirgin fark tespit edilmedi.</div>`;
      const modHtml = d.files.modified.map(m => `<div class="mono text-[11px] break-all">${m.sig_broken ? '🚨 ' : '📝 '}${esc(m.rel)} (${esc(m.base_sig)} → ${esc(m.target_sig)})</div>`).join('');
      const addHtml = d.files.added.map(a => `<div class="mono text-[11px] break-all text-cyan-300">+ ${esc(a.rel)} (${esc(a.sig)})</div>`).join('');
      const fileCount = (d.files.modified || []).length + (d.files.added || []).length;
      const stHtml = d.static_deltas.map(s => `<div class="text-[11px]">• <b>${esc(s.rel)}</b>: skor ${s.base_score ?? 'yok'} → ${s.target_score}${s.new_yara.length ? ` <span class="text-rose-300">[YARA: ${esc(s.new_yara.join(', '))}]</span>` : ''}</div>`).join('');
      const htmlBox = (title, cnt, body, color) => `<div class="p-3 rounded-lg bg-slate-900 border ${cnt ? `border-${color}-500/40` : 'border-slate-800'}">
        <div class="text-xs font-semibold text-${color}-300 mb-1">${esc(title)} (${cnt})</div>
        <div class="text-[11px] text-slate-300 space-y-1 max-h-36 overflow-y-auto">${body || '<span class="text-slate-500">yok</span>'}</div></div>`;
      const bd = d.behavior_diff || {};
      const persAll = (bd.services || []).concat(bd.tasks || [], bd.runkeys || [], bd.wmi_subscriptions || [], bd.com_hijacks || [], bd.appinit_dlls || [], bd.bits_jobs || [], bd.ps_profiles || []);
      const behPairs = [
        ['Yeni kalıcılık (Servis/Görev/Run/WMI/COM)', persAll],
        ['Defender / Firewall / hosts / Honeyfile farkı', (bd.defender || []).concat(bd.firewall || [], bd.hosts || [], bd.hosts_removed || [], bd.honeyfile_alerts || [])],
        ['Ek bırakılan / değiştirilen dosyalar & portlar', (bd.dropped_executables || []).concat(bd.modified_executables || [], bd.new_listening || [])],
        ['Ek ağ hedefleri (Domain/IP)', (d.network_diff.extra_domains || []).map(x => x.value).concat((d.network_diff.extra_ips || []).map(x => x.value))],
      ];
      const behHtml = behPairs.map(([title, items]) => listBox(title, items, items.length ? 'rose' : 'slate')).join('');
      $('compareResult').innerHTML = hi
        + `<div class="grid grid-cols-1 md:grid-cols-2 gap-3">${htmlBox('Değişen / eklenen dosyalar', fileCount, modHtml + addHtml, fileCount ? 'amber' : 'slate')}${htmlBox('Statik risk & YARA artışı', (d.static_deltas || []).length, stHtml, (d.static_deltas || []).length ? 'rose' : 'slate')}</div>`
        + `<div class="grid grid-cols-1 md:grid-cols-2 gap-3">${behHtml}</div>`;
    } catch (e) { $('compareResult').innerHTML = `<div class="text-rose-300">${esc(e.message)}</div>`; }
  };
}

// ---------------------------------------------------------------- VT / Intel modal
$('btnVtModal').onclick = () => {
  vtModalOpen = true;
  if ($('mbEnabledInput')) $('mbEnabledInput').checked = !!caps.mb_enabled;
  if ($('vtCurStatus')) $('vtCurStatus').textContent = caps.vt_api_configured ? `(Kayıtlı: ${caps.vt_api_masked})` : '(Girilmedi)';
  if ($('mbCurStatus')) $('mbCurStatus').textContent = caps.mb_api_configured ? `(Kayıtlı: ${caps.mb_api_masked})` : '(Girilmedi)';
  if ($('haCurStatus')) $('haCurStatus').textContent = caps.ha_api_configured ? `(Kayıtlı: ${caps.ha_api_masked})` : '(Girilmedi)';
  ['vtClearInput', 'mbClearInput', 'haClearInput'].forEach(id => { if ($(id)) $(id).checked = false; });
  showModal('vtModal');
};
$('btnVtSave').onclick = async () => {
  const payload = {
    vt_api_key: $('vtApiKeyInput').value.trim() || null,
    mb_api_key: $('mbApiKeyInput').value.trim() || null,
    ha_api_key: $('haApiKeyInput').value.trim() || null,
    mb_enabled: $('mbEnabledInput').checked,
    clear_vt: $('vtClearInput') ? $('vtClearInput').checked : false,
    clear_mb: $('mbClearInput') ? $('mbClearInput').checked : false,
    clear_ha: $('haClearInput') ? $('haClearInput').checked : false,
  };
  await post('/api/intel/config', payload);
  $('vtApiKeyInput').value = ''; $('mbApiKeyInput').value = ''; $('haApiKeyInput').value = '';
  ['vtClearInput', 'mbClearInput', 'haClearInput'].forEach(id => { if ($(id)) $(id).checked = false; });
  vtModalOpen = false;
  hideModal('vtModal'); loadSystemStatus();
};

loadSystemStatus(); loadJobs(); loadWatch();
setInterval(loadWatch, 5000);
setInterval(loadSystemStatus, 30000);
const last = (location.hash || '').slice(1); if (last) openJob(decodeURIComponent(last));
