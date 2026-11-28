'use strict';
// SafeBox panel. Everything that comes from inside the sandbox (behavior, live, scriptblocks, file names...) is
// attacker-controlled: it is always escaped (esc) and type-checked (asArr / asNum) before it reaches the page.

const SAFEBOX_TOKEN = (document.querySelector('meta[name="safebox-token"]') || {}).content || '';
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const asArr = x => Array.isArray(x) ? x : [];
const asNum = x => Number.isFinite(Number(x)) ? Number(x) : 0;
const asObjs = x => asArr(x).filter(o => o && typeof o === 'object');
const fmtMB = b => (asNum(b) / 1048576).toFixed(1) + ' MB';
const baseName = p => String(p || '').split(/[\\/]/).filter(Boolean).pop() || String(p || '');

let caps = {}, vtModalOpen = false, recentJobs = [], lastWatch = null;
let activeJobId = null, activeJob = null, pollTimer = null;
let previewCtx = { jobId: null, filePath: '', mode: 'text' };

async function api(url, opts = {}) {
  opts.headers = opts.headers || {};
  if (SAFEBOX_TOKEN && !opts.headers['X-SafeBox-Token']) opts.headers['X-SafeBox-Token'] = SAFEBOX_TOKEN;
  const r = await fetch(url, opts);
  let d = null; try { d = await r.json(); } catch (e) {}
  if (!r.ok) throw new Error((d && d.detail) || ('HTTP ' + r.status));
  return d;
}
const post = (url, body) => api(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-SafeBox-Token': SAFEBOX_TOKEN }, body: JSON.stringify(body || {}) });

// ---------------------------------------------------------------- icons (stroke paths, 24x24)
const ICONS = {
  shield: 'M12 3l7 3v6c0 4.5-3 7.7-7 9-4-1.3-7-4.5-7-9V6z M9 12l2 2 4-4',
  plus: 'M12 5v14 M5 12h14',
  file: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z M14 3v5h5',
  folder: 'M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z',
  link: 'M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1 M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1',
  upload: 'M12 16V4 M7 9l5-5 5 5 M4 20h16',
  download: 'M12 4v12 M7 11l5 5 5-5 M4 20h16',
  globe: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z M3 12h18 M12 3c2.6 3 2.6 15 0 18 M12 3c-2.6 3-2.6 15 0 18',
  activity: 'M3 12h4l3-8 4 16 3-8h4',
  monitor: 'M3 5h18v11H3z M8 20h8 M12 16v4',
  list: 'M9 6h12 M9 12h12 M9 18h12 M4 6h.01 M4 12h.01 M4 18h.01',
  search: 'M11 4a7 7 0 1 0 0 14a7 7 0 1 0 0-14z M20 20l-4-4',
  user: 'M12 4a4 4 0 1 0 0 8a4 4 0 1 0 0-8z M4 20c1.5-3.5 4.5-5 8-5s6.5 1.5 8 5',
  play: 'M7 5l12 7-12 7z',
  stop: 'M6 6h12v12H6z',
  x: 'M6 6l12 12 M18 6L6 18',
  trash: 'M4 7h16 M9 7V4h6v3 M6 7l1 13h10l1-13',
  left: 'M15 6l-6 6 6 6',
  right: 'M9 6l6 6-6 6',
  check: 'M5 12l5 5 9-10',
  alert: 'M12 4l9 16H3z M12 10v4 M12 17h.01',
  info: 'M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z M12 11v5 M12 8h.01',
  eye: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z M12 9a3 3 0 1 0 0 6a3 3 0 1 0 0-6z',
  compare: 'M7 4v16 M17 4v16 M3 8l4-4 4 4 M13 16l4 4 4-4',
  inbox: 'M3 13h5l2 3h4l2-3h5 M5 5h14l2 8v6H3v-6z',
  moon: 'M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z',
  sun: 'M12 8a4 4 0 1 0 0 8a4 4 0 1 0 0-8z M12 2v2 M12 20v2 M4.9 4.9l1.4 1.4 M17.7 17.7l1.4 1.4 M2 12h2 M20 12h2 M4.9 19.1l1.4-1.4 M17.7 6.3l1.4-1.4',
  report: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z M14 3v5h5 M9 13h6 M9 17h6',
  key: 'M15 4a5 5 0 1 0 0 10a5 5 0 1 0 0-10z M11.5 12.5L3 21 M6 18l3 3',
  terminal: 'M4 5h16v14H4z M8 10l3 2-3 2 M13 15h4',
  external: 'M14 4h6v6 M20 4l-9 9 M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5',
};
const ic = (name, cls = '') => `<svg class="ic ${cls}" viewBox="0 0 24 24" aria-hidden="true"><path d="${ICONS[name] || ''}"/></svg>`;
function hydrateIcons(root = document) { root.querySelectorAll('i[data-ic]').forEach(el => { el.outerHTML = ic(el.dataset.ic); }); }

// Writes only when the markup changed, so open <details>, scroll positions and focus survive the 2 s poll.
function setHtml(el, html) { if (el && el._h !== html) { el.innerHTML = html; el._h = html; } }

// ---------------------------------------------------------------- theme
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  $('btnTheme').innerHTML = ic(t === 'dark' ? 'sun' : 'moon');
}
let theme = 'dark';
try { theme = localStorage.getItem('safebox-theme') || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'); } catch (e) {}
applyTheme(theme);
$('btnTheme').onclick = () => {
  theme = theme === 'dark' ? 'light' : 'dark'; applyTheme(theme);
  try { localStorage.setItem('safebox-theme', theme); } catch (e) {}
};

// ---------------------------------------------------------------- modals and views
const showModal = id => $(id).classList.add('open');
const hideModal = id => { $(id).classList.remove('open'); if (id === 'vtModal') vtModalOpen = false; };
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  const open = Array.from(document.querySelectorAll('.modal.open')).pop();
  if (open) hideModal(open.id);
});
document.querySelectorAll('.modal').forEach(m => m.addEventListener('mousedown', e => { if (e.target === m) hideModal(m.id); }));

const VIEWS = ['viewNew', 'jobSection', 'viewSystem', 'viewWatch'];
function showView(id) {
  VIEWS.forEach(v => $(v).classList.toggle('hidden', v !== id));
  if (id !== 'jobSection') {
    clearTimeout(pollTimer); activeJobId = null; activeJob = null;
    history.replaceState(null, '', location.pathname);
    document.title = 'SafeBox';
    renderJobsList();
  }
  window.scrollTo({ top: 0 });
}
$('btnNew').onclick = () => { showView('viewNew'); goStep(0); };
$('btnInfra').onclick = () => showView('viewSystem');
$('btnWatchView').onclick = () => showView('viewWatch');

// ---------------------------------------------------------------- pagination
const pages = {};
function paginate(key, items, size) {
  items = asArr(items);
  const n = items.length, pc = Math.max(1, Math.ceil(n / size));
  const p = Math.min(Math.max(pages[key] || 0, 0), pc - 1);
  pages[key] = p;
  return { items: items.slice(p * size, (p + 1) * size), offset: p * size, ctrl: pc > 1 ? pagerHtml(key, p, pc, n, size) : '' };
}
function pagerHtml(key, p, pc, n, size) {
  const k = esc(key);
  const nums = [];
  for (let i = 0; i < pc; i++) {
    if (pc > 7 && i > 0 && i < pc - 1 && Math.abs(i - p) > 1) { if (nums[nums.length - 1] !== '…') nums.push('…'); continue; }
    nums.push(i);
  }
  const btns = nums.map(i => i === '…' ? '<span class="faint">…</span>'
    : `<button class="pager-btn ${i === p ? 'active' : ''}" data-pg-key="${k}" data-pg="${i}">${i + 1}</button>`).join('');
  return `<div class="pager"><span>${p * size + 1}–${Math.min(n, (p + 1) * size)} / ${n}</span><span class="pager-btns">
    <button class="pager-btn" data-pg-key="${k}" data-pg="${p - 1}" ${p === 0 ? 'disabled' : ''} title="Önceki">‹</button>${btns}
    <button class="pager-btn" data-pg-key="${k}" data-pg="${p + 1}" ${p >= pc - 1 ? 'disabled' : ''} title="Sonraki">›</button></span></div>`;
}
function rerenderFor(key) {
  if (key.startsWith('jobs')) renderJobsList();
  else if (key.startsWith('watch')) renderWatch();
  else if (activeJob) renderJob(activeJob);
}

// ---------------------------------------------------------------- infrastructure
async function loadVboxSnapshots(vmName, selectEl) {
  if (!selectEl) return;
  selectEl.innerHTML = '<option value="">Son SafeBox_Temiz snapshot</option>';
  if (!vmName) return;
  try {
    const d = await api('/api/vbox/snapshots/' + encodeURIComponent(vmName));
    asArr(d.snapshots).forEach(s => { const o = document.createElement('option'); o.value = s; o.textContent = s; selectEl.appendChild(o); });
  } catch (e) {}
}

function capGroups() {
  const vms = asObjs(caps.virtualbox_vms);
  const y = caps.yara || null, yProbs = y ? asArr(y.problems) : [];
  const yOk = y && y.engine === 'yara-python' && !yProbs.length;
  return [
    ['İzole ortam', 'cat-proc', [
      { name: 'Windows Sandbox', tone: caps.windows_sandbox_enabled ? 'ok' : 'crit',
        desc: caps.windows_sandbox_enabled ? 'Hazır. Her analiz sıfırdan açılan, kapanınca silinen bir Windows içinde çalışır.' : 'Kapalı. Dosyaları çalıştırıp izlemek için gerekli; etkinleştirmek yeniden başlatma isteyebilir.',
        action: caps.windows_sandbox_enabled ? '' : '<button class="btn btn-sm btn-primary" data-act="enable-wsb">Etkinleştir</button>' },
      { name: 'VirtualBox', tone: vms.length ? 'ok' : 'info',
        desc: vms.length ? `${vms.length} sanal makine bulundu. Analizden önce ağını kapatıp temiz snapshot almak için "İzole et".` : 'İsteğe bağlı. Kurulu değil ya da sanal makine yok.',
        action: vms.length ? `<select id="vmSelect" class="select">${vms.map(v => `<option>${esc(v.name)}</option>`).join('')}</select><button class="btn btn-sm" data-act="harden">İzole et + snapshot</button>` : '' },
    ]],
    ['Analiz araçları', 'cat-file', [
      { name: '7-Zip', tone: caps.seven_zip ? 'ok' : 'med', desc: caps.seven_zip ? 'RAR, 7z ve ISO arşivleri açılabilir.' : 'Yok. RAR / 7z / ISO açmak için gerekli.', action: caps.seven_zip ? '' : '<a class="btn btn-sm" href="https://www.7-zip.org" target="_blank" rel="noopener">İndir ' + ic('external') + '</a>' },
      { name: 'Wireshark / tshark', tone: caps.tshark ? 'ok' : 'info', desc: caps.tshark ? 'Ağ kaydı otomatik özetlenir (DNS, TLS adları, HTTP).' : 'Yok. Ağ kaydı alınır ama özet çıkarılmaz.', action: caps.tshark ? '' : '<a class="btn btn-sm" href="https://www.wireshark.org/download.html" target="_blank" rel="noopener">İndir ' + ic('external') + '</a>' },
      { name: 'Process Monitor', tone: caps.procmon ? 'ok' : 'info', desc: caps.procmon ? 'Ayrıntılı dosya / kayıt defteri izi alınır.' : 'Yok. İsteğe bağlı ayrıntılı iz.', action: '' },
      { name: 'YARA', tone: !y ? 'info' : yOk ? 'ok' : 'med',
        desc: y ? `${asNum(y.rules_count)} kural${yProbs.length ? `, ${yProbs.length} dosya atlandı` : ''}${y.engine !== 'yara-python' ? ' · yerleşik motor' : ''}.` : 'Durum bilinmiyor.',
        action: y ? '<button class="btn btn-sm" data-act="yara">Kuralları yönet</button>' : '' },
      { name: 'Zararlı ailesi ve ayar ayıklama (CAPE)', tone: caps.config_extractor ? 'ok' : 'info', desc: caps.config_extractor ? 'Bilinen ailelerin C2 adresleri ve ayarları çıkarılır.' : 'Kurulu değil.', action: '' },
      { name: 'Yetenek ve gizli metin (capa / FLOSS)', tone: caps.capa && caps.floss ? 'ok' : (caps.capa || caps.floss) ? 'med' : 'info',
        desc: caps.capa && caps.floss ? 'İmzasız programların ne yapabildiği (capa) ve gizlediği metinler (FLOSS) çıkarılır.' : (caps.capa || caps.floss) ? `Yalnızca ${caps.capa ? 'capa' : 'FLOSS'} kurulu.` : 'Kurulu değil.', action: '' },
      { name: 'HTTPS çözme (mitmproxy)', tone: caps.mitmproxy ? 'ok' : 'info', desc: caps.mitmproxy ? 'Şifreli trafiğin içeriği isteğe bağlı kaydedilebilir.' : 'Kurulu değil.', action: '' },
    ]],
    ['İstihbarat', 'cat-intel', [
      { name: 'VirusTotal', tone: caps.vt_api_configured ? 'ok' : 'med', desc: caps.vt_api_configured ? `Anahtar kayıtlı (${esc(caps.vt_api_masked)}).` : 'Anahtar girilmedi; hash sorgusu yapılamaz.', action: '<button class="btn btn-sm" data-act="keys">Anahtarlar</button>' },
      { name: 'MalwareBazaar / Hybrid Analysis yedeği', tone: caps.mb_enabled ? 'ok' : 'info', desc: caps.mb_enabled ? 'VirusTotal yokken yalnızca hash sorulur.' : 'Kapalı.', action: '' },
      { name: 'CIRCL Hashlookup (NSRL)', tone: caps.circl_enabled ? 'ok' : 'info', desc: caps.circl_enabled ? 'Bilinen temiz yazılım kontrolü açık.' : 'Kapalı.', action: '' },
      { name: 'ThreatFox', tone: caps.tf_enabled ? 'ok' : 'info', desc: caps.tf_enabled ? 'Zararlı hash veritabanı sorgusu açık.' : 'Kapalı.', action: '' },
    ]],
    ['Bilgisayarla bütünleşme', 'cat-sys', [
      { name: 'Dosya Gezgini sağ tık menüsü', tone: caps.context_menu ? 'ok' : 'info', desc: caps.context_menu ? '"SafeBox ile analiz et" menüde.' : 'Eklenmemiş. Dosyaya sağ tıklayıp analiz başlatmayı sağlar.', action: `<button class="btn btn-sm" data-act="ctxmenu">${caps.context_menu ? 'Kaldır' : 'Ekle'}</button>` },
      { name: 'İndirilenler izleme', tone: lastWatch && lastWatch.enabled ? 'ok' : 'info', desc: lastWatch && lastWatch.enabled ? 'Açık.' : 'Kapalı.', action: '<button class="btn btn-sm" data-act="open-watch">Ayarlar</button>' },
    ]],
  ];
}

async function loadSystemStatus() {
  try {
    caps = await api('/api/system-status');
    $('vtStatusDot').className = 'dot ' + (caps.vt_api_configured ? 'tone-ok' : 'tone-med');
    $('vtStatusText').textContent = caps.vt_api_configured ? 'API anahtarları' : 'VT anahtarı yok';
    if (!vtModalOpen) {
      $('mbEnabledInput').checked = !!caps.mb_enabled;
      $('chkCirclEnabled').checked = !!caps.circl_enabled;
      $('chkTfEnabled').checked = !!caps.tf_enabled;
    }
    $('sysSubText').textContent = caps.os || '';
    const groups = capGroups();
    const req = [caps.windows_sandbox_enabled, caps.seven_zip, caps.vt_api_configured];
    const missing = req.filter(x => !x).length;
    $('infraDot').className = 'dot ' + (!caps.windows_sandbox_enabled ? 'tone-crit' : missing ? 'tone-med' : 'tone-ok');
    $('infraText').textContent = !caps.windows_sandbox_enabled ? 'Windows Sandbox kapalı' : missing ? `Altyapı: ${missing} eksik` : 'Altyapı hazır';
    const vmSel = $('vmSelect') ? $('vmSelect').value : '';
    setHtml($('sysCapsBadges'), groups.map(([title, cat, items]) => `<div class="card">
        <div class="section-title ${cat}"><span class="dot"></span> ${esc(title)}</div>
        ${items.map(it => `<div class="cap"><span class="dot tone-${it.tone}"></span><div class="grow"><div class="cap-name">${esc(it.name)}</div><div class="cap-desc">${it.desc}</div></div><div class="btn-group">${it.action}</div></div>`).join('')}
      </div>`).join(''));
    if (vmSel && $('vmSelect')) $('vmSelect').value = vmSel;
    const vms = asObjs(caps.virtualbox_vms);
    const vmHtml = vms.length ? vms.map(v => `<option value="${esc(v.name)}">${esc(v.name)}</option>`).join('') : '<option value="">VirtualBox sanal makinesi yok</option>';
    if ($('vboxVmInput').innerHTML !== vmHtml) { $('vboxVmInput').innerHTML = vmHtml; loadVboxSnapshots($('vboxVmInput').value, $('vboxSnapInput')); }
    if ($('sbModalVm').innerHTML !== vmHtml) $('sbModalVm').innerHTML = vmHtml;
  } catch (e) {
    $('sysSubText').textContent = 'Sunucuya ulaşılamadı: ' + e.message;
    $('infraDot').className = 'dot tone-crit'; $('infraText').textContent = 'Sunucuya ulaşılamadı';
  }
}
async function hardenVm() {
  const vm = $('vmSelect') ? $('vmSelect').value : '';
  if (!vm) return;
  if (!confirm(`'${vm}' sanal makinesinin TÜM ağ kartları, pano paylaşımı ve sürükle-bırak kalıcı olarak kapatılacak ve snapshot alınacak.\n\nVM kapalı olmalı. Bu VM'i başka işler için kullanıyorsanız (ör. hesap oturumları) zararlı testi için ayrı bir VM kullanmanız daha güvenli.\n\nDevam edilsin mi?`)) return;
  try { const d = await post('/api/vbox/harden', { vm_name: vm }); alert(d.message + (d.steps ? '\n\n• ' + d.steps.join('\n• ') : '')); }
  catch (e) { alert(e.message); }
}

// ---------------------------------------------------------------- new analysis wizard
const OPT_IDS = ['optNetwork', 'optHttps', 'optFakeNet', 'optShowWindow', 'optKeepOpen', 'optVgpu', 'optSimUser', 'optStdUser', 'optHoneyfiles', 'optUpload', 'optSandbox', 'optNotify'];
const DEFAULTS = {
  optNetwork: true, optHttps: false, optFakeNet: false, optShowWindow: false, optKeepOpen: false, optVgpu: false,
  optSimUser: true, optStdUser: false, optHoneyfiles: true, optUpload: true, optSandbox: true, optNotify: true,
  durationInput: '10', memoryInput: '4096',
};
const PRESETS = [
  { id: 'standard', title: 'Standart', tone: 'tone-accent', desc: 'Çoğu dosya için. İnternet açık (ev ağı engelli), yem dosyalar ve otomatik tıklama açık.', tags: ['10 dk', '4 GB', 'İnternet açık'], set: {} },
  { id: 'installer', title: 'Büyük kurulum', tone: 'cat-proc', desc: 'Adobe, oyun gibi uzun süren kurulumlar. Pencere ekranda açılır; gerekirse düğmelere kendiniz basarsınız.', tags: ['30 dk', '8 GB', 'Pencere ekranda'], set: { durationInput: '30', memoryInput: '8192', optShowWindow: true } },
  { id: 'suspicious', title: 'Şüpheli dosya', tone: 'tone-high', desc: 'Crack, keygen ya da tanımadığınız bir kaynaktan gelen dosya. Şifreli trafik de çözülür; nereye ne gönderdiği görünür.', tags: ['15 dk', 'HTTPS çözülür', 'Yem dosyalar'], set: { durationInput: '15', optHttps: true } },
  { id: 'offline', title: 'İnternetsiz', tone: 'cat-net', desc: 'Örnek dışarıya hiç çıkamaz. Bağlanmak istediği adresler sahte DNS / HTTP sunucusuyla yakalanır.', tags: ['İnternet kapalı', 'FakeNet'], set: { optNetwork: false, optFakeNet: true } },
  { id: 'static', title: 'Yalnızca statik', tone: 'cat-file', desc: 'Dosya çalıştırılmaz: statik analiz ve VirusTotal. Sandbox adımını sonra isterseniz elle başlatırsınız.', tags: ['Çalıştırılmaz', 'Hızlı'], set: { optSandbox: false } },
];
const GROUP_OPTS = {
  run: [], env: ['optShowWindow', 'optKeepOpen', 'optVgpu'], net: ['optNetwork', 'optHttps', 'optFakeNet'],
  user: ['optSimUser', 'optStdUser', 'optHoneyfiles'], intel: ['optUpload', 'optSandbox', 'optNotify'],
};
const OPT_SHORT = {
  optNetwork: 'İnternet açık', optHttps: 'HTTPS çözülür', optFakeNet: 'FakeNet', optShowWindow: 'Pencere ekranda', optKeepOpen: 'Sonunda açık kalır',
  optVgpu: 'Ekran kartı (GPU)', optSimUser: 'Sahte kullanıcı', optStdUser: 'Standart kullanıcı', optHoneyfiles: 'Yem dosyalar',
  optUpload: "Bilinmeyenler VT'ye yüklenir", optSandbox: 'Sandbox otomatik', optNotify: 'Bildirim',
};
const URL_LOCK = { optNetwork: true, optHttps: true, optSimUser: false };
let wizStep = 0, wizMax = 0, srcMode = 'file', presetId = 'standard', setGroup = 'run';

function presetValues(id) { const p = PRESETS.find(x => x.id === id) || PRESETS[0]; return Object.assign({}, DEFAULTS, p.set); }
function readVal(id) { const el = $(id); return el.type === 'checkbox' ? el.checked : el.value; }
function writeVal(id, v) { const el = $(id); if (el.type === 'checkbox') el.checked = !!v; else el.value = v; }
function applyPreset(id) {
  const vals = presetValues(id);
  Object.entries(vals).forEach(([k, v]) => { if (!(srcMode === 'url' && k in URL_LOCK)) writeVal(k, v); });
  presetId = id;
  renderWizard();
}
function matchPreset() {
  for (const p of PRESETS) {
    const vals = presetValues(p.id);
    if (Object.entries(vals).every(([k, v]) => (srcMode === 'url' && k in URL_LOCK) || String(readVal(k)) === String(v))) return p.id;
  }
  return 'custom';
}
function sourceValue() { return (srcMode === 'url' ? $('urlInput').value : $('pathInput').value).trim(); }
function sourceProblem() {
  const v = sourceValue();
  if (!v) return srcMode === 'url' ? 'Önce incelenecek bağlantıyı yazın.' : 'Önce bir dosya bırakın, seçin ya da yolunu yazın.';
  if (srcMode === 'url' && !/^https?:\/\/\S+$/i.test(v)) return 'Bağlantı http:// ya da https:// ile başlamalı.';
  return '';
}
function setSrcMode(mode) {
  srcMode = mode;
  document.querySelectorAll('#srcMode [data-src]').forEach(b => b.classList.toggle('active', b.dataset.src === mode));
  $('srcFile').classList.toggle('hidden', mode !== 'file');
  $('srcUrl').classList.toggle('hidden', mode !== 'url');
  // the backend forces these for links; mirror that here so the summary is honest
  Object.entries(URL_LOCK).forEach(([id, v]) => {
    const el = $(id);
    if (mode === 'url') { el.dataset.prev = el.checked ? '1' : '0'; el.checked = v; }
    else if (el.dataset.prev !== undefined) { el.checked = el.dataset.prev === '1'; delete el.dataset.prev; }
    el.disabled = mode === 'url';
    el.closest('.opt').classList.toggle('locked', mode === 'url');
  });
  ['targetInput', 'targetArgsInput', 'dllExportInput'].forEach(id => { $(id).disabled = mode === 'url'; });
  renderWizard();
}
function goStep(n) {
  if (n > 0 && sourceProblem()) { n = 0; }
  wizStep = Math.max(0, Math.min(3, n));
  wizMax = Math.max(wizMax, wizStep);
  renderWizard();
}
function goGroup(g) {
  setGroup = g;
  document.querySelectorAll('#setNav [data-group]').forEach(b => b.classList.toggle('active', b.dataset.group === g));
  document.querySelectorAll('[data-group-pane]').forEach(p => p.classList.toggle('hidden', p.dataset.groupPane !== g));
}

function renderPresets() {
  const note = srcMode === 'url'
    ? `<div class="callout tone-low">${ic('info')}<div><div class="callout-title">Bağlantı modu</div><div class="callout-body">Bağlantılar için internet ve HTTPS çözme her zaman açık, otomatik tıklama kapalıdır. Profil yalnızca süre, bellek ve diğer ayarları belirler.</div></div></div>` : '';
  setHtml($('presetGrid'), PRESETS.map(p => `<button class="preset ${p.tone} ${presetId === p.id ? 'active' : ''}" data-preset="${p.id}">
      <span class="preset-title"><span class="dot"></span>${esc(p.title)}</span>
      <span class="preset-desc">${esc(p.desc)}</span>
      <span class="preset-tags">${p.tags.map(t => `<span class="chip">${esc(t)}</span>`).join('')}</span>
    </button>`).join(''));
  setHtml($('presetNote'), (presetId === 'custom'
    ? `<div class="callout tone-info">${ic('info')}<div><div class="callout-title">Özel ayarlar</div><div class="callout-body">Ayarları profilden farklı değiştirdiniz. Bir profile basarsanız ayarlar o profile döner.</div></div></div>` : '') + note);
}

function wizardWarnings() {
  const w = [];
  if ($('optVgpu').checked) w.push(['tone-high', 'Ekran kartı sandbox\'a açılıyor', 'Yalıtım zayıflar. Yalnızca güvendiğiniz, ekran kartı isteyen programlarda kullanın.']);
  if ($('optUpload').checked && srcMode === 'file') w.push(['tone-med', "Bilinmeyen dosyalar VirusTotal'a yüklenecek", 'Yüklenen dosyalar başkalarınca indirilebilir. Kişisel belge içeren dosyalarda bu ayarı kapatın.']);
  if (!$('optNetwork').checked && !$('optFakeNet').checked && srcMode === 'file') w.push(['tone-info', 'İnternet kapalı, FakeNet de kapalı', 'Örnek hiçbir yere bağlanamaz; ağ davranışı hakkında bilgi toplanmaz.']);
  if (!$('optSandbox').checked && srcMode === 'file') w.push(['tone-info', 'Dosya çalıştırılmayacak', 'Yalnızca statik analiz ve VirusTotal yapılır. Davranış incelemesi için sonradan "Sandbox\'ta çalıştır"a basın.']);
  if ($('optHttps').checked && srcMode === 'file') w.push(['tone-info', 'HTTPS çözme açık', 'Sertifika sabitleyen programlar (bazı kurulumlar, güncelleyiciler) bağlanamayabilir; bu davranışı değiştirebilir.']);
  if ($('optShowWindow').checked) w.push(['tone-info', 'Sandbox penceresi ekrana gelecek', 'Kurulum sırasında düğmelere kendiniz basabilirsiniz; analiz bitene kadar pencereyi kapatmayın.']);
  return w;
}
function renderSummary() {
  const on = ids => ids.filter(id => $(id).checked).map(id => `<span class="chip tone-ok">${esc(OPT_SHORT[id])}</span>`).join('') || '<span class="faint">Hepsi kapalı</span>';
  const off = ids => ids.filter(id => !$(id).checked).map(id => `<span class="chip">${esc(OPT_SHORT[id])} kapalı</span>`).join('');
  const edit = (step, group) => `<button class="link-btn" data-goto-step="${step}"${group ? ` data-goto-group="${group}"` : ''}>Düzenle</button>`;
  const preset = PRESETS.find(p => p.id === presetId);
  const sel = id => { const el = $(id); return el.options[el.selectedIndex] ? el.options[el.selectedIndex].text : ''; };
  const item = (title, body, e) => `<div class="summary-item"><dt>${esc(title)}${e}</dt><dd>${body}</dd></div>`;
  const src = sourceValue();
  const items = [
    item('Kaynak', `<div class="strong break">${esc(srcMode === 'url' ? src : baseName(src))}</div><div class="faint small mono break">${esc(srcMode === 'url' ? 'Bağlantı · sandbox içindeki Edge\'de açılır' : src)}</div>${$('pwInput').value && srcMode === 'file' ? '<div class="small muted">Arşiv şifresi girildi</div>' : ''}`, edit(0)),
    item('Profil', `<div class="strong">${esc(preset ? preset.title : 'Özel ayarlar')}</div><div class="small muted">${esc(preset ? preset.desc : 'Profilden farklı ayarlar seçildi.')}</div>`, edit(1)),
    item('Çalıştırma', srcMode === 'url' ? '<div class="small">Bağlantı Edge ile açılır.</div>'
      : `<div class="small">Hedef: <span class="mono">${esc($('targetInput').value.trim() || 'otomatik seçilir')}</span>${$('targetArgsInput').value.trim() ? ` · argüman <span class="mono">${esc($('targetArgsInput').value.trim())}</span>` : ''}${$('dllExportInput').value.trim() ? ` · export <span class="mono">${esc($('dllExportInput').value.trim())}</span>` : ''}</div>`
      + `<div class="small muted">${esc(sel('durationInput'))} izlenir · ${esc(sel('memoryInput'))} bellek</div>`, edit(2, 'run')),
    item('Ortam ve pencere', `<div class="small">${esc(sel('backendInput'))}</div><div class="sum-list mt">${on(GROUP_OPTS.env)}</div>`, edit(2, 'env')),
    item('Ağ', `<div class="sum-list">${on(GROUP_OPTS.net)}${off(['optNetwork'])}</div>`, edit(2, 'net')),
    item('Kullanıcı ve tuzaklar', `<div class="sum-list">${on(GROUP_OPTS.user)}</div>`, edit(2, 'user')),
    item('İstihbarat ve bildirim', `<div class="sum-list">${on(GROUP_OPTS.intel)}</div>`, edit(2, 'intel')),
  ];
  const warns = wizardWarnings().map(([t, title, body]) => `<div class="callout ${t}">${ic(t === 'tone-info' ? 'info' : 'alert')}<div><div class="callout-title">${esc(title)}</div><div class="callout-body">${esc(body)}</div></div></div>`).join('');
  setHtml($('wizSummary'), `<dl class="summary-grid">${items.join('')}</dl>${warns ? `<div class="stack-sm">${warns}</div>` : ''}`);
}
function renderWizard() {
  presetId = matchPreset();
  document.querySelectorAll('[data-pane]').forEach(p => p.classList.toggle('hidden', +p.dataset.pane !== wizStep));
  const prob = sourceProblem();
  document.querySelectorAll('#stepper .step').forEach(b => {
    const n = +b.dataset.step;
    b.classList.toggle('active', n === wizStep);
    b.classList.toggle('done', n < wizStep || (n <= wizMax && n !== wizStep && !prob));
  });
  const src = sourceValue();
  $('stepSub0').textContent = src ? (srcMode === 'url' ? src.replace(/^https?:\/\//i, '') : baseName(src)) : 'Dosya, klasör veya bağlantı';
  const preset = PRESETS.find(p => p.id === presetId);
  $('stepSub1').textContent = preset ? preset.title : 'Özel ayarlar';
  const changed = OPT_IDS.filter(id => readVal(id) !== DEFAULTS[id]).length + (readVal('durationInput') !== DEFAULTS.durationInput) + (readVal('memoryInput') !== DEFAULTS.memoryInput);
  $('stepSub2').textContent = changed ? `${changed} ayar varsayılandan farklı` : 'Varsayılan ayarlar';
  Object.entries(GROUP_OPTS).forEach(([g, ids]) => {
    const el = document.querySelector(`[data-group-count="${g}"]`);
    if (el) el.textContent = ids.length ? `${ids.filter(id => $(id).checked).length}/${ids.length}` : '';
  });
  const runCount = document.querySelector('[data-group-count="run"]');
  if (runCount) runCount.textContent = ($('durationInput').value || '') + ' dk';
  const pick = $('pathInput').value.trim();
  setHtml($('pickedBox'), srcMode === 'file' && pick
    ? `<div class="picked">${ic('check')}<div class="grow"><div class="strong break">${esc(baseName(pick))}</div><div class="faint small mono break">${esc(pick)}</div></div><button class="btn btn-sm btn-ghost" data-act="clear-source">Temizle</button></div>` : '');
  renderPresets();
  if (wizStep === 3) renderSummary();
  $('wizBack').classList.toggle('hidden', wizStep === 0);
  $('wizNext').classList.toggle('hidden', wizStep === 3);
  $('wizSkip').classList.toggle('hidden', wizStep !== 1);
  $('btnStart').classList.toggle('hidden', wizStep !== 3);
  $('wizHint').textContent = wizStep === 0 ? (prob && src ? prob : '') : '';
  $('wizNext').innerHTML = (wizStep === 1 ? 'Ayarlar' : wizStep === 2 ? 'Özete geç' : 'İleri') + ' ' + ic('right');
}
$('wizNext').onclick = () => {
  if (wizStep === 0 && sourceProblem()) { $('wizHint').textContent = sourceProblem(); return; }
  goStep(wizStep + 1);
};
$('wizBack').onclick = () => goStep(wizStep - 1);
$('wizSkip').onclick = () => goStep(3);
[...OPT_IDS, 'durationInput', 'memoryInput', 'backendInput', 'targetInput', 'targetArgsInput', 'dllExportInput', 'pwInput'].forEach(id => $(id).addEventListener('change', () => renderWizard()));
['pathInput', 'urlInput'].forEach(id => $(id).addEventListener('input', () => renderWizard()));
['pathInput', 'urlInput'].forEach(id => $(id).addEventListener('keydown', e => { if (e.key === 'Enter' && !sourceProblem()) goStep(1); }));

$('backendInput').onchange = () => {
  const isVbox = $('backendInput').value === 'vbox';
  $('vboxOpts').classList.toggle('hidden', !isVbox);
  if (isVbox && $('vboxVmInput').value) loadVboxSnapshots($('vboxVmInput').value, $('vboxSnapInput'));
  renderWizard();
};
$('vboxVmInput').onchange = () => loadVboxSnapshots($('vboxVmInput').value, $('vboxSnapInput'));

function options() {
  return {
    password: $('pwInput').value,
    target: $('targetInput').value.trim(),
    target_args: $('targetArgsInput').value.trim(),
    dll_export: $('dllExportInput').value.trim(),
    duration_min: parseInt($('durationInput').value, 10),
    memory_mb: parseInt($('memoryInput').value, 10) || 4096,
    network: $('optNetwork').checked,
    vt_upload: $('optUpload').checked,
    run_sandbox: $('optSandbox').checked,
    keep_sandbox_open: $('optKeepOpen').checked,
    show_sandbox_window: $('optShowWindow').checked,
    enable_vgpu: $('optVgpu').checked,
    decrypt_https: $('optHttps').checked,
    simulate_user: $('optSimUser').checked,
    run_as_standard_user: $('optStdUser').checked,
    seed_honeyfiles: $('optHoneyfiles').checked,
    fake_net: $('optFakeNet').checked,
    notify: $('optNotify').checked,
    sandbox_backend: $('backendInput').value,
    vbox_vm: $('vboxVmInput').value,
    vbox_snapshot: $('vboxSnapInput').value,
    vbox_user: $('vboxUserInput').value.trim(),
    vbox_password: $('vboxPassInput').value,
  };
}
async function startAnalysis(path, extra = {}) {
  if (!path) { showView('viewNew'); goStep(0); return; }
  const btn = $('btnStart'); btn.disabled = true;
  try {
    const d = await post('/api/jobs', Object.assign({ path }, options(), extra));
    resetSource();
    openJob(d.id);
    loadJobs();
  } catch (e) { alert('Başlatılamadı: ' + e.message); }
  finally { btn.disabled = false; }
}
function resetSource() {
  ['pathInput', 'urlInput', 'pwInput', 'targetInput', 'targetArgsInput', 'dllExportInput'].forEach(id => { $(id).value = ''; });
  wizStep = 0; wizMax = 0;
  renderWizard();
}
$('btnStart').onclick = () => { const p = sourceProblem(); if (p) { goStep(0); $('wizHint').textContent = p; return; } startAnalysis(sourceValue()); };
$('btnDemo').onclick = async () => {
  try {
    const d = await post('/api/demo');
    setSrcMode('file');
    $('pathInput').value = d.path; $('targetInput').value = d.target || '';
    $('optNetwork').checked = false; $('optFakeNet').checked = false;
    wizMax = 3; goStep(3);
  } catch (e) { alert(e.message); }
};
document.querySelectorAll('[data-browse]').forEach(b => b.onclick = async () => {
  try {
    const d = await api('/api/browse-dialog?mode=' + b.dataset.browse);
    if (d.selected_path) { $('pathInput').value = d.selected_path; renderWizard(); }
  } catch (e) { alert(e.message); }
});

// ---------------------------------------------------------------- uploads (drop zone)
const MAX_UPLOAD = 4 * 1024 ** 3;
function dropStatus(text) {
  const dz = $('dropZone');
  if (text === null) { setHtml(dz.querySelector('.strong'), 'Dosyaları buraya bırakın ya da tıklayıp seçin'); return; }
  setHtml(dz.querySelector('.strong'), `<span class="row"><span class="spin"></span>${esc(text)}</span>`);
}
function picked(path) { setSrcMode('file'); $('pathInput').value = path; goStep(1); }
async function uploadOne(file) {
  if (!file) return;
  if (file.size > MAX_UPLOAD) {
    alert(`"${file.name}" ${(file.size / 1024 ** 3).toFixed(1)} GB. Panele bırakma sınırı 4 GB.\n\nBüyük dosyaları "Dosya" / "Klasör" düğmesiyle seçin; kopyalanmadan analiz edilir.`);
    return;
  }
  dropStatus(`"${file.name}" alınıyor (${fmtMB(file.size)})…`);
  try {
    const fd = new FormData(); fd.append('file', file);
    const d = await api('/api/upload', { method: 'POST', body: fd });
    picked(d.path);
  } catch (e) { alert('Yükleme hatası: ' + e.message); }
  finally { dropStatus(null); }
}
// Several files and/or folders dropped together are uploaded into one batch folder and analysed as ONE sample.
// Nothing is uploaded if any file is over the limit: a partial upload would analyse e.g. only the checksum files
// next to a huge .iso and could report "clean" for something that was never looked at.
function readAllEntries(dirEntry) {
  const reader = dirEntry.createReader();
  return new Promise((resolve, reject) => {
    const all = [];
    const next = () => reader.readEntries(batch => { if (!batch.length) resolve(all); else { all.push(...batch); next(); } }, reject);
    next();
  });
}
async function collectEntry(entry, prefix, out) {
  if (entry.isFile) {
    const file = await new Promise((res, rej) => entry.file(res, rej));
    out.push({ file, rel: prefix + file.name });
  } else if (entry.isDirectory) {
    for (const child of await readAllEntries(entry)) await collectEntry(child, prefix + entry.name + '/', out);
  }
}
async function collectDropped(dt) {
  const items = Array.from(dt.items || []).filter(i => i.kind === 'file');
  const entries = items.map(i => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null));
  const out = [];
  if (entries.length && entries.every(Boolean)) { for (const en of entries) await collectEntry(en, '', out); }
  else { for (const f of Array.from(dt.files || [])) out.push({ file: f, rel: f.name }); }
  return { list: out, hasFolder: entries.some(en => en && en.isDirectory) };
}
async function uploadBatch(list) {
  if (!list.length) { alert('Bırakılan klasör boş.'); return; }
  const big = list.filter(x => x.file.size > MAX_UPLOAD);
  const total = list.reduce((s, x) => s + x.file.size, 0);
  if (big.length || total > MAX_UPLOAD) {
    const names = big.map(x => `• ${x.rel} (${(x.file.size / 1024 ** 3).toFixed(1)} GB)`).join('\n');
    alert(`Bırakılan dosyalar panele yüklenemeyecek kadar büyük (toplam ${(total / 1024 ** 3).toFixed(1)} GB, sınır 4 GB).\n${names}\n\n`
      + 'Hiçbiri yüklenmedi. Klasörü "Klasör" düğmesiyle seçin: kopyalanmadan, olduğu yerden analiz edilir.');
    return;
  }
  const batch = Array.from(crypto.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join('');
  let batchDir = null;
  try {
    for (let i = 0; i < list.length; i++) {
      const { file, rel } = list[i];
      dropStatus(`${i + 1} / ${list.length} dosya alınıyor: "${rel}" (${fmtMB(file.size)})`);
      const fd = new FormData();
      fd.append('file', file); fd.append('batch', batch); fd.append('relpath', rel);
      const d = await api('/api/upload', { method: 'POST', body: fd });
      batchDir = d.batch_dir;
    }
    picked(batchDir);
  } catch (e) { alert('Yükleme hatası: ' + e.message + '\n\nAnaliz başlatılmadı.'); }
  finally { dropStatus(null); }
}
async function handleDrop(dt) {
  let collected;
  try { collected = await collectDropped(dt); } catch (e) { alert('Bırakılan dosyalar okunamadı: ' + e.message); return; }
  const { list, hasFolder } = collected;
  if (!list.length) return;
  if (list.length === 1 && !hasFolder) uploadOne(list[0].file);
  else uploadBatch(list);
}
(() => {
  const dz = $('dropZone');
  dz.onclick = () => $('fileInput').click();
  $('fileInput').onchange = e => {
    const files = Array.from(e.target.files || []);
    if (files.length === 1) uploadOne(files[0]);
    else if (files.length > 1) uploadBatch(files.map(f => ({ file: f, rel: f.name })));
    e.target.value = '';
  };
  ['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('drop-active'); }));
  ['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('drop-active'); }));
  dz.addEventListener('drop', e => { if (e.dataTransfer) handleDrop(e.dataTransfer); });
})();

// ---------------------------------------------------------------- downloads watcher
let watchInit = false;
async function loadWatch() {
  try {
    const w = await api('/api/watch');
    lastWatch = w;
    if (!watchInit) { $('watchFolder').value = w.folder; $('watchEnabled').checked = w.enabled; $('watchAuto').checked = w.auto_start; watchInit = true; }
    const fresh = asObjs(w.found).filter(f => !f.job && !f.later_part).length;
    $('watchPillText').textContent = w.enabled ? (fresh ? `İndirilenler · ${fresh} yeni` : 'İndirilenler izleniyor') : 'İndirilenler';
    renderWatch();
  } catch (e) {}
}
function renderWatch() {
  const w = lastWatch;
  if (!w) return;
  const found = asObjs(w.found).slice().reverse();
  if (!found.length) { setHtml($('watchList'), `<div class="empty">${w.enabled ? 'İzleniyor — yeni indirme bekleniyor.' : 'İzleme kapalı.'}</div>`); return; }
  const pg = paginate('watch', found, 10);
  setHtml($('watchList'), `<div class="table-wrap"><table class="tbl"><tr><th>Dosya</th><th>Zaman</th><th>Boyut</th><th></th></tr>${pg.items.map(f => `<tr>
      <td class="break">${esc(f.name)}${f.later_part ? ' <span class="chip">arşiv parçası</span>' : ''}</td><td class="nowrap muted">${esc(f.time)}</td><td class="nowrap muted">${fmtMB(f.size)}</td>
      <td class="nowrap">${f.job ? `<button class="btn btn-sm" data-open-job="${esc(f.job)}">Analizi aç</button>` : f.later_part ? '' : `<button class="btn btn-sm btn-primary" data-analyze="${esc(f.path)}">Analiz et</button>`}</td></tr>`).join('')}</table></div>${pg.ctrl}`);
}
async function saveWatch() {
  try { await post('/api/watch', { folder: $('watchFolder').value.trim(), enabled: $('watchEnabled').checked, auto_start: $('watchAuto').checked }); loadWatch(); }
  catch (e) { alert(e.message); }
}
$('btnWatchSave').onclick = saveWatch; $('watchEnabled').onchange = saveWatch; $('watchAuto').onchange = saveWatch;

// ---------------------------------------------------------------- analyses list (sidebar)
const statusTr = { running: 'çalışıyor', done: 'bitti', error: 'hata', waiting_sandbox: 'sandbox bekliyor', interrupted: 'yarıda kaldı', cancelled: 'iptal edildi' };
const statusTone = { running: 'tone-accent', done: 'tone-ok', error: 'tone-crit', waiting_sandbox: 'tone-med', interrupted: 'tone-med', cancelled: 'tone-info' };
const levelTone = { red: 'tone-crit', yellow: 'tone-med', green: 'tone-ok' };
const levelWord = { red: 'kırmızı', yellow: 'incele', green: 'bayrak yok' };
const JOB_FILTERS = [['all', 'Tümü'], ['red', 'Kırmızı'], ['yellow', 'İncele'], ['green', 'Temiz']];
let jobsFilter = 'all';
async function loadJobs() {
  try { recentJobs = asObjs(await api('/api/jobs')); renderJobsList(); } catch (e) {}
}
function renderJobsList() {
  const q = $('jobsSearch').value.trim().toLocaleLowerCase('tr');
  const list = recentJobs.filter(j => (jobsFilter === 'all' || j.verdict === jobsFilter) && (!q || String(j.sample).toLocaleLowerCase('tr').includes(q)));
  $('jobsCount').textContent = recentJobs.length ? String(recentJobs.length) : '';
  setHtml($('jobsFilter'), JOB_FILTERS.map(([id, label]) => {
    const n = id === 'all' ? recentJobs.length : recentJobs.filter(j => j.verdict === id).length;
    return `<button class="seg-btn ${jobsFilter === id ? 'active' : ''}" data-jobs-filter="${id}">${label} <span class="count">${n}</span></button>`;
  }).join(''));
  if (!list.length) { setHtml($('jobsList'), `<div class="empty">${recentJobs.length ? 'Bu filtreye uyan analiz yok.' : 'Henüz analiz yok.'}</div>`); setHtml($('jobsPager'), ''); return; }
  const pg = paginate('jobs', list, 12);
  setHtml($('jobsList'), pg.items.map(j => {
    const dot = j.status === 'running' ? '<span class="verdict-dot tone-accent dot-pulse"></span>' : `<span class="verdict-dot ${levelTone[j.verdict] || ''}"></span>`;
    return `<button class="job-item ${j.id === activeJobId ? 'active' : ''}" data-open-job="${esc(j.id)}" title="${esc(j.sample)}">${dot}
      <span class="grow"><span class="job-name truncate">${esc(baseName(j.sample))}</span><span class="job-meta">${esc(String(j.created || '').slice(5, 16))} · ${esc(statusTr[j.status] || j.status)}${levelWord[j.verdict] && j.status !== 'running' ? ' · ' + levelWord[j.verdict] : ''}</span></span></button>`;
  }).join(''));
  setHtml($('jobsPager'), pg.ctrl);
}
$('jobsSearch').addEventListener('input', () => { pages.jobs = 0; renderJobsList(); });
$('btnCleanup').onclick = async () => {
  if (!confirm('30 günden eski, bitmiş bütün analizlerin klasörleri kalıcı olarak silinecek. Orijinal dosyalara dokunulmaz.\n\nDevam edilsin mi?')) return;
  try { const d = await post('/api/jobs-cleanup', { days: 30 }); alert(`${asArr(d.deleted).length} analiz silindi.`); loadJobs(); }
  catch (e) { alert(e.message); }
};

// ---------------------------------------------------------------- global click delegation
document.addEventListener('click', e => {
  const t = e.target.closest('[data-open-job],[data-analyze],[data-close],[data-vt-query],[data-vt-upload],[data-intel-query],[data-preview],[data-preview-mode],[data-yara-file],'
    + '[data-pg-key],[data-tab],[data-act],[data-src],[data-step],[data-group],[data-preset],[data-goto-step],[data-jobs-filter],[data-static-filter],[data-files-sub],[data-proc-filter]');
  if (!t || t.disabled) return;
  const d = t.dataset;
  if (d.openJob) openJob(d.openJob);
  else if (d.analyze) startAnalysis(d.analyze);
  else if (d.close) hideModal(d.close);
  else if (d.vtQuery) manualVtQuery(parseInt(d.vtQuery, 10));
  else if (d.vtUpload) manualVtUpload(parseInt(d.vtUpload, 10));
  else if (d.intelQuery) manualIntelQuery(parseInt(d.intelQuery, 10));
  else if (d.preview !== undefined) openPreviewModal(parseInt(d.preview, 10));
  else if (d.previewMode) loadPreviewContent(d.previewMode);
  else if (d.yaraFile) selectYaraFile(d.yaraFile);
  else if (d.pgKey) { pages[d.pgKey] = parseInt(d.pg, 10) || 0; rerenderFor(d.pgKey); }
  else if (d.tab) { activeTab = d.tab; if (activeJob) renderJob(activeJob); }
  else if (d.act) doAction(d.act);
  else if (d.src) setSrcMode(d.src);
  else if (d.step !== undefined) goStep(parseInt(d.step, 10));
  else if (d.group) goGroup(d.group);
  else if (d.preset) applyPreset(d.preset);
  else if (d.gotoStep !== undefined) { if (d.gotoGroup) goGroup(d.gotoGroup); goStep(parseInt(d.gotoStep, 10)); }
  else if (d.jobsFilter) { jobsFilter = d.jobsFilter; pages.jobs = 0; renderJobsList(); }
  else if (d.staticFilter) { staticFilter = d.staticFilter; pages.static = 0; if (activeJob) renderJob(activeJob); }
  else if (d.filesSub) { filesSub = d.filesSub; if (activeJob) renderJob(activeJob); }
  else if (d.procFilter) { procFilter = d.procFilter; pages.procs = 0; if (activeJob) renderJob(activeJob); }
});

async function doAction(act) {
  const st = activeJob, enc = st ? encodeURIComponent(st.id) : '';
  try {
    switch (act) {
      case 'enable-wsb': alert((await post('/api/sandbox/enable')).message); break;
      case 'harden': hardenVm(); break;
      case 'yara': openYaraModal(); break;
      case 'keys': openKeysModal(); break;
      case 'open-watch': showView('viewWatch'); break;
      case 'ctxmenu': { const d = await post('/api/context-menu', { enabled: !caps.context_menu }); alert(d.message); loadSystemStatus(); break; }
      case 'clear-source': $('pathInput').value = ''; renderWizard(); break;
      case 'folder': await post(`/api/jobs/${enc}/open?what=folder`); break;
      case 'pcap': await post(`/api/jobs/${enc}/open?what=pcap`); break;
      case 'procmon': await post(`/api/jobs/${enc}/open?what=procmon`); break;
      case 'stop': await post(`/api/jobs/${enc}/stop`); break;
      case 'sandbox': openSandboxModal(st); break;
      case 'report': {
        const r = await fetch(`/api/jobs/${enc}/report`, { headers: SAFEBOX_TOKEN ? { 'X-SafeBox-Token': SAFEBOX_TOKEN } : {} });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        $('reportText').textContent = await r.text(); showModal('reportModal'); break;
      }
      case 'cancel':
        if (confirm('Analiz iptal edilsin mi? Çalışan adım güvenli bir noktada durur.')) await post(`/api/jobs/${enc}/cancel`);
        break;
      case 'delete':
        if (!confirm('Bu analizin klasörü (açılmış dosyalar, ağ kaydı, rapor) kalıcı olarak silinecek. Orijinal dosyanıza dokunulmaz.\n\nSilinsin mi?')) return;
        await api(`/api/jobs/${enc}`, { method: 'DELETE' });
        showView('viewNew'); loadJobs(); break;
      default: break;
    }
  } catch (e) { alert(e.message); }
}

// ---------------------------------------------------------------- active job
let activeTab = 'summary', staticFilter = 'all', filesSub = 'static', procFilter = 'auto';
function openJob(id) {
  if (id !== activeJobId) { activeTab = 'summary'; filesSub = 'static'; procFilter = 'auto'; Object.keys(pages).forEach(k => { if (!k.startsWith('jobs') && !k.startsWith('watch')) delete pages[k]; }); }
  showView('jobSection');
  activeJobId = id; activeJob = null;
  history.replaceState(null, '', '#' + encodeURIComponent(id));
  clearTimeout(pollTimer);
  pollJob();
  renderJobsList();
}
async function pollJob() {
  if (!activeJobId) return;
  const id = activeJobId;
  try {
    const st = await api('/api/jobs/' + encodeURIComponent(id));
    if (id !== activeJobId) return;
    const first = !activeJob;
    activeJob = st;
    if (first && st.stages && st.stages.sandbox && st.stages.sandbox.status === 'running' && st.has_live_screen) activeTab = 'screen';
    renderJob(st);
    if (st.status === 'running') { pollTimer = setTimeout(pollJob, 2000); return; }
    loadJobs();
  } catch (e) {
    if (id !== activeJobId) return;
    $('jobTitle').textContent = 'Analiz yüklenemedi';
    $('jobSample').textContent = e.message;
    pollTimer = setTimeout(pollJob, 5000);
  }
}

const stageWord = { pending: 'Sırada', running: 'Çalışıyor', done: 'Bitti', skipped: 'Atlandı', waiting: 'Onayınızı bekliyor', queued: 'Sırada', unavailable: 'Kullanılamıyor', error: 'Hata' };
function renderJob(st) {
  const o = st.options || {};
  $('jobTitle').textContent = o.mode === 'url' || st.mode === 'url' ? st.sample : baseName(st.sample);
  $('jobSample').textContent = st.sample;
  const chip = (t, tone = '') => `<span class="chip ${tone}">${t}</span>`;
  setHtml($('jobMeta'), [
    chip(esc(statusTr[st.status] || st.status), statusTone[st.status] || ''),
    chip(esc(st.created || '')),
    chip(o.sandbox_backend === 'vbox' ? 'VirtualBox' : 'Windows Sandbox'),
    chip(`${asNum(o.duration_min)} dk izleme`),
    chip(o.network ? 'internet açık' : 'internet kapalı', o.network ? '' : 'tone-info'),
    o.decrypt_https ? chip('HTTPS çözülüyor', 'cat-net') : '',
    o.enable_vgpu ? chip('GPU açık', 'tone-high') : '',
  ].join(''));
  renderActions(st);
  setHtml($('stageList'), `<div class="progress">${Object.values(st.stages || {}).map(s => `<div class="pstep s-${esc(s.status)}" title="${esc(s.msg || '')}">
      <div class="pbar"></div><div class="plabel truncate">${esc(s.label)}</div><div class="pmsg">${esc(s.msg || stageWord[s.status] || '')}</div></div>`).join('')}</div>`);
  renderBanner(st);

  const ctx = jobContext(st);
  const tabs = [
    ['summary', 'Özet', 'shield', '', 0, false],
    ['behavior', 'Davranış', 'activity', 'cat-proc', ctx.behaviorHits, ctx.behaviorHot],
    ['network', 'Ağ', 'globe', 'cat-net', ctx.netCount, false],
    ['files', 'Dosyalar', 'file', 'cat-file', ctx.files.length + ctx.dropped.length + ctx.downloads.length + ctx.blocks.length, ctx.filesHot],
    ['intel', 'İstihbarat', 'search', 'cat-intel', asArr(st.vt).length, ctx.vtHot],
    ['screen', 'Ekran', 'monitor', 'cat-sys', ctx.shots.length, false],
    ['log', 'Günlük', 'list', 'cat-sys', 0, false],
  ];
  if (!tabs.some(t => t[0] === activeTab)) activeTab = 'summary';
  setHtml($('jobTabs'), tabs.map(([id, label, icon, cat, n, hot]) => `<button class="tab ${cat} ${activeTab === id ? 'active' : ''}" data-tab="${id}">${ic(icon)} ${label}${
    id === 'screen' && ctx.liveOn ? ' <span class="tab-badge hot">canlı</span>' : n ? ` <span class="tab-badge ${hot ? 'hot' : ''}">${n}</span>` : ''}</button>`).join(''));
  document.querySelectorAll('[data-panel]').forEach(p => p.classList.toggle('hidden', p.dataset.panel !== activeTab));
  if (activeTab === 'summary') renderSummaryTab(st, ctx);
  else if (activeTab === 'behavior') renderBehaviorTab(st, ctx);
  else if (activeTab === 'network') renderNetworkTab(st, ctx);
  else if (activeTab === 'files') renderFilesTab(st, ctx);
  else if (activeTab === 'intel') renderIntelTab(st);
  else if (activeTab === 'log') renderLogTab(st);
  renderScreenTab(st, ctx);
}

function renderActions(st) {
  const sb = (st.stages.sandbox || {}).status, enc = encodeURIComponent(st.id);
  const main = [];
  if (sb === 'running') main.push(`<button class="btn btn-danger" data-act="stop">${ic('stop')} İzlemeyi şimdi bitir</button>`);
  else if (st.status !== 'running' && ['waiting', 'unavailable', 'error', 'done'].includes(sb))
    main.push(`<button class="btn btn-primary" data-act="sandbox">${ic('play')} ${sb === 'done' ? "Sandbox'ta tekrar çalıştır" : "Sandbox'ta çalıştır"}</button>`);
  if (st.status === 'running' && sb !== 'running') main.push(`<button class="btn btn-danger" data-act="cancel">${ic('x')} İptal et</button>`);
  if (st.has_report) main.push(`<button class="btn" data-act="report">${ic('report')} Raporu aç</button>`);
  main.push(`<button class="btn" data-act="folder">${ic('folder')} Klasör</button>`);
  if (st.has_pcap) main.push(`<button class="btn" data-act="pcap" ${caps.tshark ? '' : 'disabled title="Wireshark kurulu değil"'}>Wireshark</button>`);
  if (st.has_procmon) main.push(`<button class="btn" data-act="procmon">Procmon</button>`);
  if (st.status !== 'running') main.push(`<button class="btn btn-icon btn-danger" data-act="delete" title="Analiz klasörünü sil (orijinal dosyaya dokunulmaz)">${ic('trash')}</button>`);
  const exp = st.has_report ? `<span class="btn-group"><span class="hint">Dışa aktar:</span>
      <a class="btn btn-sm btn-ghost" href="/api/jobs/${enc}/report?format=html" target="_blank" rel="noopener noreferrer">HTML rapor</a>
      <a class="btn btn-sm btn-ghost" href="/api/jobs/${enc}/report?format=json" target="_blank" rel="noopener noreferrer" download="report_${enc}.json">JSON</a>
      <a class="btn btn-sm btn-ghost" href="/api/jobs/${enc}/iocs?format=csv" download="iocs_${enc}.csv">IOC (CSV)</a>
      <a class="btn btn-sm btn-ghost" href="/api/jobs/${enc}/iocs?format=stix" download="iocs_${enc}.stix.json">IOC (STIX 2.1)</a></span>` : '';
  setHtml($('jobButtons'), `<div class="stack-sm"><div class="btn-group end">${main.join('')}</div>${exp ? `<div class="btn-group end">${exp}</div>` : ''}</div>`);
}

// ---------------------------------------------------------------- status banner
const parseTs = t => { const m = /^(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)$/.exec(t || ''); return m ? new Date(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6]) : null; };
const fmtDur = ms => { const m = Math.round(ms / 60000); return m < 1 ? '1 dakikadan kısa' : (m < 60 ? `${m} dk` : `${Math.floor(m / 60)} sa ${m % 60} dk`); };
function callout(tone, icon, title, lines) {
  return `<div class="callout ${tone}">${icon === 'spin' ? '<span class="spin"></span>' : ic(icon)}<div class="grow"><div class="callout-title">${title}</div>${lines.map(l => `<div class="callout-body">${l}</div>`).join('')}</div></div>`;
}
function renderBanner(st) {
  const stages = st.stages || {}, sb = stages.sandbox || {};
  const target = String(((st.behavior || {}).Target) || '').trim();
  let html = '', tab = 'SafeBox';
  if (st.status === 'running') {
    // VirusTotal runs next to the sandbox, so more than one stage can be running at once
    const curs = Object.values(stages).filter(x => ['running', 'queued'].includes(x.status));
    const names = curs.map(x => x.label).join(' + ');
    html = callout('tone-accent', 'spin', `Analiz sürüyor — ${esc(names || 'hazırlanıyor')}`,
      curs.filter(x => x.msg).map(x => curs.length > 1 ? `<b>${esc(x.label)}:</b> ${esc(x.msg)}` : esc(x.msg)));
    tab = (names || 'Analiz sürüyor') + ' — SafeBox';
  } else {
    const ends = Object.values(stages).map(x => parseTs(x.ended)).filter(Boolean);
    const start = parseTs(st.created), end = ends.length ? new Date(Math.max(...ends)) : null;
    const dur = start && end ? ` — ${fmtDur(end - start)} sürdü (${esc(String(st.created).slice(11, 16))} → ${String(end.getHours()).padStart(2, '0')}:${String(end.getMinutes()).padStart(2, '0')})` : '';
    const lines = [];
    if (sb.status === 'done' && target) lines.push(`Sandbox'ta çalıştırılan: <span class="mono">${esc(target)}</span>`);
    if (sb.status === 'waiting') lines.push("Sandbox adımı onayınızı bekliyor: sağ üstteki <b>Sandbox'ta çalıştır</b> düğmesine basın.");
    if (st.status === 'done' || st.status === 'waiting_sandbox') { html = callout('tone-ok', 'check', `Analiz tamamlandı${dur}`, lines); tab = 'Tamamlandı — SafeBox'; }
    else if (st.status === 'cancelled') { html = callout('tone-info', 'stop', `Analiz iptal edildi${dur}`, lines); tab = 'İptal — SafeBox'; }
    else { html = callout('tone-crit', 'alert', `Analiz hatayla bitti${dur}`, lines); tab = 'Hata — SafeBox'; }
    if (sb.status === 'done' && !target) {
      html += callout('tone-crit', 'alert', 'Sandbox açıldı ama içinde hiçbir şey çalıştırılmadı',
        ['Dosyanın davranışı incelenmedi; ekran görüntülerinde yalnızca boş masaüstü görünür. Nedeni Özet sekmesindeki notlarda.']);
    } else if (sb.status === 'done' && (st.verdict || {}).install_not_started) {
      html += callout('tone-med', 'alert', 'Kurulum başlamamış görünüyor — sonuç eksik',
        [`<span class="mono">${esc(target)}</span> çalıştı ama hiçbir alt işlem başlatmadı ve otomatik tıklayıcı hiçbir düğmeye basamadı. Büyük olasılıkla bir düğmeye (ör. "Install") basılmasını bekledi; kurulumun ne yaptığı incelenmedi.`,
          "Ne yapabilirsiniz: <b>Sandbox'ta tekrar çalıştır</b> → listeden asıl kurulum dosyasını seçin (ör. <span class=\"mono\">Set-up.exe</span>) ve/veya <b>Pencereyi ekranda göster</b>'i açıp düğmeye kendiniz basın."]);
    }
  }
  setHtml($('jobBanner'), `<div class="stack-sm">${html}</div>`);
  document.title = tab;
}

// ---------------------------------------------------------------- derived data shared by the tabs
function jobContext(st) {
  const b = st.behavior && typeof st.behavior === 'object' ? st.behavior : null;
  const live = ((st.sandbox || {}).live) || null;
  const sbStage = (st.stages || {}).sandbox || {};
  const procs = asObjs(b ? b.Processes : (live || {}).Processes);
  const conns = asObjs(b ? (b.Network || {}).Connections : (live || {}).Connections);
  const files = asObjs(st.static);
  const vt = asObjs(st.vt);
  const dropped = asObjs(st.dropped_files), downloads = asObjs(st.downloads), blocks = asObjs(st.scriptblocks);
  const shots = asArr(st.screenshots || (st.sandbox || {}).screenshots);
  const n = st.network && typeof st.network === 'object' ? st.network : null;
  const cats = behaviorCategories(st, b, live);
  const hits = cats.flatMap(c => c.boxes).filter(x => x.items.length && x.tone !== 'info');
  return {
    b, live, procs, conns, files, vt, dropped, downloads, blocks, shots, n, cats,
    liveOn: sbStage.status === 'running' && !!st.has_live_screen,
    behaviorHits: hits.length, behaviorHot: hits.some(x => x.tone === 'crit'),
    netCount: n ? asArr(n.dns).length + asArr(n.sni).length : conns.length,
    filesHot: files.some(f => asNum(f.risk_score) >= 65) || dropped.some(d => d.missing) || downloads.some(d => d.missing),
    vtHot: vt.some(e => e.result && e.result.stats && asNum(e.result.stats.malicious) >= 3),
  };
}

// ---------------------------------------------------------------- Summary tab
function verdictHtml(st) {
  const v = st.verdict || { level: 'pending', red: [], notes: [] };
  const vRed = asArr(v.red), vNotes = asArr(v.notes), vCrack = asArr(v.crack);
  const tone = { red: 'tone-crit', yellow: (!vNotes.length && vCrack.length) ? 'tone-high' : 'tone-med', green: 'tone-ok' }[v.level] || 'tone-info';
  const [lvl, title, sub] = {
    red: ['Kırmızı bulgu', 'Ciddi bulgular var — ana bilgisayarda çalıştırmayın', 'Aşağıdaki kırmızı bulgulardan en az biri zararlı davranışa işaret ediyor.'],
    yellow: (!vNotes.length && vCrack.length)
      ? ['Crack / lisans müdahalesi', 'Crack ya da lisans müdahalesi bulundu', 'Zararlı yazılım sinyali yok; bulgular crack\'li yazılımda beklenen davranış.']
      : ['İncele', 'İncelenmesi gereken bulgular var', 'Tek başına zararlı sayılmayan ama bakılması gereken işaretler.'],
    green: ['Kırmızı bayrak yok', 'Otomatik kontroller kırmızı bayrak bulmadı', 'Bu, dosyanın temiz olduğunu kanıtlamaz; yalnızca bilinen işaretlere rastlanmadı.'],
  }[v.level] || ['Sürüyor', 'Analiz sürüyor…', 'Sonuç adımlar bittikçe güncellenir.'];
  const score = asNum(v.score);
  const sTone = score >= 8 ? 'tone-crit' : score >= 5 ? 'tone-med' : 'tone-ok';
  const scoreHtml = score ? `<div class="score ${sTone}" title="10 bilinen zararlı · 8-9 büyük olasılıkla zararlı · 5-7 şüpheli · 2-4 büyük olasılıkla zararsız · 1 zararlı davranış yok">
      <div class="score-num tone-text">${score}<small>/10</small></div><div class="tiny muted">${esc(v.label || '')}${v.incomplete ? ' · eksik analiz' : ''}</div>
      <div class="meter">${Array.from({ length: 10 }, (_, i) => `<i class="${i < score ? 'on' : ''}"></i>`).join('')}</div></div>` : '';
  return `<div class="verdict ${tone}"><div class="verdict-top"><div class="grow"><div class="verdict-level">${esc(lvl)}</div><div class="verdict-title">${esc(title)}</div><div class="verdict-sub">${esc(sub)}</div></div>${scoreHtml}</div></div>`;
}
const COMPOSITE_PREFIX = 'Birleşik kural — ';
function findingRows(list, tone, tag) {
  return list.map(x => {
    const s = String(x);
    if (!s.startsWith(COMPOSITE_PREFIX)) return `<div class="finding ${tone}"><span class="finding-tag">${esc(tag)}</span><span class="grow break">${esc(s)}</span></div>`;
    const body = s.slice(COMPOSITE_PREFIX.length), cut = body.indexOf(': ');
    const title = cut > 0 ? body.slice(0, cut) : body, ev = cut > 0 ? body.slice(cut + 2).split(' + ') : [];
    return `<div class="finding ${tone}"><span class="finding-tag" title="Birden çok farklı türde kanıtın birlikte görüldüğü kural">Birleşik</span><span class="grow break"><b>${esc(title)}</b>${ev.length ? `<span class="row row-wrap mt-sm">${ev.map(e => `<span class="chip">${esc(e)}</span>`).join('')}</span>` : ''}</span></div>`;
  }).join('');
}
function renderSummaryTab(st, ctx) {
  const v = st.verdict || {};
  const vRed = asArr(v.red), vNotes = asArr(v.notes), vCrack = asArr(v.crack), fams = asObjs(v.families), attack = asObjs(v.attack);
  const susp = ctx.procs.filter(p => p.Suspicious).length, fromSample = ctx.procs.filter(p => p.InTree).length;
  const highRisk = ctx.files.filter(f => asNum(f.risk_score) >= 65).length;
  const vtFlagged = ctx.vt.filter(e => e.result && e.result.stats && asNum(e.result.stats.malicious) > 0).length;
  const stat = (label, value, sub, tab, hot) => `<button class="stat jump" data-tab="${tab}"><div class="stat-label">${label}</div><div class="stat-value ${hot ? 'hot' : ''}">${esc(value)}</div><div class="tiny faint">${sub}</div></button>`;
  const stats = `<div class="grid-4">
      ${stat('Başlayan işlem', ctx.procs.length, `${fromSample} tanesi örnekten · ${susp} şüpheli`, 'behavior', susp > 0)}
      ${stat('Davranış bulgusu', ctx.behaviorHits, 'kalıcılık, güvenlik, bellek…', 'behavior', ctx.behaviorHot)}
      ${stat('İncelenen dosya', ctx.files.length, `${highRisk} yüksek riskli`, 'files', highRisk > 0)}
      ${stat('VirusTotal', ctx.vt.length ? `${vtFlagged}/${ctx.vt.length}` : '—', ctx.vt.length ? 'dosyada en az bir motor uyardı' : 'sorgu yok', 'intel', ctx.vtHot)}
    </div>`;
  const liveCall = ctx.liveOn ? callout('tone-accent', 'monitor', 'Sandbox şu an çalışıyor', [`Canlı ekranı izleyebilir, gerekirse pencereyi öne alıp kurulumu kendiniz ilerletebilirsiniz. <button class="link-btn" data-tab="screen">Canlı ekranı aç</button>`]) : '';
  const redPg = paginate('sum-red', vRed, 10), notePg = paginate('sum-notes', vNotes, 10);
  const famBlock = fams.length ? `<div class="card"><div class="section-title cat-mem"><span class="dot"></span> Zararlı ailesi (${fams.length})</div><div class="findings mt">${fams.map(f => `<div class="finding tone-crit"><span class="finding-tag">Aile</span><span class="grow break"><b>${esc(f.family)}</b> — <span class="mono">${esc(f.label)}</span> <span class="faint">(${esc(f.source)})</span>${asArr(f.c2).length ? `<div class="mini-code">C2: ${asArr(f.c2).map(esc).join(' · ')}</div>` : ''}</span></div>`).join('')}</div></div>` : '';
  const sections = [];
  if (vRed.length) sections.push(`<div class="card"><div class="section-title tone-crit"><span class="dot"></span> Kırmızı bulgular (${vRed.length})</div><div class="findings mt">${findingRows(redPg.items, 'tone-crit', 'Kırmızı')}</div>${redPg.ctrl}</div>`);
  if (vCrack.length) sections.push(`<div class="card"><div class="section-title tone-high"><span class="dot"></span> Crack / lisans müdahalesi (${vCrack.length})</div><p class="small muted mt">Crack'li yazılımda beklenen davranış; aynı dosyada zararlı sinyali olmadığı için kırmızı sayılmadı.</p><div class="findings mt">${findingRows(vCrack, 'tone-high', 'Crack')}</div></div>`);
  if (vNotes.length) sections.push(`<div class="card"><div class="section-title tone-med"><span class="dot"></span> Notlar ve incelenecekler (${vNotes.length})</div><div class="findings mt">${findingRows(notePg.items, 'tone-med', 'Not')}</div>${notePg.ctrl}</div>`);
  const attackBlock = attack.length ? `<div class="card"><div class="section-title cat-intel"><span class="dot"></span> MITRE ATT&amp;CK teknikleri (${attack.length})</div><div class="row row-wrap mt">${attack.map(t =>
    `<a class="chip ${t.level === 'red' ? 'tone-crit' : t.level === 'crack' ? 'tone-high' : ''}" href="${esc(t.url)}" target="_blank" rel="noopener noreferrer" title="${esc(t.tactic + ' — ' + t.evidence)}">${esc(t.id)} · ${esc(t.name)}</a>`).join('')}</div></div>` : '';
  const empty = !vRed.length && !vNotes.length && !vCrack.length && st.status !== 'running' ? '<div class="empty">Not edilecek bir bulgu yok.</div>' : '';
  setHtml($('panelSummary'), `<div class="stack">${verdictHtml(st)}${liveCall}${stats}${famBlock}${sections.join('')}${attackBlock}${empty}</div>`);
}

// ---------------------------------------------------------------- Behaviour tab
function behaviorCategories(st, b, live) {
  if (b) {
    const P = b.Persistence || {}, D = b.Defender || {}, F = b.Files || {};
    const advPers = asArr(P.WmiSubscriptions).concat(asArr(P.AppInitDlls), asArr(P.BitsJobs), asArr(P.PsProfiles), asArr(P.ComHijacks), asArr(P.ActiveSetup));
    const hosts = asArr((b.Hosts || {}).Added).concat(asArr((b.Hosts || {}).Removed).map(x => `[silindi] ${x}`));
    const memYara = asObjs(b.MemoryYara).map(h => `${h.rule} — ${h.proc} (pid ${h.pid}): ${h.description}`);
    const pm = asArr((st.procmon_summary || {}).SensitiveEvents);
    return [
      { title: 'Kalıcılık', cat: 'cat-pers', boxes: [
        { key: 'svc', title: 'Yeni servisler', items: asArr(P.Services), tone: 'crit' },
        { key: 'drv', title: 'Yeni sürücüler', items: asArr(P.Drivers), tone: 'crit' },
        { key: 'adv', title: 'Gelişmiş kalıcılık (WMI, COM, AppInit, BITS, PS profili)', items: advPers, tone: 'crit' },
        { key: 'task', title: 'Zamanlanmış görevler', items: asArr(P.Tasks), tone: 'med' },
        { key: 'run', title: 'Otomatik başlatma (Run, IFEO, Başlangıç)', items: asArr(P.RunKeys).concat(asArr(P.Startup)), tone: 'med' },
        { key: 'svcchg', title: 'Ayarı değişen mevcut servisler', items: asArr(P.ServicesChanged), tone: 'med' },
      ] },
      { title: 'Güvenlik ayarları', cat: 'cat-sys', boxes: [
        { key: 'defadd', title: 'Defender ayar değişiklikleri', items: asArr(D.Added), tone: 'crit' },
        { key: 'defhit', title: 'Defender tespitleri', items: asArr(D.ThreatsDetected), tone: 'crit' },
        { key: 'fw', title: 'Güvenlik duvarı kuralları', items: asArr((b.Firewall || {}).Added), tone: 'med' },
        { key: 'hosts', title: 'hosts dosyası', items: hosts, tone: 'med' },
      ] },
      { title: 'Dosya sistemi', cat: 'cat-file', boxes: [
        { key: 'honey', title: 'Yem dosya uyarıları', items: asArr(b.HoneyfileAlerts), tone: 'crit' },
        { key: 'modexe', title: 'Değiştirilen çalıştırılabilirler', items: asArr(F.ModifiedExecutables), tone: 'crit' },
        { key: 'newexe', title: `Yeni çalıştırılabilirler (toplam ${asNum(F.NewCount)} yeni dosya)`, items: asArr(F.NewExecutables), tone: 'info' },
      ] },
      { title: 'Bellek', cat: 'cat-mem', boxes: [
        { key: 'memyara', title: 'Bellek dökümünde YARA eşleşmeleri', items: memYara, tone: 'crit' },
        { key: 'memlive', title: 'Canlı bellek taraması', items: asArr(b.MemoryFindings), tone: 'crit' },
      ] },
      { title: 'Kararlılık ve etkileşim', cat: 'cat-proc', boxes: [
        { key: 'crash', title: 'Çöken programlar (Windows hata kayıtları)', items: asArr(b.Crashes), tone: 'med' },
        { key: 'pm', title: 'Procmon hassas erişimler', items: pm, tone: 'crit' },
        { key: 'clicks', title: 'Otomatik kurulum tıklamaları', items: asArr(b.AutoClicks), tone: 'info' },
      ] },
    ];
  }
  if (live) {
    const q = live.Quick || {};
    return [{ title: 'Anlık kontroller (30 sn\'de bir güncellenir)', cat: 'cat-pers', boxes: [
      { key: 'qdef', title: 'Defender değişiklikleri', items: asArr(q.Defender), tone: 'crit' },
      { key: 'qsvc', title: 'Yeni servisler', items: asArr(q.Services), tone: 'crit' },
      { key: 'qtask', title: 'Zamanlanmış görevler', items: asArr(q.Tasks), tone: 'med' },
      { key: 'qrun', title: 'Otomatik başlatma', items: asArr(q.RunKeys).concat(asArr(q.Startup)), tone: 'med' },
      { key: 'qhosts', title: 'hosts değişiklikleri', items: asArr(q.Hosts), tone: 'med' },
    ] }];
  }
  return [];
}
function lcard(key, title, items, tone, size = 8) {
  const pg = paginate('lc:' + key, items, size);
  return `<div class="lcard tone-${tone}"><div class="lcard-head"><span class="dot"></span><span class="lcard-title">${esc(title)}</span><span class="count">${items.length}</span></div>
    <div class="lcard-body">${pg.items.map(x => `<div class="lrow mono">${esc(typeof x === 'object' ? JSON.stringify(x) : x)}</div>`).join('')}${pg.ctrl}</div></div>`;
}
function categoryHtml(c) {
  const full = c.boxes.filter(x => x.items.length), clean = c.boxes.filter(x => !x.items.length);
  return `<div class="stack-sm"><div class="section-title ${c.cat}"><span class="dot"></span> ${esc(c.title)}</div>
    ${full.length ? `<div class="grid-2">${full.map(x => lcard(x.key, x.title, x.items, x.tone)).join('')}</div>` : ''}
    ${clean.length ? `<div class="clean-line">${full.length ? 'Bulgu çıkmayanlar' : 'Bulgu yok'}: <b>${clean.map(x => esc(x.title)).join(' · ')}</b></div>` : ''}</div>`;
}
// Process tree of the sample: children grouped under the process that started them (Ppid). PIDs can be reused in a
// long run, so each node is visited once and a parent must have been seen before its child.
function procTreeHtml(procs, conns) {
  const byPid = new Map(), kids = new Map();
  procs.forEach((p, i) => { if (!byPid.has(p.Pid)) byPid.set(p.Pid, { p, i }); });
  const roots = [];
  procs.forEach((p, i) => {
    const par = byPid.get(p.Ppid);
    if (par && par.i < i && p.Ppid !== p.Pid) { if (!kids.has(p.Ppid)) kids.set(p.Ppid, []); kids.get(p.Ppid).push(p); }
    else roots.push(p);
  });
  const netBy = new Map();
  asObjs(conns).forEach(c => { if (!netBy.has(c.Pid)) netBy.set(c.Pid, []); netBy.get(c.Pid).push(`${c.Remote}:${c.Port}`); });
  const seen = new Set();
  let count = 0;
  const node = (p, depth) => {
    if (seen.has(p) || count >= 300) return '';
    seen.add(p); count++;
    const net = netBy.get(p.Pid) || [];
    const cmd = String(p.CommandLine || p.Path || '');
    const children = (kids.get(p.Pid) || []).map(c => node(c, depth + 1)).join('');
    return `<li class="ptree-item"><div class="ptree-row ${p.Suspicious ? 'tone-crit' : ''}">
      <span class="ptree-name">${esc(p.Name)}</span><span class="faint tiny">pid ${esc(p.Pid)} · ${esc(p.FirstSeen)}</span>
      ${p.Suspicious ? '<span class="chip tone-crit">şüpheli komut</span>' : ''}${net.length ? `<span class="chip cat-net" title="${esc(net.slice(0, 8).join(' · '))}">${net.length} bağlantı</span>` : ''}
      ${cmd ? `<div class="ptree-cmd mono" title="${esc(cmd.slice(0, 1000))}">${esc(cmd.slice(0, 300))}</div>` : ''}</div>${children ? `<ul class="ptree">${children}</ul>` : ''}</li>`;
  };
  const html = roots.map(r => node(r, 0)).join('');
  return `<ul class="ptree ptree-root">${html}</ul>${count >= 300 ? '<div class="clean-line">İlk 300 işlem gösteriliyor; tamamı için "Tümü" listesine bakın.</div>' : ''}`;
}
function renderBehaviorTab(st, ctx) {
  const s = (st.stages || {}).sandbox || {};
  if (!ctx.b && !ctx.live) {
    setHtml($('panelBehavior'), `<div class="empty">Sandbox henüz çalışmadı. ${s.status === 'waiting' ? "Sağ üstteki <b>Sandbox'ta çalıştır</b> ile başlatabilirsiniz." : esc(s.msg || '')}</div>`);
    return;
  }
  const src = ctx.b || ctx.live || {}, lan = src.LanBlock || {}, o = st.options || {};
  const susp = ctx.procs.filter(p => p.Suspicious).length, fromSample = ctx.procs.filter(p => p.InTree).length;
  const stat = (label, value, hot) => `<div class="stat"><div class="stat-label">${label}</div><div class="stat-value ${hot ? 'hot' : ''}">${esc(value)}</div></div>`;
  const left = ctx.live && s.status === 'running' ? asNum(ctx.live.SecondsLeft) + ' sn' : (ctx.b ? 'bitti' : '—');
  const lanChip = lan.Tampered ? `<span class="chip tone-crit">Yerel ağ engeli kaldırılmaya çalışıldı (yeniden uygulandı): ${esc(asArr(lan.Details).join(', '))}</span>`
    : lan.Applied ? '<span class="chip tone-ok">Ev ağı ve bu bilgisayar engelli — yalnızca internet ve DNS açık</span>'
    : lan.Requested ? `<span class="chip tone-med">Yerel ağ engeli uygulanamadı: ${esc(lan.Status)}</span>` : '<span class="chip">İnternet kapalı</span>';
  const chips = [lanChip, o.enable_vgpu ? '<span class="chip tone-high">Ekran kartı açık — yalıtım daha zayıf</span>' : '',
    src.RunMode ? `<span class="chip">${esc(src.RunMode === 'copied' ? 'Örnek sandbox diskine kopyalanıp çalıştırıldı' : 'Örnek kopyalanmadan, salt okunur klasörden çalıştırıldı')}</span>` : ''].join('');

  const PF = [['tree', 'Ağaç (örnek)', p => p.InTree], ['all', 'Tümü', () => true], ['sample', 'Örnekten', p => p.InTree], ['susp', 'Şüpheli', p => p.Suspicious]];
  const pf = PF.find(x => x[0] === procFilter) || (ctx.procs.some(p => p.InTree) ? PF[0] : PF[1]);
  const plist = ctx.procs.filter(pf[2]);
  const pg = paginate('procs', plist, 20);
  const listHtml = !plist.length ? '<div class="empty">Bu filtreye uyan işlem yok.</div>'
    : pf[0] === 'tree' ? procTreeHtml(plist, ctx.conns)
    : `<div class="table-wrap"><table class="tbl"><tr><th>Saat</th><th>İşlem</th><th>Üst işlem</th><th>Komut satırı</th></tr>${pg.items.map(p => `<tr class="${p.Suspicious ? 'hl tone-crit' : p.InTree ? 'hl cat-proc' : ''}">
      <td class="nowrap muted">${esc(p.FirstSeen)}</td><td class="nowrap">${esc(p.Name)} <span class="faint">${esc(p.Pid)}</span>${p.Suspicious ? ' <span class="chip tone-crit">şüpheli</span>' : p.InTree ? ' <span class="chip cat-proc">örnek</span>' : ''}</td>
      <td class="muted">${esc(p.ParentName)}</td><td class="mono break">${esc(String(p.CommandLine || p.Path || '').slice(0, 400))}</td></tr>`).join('')}</table></div>${pg.ctrl}`;
  const procTable = `<div class="card"><div class="card-head"><div><h3>Başlayan işlemler</h3><p>${pf[0] === 'tree' ? 'Örneğin başlattığı işlemler, kimin kimi başlattığına göre. Şüpheli komut satırları ve ağ bağlantısı kuran işlemler işaretli.' : "Sandbox'ta izleme süresince başlayan her işlem; örneğin kendi başlattıkları ve şüpheli komut satırları işaretli."}</p></div>
      <div class="seg">${PF.map(([id, label, fn]) => `<button class="seg-btn ${pf[0] === id ? 'active' : ''}" data-proc-filter="${id}">${label} <span class="count">${ctx.procs.filter(fn).length}</span></button>`).join('')}</div></div>
    ${listHtml}</div>`;
  setHtml($('panelBehavior'), `<div class="stack-lg">
    <div class="grid-4">${stat('Kalan süre', left)}${stat('Yeni işlem (örnekten)', `${ctx.procs.length} (${fromSample})`)}${stat('Şüpheli komut', susp, susp > 0)}${stat('TCP bağlantısı', ctx.conns.length)}</div>
    <div class="row row-wrap">${chips}</div>
    ${ctx.cats.map(categoryHtml).join('')}
    ${ctx.b ? '' : '<div class="clean-line">Dosya sistemi, sürücü, yem dosya ve güvenlik duvarı karşılaştırması izleme bitince yapılır.</div>'}
    ${procTable}</div>`);
}

// ---------------------------------------------------------------- Network tab
const classRank = c => String(c).startsWith('KÖTÜYE') ? 0 : String(c).startsWith('BİLİNMEYEN') ? 1 : String(c).startsWith('Paylaşımlı') ? 2 : 3;
const classTone = c => String(c).startsWith('KÖTÜYE') ? 'tone-crit' : String(c).startsWith('BİLİNMEYEN') ? 'tone-high' : String(c).startsWith('Paylaşımlı') ? 'tone-med' : c === 'Adobe' ? 'tone-low' : '';
function procChip(row) {
  const ps = asArr(row && row.processes);
  if (!ps.length) return '<span class="faint">—</span>';
  return `<span class="${row.from_sample ? 'strong' : 'muted'}">${esc(ps.slice(0, 3).join(', '))}</span>${row.from_sample ? ' <span class="chip cat-proc">örnek</span>' : ''}`;
}
function domainTable(key, title, desc, rows) {
  rows = asObjs(rows).slice().sort((a, b) => classRank(a.class) - classRank(b.class) || asNum(b.count) - asNum(a.count));
  const pg = paginate(key, rows, 12);
  return `<div class="card"><div class="card-head"><div><h3>${title} <span class="count">${rows.length}</span></h3><p>${desc}</p></div></div>
    ${rows.length ? `<div class="table-wrap"><table class="tbl"><tr><th>Ad</th><th>İşlem</th><th>Adet</th><th>Sınıf</th></tr>${pg.items.map(d => `<tr class="${classRank(d.class) < 2 ? 'hl ' + classTone(d.class) : ''}">
      <td class="mono break">${esc(d.name)}</td><td>${procChip(d)}</td><td class="nowrap">${asNum(d.count)}</td><td>${d.class ? `<span class="chip ${classTone(d.class)}">${esc(d.class)}</span>` : ''}</td></tr>`).join('')}</table></div>${pg.ctrl}` : '<div class="empty">Kayıt yok.</div>'}</div>`;
}
function renderNetworkTab(st, ctx) {
  const n = ctx.n, b = ctx.b || {};
  const parts = [];
  if (n && asArr(n.doh_domains).length) parts.push(callout('tone-med', 'alert', 'DNS-over-HTTPS sunucuları görüldü', [`DNS sorguları şifreli gönderilmiş olabilir: <span class="mono">${asArr(n.doh_domains).map(esc).join(', ')}</span>`]));
  if (!n && st.has_pcap) parts.push(callout('tone-info', 'info', 'Ağ kaydı hazır, özeti çıkarılmadı', ["Otomatik özet için Wireshark'ı kurun ve analizi yeniden açın; ya da kaydı sağ üstten Wireshark'ta açın."]));
  if (n) {
    parts.push(`<div class="grid-2">${domainTable('dns', 'DNS sorguları', 'Sandbox içinden sorulan alan adları; bilinmeyen ve kötüye kullanılan sınıflar üstte.', n.dns)}${domainTable('sni', 'TLS / QUIC sunucu adları', 'Şifreli bağlantılarda açıkça görünen sunucu adı (SNI).', n.sni)}</div>`);
    const http = asObjs(n.http).map(h => `${h.method} http://${h.host}${h.uri}${asArr(h.processes).length ? '  ← ' + asArr(h.processes).slice(0, 3).join(', ') : ''}`);
    const tcp = asObjs(n.tcp_targets).map(t => `${t.target} ×${asNum(t.count)}${asArr(t.processes).length ? '  ← ' + asArr(t.processes).slice(0, 3).join(', ') : ''}`);
    const udp = asObjs(n.udp_targets).map(u => `${u.target} ×${asNum(u.count)}${asArr(u.processes).length ? '  ← ' + asArr(u.processes).slice(0, 3).join(', ') : ''}`);
    parts.push(`<div class="grid-3">${lcard('http', 'Şifresiz HTTP istekleri', http, http.length ? 'med' : 'info')}${lcard('tcp', 'TCP bağlantı denemeleri', tcp, 'info')}${lcard('udp', 'UDP hedefleri', udp, 'info')}</div>`);
  }
  const https = asObjs((b.Https || {}).flows).map(f => `${f.method} ${f.url} → ${f.status ?? '-'} · ${asNum(f.req_bytes)} bayt gönderildi${f.req_preview ? ' · ' + String(f.req_preview).slice(0, 160) : ''}`);
  const listen = asArr((b.Network || {}).NewListening), fake = asArr(b.FakeNetRequests);
  const extra = [https.length ? lcard('https', 'Çözülmüş HTTPS istekleri', https, 'med') : '', listen.length ? lcard('listen', 'Yeni dinleyen portlar (TCP)', listen, 'crit') : '', fake.length ? lcard('fake', 'FakeNet\'in yakaladığı istekler', fake, 'med') : ''].filter(Boolean);
  if (extra.length) parts.push(`<div class="grid-2">${extra.join('')}</div>`);
  if (ctx.conns.length) {
    const pg = paginate('conns', ctx.conns, 15);
    parts.push(`<div class="card"><div class="card-head"><div><h3>Sandbox'taki TCP bağlantıları <span class="count">${ctx.conns.length}</span></h3><p>İzleyicinin işlem tablosundan gördüğü bağlantılar.</p></div></div>
      <div class="table-wrap"><table class="tbl"><tr><th>Saat</th><th>İşlem</th><th>Hedef</th><th>Durum</th></tr>${pg.items.map(c => `<tr class="${c.FromSample ? 'hl cat-proc' : ''}">
        <td class="nowrap muted">${esc(c.FirstSeen)}</td><td>${esc(c.Process)}${c.FromSample ? ' <span class="chip cat-proc">örnek</span>' : ''}</td><td class="mono">${esc(c.Remote)}:${esc(c.Port)}</td><td class="muted">${esc(c.State)}</td></tr>`).join('')}</table></div>${pg.ctrl}</div>`);
  }
  setHtml($('panelNetwork'), parts.length ? `<div class="stack-lg">${parts.join('')}</div>` : `<div class="empty">${(st.options || {}).network === false ? 'İnternet kapalıydı; ağ kaydı yok.' : 'Henüz ağ verisi yok.'}</div>`);
}

// ---------------------------------------------------------------- Files tab
const riskTone = s => s >= 65 ? 'tone-crit' : s >= 35 ? 'tone-med' : 'tone-ok';
const sevTone = s => s === 'critical' ? 'tone-crit' : s === 'high' ? 'tone-high' : 'tone-med';
function sigChip(sig) {
  const s = (sig || {}).status || 'Unknown';
  if (s === 'Valid') return `<span class="chip tone-ok">İmzalı · ${esc(((sig.signer || '').split(',')[0] || '').replace('CN=', ''))}</span>`;
  if (s === 'HashMismatch') return '<span class="chip tone-crit">İmza bozuk (sonradan değiştirilmiş)</span>';
  return `<span class="chip tone-med">İmzasız (${esc(s)})</span>`;
}
function vtCell(r, intel) {
  const parts = [];
  if (r && r.stats) {
    const m = asNum(r.stats.malicious);
    parts.push(`<span class="chip ${m >= 3 ? 'tone-crit' : m > 0 ? 'tone-med' : 'tone-ok'}">VT ${m} / ${asNum(r.stats.total)}</span>`);
  }
  if (intel) {
    if (intel.threatfox && intel.threatfox.found) parts.push(`<span class="chip tone-crit">ThreatFox: ${esc(intel.threatfox.family || 'zararlı')}</span>`);
    if (intel.known_good || (intel.circl && intel.circl.found && intel.circl.verdict === 'known_good' && !intel.malicious)) parts.push('<span class="chip tone-ok">NSRL: bilinen temiz</span>');
    else if (intel.circl && intel.circl.found && intel.circl.verdict === 'malicious') parts.push('<span class="chip tone-crit">CIRCL: zararlı</span>');
  }
  return parts.join(' ');
}
const STATIC_FILTERS = [
  ['all', 'Tümü', () => true, ''],
  ['high', 'Yüksek risk (65+)', (r) => r >= 65, 'tone-crit'],
  ['50', '50+', (r) => r >= 50, 'tone-high'],
  ['mid', 'Orta (35–64)', (r) => r >= 35 && r < 65, 'tone-med'],
  ['low', 'Düşük (0–34)', (r) => r < 35, 'tone-ok'],
  ['vt', 'VirusTotal uyardı', (r, vt) => vt > 0, 'tone-crit'],
];
const CAPA_GROUP_TONE = { family: 'tone-crit', inject: 'tone-high', credentials: 'tone-high', spy: 'tone-high', impact: 'tone-high', c2: 'tone-high', evasion: 'tone-med', persistence: 'tone-med' };
const CAPA_GROUP_LABEL = { family: 'Zararlı ailesi', inject: 'Enjeksiyon / kabuk kodu', credentials: 'Kimlik verisi toplama', spy: 'Tuş / ekran kaydı', evasion: 'VM / antivirüs tespiti', persistence: 'Kalıcılık', impact: 'Kurtarmayı engelleme', c2: 'Uzaktan komut (C2)' };
const TOOL_STATUS = { error: 'hata', timeout: 'zaman aşımı', skipped: 'atlandı', cancelled: 'iptal' };
function capaChip(fl) {
  const g = Object.keys(((fl || {}).capa || {}).groups || {});
  if (!g.length) return '';
  const tone = g.includes('family') ? 'tone-crit' : g.some(k => CAPA_GROUP_TONE[k] === 'tone-high') ? 'tone-high' : 'tone-med';
  return `<span class="chip ${tone}" title="capa yetenek grupları">capa: ${g.map(k => esc(CAPA_GROUP_LABEL[k] || k)).join(', ')}</span>`;
}
function flareBlock(fl) {
  if (!fl) return '';
  const capa = fl.capa || {}, floss = fl.floss || {};
  const parts = [];
  if (capa.status === 'done') {
    const groups = capa.groups || {}, caps = asObjs(capa.capabilities);
    const chips = Object.keys(groups).map(k => `<span class="chip ${CAPA_GROUP_TONE[k] || ''}" title="${esc(asArr(groups[k]).join(' · '))}">${esc(CAPA_GROUP_LABEL[k] || k)}</span>`).join('');
    parts.push(`<div class="mini cat-intel"><div class="mini-title">capa: ${caps.length} yetenek</div>
      <div class="mini-desc">${chips ? 'Karara giren gruplar: ' : 'Karara giren bir yetenek grubu yok. '}Sıradan programlarda da onlarca yetenek çıkar; tek başına zararlı anlamına gelmez.</div>
      ${chips ? `<div class="row row-wrap mt-sm">${chips}</div>` : ''}
      ${caps.length ? `<details class="sub"><summary>Tüm yetenekler (${caps.length})</summary><div class="table-wrap table-scroll"><table class="tbl"><tr><th>Yetenek</th><th>Kategori</th><th>ATT&amp;CK</th></tr>${caps.map(c => `<tr><td>${esc(c.name)}</td><td class="mono muted">${esc(c.namespace)}</td><td class="mono">${asArr(c.attack).map(esc).join(' ')}</td></tr>`).join('')}</table></div></details>` : ''}</div>`);
  } else if (capa.status) parts.push(`<div class="clean-line">capa: ${esc(TOOL_STATUS[capa.status] || capa.status)}${capa.error ? ' — ' + esc(capa.error) : ''}</div>`);
  if (floss.status === 'done') {
    const strs = ['decoded', 'stack', 'tight'].flatMap(k => asArr(floss[k]).map(s => `[${k}] ${s}`));
    const finds = asObjs(floss.findings).map(s => `<div class="mini ${sevTone(s.severity)}"><div class="mini-title">FLOSS: ${esc(s.category)}</div><div class="mini-code">${esc(asArr(s.matches).join(' | '))}</div></div>`).join('');
    parts.push(`<div class="mini cat-file"><div class="mini-title">FLOSS: ${asNum(floss.total)} gizlenmiş metin</div>
      <div class="mini-desc">Programın dosyada açıkça tutmayıp çalışırken oluşturduğu metinler (çözülen, yığında kurulan).</div>
      ${asArr(floss.urls).length ? `<div class="mini-code">${asArr(floss.urls).map(esc).join(' · ')}</div>` : ''}
      ${strs.length ? `<details class="sub"><summary>Metinleri göster (${strs.length})</summary><pre class="codebox">${esc(strs.slice(0, 400).join('\n'))}</pre></details>` : ''}</div>${finds}`);
  } else if (floss.status) parts.push(`<div class="clean-line">FLOSS: ${esc(TOOL_STATUS[floss.status] || floss.status)}${floss.error ? ' — ' + esc(floss.error) : ''}</div>`);
  return parts.length ? `<div class="stack-sm">${parts.join('')}</div>` : '';
}
function fileCard(f, idx, vt, fl) {
  const sha = (f.hashes || {}).sha256 || '', pe = f.pe_info || {};
  const mini = (tone, title, desc, code) => `<div class="mini ${tone}"><div class="mini-title">${esc(title)}</div>${desc ? `<div class="mini-desc">${esc(desc)}</div>` : ''}${code ? `<div class="mini-code">${esc(code)}</div>` : ''}</div>`;
  const left = [
    ...asObjs(f.spoof_flags).map(sf => mini('tone-crit', 'Kimlik taklidi', sf.reason)),
    ...asObjs(f.format_findings).map(ff => mini(sevTone(ff.severity), ff.category, ff.description)),
    ...asObjs(f.yara_matches).map(y => mini(sevTone(y.severity), 'YARA: ' + y.rule, y.description, asArr(y.strings).join(' | '))),
    ...asObjs(pe.dotnet_indicators).map(di => mini('cat-file', '.NET', di.description)),
    ...asObjs(f.string_findings).map(s => mini(sevTone(s.severity), s.category, s.description, asArr(s.matches).join(' | '))),
  ];
  const deobf = asObjs(f.deobfuscated_snippets);
  if (deobf.length) left.push(`<details class="sub"><summary>Çözülen gizli komutlar (${deobf.length})</summary><pre class="codebox">${deobf.map(d => `[${esc(d.kind)}]\n${esc(d.decoded)}`).join('\n---\n')}</pre></details>`);
  if (asArr(f.interesting_ips).length) left.push(mini('tone-high', 'IPv4 izleri', '', asArr(f.interesting_ips).join(' · ')));
  if (asArr(f.interesting_urls).length) left.push(mini('tone-info', 'Adresler (URL)', '', asArr(f.interesting_urls).join(' · ')));
  const apis = Object.entries(pe.suspicious_imports || {});
  const right = apis.length ? apis.map(([c, l]) => mini('tone-med', c, '', asArr(l).join(', '))).join('') : '<div class="clean-line">Şüpheli API çağrısı yok.</div>';
  let peMeta = '';
  if (pe.is_pe) {
    const vi = pe.version_info || {};
    const kv = [['Mimari', pe.architecture], ['Derleme', pe.compile_time], ['İmport', asNum(pe.total_imports)], ['imphash', pe.imphash],
      ['Ürün', vi.ProductName], ['Üretici', vi.CompanyName], ['Orijinal ad', vi.OriginalFilename], ['Sürüm', vi.FileVersion],
      ['Overlay', pe.overlay ? `${fmtMB(pe.overlay.size)} (entropi ${pe.overlay.entropy}${pe.overlay.packer_hint ? ', ' + pe.overlay.packer_hint : ''})` : '']]
      .filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => `<span>${k}: <b>${esc(v)}</b></span>`).join('');
    const flags = (pe.is_dotnet ? '<span class="chip cat-file">.NET</span>' : '') + (pe.has_tls_callbacks ? '<span class="chip tone-high">TLS callback</span>' : '');
    const secs = asObjs(pe.sections);
    peMeta = `<div class="kv">${kv}</div>${flags ? `<div class="row row-wrap">${flags}</div>` : ''}
      ${secs.length ? `<details class="sub"><summary>PE bölümleri (${secs.length})</summary><div class="table-wrap"><table class="tbl"><tr><th>Bölüm</th><th>Entropi</th><th>Sanal boyut</th><th>Ham boyut</th><th>Bayrak</th></tr>${secs.map(sc => `<tr class="${sc.rwx ? 'hl tone-crit' : ''}"><td class="mono">${esc(sc.name)}</td><td>${esc(sc.entropy)}</td><td>${esc(sc.virtual_size)}</td><td>${esc(sc.raw_size)}</td><td>${sc.rwx ? '<span class="chip tone-crit">RWX</span>' : sc.executable ? 'çalıştırılabilir' : ''}</td></tr>`).join('')}</table></div></details>` : ''}`;
  }
  const risk = asNum(f.risk_score);
  return `<details class="fcard">
    <summary>${ic('right', 'chev')}<span class="risk ${riskTone(risk)}" title="Statik risk puanı (0-100)">${risk}</span>
      <span class="grow"><span class="strong mono break">${esc(f.rel)}</span><span class="row row-wrap">${sigChip(f.signature)}${vt ? vtCell(vt.result, vt.intel) : ''}${capaChip(fl)}<span class="tiny faint">${esc(f.file_size_mb)} MB · entropi ${esc(f.entropy)}/8</span></span></span></summary>
    <div class="fbody">
      <div class="kv"><span>SHA-256: <b class="mono">${esc(sha)}</b></span></div>
      ${peMeta}
      ${asArr(f.risk_reasons).length ? `<ul class="reasons">${asArr(f.risk_reasons).map(r => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
      <div class="grid-2"><div class="stack-sm">${left.join('') || '<div class="clean-line">Bilinen stealer / RAT / anti-VM izi yok.</div>'}</div><div class="stack-sm">${right}</div></div>
      ${flareBlock(fl)}
      <div class="btn-group">
        <button class="btn btn-sm" data-preview="${idx}">${ic('eye')} İçeriği incele</button>
        ${vt ? `<span class="hint">VirusTotal: ${esc(vt.status)}</span>` : `<button class="btn btn-sm" data-vt-query="${idx}">VirusTotal'da sorgula</button>`}
        <button class="btn btn-sm" data-intel-query="${idx}">Diğer kaynaklara sor (MB / HA / CIRCL / TF)</button>
        <span class="btn-sep"></span>
        <a class="btn btn-sm btn-ghost" href="https://www.virustotal.com/gui/file/${esc(sha)}" target="_blank" rel="noopener">VT ${ic('external')}</a>
        <a class="btn btn-sm btn-ghost" href="https://www.hybrid-analysis.com/search?query=${esc(sha)}" target="_blank" rel="noopener">Hybrid Analysis ${ic('external')}</a>
        <a class="btn btn-sm btn-ghost" href="https://app.any.run/submissions/#filehash:${esc(sha)}" target="_blank" rel="noopener">ANY.RUN ${ic('external')}</a>
        <a class="btn btn-sm btn-ghost" href="https://tria.ge/s?q=${esc(sha)}" target="_blank" rel="noopener">Triage ${ic('external')}</a>
      </div>
      <div id="vtBox_${idx}" class="panel small hidden"></div>
    </div></details>`;
}
function extractedTable(rows, what) {
  if (!rows.length) return `<div class="empty">${what} dosya yok.</div>`;
  return `<div class="table-wrap"><table class="tbl"><tr><th>Dosya</th><th>Boyut</th><th>SHA-256 / durum</th></tr>${rows.map(d => `<tr class="${d.missing ? 'hl tone-crit' : ''}">
    <td class="mono break">${esc(d.name)}</td><td class="nowrap muted">${fmtMB(d.size || 0)}</td><td class="mono break">${d.missing ? '<span class="chip tone-crit">Ana bilgisayarda kayboldu — antivirüs silmiş olabilir</span>' : esc(d.sha256 || '')}</td></tr>`).join('')}</table></div>`;
}
function renderFilesTab(st, ctx) {
  const subs = [['static', 'Statik analiz', ctx.files.length], ['dropped', 'Örneğin bıraktıkları', ctx.dropped.length], ['downloads', 'Bağlantının indirdikleri', ctx.downloads.length], ['ps', 'PowerShell betikleri', ctx.blocks.length]]
    .filter(([id, , n]) => id === 'static' || n > 0);
  if (!subs.some(s => s[0] === filesSub)) filesSub = 'static';
  const seg = subs.length > 1 ? `<div class="seg">${subs.map(([id, label, n]) => `<button class="seg-btn ${filesSub === id ? 'active' : ''}" data-files-sub="${id}">${label} <span class="count">${n}</span></button>`).join('')}</div>` : '';
  let body = '';
  if (filesSub === 'static') {
    const vtBySha = {}; ctx.vt.forEach(e => { vtBySha[e.sha256] = e; });
    const all = ctx.files.map((f, idx) => ({ f, idx, vt: vtBySha[(f.hashes || {}).sha256], r: asNum(f.risk_score) }));
    const vm = x => x.vt && x.vt.result && x.vt.result.stats ? asNum(x.vt.result.stats.malicious) : 0;
    const active = STATIC_FILTERS.find(x => x[0] === staticFilter) || STATIC_FILTERS[0];
    const list = all.filter(x => active[2](x.r, vm(x)));
    const pg = paginate('static', list, 10);
    const flare = st.flare || {}, flareBy = {};
    asObjs(flare.files).forEach(x => { flareBy[x.label] = x; });
    const fFiles = asObjs(flare.files), tooBig = asArr(flare.too_big);
    const notDone = fFiles.flatMap(x => [['capa', x.capa], ['FLOSS', x.floss]].filter(([, r]) => r && r.status && r.status !== 'done').map(([t, r]) => `${t}: ${x.label} (${TOOL_STATUS[r.status] || r.status})`));
    const extraLines = [tooBig.length ? `${tooBig.length} imzasız program 2 MB'tan büyük olduğu için incelenmedi (bu araçlar büyük dosyalarda saatler sürebilir): <span class="mono">${tooBig.slice(0, 4).map(esc).join(', ')}</span>` : '',
      notDone.length ? `Sonuç vermeyen ${notDone.length} inceleme: <span class="mono">${notDone.slice(0, 4).map(esc).join(' · ')}</span>` : ''].filter(Boolean);
    const flareLine = (flare.status === 'running' ? `<div class="clean-line"><span class="spin"></span> capa / FLOSS sürüyor: ${esc(flare.msg || '')}</div>`
      : flare.status === 'done' && fFiles.length ? `<div class="clean-line">capa / FLOSS: ${esc(flare.msg || '')} Sonuçlar ilgili dosyanın kartında.</div>`
      : flare.status === 'done' ? `<div class="clean-line">capa / FLOSS: ${esc(flare.msg || 'incelenecek imzasız program yoktu.')}</div>`
      : flare.status === 'unavailable' ? '<div class="clean-line">capa / FLOSS kurulu değil; yetenek ve gizli metin incelemesi yapılmadı.</div>'
      : flare.status === 'error' ? `<div class="clean-line">capa / FLOSS hata verdi: ${esc(flare.error || '')}</div>` : '')
      + extraLines.map(l => `<div class="clean-line">${l}</div>`).join('');
    body = !ctx.files.length ? '<div class="empty">Statik analiz henüz sonuç üretmedi.</div>' : `<div class="stack">
      <div class="row row-wrap between"><p class="small muted">En riskliden sıralı. Ayrıntı için bir dosyaya tıklayın. Sandbox'tan alınan dosyalar <span class="mono">[bırakılan]</span>, <span class="mono">[indirilen]</span> ve <span class="mono">[PowerShell betiği]</span> etiketiyle bu listededir.</p>
        <div class="row row-wrap">${STATIC_FILTERS.map(([id, label, fn, tone]) => `<button class="chip chip-btn ${tone} ${staticFilter === id ? 'active' : ''}" data-static-filter="${id}">${label} <span class="count">${all.filter(x => fn(x.r, vm(x))).length}</span></button>`).join('')}</div></div>
      ${flareLine}
      ${list.length ? `<div>${pg.items.map(x => fileCard(x.f, x.idx, x.vt, flareBy[x.f.rel])).join('')}</div>${pg.ctrl}` : '<div class="empty">Bu filtreye uyan dosya yok.</div>'}</div>`;
  } else if (filesSub === 'dropped') {
    body = `<div class="stack"><p class="small muted">Örneğin sandbox'ta oluşturduğu imzasız dosyalar şifrelenerek dışarı alındı ve bu bilgisayarda <b>çalıştırılmadan</b> incelendi. Statik sonuçları "Statik analiz" listesinde <span class="mono">[bırakılan]</span> etiketiyle.</p>${extractedTable(ctx.dropped, 'Bırakılan')}</div>`;
  } else if (filesSub === 'downloads') {
    body = `<div class="stack"><p class="small muted">Bağlantının sandbox içinde indirdiği dosyalar; çalıştırılmadan incelendi ve VirusTotal'da hash'leri soruldu.</p>${extractedTable(ctx.downloads, 'İndirilen')}</div>`;
  } else {
    const pg = paginate('ps', ctx.blocks, 5);
    body = `<div class="stack"><p class="small muted">Örneğin PowerShell işlemlerinin çalıştırdığı betikler, Windows'un kaydettiği (4104) çözülmüş hâlleriyle. Base64 ve <span class="mono">-EncodedCommand</span> katmanları açılmış olarak görünür; çalışırken birleştirilen metinler görünmeyebilir.</p>
      ${pg.items.map((x, i) => `<div class="card card-tight"><div class="row between"><span class="strong">#${pg.offset + i + 1} · pid ${esc(x.pid)}</span><span class="hint">${asNum(x.chars)} karakter${asNum(x.parts) > 1 ? ` · ${asNum(x.parts)} parçadan birleştirildi` : ''}</span></div>
        ${x.path ? `<div class="tiny faint mono break">${esc(x.path)}</div>` : ''}<pre class="codebox mt">${esc(x.preview)}</pre></div>`).join('')}${pg.ctrl}</div>`;
  }
  setHtml($('panelFiles'), `<div class="stack">${seg}${body}</div>`);
}

async function manualVtQuery(idx) {
  const f = activeJob.static[idx], box = $('vtBox_' + idx);
  box.classList.remove('hidden'); box.innerHTML = '<div class="row"><span class="spin"></span> Sorgulanıyor (ücretsiz API kotası nedeniyle 15 sn sürebilir)…</div>';
  try {
    const d = await api('/api/vt/query/' + f.hashes.sha256);
    if (d.status === 'not_found') { box.innerHTML = `${esc(d.message)} <button data-vt-upload="${idx}" class="btn btn-sm">Yükle ve tara</button>`; return; }
    if (d.status !== 'found') { box.innerHTML = `<span class="tone-crit tone-text">${esc(d.message)}</span>`; return; }
    box.innerHTML = `<div class="row row-wrap">${vtCell(d)} <span>${esc(d.suggested_threat_label)}</span> ${d.has_dangerous_malware_family ? '<span class="chip tone-crit">Zararlı ailesi</span>' : ''}</div>
      <div class="muted tiny mt">${asObjs(d.flagged_engines).map(x => `${esc(x.engine)}: ${esc(x.result)}`).join(' · ')}</div>`;
  } catch (e) { box.innerHTML = `<span class="tone-crit tone-text">${esc(e.message)}</span>`; }
}
async function manualVtUpload(idx) {
  const f = activeJob.static[idx], box = $('vtBox_' + idx);
  box.innerHTML = '<div class="row"><span class="spin"></span> Yükleniyor…</div>';
  try { const d = await post('/api/vt/upload', { file_path: f.file_path }); box.innerHTML = esc(d.message); }
  catch (e) { box.innerHTML = `<span class="tone-crit tone-text">${esc(e.message)}</span>`; }
}
async function manualIntelQuery(idx) {
  const f = activeJob.static[idx], box = $('vtBox_' + idx);
  box.classList.remove('hidden'); box.innerHTML = '<div class="row"><span class="spin"></span> Tehdit istihbaratı sorgulanıyor (yalnızca hash)…</div>';
  try {
    const d = await api('/api/intel/query/' + f.hashes.sha256);
    const line = (tone, name, text, url) => `<div class="row row-wrap"><span class="chip ${tone}">${esc(name)}</span><span>${text}</span>${url ? ` <a href="${esc(url)}" target="_blank" rel="noopener">ayrıntı ${ic('external')}</a>` : ''}</div>`;
    const lines = [];
    if (d.malwarebazaar) { const m = d.malwarebazaar; lines.push(m.found ? line('tone-crit', 'MalwareBazaar', `Zararlı olarak kayıtlı (${esc(m.family || 'etiketsiz')})`, m.gui_url) : line('', 'MalwareBazaar', esc(m.message || 'kayıt yok'))); }
    if (d.hybrid_analysis) { const h = d.hybrid_analysis; lines.push(h.found ? line(h.verdict === 'malicious' ? 'tone-crit' : 'tone-med', 'Hybrid Analysis', `${esc(h.verdict)} (puan ${esc(h.threat_score)}/100${h.family ? ', ' + esc(h.family) : ''})`, h.gui_url) : line('', 'Hybrid Analysis', esc(h.message || 'kayıt yok'))); }
    if (d.threatfox) { const tf = d.threatfox; lines.push(tf.found ? line('tone-crit', 'ThreatFox', `Zararlı IOC (${esc(tf.family || tf.threat_type || 'kayıtlı')})`, tf.gui_url) : line('', 'ThreatFox', esc(tf.message || 'kayıt yok'))); }
    if (d.circl) {
      const c = d.circl;
      lines.push(c.found && c.verdict === 'known_good' ? line('tone-ok', 'CIRCL (NSRL)', `Bilinen temiz (${esc(c.product_name || c.file_name || 'kayıtlı')})`, c.gui_url)
        : c.found ? line('tone-crit', 'CIRCL', `Zararlı işaretli (${esc(c.known_malicious || c.verdict || '')})`, c.gui_url) : line('', 'CIRCL', esc(c.message || 'kayıt yok')));
    }
    box.innerHTML = `<div class="stack-sm">${lines.join('') || 'Sonuç yok.'}</div>`;
  } catch (e) { box.innerHTML = `<span class="tone-crit tone-text">${esc(e.message)}</span>`; }
}

// ---------------------------------------------------------------- Intel tab
function renderIntelTab(st) {
  const rows = asObjs(st.vt);
  const noKey = !caps.vt_api_configured ? callout('tone-med', 'key', 'VirusTotal anahtarı girilmedi', ['Hash sorgusu yapılamıyor. <button class="link-btn" data-act="keys">Anahtar ekleyin</button>; yoksa MalwareBazaar / Hybrid Analysis yedeği kullanılabilir.']) : '';
  if (!rows.length) { setHtml($('panelIntel'), `<div class="stack">${noKey}<div class="empty">VirusTotal sorgusu yapılmadı ya da sürüyor.</div></div>`); return; }
  const pg = paginate('vt', rows, 15);
  setHtml($('panelIntel'), `<div class="stack">${noKey}<div class="card"><div class="card-head"><div><h3>VirusTotal ve diğer kaynaklar <span class="count">${rows.length}</span></h3><p>Dosyaların hash'leri soruldu. "3 ve üzeri motor" kırmızı, 1-2 motor tek başına zararlı sayılmaz.</p></div></div>
    <div class="table-wrap"><table class="tbl"><tr><th>Dosya</th><th>Durum</th><th>Sonuç</th><th>Etiket ve motorlar</th><th></th></tr>${pg.items.map(e => {
      const r = e.result, intel = e.intel, m = r && r.stats ? asNum(r.stats.malicious) : 0;
      const engines = r ? asObjs(r.flagged_engines).slice(0, 4).map(x => `${esc(x.engine)}: ${esc(x.result)}`).join(' · ') : '';
      return `<tr class="${m >= 3 || (intel && intel.malicious) ? 'hl tone-crit' : ''}"><td class="mono break">${esc(e.rel)}</td><td class="muted">${esc(e.status)}</td><td class="nowrap">${vtCell(r, intel) || '<span class="faint">—</span>'}</td>
        <td>${r && r.has_dangerous_malware_family ? '<span class="chip tone-crit">Zararlı ailesi</span> ' : ''}${r ? esc(r.suggested_threat_label) : ''}${intel && intel.summary ? `<div class="small strong">${esc(intel.summary)}</div>` : ''}<div class="tiny faint">${engines}</div></td>
        <td><a class="btn btn-sm btn-ghost" target="_blank" rel="noopener" href="${esc(e.gui_url)}">VT ${ic('external')}</a></td></tr>`;
    }).join('')}</table></div>${pg.ctrl}</div></div>`);
}

// ---------------------------------------------------------------- Screen tab
let lastLiveRefresh = 0;
function renderScreenTab(st, ctx) {
  $('sbLiveWrap').classList.toggle('hidden', !ctx.liveOn);
  if (ctx.liveOn && activeTab === 'screen' && Date.now() - lastLiveRefresh > 4000) {
    lastLiveRefresh = Date.now();
    const img = $('sbLiveImg'), next = new Image();
    next.onload = () => { img.src = next.src; $('sbLiveAge').textContent = '· ' + new Date().toLocaleTimeString('tr-TR'); };
    next.src = `/api/jobs/${encodeURIComponent(st.id)}/live-screen?t=${Date.now()}`;   // keeps the last good frame if this one fails
  }
  if (activeTab !== 'screen') return;
  if (!ctx.shots.length) { setHtml($('panelScreenShots'), ctx.liveOn ? '' : '<div class="empty">Ekran görüntüsü yok.</div>'); return; }
  const encId = encodeURIComponent(st.id), pg = paginate('shots', ctx.shots, 12);
  setHtml($('panelScreenShots'), `<div class="card"><div class="card-head"><div><h3>Ekran görüntüleri <span class="count">${ctx.shots.length}</span></h3><p>İzleme süresince belirli aralıklarla alındı. Büyütmek için tıklayın.</p></div></div>
    <div class="shots">${pg.items.map(name => { const url = `/api/jobs/${encId}/screenshots/${encodeURIComponent(name)}`; return `<a class="shot" href="${url}" target="_blank" rel="noopener noreferrer"><img src="${url}" alt="${esc(name)}" loading="lazy" /><span class="mono">${esc(name)}</span></a>`; }).join('')}</div>${pg.ctrl}</div>`);
}

// ---------------------------------------------------------------- Log tab
function renderLogTab(st) {
  const log = asObjs(st.log).slice().reverse();
  if (!log.length) { setHtml($('panelLog'), '<div class="empty">Günlük boş.</div>'); return; }
  const pg = paginate('log', log, 50);
  setHtml($('panelLog'), `<div class="card"><div class="card-head"><div><h3>İşlem günlüğü</h3><p>En yeni üstte.</p></div></div><div class="log">${pg.items.map(l => `<div><span>${esc(l.t)}</span>${esc(l.msg)}</div>`).join('')}</div>${pg.ctrl}</div>`);
}

// ---------------------------------------------------------------- Sandbox launch modal
function openSandboxModal(st) {
  const o = st.options || {};
  const targets = asArr(st.runnable_targets);
  $('sbModalTarget').innerHTML = '<option value="">Otomatik seç</option>' + targets.map(t => `<option value="${esc(t)}"${o.target === t ? ' selected' : ''}>${esc(t)}</option>`).join('');
  $('sbModalTargetCustom').value = (o.target && !targets.includes(o.target)) ? o.target : '';
  $('sbModalArgs').value = o.target_args || '';
  $('sbModalDllExport').value = o.dll_export || '';
  $('sbModalDuration').value = String(o.duration_min || 10);
  $('sbModalMemory').value = String(o.memory_mb || 4096);
  $('sbModalBackend').value = o.sandbox_backend === 'vbox' ? 'vbox' : 'wsb';
  $('sbModalNet').checked = o.network !== false;
  $('sbModalKeepOpen').checked = !!o.keep_sandbox_open;
  $('sbModalShowWindow').checked = !!o.show_sandbox_window;
  $('sbModalVgpu').checked = !!o.enable_vgpu;
  $('sbModalHttps').checked = !!o.decrypt_https;
  $('sbModalSimUser').checked = o.simulate_user !== false;
  $('sbModalStdUser').checked = !!o.run_as_standard_user;
  $('sbModalHoney').checked = o.seed_honeyfiles !== false;
  $('sbModFakeNet').checked = !!o.fake_net;
  $('sbModalUser').value = o.vbox_user || '';
  $('sbModalPass').value = '';
  const syncVbox = () => {
    const isVbox = $('sbModalBackend').value === 'vbox';
    $('sbModalVboxOpts').classList.toggle('hidden', !isVbox);
    if (isVbox && $('sbModalVm').value) loadVboxSnapshots($('sbModalVm').value, $('sbModalSnap'));
  };
  $('sbModalBackend').onchange = syncVbox;
  $('sbModalVm').onchange = () => loadVboxSnapshots($('sbModalVm').value, $('sbModalSnap'));
  if (o.vbox_vm) $('sbModalVm').value = o.vbox_vm;
  syncVbox();
  showModal('sandboxModal');
}
$('btnSbModalStart').onclick = async () => {
  if (!activeJob) return;
  const payload = {
    target: $('sbModalTargetCustom').value.trim() || $('sbModalTarget').value,
    target_args: $('sbModalArgs').value.trim(),
    dll_export: $('sbModalDllExport').value.trim(),
    duration_min: parseInt($('sbModalDuration').value, 10) || 10,
    memory_mb: parseInt($('sbModalMemory').value, 10) || 4096,
    network: $('sbModalNet').checked,
    keep_sandbox_open: $('sbModalKeepOpen').checked,
    show_sandbox_window: $('sbModalShowWindow').checked,
    enable_vgpu: $('sbModalVgpu').checked,
    decrypt_https: $('sbModalHttps').checked,
    simulate_user: $('sbModalSimUser').checked,
    run_as_standard_user: $('sbModalStdUser').checked,
    seed_honeyfiles: $('sbModalHoney').checked,
    fake_net: $('sbModFakeNet').checked,
    sandbox_backend: $('sbModalBackend').value,
    vbox_vm: $('sbModalVm').value || '',
    vbox_snapshot: $('sbModalSnap').value || '',
    vbox_user: $('sbModalUser').value.trim(),
    vbox_password: $('sbModalPass').value || '',
  };
  try {
    await post(`/api/jobs/${encodeURIComponent(activeJob.id)}/sandbox`, payload);
    hideModal('sandboxModal');
    activeTab = 'screen';
    setTimeout(pollJob, 600);
  } catch (e) { alert(e.message); }
};

// ---------------------------------------------------------------- Safe file preview modal
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
  document.querySelectorAll('#previewModes [data-preview-mode]').forEach(b => b.classList.toggle('active', b.dataset.previewMode === mode));
  $('previewText').textContent = 'Yükleniyor…';
  try {
    const d = await api(`/api/jobs/${encodeURIComponent(previewCtx.jobId)}/preview?file_path=${encodeURIComponent(previewCtx.filePath)}&mode=${encodeURIComponent(mode)}`);
    $('previewMeta').textContent = `${String(d.mode).toUpperCase()} · ${fmtMB(d.size)}${d.truncated ? ' · ilk kısım gösteriliyor' : ''}`;
    $('previewText').textContent = d.content || '(boş)';
  } catch (e) { $('previewText').textContent = 'Hata: ' + e.message; }
}

// ---------------------------------------------------------------- YARA rules manager modal
async function openYaraModal() { $('yaraErr').classList.add('hidden'); showModal('yaraModal'); await refreshYaraModal(); }
async function refreshYaraModal() {
  try {
    const d = await api('/api/yara/rules');
    const st = d.status || {};
    $('yaraEngineInfo').textContent = `Motor: ${st.engine} · toplam ${asNum(st.rules_count)} kural` + (st.hint ? ` · ${st.hint}` : '');
    const files = asObjs(d.files);
    $('yaraFilesList').innerHTML = files.map(f => `<button data-yara-file="${esc(f.name)}" class="job-item ${$('yaraFileName').value === f.name ? 'active' : ''}">
        <span class="grow"><span class="job-name mono truncate">${esc(f.name)}</span><span class="job-meta">${asNum(f.rules_count)} kural${f.builtin ? ' · yerleşik, salt okunur' : ''}${asArr(f.problems).length ? ' · sorunlu' : ''}</span></span></button>`).join('');
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
    $('yaraFileName').readOnly = isBuiltin; $('yaraFileContent').readOnly = isBuiltin;
    $('btnYaraSave').classList.toggle('hidden', isBuiltin);
    $('btnYaraDelete').classList.toggle('hidden', isBuiltin);
    document.querySelectorAll('#yaraFilesList [data-yara-file]').forEach(b => b.classList.toggle('active', b.dataset.yaraFile === d.name));
  } catch (e) { $('yaraErr').textContent = e.message; $('yaraErr').classList.remove('hidden'); }
}
$('btnYaraNew').onclick = () => {
  $('yaraErr').classList.add('hidden');
  $('yaraFileName').readOnly = false; $('yaraFileContent').readOnly = false;
  $('yaraFileName').value = 'custom_rules.yar';
  $('yaraFileContent').value = 'rule Custom_Sample_Rule\n{\n    meta:\n        description = "Ozel kural"\n        severity = "high"\n        score = 25\n    strings:\n        $a = "suspicious_marker" ascii wide nocase\n    condition:\n        $a\n}\n';
  $('btnYaraSave').classList.remove('hidden'); $('btnYaraDelete').classList.add('hidden');
};
$('btnYaraSave').onclick = async () => {
  $('yaraErr').classList.add('hidden');
  try { await post('/api/yara/rules', { name: $('yaraFileName').value.trim(), content: $('yaraFileContent').value }); await refreshYaraModal(); loadSystemStatus(); }
  catch (e) { $('yaraErr').textContent = e.message; $('yaraErr').classList.remove('hidden'); }
};
$('btnYaraDelete').onclick = async () => {
  const name = $('yaraFileName').value.trim();
  if (!name || !confirm(`'${name}' kural dosyası silinsin mi?`)) return;
  try {
    await api('/api/yara/rules/' + encodeURIComponent(name), { method: 'DELETE' });
    $('yaraFileName').value = ''; $('yaraFileContent').value = '';
    await refreshYaraModal(); loadSystemStatus();
  } catch (e) { $('yaraErr').textContent = e.message; $('yaraErr').classList.remove('hidden'); }
};

// ---------------------------------------------------------------- Compare two jobs
$('btnCompareModal').onclick = async () => {
  await loadJobs();
  const optsHtml = recentJobs.map(j => `<option value="${esc(j.id)}">${esc(baseName(j.sample))} (${esc(j.created)})</option>`).join('');
  $('cmpBase').innerHTML = optsHtml; $('cmpTarget').innerHTML = optsHtml;
  if (recentJobs.length >= 2) { $('cmpBase').selectedIndex = 1; $('cmpTarget').selectedIndex = 0; }
  $('compareResult').innerHTML = recentJobs.length < 2 ? callout('tone-med', 'info', 'Karşılaştırma için en az iki analiz gerekir', []) : '';
  showModal('compareModal');
};
$('btnRunCompare').onclick = async () => {
  const baseId = $('cmpBase').value, targetId = $('cmpTarget').value;
  if (!baseId || !targetId) return;
  $('compareResult').innerHTML = '<div class="row"><span class="spin"></span> Farklar hesaplanıyor…</div>';
  try {
    const d = await api(`/api/compare?base=${encodeURIComponent(baseId)}&target=${encodeURIComponent(targetId)}`);
    const hi = asArr(d.highlights).length ? `<div class="findings">${findingRows(asArr(d.highlights), 'tone-med', 'Fark')}</div>` : '<div class="empty">Belirgin fark bulunmadı.</div>';
    const files = d.files || {};
    const fileRows = asObjs(files.modified).map(m => `${m.sig_broken ? '[imza bozuldu] ' : '[değişti] '}${m.rel} (${m.base_sig} → ${m.target_sig})`)
      .concat(asObjs(files.added).map(a => `[eklendi] ${a.rel} (${a.sig})`));
    const stRows = asObjs(d.static_deltas).map(s => `${s.rel}: puan ${s.base_score ?? 'yok'} → ${s.target_score}${asArr(s.new_yara).length ? ` · yeni YARA: ${asArr(s.new_yara).join(', ')}` : ''}`);
    const bd = d.behavior_diff || {}, nd = d.network_diff || {};
    const persAll = asArr(bd.services).concat(asArr(bd.tasks), asArr(bd.runkeys), asArr(bd.wmi_subscriptions), asArr(bd.com_hijacks), asArr(bd.appinit_dlls), asArr(bd.bits_jobs), asArr(bd.ps_profiles));
    const boxes = [
      ['cmp-files', 'Değişen / eklenen dosyalar', fileRows, 'med'],
      ['cmp-static', 'Statik risk ve YARA artışı', stRows, 'crit'],
      ['cmp-pers', 'Yeni kalıcılık (servis, görev, Run, WMI, COM)', persAll, 'crit'],
      ['cmp-sec', 'Defender / güvenlik duvarı / hosts / yem dosya farkı', asArr(bd.defender).concat(asArr(bd.firewall), asArr(bd.hosts), asArr(bd.hosts_removed), asArr(bd.honeyfile_alerts)), 'crit'],
      ['cmp-drop', 'Ek bırakılan / değiştirilen dosyalar ve portlar', asArr(bd.dropped_executables).concat(asArr(bd.modified_executables), asArr(bd.new_listening)), 'med'],
      ['cmp-mem', 'Canlı bellek / FakeNet farkı', asArr(bd.memory_findings).concat(asArr(bd.fakenet_requests)), 'med'],
      ['cmp-net', 'Ek ağ hedefleri (alan adı / IP)', asObjs(nd.extra_domains).map(x => x.value).concat(asObjs(nd.extra_ips).map(x => x.value)), 'med'],
    ];
    const full = boxes.filter(b => b[2].length), clean = boxes.filter(b => !b[2].length);
    $('compareResult').innerHTML = hi + (full.length ? `<div class="grid-2">${full.map(([k, t, items, tone]) => lcard(k, t, items, tone, 50)).join('')}</div>` : '')
      + (clean.length ? `<div class="clean-line">Fark çıkmayanlar: <b>${clean.map(b => esc(b[1])).join(' · ')}</b></div>` : '');
  } catch (e) { $('compareResult').innerHTML = callout('tone-crit', 'alert', esc(e.message), []); }
};

// ---------------------------------------------------------------- API keys modal
function openKeysModal() {
  vtModalOpen = true;
  $('mbEnabledInput').checked = !!caps.mb_enabled;
  $('chkCirclEnabled').checked = !!caps.circl_enabled;
  $('chkTfEnabled').checked = !!caps.tf_enabled;
  $('vtCurStatus').textContent = caps.vt_api_configured ? `(kayıtlı: ${caps.vt_api_masked})` : '(girilmedi)';
  $('mbCurStatus').textContent = caps.mb_api_configured ? `(kayıtlı: ${caps.mb_api_masked})` : '(girilmedi)';
  $('haCurStatus').textContent = caps.ha_api_configured ? `(kayıtlı: ${caps.ha_api_masked})` : '(girilmedi)';
  ['vtClearInput', 'mbClearInput', 'haClearInput'].forEach(id => { $(id).checked = false; });
  showModal('vtModal');
}
$('btnVtModal').onclick = openKeysModal;
$('btnVtSave').onclick = async () => {
  const payload = {
    vt_api_key: $('vtApiKeyInput').value.trim() || null,
    mb_api_key: $('mbApiKeyInput').value.trim() || null,
    ha_api_key: $('haApiKeyInput').value.trim() || null,
    mb_enabled: $('mbEnabledInput').checked,
    circl_enabled: $('chkCirclEnabled').checked,
    tf_enabled: $('chkTfEnabled').checked,
    clear_vt: $('vtClearInput').checked,
    clear_mb: $('mbClearInput').checked,
    clear_ha: $('haClearInput').checked,
  };
  try {
    await post('/api/intel/config', payload);
    $('vtApiKeyInput').value = ''; $('mbApiKeyInput').value = ''; $('haApiKeyInput').value = '';
    hideModal('vtModal'); loadSystemStatus();
  } catch (e) { alert(e.message); }
};

// ---------------------------------------------------------------- sandbox window front / back
const sandboxWindow = async mode => {
  $('sbFocusMsg').textContent = '';
  try { const d = await post('/api/sandbox/focus', { mode }); $('sbFocusMsg').textContent = d.message || ''; }
  catch (e) { $('sbFocusMsg').textContent = e.message; }
};
$('btnSbFocus').onclick = () => sandboxWindow('front');
$('btnSbBack').onclick = () => sandboxWindow('back');

// ---------------------------------------------------------------- start
hydrateIcons();
renderWizard();
loadSystemStatus(); loadJobs(); loadWatch();
setInterval(loadWatch, 5000);
setInterval(loadSystemStatus, 30000);
const last = (location.hash || '').slice(1); if (last) openJob(decodeURIComponent(last));
window.addEventListener('hashchange', () => { const h = decodeURIComponent((location.hash || '').slice(1)); if (h && h !== activeJobId) openJob(h); });
