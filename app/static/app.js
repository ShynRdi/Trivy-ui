let currentTab = 'local';
let currentReport = null;
let currentDownloads = null;
let allRows = [];
let selectedSeverity = 'ALL';
let imagesLoading = false;
let lastImagesLoadAt = 0;

const $ = (id) => document.getElementById(id);

function setStatus(text, type = '') {
  const el = $('scanStatus');
  el.textContent = text;
  el.className = `status ${type}`;
}

function flattenVulns(report) {
  const rows = [];
  for (const result of report.Results || []) {
    for (const vuln of result.Vulnerabilities || []) {
      rows.push({
        target: result.Target || '',
        package: vuln.PkgName || '',
        severity: (vuln.Severity || 'UNKNOWN').toUpperCase(),
        cve: vuln.VulnerabilityID || '',
        installed: vuln.InstalledVersion || '',
        fixed: vuln.FixedVersion || 'Not fixed',
        title: vuln.Title || vuln.Description || ''
      });
    }
  }
  return rows;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}

function renderTable() {
  const q = $('searchBox').value.trim().toLowerCase();
  let rows = allRows;
  if (selectedSeverity !== 'ALL') rows = rows.filter(r => r.severity === selectedSeverity);
  if (q) rows = rows.filter(r => Object.values(r).join(' ').toLowerCase().includes(q));
  const body = $('resultsBody');
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty">موردی برای نمایش وجود ندارد.</td></tr>';
    return;
  }
  body.innerHTML = rows.slice(0, 250).map(r => `
    <tr>
      <td>${escapeHtml(r.package)}</td>
      <td><span class="sev ${escapeHtml(r.severity)}">${escapeHtml(r.severity)}</span></td>
      <td>${escapeHtml(r.cve)}</td>
      <td>${escapeHtml(r.installed)}</td>
      <td>${escapeHtml(r.fixed)}</td>
      <td>${escapeHtml(r.title)}</td>
    </tr>
  `).join('');
}

function updateSummary(summary) {
  const critical = summary.CRITICAL || 0;
  const high = summary.HIGH || 0;
  const medium = summary.MEDIUM || 0;
  const low = summary.LOW || 0;
  const total = critical + high + medium + low + (summary.UNKNOWN || 0);
  $('criticalCount').textContent = critical;
  $('highCount').textContent = high;
  $('mediumCount').textContent = medium;
  $('lowCount').textContent = low;
  $('donut').querySelector('span').textContent = total;
  if (total > 0) {
    let a = critical / total * 360;
    let b = a + high / total * 360;
    let c = b + medium / total * 360;
    $('donut').style.background = `conic-gradient(var(--critical) 0deg ${a}deg, var(--high) ${a}deg ${b}deg, var(--medium) ${b}deg ${c}deg, var(--low) ${c}deg 360deg)`;
  }
}

async function loadTrivyVersion() {
  try {
    const res = await fetch('/api/trivy-version', { cache: 'no-store' });
    const data = await res.json();
    const version = data.version ? ` ${data.version}` : '';
    $('trivyTitle').textContent = `اسکن کانتینر با Trivy${version}`;
  } catch (err) {
    $('trivyTitle').textContent = 'اسکن کانتینر با Trivy';
  }
}

async function loadImages(options = {}) {
  const { force = false } = options;

  // جلوی درخواست‌های پشت سر هم را می‌گیرد، مگر اینکه کاربر دکمه رفرش را زده باشد.
  if (imagesLoading) return;
  const now = Date.now();
  if (!force && now - lastImagesLoadAt < 1200) return;

  const select = $('localImages');
  const refreshBtn = $('refreshImages');
  const status = $('imagesStatus');
  const previousValue = select.value;

  imagesLoading = true;
  lastImagesLoadAt = now;
  if (refreshBtn) refreshBtn.disabled = true;
  if (status) status.textContent = 'در حال به‌روزرسانی لیست ایمیج‌ها...';

  try {
    const res = await fetch(`/api/images?t=${Date.now()}`, { cache: 'no-store' });
    const data = await res.json();

    $('dockerStatus').textContent = data.docker_connected ? 'Docker متصل است' : 'Docker وصل نیست؛ socket را mount کنید';

    if (!data.docker_connected) {
      select.innerHTML = '<option value="">Docker وصل نیست</option>';
      if (status) status.textContent = 'اتصال به Docker برقرار نیست. Docker socket را mount کنید.';
      return;
    }

    if (!data.images.length) {
      select.innerHTML = '<option value="">ایمیجی پیدا نشد؛ آدرس را دستی وارد کنید</option>';
      if (status) status.textContent = 'هیچ ایمیج لوکالی پیدا نشد.';
      return;
    }

    select.innerHTML = data.images
      .map(img => `<option value="${escapeHtml(img)}">${escapeHtml(img)}</option>`)
      .join('');

    // اگر ایمیج قبلی هنوز وجود داشت، همان انتخاب قبلی حفظ شود.
    if (previousValue && data.images.includes(previousValue)) {
      select.value = previousValue;
    }

    if (status) status.textContent = `لیست به‌روز شد. تعداد ایمیج‌های لوکال: ${data.images.length}`;
  } catch (err) {
    select.innerHTML = '<option value="">خطا در دریافت لیست ایمیج‌ها</option>';
    $('dockerStatus').textContent = 'خطا در اتصال به Docker';
    if (status) status.textContent = 'خطا در دریافت لیست ایمیج‌ها.';
  } finally {
    imagesLoading = false;
    if (refreshBtn) refreshBtn.disabled = false;
  }
}

document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    currentTab = btn.dataset.tab;
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    btn.classList.add('active');
    $('localPanel').classList.toggle('active-panel', currentTab === 'local');
    $('remotePanel').classList.toggle('active-panel', currentTab === 'remote');

    if (currentTab === 'local') {
      loadImages({ force: true });
    }
  });
});

document.querySelectorAll('.filter').forEach(btn => {
  btn.addEventListener('click', () => {
    selectedSeverity = btn.dataset.sev;
    document.querySelectorAll('.filter').forEach(x => x.classList.remove('active'));
    btn.classList.add('active');
    renderTable();
  });
});

$('searchBox').addEventListener('input', renderTable);

// وقتی کاربر لیست کشویی را باز می‌کند یا با کیبورد/ماوس روی آن می‌رود، لیست تازه می‌شود.
$('localImages').addEventListener('focus', () => loadImages({ force: false }));
$('localImages').addEventListener('mousedown', () => loadImages({ force: false }));
$('localImages').addEventListener('pointerdown', () => loadImages({ force: false }));

$('updateDb').addEventListener('click', async () => {
  $('updateDb').disabled = true;
  $('dbStatus').textContent = 'در حال آپدیت دیتابیس...';
  try {
    const res = await fetch('/api/update-db', { method: 'POST', cache: 'no-store' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'آپدیت ناموفق بود');
    $('dbStatus').textContent = 'آخرین آپدیت: همین حالا';
  } catch (err) {
    $('dbStatus').textContent = err.message;
  } finally {
    $('updateDb').disabled = false;
  }
});

$('scanBtn').addEventListener('click', async () => {
  const image = currentTab === 'local' ? $('localImages').value : $('remoteImage').value.trim();
  if (!image) {
    setStatus('لطفاً یک ایمیج انتخاب یا وارد کنید.');
    return;
  }
  $('scanBtn').disabled = true;
  setStatus('در حال آماده‌سازی و اسکن...');
  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ image, pull_if_missing: true })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'اسکن ناموفق بود');
    currentReport = data.report;
    currentDownloads = data.downloads;
    allRows = flattenVulns(currentReport);
    updateSummary(data.summary);
    renderTable();
    $('downloadBtn').disabled = false;
    setStatus(data.pulled ? 'ایمیج دانلود و اسکن شد.' : 'اسکن با موفقیت انجام شد.');

    // اگر طی اسکن ایمیج pull شده باشد، لیست ایمیج‌های لوکال را هم تازه کن.
    loadImages({ force: true });
  } catch (err) {
    setStatus(err.message);
  } finally {
    $('scanBtn').disabled = false;
  }
});

$('downloadBtn').addEventListener('click', () => {
  if (!currentDownloads) return;
  const fmt = $('exportFormat').value;
  window.location.href = currentDownloads[fmt];
});

loadTrivyVersion();
loadImages({ force: true });
