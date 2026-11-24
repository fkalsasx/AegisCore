// AegisCore Desktop Security Controller — SuperLX 1.0 Birleşik Masaüstü Sürümü
const AEGIS_CSRF_TOKEN = document.querySelector('meta[name="aegis-token"]')?.getAttribute('content') || '';
const _origFetch = window.fetch.bind(window);
window.fetch = function(input, init = {}) {
  const method = String(init?.method || 'GET').toUpperCase();
  const urlStr = typeof input === 'string' ? input : (input?.url || '');
  const isSameOrigin = urlStr.startsWith('/') || urlStr.startsWith(window.location.origin);
  if (isSameOrigin && method !== 'GET' && method !== 'HEAD') {
    const headers = new Headers(init?.headers || {});
    if (AEGIS_CSRF_TOKEN && !headers.has('X-Aegis-Token')) {
      headers.set('X-Aegis-Token', AEGIS_CSRF_TOKEN);
    }
    return _origFetch(input, { ...init, credentials: 'same-origin', headers });
  }
  return _origFetch(input, init);
};

document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-aegis-action]');
  if (!btn) return;
  const action = btn.getAttribute('data-aegis-action');
  if (action === 'open-location') {
    window.openFileLocation(btn.getAttribute('data-path') || '');
  } else if (action === 'restore-event') {
    window.restoreFromEvent(btn.getAttribute('data-id') || '');
  } else if (action === 'isolate-path') {
    window.isolatePath(btn.getAttribute('data-path') || '', btn.getAttribute('data-threat') || '', Number(btn.getAttribute('data-score') || 0));
  } else if (action === 'inspect-deep') {
    window.inspectDeep(btn.getAttribute('data-path') || '');
  } else if (action === 'kill-proc') {
    window.killProc(Number(btn.getAttribute('data-pid') || 0));
  } else if (action === 'kill-quarantine-proc') {
    window.killAndQuarantineProc(Number(btn.getAttribute('data-pid') || 0), btn.getAttribute('data-path') || '');
  } else if (action === 'restore-q') {
    window.restoreQ(btn.getAttribute('data-id') || '');
  } else if (action === 'delete-q') {
    window.deleteQ(btn.getAttribute('data-id') || '');
  }
});

const tabViews = document.querySelectorAll('.tab-view');

const VIEW_TITLES = {
  overview: 'Ana Sayfa',
  scanner: 'Bilgisayar Taraması',
  realtime: 'Gerçek Zamanlı Koruma',
  firewall: 'Güvenlik Duvarı & Başlangıç',
  events: 'Güvenlik Olayları ve Raporlar',
  tools: 'Sistem Araçları ve Doğrulama',
  settings: 'Ayarlar ve Sistem Bilgisi'
};

let latestStatus = null;
let recentEvents = [];
let latestDownloads = [];
let latestWatchedZones = [];
let latestActiveDownloadsCount = 0;
let latestScanDetections = [];
let latestProcNetData = null;
let activeEventFilter = 'all';
const expandedEventIds = new Set();
let eventsDirty = false;
let downloadsDirty = false;
let statusSyncTimer = null;

function scheduleStatusSync(delayMs = 500) {
  if (statusSyncTimer) return;
  statusSyncTimer = setTimeout(() => {
    statusSyncTimer = null;
    fetchStatus();
  }, delayMs);
}

function applyTheme(themeName) {
  const chosen = themeName === 'dark' ? 'dark' : 'light';
  localStorage.setItem('aegis_theme', chosen);
  document.body.classList.toggle('theme-dark', chosen === 'dark');

  document.querySelectorAll('[data-theme-choice]').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-theme-choice') === chosen);
  });
}

applyTheme(localStorage.getItem('aegis_theme') || 'light');

document.querySelectorAll('[data-theme-choice]').forEach(btn => {
  btn.addEventListener('click', () => {
    applyTheme(btn.getAttribute('data-theme-choice'));
  });
});

function switchTab(tabName, customTitle) {
  tabViews.forEach(view => {
    view.classList.toggle('active', view.id === `view-${tabName}`);
  });

  const backBar = document.getElementById('subpageBackBar');
  const titleEl = document.getElementById('subpageTitle');
  if (backBar) {
    backBar.classList.toggle('hidden', tabName === 'overview');
  }
  if (titleEl && tabName !== 'overview') {
    titleEl.textContent = customTitle || VIEW_TITLES[tabName] || 'Detaylar';
  }

  document.getElementById('topbarPopover')?.classList.add('hidden');

  if (tabName === 'events' && eventsDirty) {
    renderRecentActivities(recentEvents, true);
  }
  if (tabName === 'realtime' && downloadsDirty) {
    renderRealtimeDownloads(latestDownloads, latestWatchedZones, latestActiveDownloadsCount, true);
  }
  if (tabName === 'firewall') {
    loadProcNet();
    loadStartupGuard();
    loadQuarantine();
  }
  if (tabName === 'tools') {
    loadTimeMachine();
  }
  if (tabName === 'realtime' || tabName === 'settings') {
    loadDefenderCoexistence();
  }
}

document.getElementById('backToHomeBtn')?.addEventListener('click', () => switchTab('overview'));
document.getElementById('openSettingsBtn')?.addEventListener('click', () => switchTab('settings'));
document.getElementById('openEventsBtn')?.addEventListener('click', () => switchTab('events'));
document.getElementById('homeOtherToolsBtn')?.addEventListener('click', () => switchTab('events'));
document.getElementById('footerEventsBtn')?.addEventListener('click', () => switchTab('events'));
document.getElementById('footerSettingsBtn')?.addEventListener('click', () => switchTab('settings'));
document.getElementById('footerSupportLink')?.addEventListener('click', () => switchTab('firewall'));
document.getElementById('footerToolsLink')?.addEventListener('click', () => switchTab('tools'));

document.querySelectorAll('.feature-tile[data-nav]').forEach(tile => {
  tile.addEventListener('click', () => {
    const targetTab = tile.getAttribute('data-nav');
    const customTitle = tile.getAttribute('data-title');
    const nwTarget = tile.getAttribute('data-nwtarget');
    if (targetTab) switchTab(targetTab, customTitle);
    if (nwTarget) switchNwTab(nwTarget);
  });
});

function switchSubtab(subName) {
  document.querySelectorAll('[data-subtab]').forEach(b => {
    b.classList.toggle('active', b.getAttribute('data-subtab') === subName);
  });
  document.querySelectorAll('.subtab-panel').forEach(p => {
    p.classList.toggle('active', p.id === `subtab-${subName}`);
  });
}

document.querySelectorAll('[data-subtab]').forEach(btn => {
  btn.addEventListener('click', () => switchSubtab(btn.getAttribute('data-subtab')));
});

function switchNwTab(nwName) {
  document.querySelectorAll('[data-nwtab]').forEach(b => {
    b.classList.toggle('active', b.getAttribute('data-nwtab') === nwName);
  });
  document.querySelectorAll('.nw-panel').forEach(p => {
    p.classList.toggle('active', p.id === nwName);
  });
  if (nwName === 'nw-startup') loadStartupGuard();
  if (nwName === 'nw-quarantine') loadQuarantine();
}

document.querySelectorAll('[data-nwtab]').forEach(btn => {
  btn.addEventListener('click', () => switchNwTab(btn.getAttribute('data-nwtab')));
});

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safeUriArg(str) {
  return encodeURIComponent(String(str ?? '')).replace(/'/g, '%27');
}

function decodeUriArg(str) {
  try {
    return decodeURIComponent(String(str ?? ''));
  } catch (_) {
    return String(str ?? '');
  }
}

function severityToTier(severity) {
  const s = String(severity || '').toUpperCase();
  if (s === 'CRITICAL' || s === 'INFECTED') return 'danger';
  if (s === 'WARNING' || s === 'SUSPICIOUS' || s === 'MEDIUM') return 'warning';
  if (s === 'INFO') return 'info';
  return 'safe';
}

function renderRecentActivities(logs, force = false) {
  const wrap = document.getElementById('recentActivityList');
  if (!wrap) return;
  const viewEvents = document.getElementById('view-events');
  if (!force && viewEvents && !viewEvents.classList.contains('active')) {
    eventsDirty = true;
    return;
  }
  eventsDirty = false;

  const noteEl = document.getElementById('eventsCountNote');
  const searchEl = document.getElementById('eventSearchInput');

  const query = (searchEl?.value || '').trim().toLowerCase();
  const rawLogs = Array.isArray(logs) ? logs : [];
  const filtered = rawLogs.filter(evt => {
    const sev = String(evt.severity || '').toUpperCase();
    const evType = String(evt.eventType || evt.type || '').toLowerCase();
    const title = String(evt.title || '').toLowerCase();
    if (activeEventFilter === 'critical' && sev !== 'CRITICAL' && sev !== 'INFECTED') return false;
    if (activeEventFilter === 'warning' && sev !== 'WARNING' && sev !== 'SUSPICIOUS' && sev !== 'MEDIUM') return false;
    if (activeEventFilter === 'download' && !evType.includes('indirme') && !title.includes('indirme')) return false;
    if (query) {
      const hay = `${evt.timestamp || ''} ${evType} ${title} ${evt.filePath || ''} ${evt.sha256 || ''} ${evt.engineDecision || ''}`.toLowerCase();
      if (!hay.includes(query)) return false;
    }
    return true;
  });

  if (noteEl) {
    noteEl.textContent = `${filtered.length} / ${rawLogs.length} Kayıt · Canlı Akış`;
  }

  if (!filtered.length) {
    wrap.innerHTML = '<div class="empty-note">Seçilen filtreye uygun güvenlik olayı bulunamadı.</div>';
    return;
  }

  wrap.innerHTML = filtered.slice(0, 50).map(evt => {
    const tier = severityToTier(evt.severity);
    const statusText = evt.statusLabel || (evt.severity === 'CRITICAL' ? 'Engellendi' : evt.severity === 'SAFE' ? 'Temiz' : 'Aktif');
    const eventType = evt.eventType || evt.type || 'Sistem Olayı';
    const filePath = evt.filePath || evt.detail || '-';
    const isOpen = expandedEventIds.has(evt.id);
    const riskScore = Number(evt.riskScore ?? 0);
    const barColor = riskScore >= 80 ? '#C81E1E' : riskScore >= 30 ? '#D97706' : '#009E60';

    const hasFileLocation = filePath && filePath !== '-' &&
      !filePath.startsWith('Sistem Geneli') &&
      !filePath.startsWith('Çekirdek') &&
      !filePath.startsWith('PID:');
    const encodedPathArg = safeUriArg(filePath);

    return `
      <div class="stream-item">
        <div class="stream-row" data-evt-id="${escapeHtml(evt.id)}">
          <span class="stream-time mono">${escapeHtml(evt.timestamp)}</span>
          <span class="stream-type">${escapeHtml(eventType)}</span>
          <span class="stream-path mono" title="${escapeHtml(filePath)}">${escapeHtml(filePath)}</span>
          <div class="stream-status-col">
            <span class="status-pill ${tier}">${escapeHtml(statusText)}</span>
          </div>
        </div>
        <div class="stream-accordion ${isOpen ? 'open' : ''}" id="acc-${escapeHtml(evt.id)}">
          <div class="accordion-glass-inner">
            <div class="acc-3col">
              <div class="acc-box">
                <span class="section-kicker">SHA-256 HASH</span>
                <div class="acc-val-text mono">${escapeHtml(evt.sha256 || '-')}</div>
              </div>
              <div class="acc-box">
                <span class="section-kicker">SÜREÇ SOY AĞACI</span>
                <div class="acc-val-text mono">${escapeHtml(evt.lineage || `services.exe -> AegisCore.exe (PID ${evt.pid || '-'})`)}</div>
              </div>
              <div class="acc-box">
                <span class="section-kicker">RİSK BAROMETRESİ</span>
                <div class="acc-val-text mono">${riskScore} / 100 (${escapeHtml(evt.threatLevel || 'Güvenli')})</div>
                <div class="barometer-track">
                  <div class="barometer-fill" style="width:${Math.max(4, riskScore)}%;background:${barColor};"></div>
                </div>
              </div>
            </div>
            <div class="acc-footer-row">
              <span class="acc-decision-note">${escapeHtml(evt.engineDecision || evt.detail || '')}</span>
              <div style="display:flex;gap:8px;">
                ${hasFileLocation ? `<button class="btn-ghost" data-aegis-action="open-location" data-path="${encodedPathArg}">Konumu Aç</button>` : ''}
                ${evt.quarantineId ? `<button class="btn-ghost" data-aegis-action="restore-event" data-id="${safeUriArg(evt.quarantineId)}">Geri Yükle</button>` : ''}
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

document.getElementById('recentActivityList')?.addEventListener('click', (e) => {
  if (e.target.closest('[data-aegis-action]')) return;
  const row = e.target.closest('.stream-row');
  if (!row) return;
  const id = row.getAttribute('data-evt-id');
  const acc = document.getElementById(`acc-${id}`);
  if (!acc) return;
  if (expandedEventIds.has(id)) {
    expandedEventIds.delete(id);
    acc.classList.remove('open');
  } else {
    expandedEventIds.add(id);
    acc.classList.add('open');
  }
});

window.openFileLocation = async function(encodedPath) {
  await fetch('/api/open-location', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ filePath: decodeUriArg(encodedPath) })
  });
};

window.restoreFromEvent = async function(encodedId) {
  await fetch('/api/quarantine/restore', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: decodeUriArg(encodedId) })
  });
  fetchStatus();
};

function updateHeroShieldState(realtimeOn, netOn, webOn) {
  const card = document.getElementById('heroStatusCard');
  const titleEl = document.getElementById('heroTitle');
  const emblem = document.getElementById('heroShieldEmblem');
  const screenRect = document.getElementById('monitorScreenRect');
  const checkPath = document.getElementById('monitorCheckPath');
  const shieldsPill = document.getElementById('shieldsStatusPill');

  const allActive = realtimeOn && netOn && webOn;
  const anyActive = realtimeOn || netOn || webOn;

  let mode = 'safe';
  let headline = 'Bilgisayarınız Güvende';
  let screenFill = '#009E60';
  let pathData = 'M27 26l6 6 12-12';

  if (!anyActive) {
    mode = 'danger';
    headline = 'Koruma Kalkanları Devre Dışı';
    screenFill = '#C81E1E';
    pathData = 'M29 19l14 14M43 19L29 33';
  } else if (!allActive) {
    mode = 'warning';
    headline = 'Kısmi Koruma Aktif';
    screenFill = '#D97706';
    pathData = 'M36 17v11M36 33v.01';
  }

  if (card) {
    card.classList.remove('safe', 'warning', 'danger');
    card.classList.add(mode);
  }
  if (emblem) {
    emblem.classList.remove('safe', 'warning', 'danger');
    emblem.classList.add(mode);
  }
  if (screenRect) screenRect.setAttribute('fill', screenFill);
  if (checkPath) checkPath.setAttribute('d', pathData);
  if (titleEl) titleEl.textContent = headline;
  if (shieldsPill) {
    shieldsPill.textContent = allActive ? 'Tüm Kalkanlar Aktif' : anyActive ? 'Kısmi Koruma' : 'Kalkanlar Kapalı';
  }

  const fsSub = document.getElementById('fsShieldSub');
  if (fsSub) fsSub.textContent = realtimeOn ? 'Yeni ve değişen dosyaları SuperLX 1.0 ile anında tarar' : 'Dosya kalkanı duraklatıldı';
}

function renderRealtimeDownloads(downloads = [], zones = [], activeCount = 0, force = false) {
  latestDownloads = Array.isArray(downloads) ? downloads : [];
  latestWatchedZones = Array.isArray(zones) ? zones : [];
  latestActiveDownloadsCount = activeCount || 0;

  const viewRealtime = document.getElementById('view-realtime');
  if (!force && viewRealtime && !viewRealtime.classList.contains('active')) {
    downloadsDirty = true;
    return;
  }
  downloadsDirty = false;

  const pill = document.getElementById('rtActiveDlPill');
  const meta = document.getElementById('rtDownloadStatusMeta');
  if (pill) {
    if (activeCount > 0) {
      pill.textContent = `${activeCount} Aktif İndirme`;
      pill.className = 'pill-tag pill-amber mono';
    } else if (latestDownloads.length > 0) {
      pill.textContent = `${latestDownloads.length} Kayıt`;
      pill.className = 'pill-tag pill-blue mono';
    } else {
      pill.textContent = 'Hazır';
      pill.className = 'pill-tag pill-blue mono';
    }
  }
  if (meta) {
    meta.textContent = latestWatchedZones.length
      ? `${latestWatchedZones.length} korunan bölge anlık izleniyor · Tarayıcı & dosya kalkanı aktif`
      : 'Gerçek zamanlı klasör izleyici bekliyor';
  }

  const zonesBar = document.getElementById('rtZonesBar');
  if (zonesBar) {
    zonesBar.innerHTML = latestWatchedZones.length
      ? latestWatchedZones.map(z => `<span class="rt-zone-chip active" title="${escapeHtml(z.path)}">${escapeHtml(z.label)}</span>`).join('')
      : '<span class="rt-zone-chip">İzleme Kapalı</span>';
  }

  const feed = document.getElementById('rtLiveDownloadFeed');
  if (!feed) return;
  if (!latestDownloads.length) {
    feed.innerHTML = '<div class="empty-msg">Henüz yeni indirme algılanmadı. İndirilenler, Masaüstü veya korunan dizinlere düşen dosyalar burada anlık listelenir.</div>';
    return;
  }

  feed.innerHTML = latestDownloads.map(d => {
    const tier = severityToTier(d.status);
    const label = d.status === 'INFECTED' ? 'Tehdit' : d.status === 'SUSPICIOUS' ? 'Şüpheli' : 'Temiz';
    const originText = d.motwHost
      ? `Kaynak: ${d.motwHost}`
      : (d.fromInternet ? 'İnternet / İndirme Bölgesi' : d.zone || '');
    const sigText = d.isSigned && d.signer ? ` · İmza: ${d.signer}` : '';
    return `
      <div class="rt-feed-row ${tier}">
        <div class="rt-feed-main">
          <div class="rt-feed-title">${escapeHtml(d.fileName)} <span class="muted-sm">(${escapeHtml(d.zone || 'Korumalı Alan')})</span></div>
          <div class="rt-feed-meta mono">${escapeHtml(d.timestamp)} · Risk ${d.riskScore}/100 · ${escapeHtml(d.actionTaken || label)} · ${escapeHtml(originText)}${escapeHtml(sigText)}</div>
        </div>
        <div class="rt-feed-right">
          <span class="status-pill ${tier}">${label}</span>
        </div>
      </div>
    `;
  }).join('');
}

function showDownloadActivityStrip(payload) {
  const strip = document.getElementById('liveDownloadFeedStrip');
  const content = document.getElementById('liveDownloadFeedContent');
  if (!strip || !content || !payload) return;

  if (payload.kind === 'downloading') {
    strip.classList.remove('hidden');
    content.innerHTML = `
      <span class="status-pill warning">İndirme İzleniyor</span>
      <strong>${escapeHtml(payload.fileName || '')}</strong>
      <span class="mono cell-sub">${escapeHtml(payload.zone || 'İndirilenler')} · Tarayıcı aktarımı bitince SuperLX 1.0 otomatik inceleyecek...</span>
    `;
  } else if (payload.kind === 'inspected' && payload.entry) {
    const e = payload.entry;
    const tier = severityToTier(e.status);
    const label = e.status === 'INFECTED' ? 'Engellendi' : e.status === 'SUSPICIOUS' ? 'Şüpheli' : 'Temiz İndirme';
    strip.classList.remove('hidden');
    content.innerHTML = `
      <span class="status-pill ${tier}">${label}</span>
      <strong>${escapeHtml(e.fileName)}</strong>
      <span class="mono cell-sub">${escapeHtml(e.zone || '')} · ${escapeHtml(e.actionTaken || label)} · Risk ${e.riskScore}/100${e.motwHost ? ` · Kaynak: ${escapeHtml(e.motwHost)}` : ''}</span>
    `;
  }
}

async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    latestStatus = data;

    const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    const setCheck = (id, val) => { const el = document.getElementById(id); if (el) el.checked = Boolean(val); };

    const engineLabel = data.engineName || 'SuperLX 1.0';
    setText('dockEngineBadge', engineLabel);
    setText('dbStatusText', `Veritabanı v${data.signatureVersion}`);
    setText('heroEnginePill', data.engineDisplayVersion || `${engineLabel} Motoru`);
    setText('heroLastScanPill', `Son Tarama: ${data.lastScanAt || 'Bekleniyor'}`);
    setText('footerStatusLabel', `Motor: ${engineLabel} · Güncel`);
    setText('engineActivePill', engineLabel);
    setText('canaryShieldSub', `${data.canaryCount || 0} Canary yem dosyası aktif`);

    const netSub = document.getElementById('netShieldSub');
    if (netSub) netSub.textContent = data.networkProtectionEnabled ? 'Soket, RAT portu ve süreç zinciri aktif' : 'Ağ kalkanı devre dışı';

    const dropLimit = document.getElementById('dropLimitBadge');
    if (dropLimit) dropLimit.textContent = `${data.uploadLimitMb || 500} MB`;

    updateHeroShieldState(data.realtimeEnabled, data.networkProtectionEnabled, data.webProtectionEnabled);

    setCheck('gameModeToggle', data.gameMode);
    setCheck('dashToggleFs', data.realtimeEnabled);
    setCheck('dashToggleNet', data.networkProtectionEnabled);
    setCheck('dashToggleWeb', data.webProtectionEnabled);
    setCheck('rtToggleDownloads', data.watchDownloads);
    setCheck('rtToggleAutoQ', data.autoQuarantine);

    setText('statFilesScanned', Number(data.stats.totalFilesScanned || 0).toLocaleString('tr-TR'));
    setText('statThreatsBlocked', Number(data.stats.totalThreatsBlocked || 0).toLocaleString('tr-TR'));
    setText('statQuarantineCount', Number(data.quarantineCount || 0).toLocaleString('tr-TR'));

    const qBadge = document.getElementById('quarantineBadge');
    if (qBadge) {
      qBadge.textContent = data.quarantineCount;
      qBadge.classList.toggle('has-items', data.quarantineCount > 0);
    }

    applyTelemetrySample({
      cpuPercent: data.system.agentCpuPercent,
      agentMemoryMb: data.system.agentMemoryMb,
      netKbps: data.system.netKbps
    });

    const watchedInput = document.getElementById('watchedPathInput');
    if (watchedInput && !watchedInput.value) watchedInput.value = data.watchedPath;
    const scanInput = document.getElementById('scanTargetInput');
    if (scanInput && !scanInput.value) scanInput.value = data.watchedPath;

    setText('settingsEngineName', engineLabel);
    setText('settingsAvgInspectMs', `${data.perf?.avgInspectMs ?? 1.2} ms (Kalıcı Çekirdek · ${data.perf?.cacheHits ?? 0} önbellek)`);
    setText('settingsEngineVer', data.engineVersion || 'v6.0.0');
    setText('settingsZeroTrust', 'SuperLX 1.0 Tam Koruma (127.0.0.1 + Öz-Koruma Aktif)');
    setText('settingsSigVer', `v${data.signatureVersion}`);
    setText('settingsSigCount', `${data.signatureCount} Kural`);
    setText('settingsHostname', data.system.hostname);
    setText('settingsPlatform', data.system.osEdition || data.system.platform);
    setText('settingsCpuCores', `${data.system.cpuCores} Çekirdek`);
    setText('settingsWatchPath', data.watchedPath);

    const perfEl = document.getElementById('rtPerfBadge');
    if (perfEl) {
      perfEl.textContent = `${data.system.agentMemoryMb} MB RAM · ~${data.perf?.avgInspectMs ?? 1.2} ms Analiz · CPU %${data.system.agentCpuPercent}`;
    }

    const activeLayers = 2
      + (data.realtimeEnabled ? 2 : 0)
      + (data.watchDownloads ? 1 : 0)
      + (data.networkProtectionEnabled ? 1 : 0)
      + (data.webProtectionEnabled ? 1 : 0)
      + (data.autoQuarantine ? 1 : 0);
    setText('heroProtectionLayers', `${activeLayers}/8 Koruma Katmanı Aktif: Dosya · Bellek · İndirme · Ağ/C2 · Fidye Kapanı · Öz-Koruma`);
    setText('heroAvgSpeedPill', `Analiz: ~${data.perf?.avgInspectMs ?? 1.2} ms · RAM ${data.system.agentMemoryMb} MB`);

    if (Array.isArray(data.eventLogs)) {
      recentEvents = data.eventLogs;
      renderRecentActivities(recentEvents);
    }
    renderRealtimeDownloads(data.recentDownloads || [], data.watchedZones || [], data.activeDownloadsCount || 0);
  } catch (_) {}
}

function applyTelemetrySample(sample) {
  const cpuPct = Number(sample.cpuPercent ?? 0.4);
  const netKbps = Number(sample.netKbps ?? 0.0);
  const cpuEl = document.getElementById('cpuPercentText');
  const netEl = document.getElementById('netKbpsText');
  const ramEl = document.getElementById('ramSummaryBadge');
  if (cpuEl) cpuEl.textContent = `${cpuPct}%`;
  if (netEl) netEl.textContent = `${netKbps.toFixed(1)} KB/s`;
  if (sample.agentMemoryMb && latestStatus?.system?.totalMemoryGb && ramEl) {
    ramEl.textContent = `RAM ${sample.agentMemoryMb} MB / ${latestStatus.system.totalMemoryGb} GB`;
  }
}

function connectSSE() {
  const es = new EventSource('/api/stream');

  es.addEventListener('init', e => {
    const payload = JSON.parse(e.data);
    recentEvents = payload.eventLogs || [];
    renderRecentActivities(recentEvents);
    renderRealtimeDownloads(payload.recentDownloads || [], payload.watchedZones || [], payload.activeDownloadsCount || 0);
  });

  es.addEventListener('download_activity', e => {
    const payload = JSON.parse(e.data);
    if (payload.recentDownloads) {
      renderRealtimeDownloads(payload.recentDownloads, latestWatchedZones, payload.activeDownloadsCount || 0);
    } else {
      renderRealtimeDownloads(latestDownloads, latestWatchedZones, payload.activeDownloadsCount || 0);
    }
    if (!latestStatus?.gameMode) {
      showDownloadActivityStrip(payload);
    }
    scheduleStatusSync();
  });

  es.addEventListener('telemetry', e => {
    applyTelemetrySample(JSON.parse(e.data));
  });

  es.addEventListener('scan_progress', e => {
    const prog = JSON.parse(e.data);
    const drawer = document.getElementById('inlineScanDrawer');
    drawer.classList.remove('hidden');

    document.getElementById('inlineScanStats').textContent =
      `${Number(prog.scanned).toLocaleString('tr-TR')} / ${Number(prog.total).toLocaleString('tr-TR')} (%${prog.percent})`;
    document.getElementById('inlineScanProgressBar').style.width = `${prog.percent}%`;
    document.getElementById('inlineScanFile').textContent = prog.currentFile || '';

    if (prog.done && prog.summary) {
      document.getElementById('inlineScanLabel').textContent =
        `Tarama tamamlandı (${prog.summary.duration_ms} ms) — ${prog.summary.threats_found} tehdit, ${prog.summary.suspicious_found} şüpheli`;
      setTimeout(() => drawer.classList.add('hidden'), 4500);
      scheduleStatusSync(200);
    } else {
      document.getElementById('inlineScanLabel').textContent = prog.scanMode === 'fullscan'
        ? 'Tam sistem taraması yürütülüyor...'
        : 'Kritik sistem dizinleri taranıyor...';
    }
  });

  es.addEventListener('event', e => {
    const evt = JSON.parse(e.data);
    recentEvents.unshift(evt);
    if (recentEvents.length > 50) recentEvents.pop();
    renderRecentActivities(recentEvents);

    if (evt.severity === 'CRITICAL' && !latestStatus?.gameMode) {
      document.getElementById('notifDot')?.classList.remove('hidden');
    }
    scheduleStatusSync();
  });

  es.addEventListener('quarantine_updated', () => {
    scheduleStatusSync(300);
    if (document.getElementById('view-firewall')?.classList.contains('active')) {
      loadQuarantine();
    }
  });
}

// Bildirimler Popover
const popover = document.getElementById('topbarPopover');
const popoverTitle = document.getElementById('popoverTitle');
const popoverBody = document.getElementById('popoverBody');

document.getElementById('notificationsBtn')?.addEventListener('click', (e) => {
  e.stopPropagation();
  if (!popover) return;
  const isHidden = popover.classList.contains('hidden');
  if (!isHidden) {
    popover.classList.add('hidden');
    return;
  }
  document.getElementById('notifDot')?.classList.add('hidden');
  popover.classList.remove('hidden');
  if (popoverTitle) popoverTitle.textContent = 'Güvenlik Bildirimleri';
  const items = recentEvents.slice(0, 6);
  if (popoverBody) {
    popoverBody.innerHTML = items.length
      ? items.map(i => `
          <div class="popover-item">
            <div class="popover-item-title">${escapeHtml(i.title)}</div>
            <div class="popover-item-meta mono">${escapeHtml(i.timestamp)} · ${escapeHtml(i.statusLabel || '')}</div>
          </div>
        `).join('')
      : '<div class="empty-note">Yeni bildirim yok.</div>';
  }
});

document.addEventListener('click', (e) => {
  if (popover && !popover.contains(e.target) && !e.target.closest('#notificationsBtn')) {
    popover.classList.add('hidden');
  }
});

// Kalkan Ayarları
async function syncShieldConfig(payload) {
  await fetch('/api/shield', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  await fetchStatus();
}

document.getElementById('gameModeToggle')?.addEventListener('change', (e) => syncShieldConfig({ gameMode: e.target.checked }));
document.getElementById('dashToggleFs')?.addEventListener('change', (e) => syncShieldConfig({ realtimeEnabled: e.target.checked }));
document.getElementById('dashToggleNet')?.addEventListener('change', (e) => syncShieldConfig({ networkProtectionEnabled: e.target.checked }));
document.getElementById('dashToggleWeb')?.addEventListener('change', (e) => syncShieldConfig({ webProtectionEnabled: e.target.checked }));
document.getElementById('rtToggleDownloads')?.addEventListener('change', (e) => syncShieldConfig({ watchDownloads: e.target.checked }));
document.getElementById('rtToggleAutoQ')?.addEventListener('change', (e) => syncShieldConfig({ autoQuarantine: e.target.checked }));

document.getElementById('updateWatchPathBtn')?.addEventListener('click', () => {
  const watchedPath = document.getElementById('watchedPathInput').value.trim();
  if (watchedPath) syncShieldConfig({ watchedPath });
});

async function runWebUrlCheck() {
  const inp = document.getElementById('webUrlCheckInput');
  const out = document.getElementById('webUrlCheckResult');
  const url = (inp?.value || '').trim();
  if (!url || !out) return;
  out.innerHTML = '<div class="empty-note">Web bağlantısı inceleniyor...</div>';
  try {
    const res = await fetch('/api/web-shield/check-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    if (data.error) {
      out.innerHTML = `<span class="status-pill danger">${escapeHtml(data.error)}</span>`;
      return;
    }
    const tier = severityToTier(data.status);
    const label = data.status === 'INFECTED' ? 'Tehlikeli Site' : data.status === 'SUSPICIOUS' ? 'Şüpheli' : 'Güvenli';
    const reasonsHtml = (data.reasons || []).length
      ? `<ul class="findings-list" style="margin-top:6px;">${data.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul>`
      : '<div class="cell-sub" style="margin-top:4px;">Bilinen oltalama, ClickFix veya zararlı indirme kalıbı tespit edilmedi.</div>';
    out.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
        <span class="status-pill ${tier}">${label} (${Number(data.riskScore || 0)}/100)</span>
        <strong class="mono">${escapeHtml(data.threatName || data.host || url)}</strong>
      </div>
      ${reasonsHtml}
    `;
    fetchStatus();
  } catch (_) {
    out.innerHTML = '<span class="status-pill danger">URL doğrulama isteği başarısız oldu.</span>';
  }
}

document.getElementById('webUrlCheckBtn')?.addEventListener('click', runWebUrlCheck);
document.getElementById('webUrlCheckInput')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') runWebUrlCheck();
});

// Hızlı ve Tam Sistem Taraması
async function triggerHeroSystemScan(mode) {
  const qBtn = document.getElementById('quickScanBtn');
  const fBtn = document.getElementById('fullScanBtn');
  const drawer = document.getElementById('inlineScanDrawer');
  if (qBtn) qBtn.disabled = true;
  if (fBtn) fBtn.disabled = true;
  drawer.classList.remove('hidden');
  document.getElementById('inlineScanLabel').textContent = mode === 'full'
    ? 'Tam Sistem Taraması: Tüm sabit diskler ve kullanıcı dizinleri taranıyor...'
    : 'Hızlı Tarama: Kritik sistem dizinleri taranıyor...';
  document.getElementById('inlineScanProgressBar').style.width = '4%';

  try {
    await fetch(mode === 'full' ? '/api/fullscan' : '/api/quickscan', { method: 'POST' });
  } finally {
    if (qBtn) qBtn.disabled = false;
    if (fBtn) fBtn.disabled = false;
  }
}

document.getElementById('quickScanBtn')?.addEventListener('click', () => triggerHeroSystemScan('quick'));
document.getElementById('fullScanBtn')?.addEventListener('click', () => triggerHeroSystemScan('full'));

// Dosya Yükle & Tara (500 MB)
const dropZone = document.getElementById('dropZone');
const dropFileInput = document.getElementById('dropFileInput');
const dropResultBar = document.getElementById('dropResultBar');
const dropResultContent = document.getElementById('dropResultContent');

async function handleDroppedFile(file) {
  if (!file) return;
  const limitMb = latestStatus?.uploadLimitMb || 500;
  const limitBytes = limitMb * 1024 * 1024;

  if (file.size > limitBytes) {
    dropResultBar.classList.remove('hidden');
    dropResultContent.innerHTML = `<span class="status-pill warning">Dosya (${(file.size / (1024 * 1024)).toFixed(1)} MB) maksimum ${limitMb} MB sınırını aşıyor.</span>`;
    return;
  }

  document.getElementById('dropZoneText').textContent = `İnceleniyor: ${file.name}`;
  try {
    const res = await fetch('/api/scan-upload', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-File-Name': encodeURIComponent(file.name)
      },
      body: file
    });
    const v = await res.json();
    dropResultBar.classList.remove('hidden');

    if (v.error) {
      dropResultContent.innerHTML = `<span class="status-pill danger">${escapeHtml(v.error)}</span>`;
    } else {
      const tier = severityToTier(v.status);
      const label = v.status === 'INFECTED' ? 'Tehdit' : v.status === 'SUSPICIOUS' ? 'Şüpheli' : 'Temiz';
      dropResultContent.innerHTML = `
        <span class="status-pill ${tier}">${label}</span>
        <strong>${escapeHtml(v.file_name)}</strong>
        <span class="mono cell-sub">${escapeHtml(v.engine || 'SuperLX 1.0')} · ${escapeHtml(v.detection_stage || '')} · Risk: ${v.risk_score}/100</span>
        <span class="mono cell-sub">SHA-256: ${escapeHtml((v.sha256 || '').slice(0, 16))}...</span>
      `;
    }
    fetchStatus();
  } finally {
    document.getElementById('dropZoneText').textContent = 'Hızlı Dosya İncele';
  }
}

dropZone?.addEventListener('click', () => dropFileInput?.click());
dropFileInput?.addEventListener('change', (e) => {
  if (e.target.files?.[0]) handleDroppedFile(e.target.files[0]);
  dropFileInput.value = '';
});
dropZone?.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('drag-over');
});
dropZone?.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone?.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  if (e.dataTransfer.files?.[0]) handleDroppedFile(e.dataTransfer.files[0]);
});
document.getElementById('closeDropResultBtn')?.addEventListener('click', () => dropResultBar?.classList.add('hidden'));
document.getElementById('closeLiveDownloadBtn')?.addEventListener('click', () => document.getElementById('liveDownloadFeedStrip')?.classList.add('hidden'));
document.getElementById('openRealtimeFromStripBtn')?.addEventListener('click', () => switchTab('realtime', 'Gerçek Zamanlı Koruma'));

// Doğrulama Tetikleyicileri
document.querySelectorAll('[data-sim]').forEach(btn => {
  btn.addEventListener('click', async () => {
    const type = btn.getAttribute('data-sim');
    await fetch('/api/simulate-threat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, inProtectedZone: true })
    });
    setTimeout(fetchStatus, 500);
  });
});

// Tarama Merkezi
async function executeScan(targetPath, scanMode = 'custom') {
  const startBtn = document.getElementById('startScanBtn');
  const winQuickBtn = document.getElementById('runWindowsQuickScanBtn');
  const fullBtn = document.getElementById('runFullSystemScanBtn');
  const container = document.getElementById('scanResultsContainer');
  const summaryBar = document.getElementById('scanSummaryBar');

  if (startBtn) startBtn.disabled = true;
  if (winQuickBtn) winQuickBtn.disabled = true;
  if (fullBtn) fullBtn.disabled = true;
  container.innerHTML = `<div class="empty-note">${scanMode === 'full' ? 'Tam Sistem Taraması yürütülüyor...' : 'Tarama yürütülüyor...'}</div>`;

  try {
    const endpoint = scanMode === 'full' ? '/api/fullscan' : scanMode === 'quick' ? '/api/quickscan' : '/api/scan';
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(scanMode === 'custom' ? { targetPath } : {})
    });
    const data = await res.json();
    if (data.error) {
      container.innerHTML = `<div class="empty-note text-danger">${escapeHtml(data.error)}</div>`;
      return;
    }

    summaryBar.classList.remove('hidden');
    document.getElementById('scanTotalFiles').textContent = data.total_files_scanned.toLocaleString('tr-TR');
    document.getElementById('scanDuration').textContent = `${data.duration_ms} ms`;
    document.getElementById('scanSpeed').textContent = `${data.files_per_second}/sn`;
    document.getElementById('scanThreatsCount').textContent = `${data.threats_found} Kritik / ${data.suspicious_found} Şüpheli`;

    latestScanDetections = (data.scanned_files || []).filter(i => i.status !== 'CLEAN' && i.path);
    const qAllBtn = document.getElementById('quarantineAllBtn');
    if (qAllBtn) {
      qAllBtn.classList.toggle('hidden', latestScanDetections.length === 0);
      qAllBtn.textContent = `Tüm Tehditleri Karantinaya Al (${latestScanDetections.length})`;
    }

    const rows = (data.scanned_files || []).map(item => {
      const tier = severityToTier(item.status);
      const statusLabel = item.status === 'INFECTED' ? 'Tehdit' : item.status === 'SUSPICIOUS' ? 'Şüpheli' : 'Temiz';
      const reasonsHtml = (item.reasons || []).map(r => `<div>${escapeHtml(r)}</div>`).join('')
        || (item.is_signed ? `Dijital İmzalı (${escapeHtml(item.signer)})` : 'Temiz');
      const encodedPath = safeUriArg(item.path);

      const actionBtn = item.status !== 'CLEAN'
        ? `<button class="btn-danger-ghost" data-aegis-action="isolate-path" data-path="${encodedPath}" data-threat="${safeUriArg(item.threat_name)}" data-score="${Number(item.risk_score || 0)}">Karantina</button>`
        : `<button class="btn-ghost" data-aegis-action="inspect-deep" data-path="${encodedPath}">İncele</button>`;

      return `
        <tr>
          <td><span class="status-pill ${tier}">${statusLabel}</span></td>
          <td>
            <div class="cell-main">${escapeHtml(item.file_name)}</div>
            <div class="mono cell-sub">${escapeHtml(item.path)}</div>
          </td>
          <td class="mono">${Number(item.risk_score || 0)}/100</td>
          <td class="mono">${Number(item.entropy || 0).toFixed(2)}</td>
          <td style="font-size:12px;">${reasonsHtml}</td>
          <td>${actionBtn}</td>
        </tr>
      `;
    }).join('');

    container.innerHTML = `
      <table class="spatial-table">
        <thead><tr><th>Durum</th><th>Dosya</th><th>Risk</th><th>Entropi</th><th>Analiz (${escapeHtml(data.engine || 'SuperLX 1.0')})</th><th>İşlem</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6" class="empty-note">Dosya bulunamadı.</td></tr>'}</tbody>
      </table>
    `;
    fetchStatus();
  } finally {
    if (startBtn) startBtn.disabled = false;
    if (winQuickBtn) winQuickBtn.disabled = false;
    if (fullBtn) fullBtn.disabled = false;
  }
}

document.getElementById('startScanBtn')?.addEventListener('click', () => {
  executeScan(document.getElementById('scanTargetInput').value.trim(), 'custom');
});

document.getElementById('runWindowsQuickScanBtn')?.addEventListener('click', () => {
  switchSubtab('dir-scan');
  executeScan('', 'quick');
});

document.getElementById('runFullSystemScanBtn')?.addEventListener('click', () => {
  switchSubtab('dir-scan');
  executeScan('', 'full');
});

window.isolatePath = async function(encodedPath, encodedThreatName, riskScore) {
  await fetch('/api/quarantine/isolate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      filePath: decodeUriArg(encodedPath),
      threatName: decodeUriArg(encodedThreatName),
      riskScore
    })
  });
  executeScan(document.getElementById('scanTargetInput').value.trim(), 'custom');
  fetchStatus();
};

window.inspectDeep = function(encodedPath) {
  const filePath = decodeUriArg(encodedPath);
  switchTab('scanner');
  switchSubtab('pe-inspect');
  document.getElementById('deepFileInput').value = filePath;
  runDeepAnalysis(filePath);
};

async function runDeepAnalysis(filePath) {
  const box = document.getElementById('deepAnalysisResult');
  box.innerHTML = '<div class="empty-note">Dosya inceleniyor...</div>';

  const res = await fetch('/api/analyze-file', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ filePath })
  });
  const data = await res.json();
  if (data.error) {
    box.innerHTML = `<div class="empty-note text-danger">${escapeHtml(data.error)}</div>`;
    return;
  }

  const tier = severityToTier(data.status);
  const statusLabel = data.status === 'INFECTED' ? 'Kritik Tehdit' : data.status === 'SUSPICIOUS' ? 'Şüpheli' : 'Temiz';
  const sigText = data.is_signed ? `Doğrulandı (${escapeHtml(data.signer || 'Trusted')})` : 'İmzasız / Güvenilmeyen';
  const sizeKb = (Number(data.size_bytes || 0) / 1024).toFixed(1);
  const pe = data.pe_analysis || {};
  const motwInfo = data.motw?.fromInternet
    ? `İnternetten İndirildi (ZoneId=${data.motw.zoneId || 3}${data.motw.hostUrl ? ` · ${escapeHtml(data.motw.hostUrl)}` : ''})`
    : 'Yerel / MotW İşareti Yok';

  const sections = Array.isArray(pe.sections) ? pe.sections : [];
  const secTableHtml = sections.length
    ? `
      <div class="acc-box" style="margin-top:8px;">
        <span class="section-kicker">PE BÖLÜM ANALİZİ (${escapeHtml(pe.architecture || 'PE')})</span>
        <table class="spatial-table pe-sec-table">
          <thead><tr><th>Bölüm</th><th>Boyut</th><th>Entropi</th><th>RWX</th></tr></thead>
          <tbody>${sections.map(s => `
            <tr>
              <td class="mono">${escapeHtml(s.name || '-')}</td>
              <td class="mono">${Number(s.size ?? s.raw_size ?? 0).toLocaleString('tr-TR')} B</td>
              <td class="mono">${Number(s.entropy || 0).toFixed(2)}</td>
              <td>${s.rwx ? '<span class="status-pill danger">RWX</span>' : '<span class="status-pill safe">Normal</span>'}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>`
    : '';

  const apis = Array.isArray(pe.imported_apis) ? pe.imported_apis.slice(0, 18) : [];
  const apiHtml = apis.length
    ? `
      <div class="acc-box" style="margin-top:8px;">
        <span class="section-kicker">İÇE AKTARILAN API'LER (${apis.length})</span>
        <div class="api-chip-wrap">${apis.map(a => `<span class="api-chip mono">${escapeHtml(a)}</span>`).join('')}</div>
      </div>`
    : '';

  const findings = (data.findings || data.heuristic_findings || []).map(f => `<li style="margin-bottom:4px;">${escapeHtml(f)}</li>`).join('')
    || '<li>Zararlı kalıp bulunmadı.</li>';
  const encodedPathArg = safeUriArg(data.path || filePath);
  const encodedThreatArg = safeUriArg(data.threat_name || 'Manual.Quarantine');

  box.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;padding:6px 0;">
      <div class="acc-box"><span class="section-kicker">DOSYA &amp; BOYUT</span><div class="acc-val-text mono">${escapeHtml(data.file_name)} (${sizeKb} KB)</div></div>
      <div class="acc-box"><span class="section-kicker">KARAR</span><div class="acc-val-text"><span class="status-pill ${tier}">${statusLabel} (${data.risk_score}/100)</span></div></div>
      <div class="acc-box"><span class="section-kicker">SHA-256</span><div class="acc-val-text mono">${escapeHtml(data.sha256)}</div></div>
      <div class="acc-box"><span class="section-kicker">İMZA, ENTROPİ &amp; KAYNAK</span><div class="acc-val-text mono">${sigText} · ${data.entropy}/8.0 · ${motwInfo}</div></div>
    </div>
    <div class="acc-box"><span class="section-kicker">MOTOR BULGULARI (${escapeHtml(data.engine || 'SuperLX 1.0')})</span><ul class="findings-list">${findings}</ul></div>
    ${secTableHtml}
    ${apiHtml}
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:10px;">
      <button class="btn-light-sm" data-aegis-action="open-location" data-path="${encodedPathArg}">Konumu Aç</button>
      <button class="btn-danger-sm" data-aegis-action="isolate-path" data-path="${encodedPathArg}" data-threat="${encodedThreatArg}" data-score="${Number(data.risk_score || 0)}">Karantinaya Al</button>
    </div>
  `;
}

document.getElementById('analyzeFileBtn')?.addEventListener('click', () => {
  const fp = document.getElementById('deepFileInput').value.trim();
  if (fp) runDeepAnalysis(fp);
});

// Güvenlik Duvarı, Başlangıç RAT Denetimi & Karantina
function renderProcNetTables() {
  const procWrap = document.getElementById('processTableWrap');
  const netWrap = document.getElementById('networkTableWrap');
  if (!procWrap || !netWrap || !latestProcNetData) return;

  const data = latestProcNetData;
  const query = (document.getElementById('procSearchInput')?.value || '').trim().toLowerCase();
  const suspOnly = Boolean(document.getElementById('procSuspOnlyCheck')?.checked);

  document.getElementById('procCount').textContent = data.total_processes;
  document.getElementById('netCount').textContent = data.active_connections;

  const filteredProcs = (data.processes || []).filter(p => {
    if (suspOnly && p.status === 'CLEAN' && (p.risk_score || 0) < 35) return false;
    if (query) {
      const hay = `${p.pid} ${p.name || ''} ${p.path || ''}`.toLowerCase();
      if (!hay.includes(query)) return false;
    }
    return true;
  });

  const pRows = filteredProcs.map(p => {
    const tier = severityToTier(p.status);
    const label = p.status === 'INFECTED' ? 'Kritik' : p.status === 'SUSPICIOUS' ? 'Şüpheli' : 'Temiz';
    const encodedPath = safeUriArg(p.path || '');
    const sigBadge = p.is_signed
      ? '<span class="sig-badge signed">İmzalı</span>'
      : '<span class="sig-badge unsigned">İmzasız</span>';
    const quarantineBtn = (!p.is_signed && p.path && !p.path.includes('Sistem'))
      ? `<button class="btn-danger-ghost" data-aegis-action="kill-quarantine-proc" data-pid="${Number(p.pid)}" data-path="${encodedPath}">Durdur+Karantina</button>`
      : '';
    return `
      <tr>
        <td class="mono">${Number(p.pid)}</td>
        <td>
          <div class="cell-main">${escapeHtml(p.name)} ${sigBadge}</div>
          <div class="mono cell-sub" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(p.path)}</div>
        </td>
        <td class="mono">${Number(p.memory_mb || 0)} MB</td>
        <td><span class="status-pill ${tier}">${label}</span></td>
        <td><div style="display:flex;gap:6px;"><button class="btn-danger-ghost" data-aegis-action="kill-proc" data-pid="${Number(p.pid)}">Durdur</button>${quarantineBtn}</div></td>
      </tr>
    `;
  }).join('');
  procWrap.innerHTML = `<table class="spatial-table"><thead><tr><th>PID</th><th>Süreç</th><th>RAM</th><th>Durum</th><th>İşlem</th></tr></thead><tbody>${pRows || '<tr><td colspan="5" class="empty-note">Eşleşen süreç bulunamadı.</td></tr>'}</tbody></table>`;

  const filteredConns = (data.connections || []).filter(c => {
    if (suspOnly && !c.is_suspicious) return false;
    if (query) {
      const hay = `${c.pid} ${c.process_name || ''} ${c.local_address}:${c.local_port} ${c.remote_address}:${c.remote_port} ${c.state || ''}`.toLowerCase();
      if (!hay.includes(query)) return false;
    }
    return true;
  });

  const nRows = filteredConns.map(c => `
    <tr>
      <td><div class="cell-main">${escapeHtml(c.process_name || 'System')}</div><div class="mono cell-sub">PID ${c.pid}</div></td>
      <td class="mono">${escapeHtml(c.local_address)}:${c.local_port}</td>
      <td class="mono">${escapeHtml(c.remote_address)}:${c.remote_port}</td>
      <td class="mono">${escapeHtml(c.state)}</td>
      <td>${c.is_suspicious ? `<span class="status-pill danger">${escapeHtml(c.reason)}</span>` : '<span class="status-pill safe">Normal</span>'}</td>
    </tr>
  `).join('');
  netWrap.innerHTML = `<table class="spatial-table"><thead><tr><th>Süreç</th><th>Yerel</th><th>Uzak</th><th>Durum</th><th>Denetim</th></tr></thead><tbody>${nRows || '<tr><td colspan="5" class="empty-note">Eşleşen ağ bağlantısı bulunamadı.</td></tr>'}</tbody></table>`;
}

async function loadProcNet() {
  const procWrap = document.getElementById('processTableWrap');
  const netWrap = document.getElementById('networkTableWrap');
  if (!procWrap || !netWrap) return;

  const res = await fetch('/api/procnet');
  const data = await res.json();
  if (data.error) {
    procWrap.innerHTML = `<div class="empty-note text-danger">${escapeHtml(data.error)}</div>`;
    netWrap.innerHTML = procWrap.innerHTML;
    return;
  }
  latestProcNetData = data;
  renderProcNetTables();
}

document.getElementById('procSearchInput')?.addEventListener('input', renderProcNetTables);
document.getElementById('procSuspOnlyCheck')?.addEventListener('change', renderProcNetTables);

window.killProc = async function(pid) {
  await fetch('/api/kill-process', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pid })
  });
  loadProcNet();
};

window.killAndQuarantineProc = async function(pid, encodedPath) {
  await fetch('/api/pro/kill-and-quarantine', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pid, filePath: decodeUriArg(encodedPath) })
  });
  loadProcNet();
  loadQuarantine();
  fetchStatus();
};

async function loadStartupGuard() {
  const wrap = document.getElementById('startupGuardWrap');
  const badge = document.getElementById('startupSummaryBadge');
  if (!wrap) return;
  const res = await fetch('/api/plus/startup-guard');
  const data = await res.json();
  if (data.error) {
    wrap.innerHTML = `<div class="empty-note text-danger">${escapeHtml(data.error)}</div>`;
    return;
  }
  const entries = data.entries || [];
  const suspCount = entries.filter(x => x.riskLevel === 'SUSPICIOUS').length;
  if (badge) {
    badge.textContent = suspCount > 0 ? `${suspCount} şüpheli açılış öğesi` : `${entries.length} güvenli açılış öğesi`;
  }
  if (!entries.length) {
    wrap.innerHTML = '<div class="empty-note">Başlangıç kaydı bulunamadı.</div>';
    return;
  }
  const rows = entries.map(e => `
    <tr>
      <td class="mono">${escapeHtml(e.source)}</td>
      <td class="cell-main">${escapeHtml(e.name)}</td>
      <td>
        <div class="mono cell-sub" style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(e.command)}</div>
        ${e.reason ? `<div class="cell-sub">${escapeHtml(e.reason)}</div>` : ''}
      </td>
      <td><span class="status-pill ${e.riskLevel === 'SUSPICIOUS' ? 'danger' : 'safe'}">${e.riskLevel === 'SUSPICIOUS' ? 'Şüpheli RAT Kalıcılığı' : 'Güvenli'}</span></td>
    </tr>
  `).join('');
  wrap.innerHTML = `<table class="spatial-table"><thead><tr><th>Kaynak</th><th>Ad</th><th>Hedef &amp; Analiz</th><th>Durum</th></tr></thead><tbody>${rows}</tbody></table>`;
}

async function loadQuarantine() {
  const wrap = document.getElementById('quarantineTableWrap');
  const purgeBtn = document.getElementById('purgeQuarantineBtn');
  if (!wrap) return;
  const res = await fetch('/api/quarantine');
  const list = await res.json();

  if (purgeBtn) purgeBtn.classList.toggle('hidden', !list.length);

  if (!list.length) {
    wrap.innerHTML = '<div class="empty-note">Karantina kasası boş.</div>';
    return;
  }

  const rows = list.map(item => {
    const kb = (Number(item.sizeBytes || 0) / 1024).toFixed(1);
    const shortHash = (item.sha256 || '').slice(0, 12);
    const reasonHint = (item.reasons || [])[0] || '';
    return `
      <tr>
        <td>
          <div class="cell-main">${escapeHtml(item.fileName)} <span class="mono cell-sub">(${kb} KB · ${escapeHtml(shortHash)})</span></div>
          <div class="mono cell-sub">${escapeHtml(item.originalPath)}</div>
          ${reasonHint ? `<div class="cell-sub">${escapeHtml(reasonHint)}</div>` : ''}
        </td>
        <td><span class="status-pill danger">${escapeHtml(item.threatName)} (${item.riskScore}/100)</span></td>
        <td class="mono">${escapeHtml(item.encryption || 'AES-256-GCM')}</td>
        <td class="mono">${escapeHtml(item.quarantinedAt)}</td>
        <td>
          <div style="display:flex;gap:8px;">
            <button class="btn-ghost" data-aegis-action="restore-q" data-id="${safeUriArg(item.id)}">Geri Yükle</button>
            <button class="btn-danger-ghost" data-aegis-action="delete-q" data-id="${safeUriArg(item.id)}">Sil</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  wrap.innerHTML = `<table class="spatial-table"><thead><tr><th>Dosya</th><th>Tehdit</th><th>Şifreleme</th><th>Tarih</th><th>İşlem</th></tr></thead><tbody>${rows}</tbody></table>`;
}

window.restoreQ = async function(encodedId) {
  await fetch('/api/quarantine/restore', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: decodeUriArg(encodedId) })
  });
  loadQuarantine();
  fetchStatus();
};

window.deleteQ = async function(encodedId) {
  await fetch('/api/quarantine/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: decodeUriArg(encodedId) })
  });
  loadQuarantine();
  fetchStatus();
};

document.getElementById('refreshProcNetBtn')?.addEventListener('click', loadProcNet);
document.getElementById('refreshStartupGuardBtn')?.addEventListener('click', loadStartupGuard);
document.getElementById('refreshQuarantineBtn')?.addEventListener('click', loadQuarantine);

// Sistem Güçlendirici, Zaman Makinesi ve SuperLX 1.0 Test Süiti
document.getElementById('runOptimizeBtn')?.addEventListener('click', async () => {
  const btn = document.getElementById('runOptimizeBtn');
  btn.disabled = true;
  btn.textContent = 'Optimize Ediliyor...';
  try {
    const res = await fetch('/api/pro/optimize', { method: 'POST' });
    const data = await res.json();
    document.getElementById('optFreedMb').textContent = `${data.freedMb} MB (${data.cleanedTempFiles})`;
    document.getElementById('optFreeRam').textContent = `${data.freeMemoryMb} MB`;
    document.getElementById('optHardeningScore').textContent = `${data.hardeningScore} / 100`;
    document.getElementById('optimizeLastRun').textContent = `${data.timestamp} · DNS Temiz`;
    await fetchStatus();
  } finally {
    btn.disabled = false;
    btn.textContent = 'Sistemi Güçlendir';
  }
});

async function loadTimeMachine() {
  const wrap = document.getElementById('timeMachineList');
  if (!wrap) return;
  const res = await fetch('/api/timemachine/snapshot');
  const data = await res.json();
  const entries = data.entries || [];
  if (!entries.length) {
    wrap.innerHTML = '<div class="empty-note">Kayıtlı gölge geri sarma işlemi bulunmuyor.</div>';
    return;
  }
  wrap.innerHTML = `<table class="spatial-table"><thead><tr><th>Seq</th><th>PID</th><th>İşlem</th><th>Hedef</th><th>Durum</th></tr></thead><tbody>${entries.map(e => `
    <tr>
      <td class="mono">#${e.seqId}</td>
      <td class="mono">${e.pid}</td>
      <td><span class="status-pill warning">${escapeHtml(e.opType)}</span></td>
      <td class="mono cell-sub" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(e.path)}</td>
      <td>${e.rolledBack ? '<span class="status-pill safe">Geri Sarıldı</span>' : '<span class="status-pill danger">Bekliyor</span>'}</td>
    </tr>`).join('')}</tbody></table>`;
}

document.getElementById('refreshTmBtn')?.addEventListener('click', loadTimeMachine);
document.getElementById('runTmRollbackBtn')?.addEventListener('click', async () => {
  await fetch('/api/timemachine/rollback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pid: 0 })
  });
  loadTimeMachine();
  fetchStatus();
});

document.getElementById('runSuperlxBenchBtn')?.addEventListener('click', async () => {
  const btn = document.getElementById('runSuperlxBenchBtn');
  const wrap = document.getElementById('superlxBenchWrap');
  if (!wrap) return;
  btn.disabled = true;
  btn.textContent = 'Test Ediliyor...';
  wrap.innerHTML = '<div class="empty-note">SuperLX 1.0 saldırı ve koruma doğrulama testleri çalıştırılıyor...</div>';
  try {
    const res = await fetch('/api/pro/superlx-benchmark', { method: 'POST' });
    const data = await res.json();
    if (data.error) {
      wrap.innerHTML = `<div class="empty-note text-danger">${escapeHtml(data.error)}</div>`;
      return;
    }
    const rows = (data.results || []).map(r => `
      <tr>
        <td><div class="cell-main">${escapeHtml(r.label)}</div><div class="mono cell-sub">${escapeHtml(r.fileName)}</div></td>
        <td class="mono">${r.score}/100</td>
        <td><span class="status-pill ${r.actual === 'CLEAN' ? 'safe' : 'danger'}">${escapeHtml(r.actual)}</span></td>
        <td><span class="status-pill ${r.passed ? 'safe' : 'danger'}">${r.passed ? 'GEÇTİ' : 'HATA'}</span></td>
      </tr>
    `).join('');
    wrap.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0 8px;">
        <span class="row-title">Sonuç: ${data.passedCount} / ${data.totalCount} Başarılı</span>
        <span class="status-pill ${data.passedCount === data.totalCount ? 'safe' : 'warning'}">%${Math.round((data.passedCount / Math.max(1, data.totalCount)) * 100)}</span>
      </div>
      <table class="spatial-table"><thead><tr><th>Test Vektörü</th><th>Skor</th><th>Karar</th><th>Durum</th></tr></thead><tbody>${rows}</tbody></table>
    `;
    fetchStatus();
  } finally {
    btn.disabled = false;
    btn.textContent = 'Testleri Çalıştır';
  }
});

async function loadDefenderCoexistence() {
  const badge = document.getElementById('defenderCoexistBadge');
  if (!badge) return;
  try {
    const res = await fetch('/api/defender-status');
    const data = await res.json();
    const layers = data.activeLayersCount || 8;
    const primaryTxt = data.primaryShieldReady
      ? `Birincil Kalkan Hazır (${layers}/${layers} Katman)`
      : 'Koruma Kısmen Hazır';
    const defTxt = data.defenderActive ? 'Defender: Aktif (Devredilebilir)' : 'Defender: Pasif / İkincil';
    badge.textContent = `${primaryTxt} · ${defTxt}`;
  } catch (_) {
    badge.textContent = 'Birincil Kalkan Durumu Okunamadı';
  }
}

document.getElementById('openWinDefenderBtn')?.addEventListener('click', async () => {
  await fetch('/api/open-windows-security', { method: 'POST' });
});

document.getElementById('quarantineAllBtn')?.addEventListener('click', async () => {
  if (!latestScanDetections.length) return;
  const btn = document.getElementById('quarantineAllBtn');
  if (btn) btn.disabled = true;
  try {
    await fetch('/api/quarantine/isolate-batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        items: latestScanDetections.map(d => ({
          filePath: d.path,
          threatName: d.threat_name,
          riskScore: d.risk_score,
          reasons: d.reasons
        }))
      })
    });
    await executeScan(document.getElementById('scanTargetInput')?.value.trim() || '', 'custom');
    await loadQuarantine();
    await fetchStatus();
  } finally {
    if (btn) btn.disabled = false;
  }
});

document.getElementById('purgeQuarantineBtn')?.addEventListener('click', async () => {
  const btn = document.getElementById('purgeQuarantineBtn');
  if (btn) btn.disabled = true;
  try {
    await fetch('/api/quarantine/purge', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    await loadQuarantine();
    await fetchStatus();
  } finally {
    if (btn) btn.disabled = false;
  }
});

document.querySelectorAll('[data-evtfilter]').forEach(btn => {
  btn.addEventListener('click', () => {
    activeEventFilter = btn.getAttribute('data-evtfilter') || 'all';
    document.querySelectorAll('[data-evtfilter]').forEach(b => {
      b.classList.toggle('active', b === btn);
    });
    renderRecentActivities(recentEvents);
  });
});

document.getElementById('eventSearchInput')?.addEventListener('input', () => {
  renderRecentActivities(recentEvents);
});

document.getElementById('exportEventsBtn')?.addEventListener('click', () => {
  const payload = {
    generatedAt: new Date().toISOString(),
    engine: latestStatus?.engineName || 'SuperLX 1.0',
    stats: latestStatus?.stats || {},
    events: recentEvents
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `aegiscore-guvenlik-raporu-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  const pop = document.getElementById('topbarPopover');
  if (pop && !pop.classList.contains('hidden')) {
    pop.classList.add('hidden');
    return;
  }
  const overview = document.getElementById('view-overview');
  if (overview && !overview.classList.contains('active')) {
    switchTab('overview');
  }
});

fetchStatus();
connectSSE();
loadStartupGuard();
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) fetchStatus();
});
setInterval(() => {
  if (!document.hidden) fetchStatus();
}, 30000);
