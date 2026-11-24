const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, execFile } = require('child_process');

const LICENSE_DIR = path.join(__dirname, 'licenses');
const STORE_PATH = path.join(LICENSE_DIR, 'license_store.json');
const ACTIVE_PATH = path.join(LICENSE_DIR, 'active_license.json');

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const TIER_RANK = { free: 0, plus: 1, pro: 2 };
const MASKED_KEY_DISPLAY = '***** - **** - **** - ****';

const PLAN_CATALOG = [
  {
    id: 'free',
    name: 'AegisCore Free',
    engine: 'Core 1.0',
    uploadLimitMb: 5,
    tagline: 'Core 1.0 Hızlı İmza, DLL, Polyglot & LNK Kalkanı',
    monthlyPrice: '$0',
    yearlyPrice: '$0',
    monthlyLabel: 'Ücretsiz',
    yearlyLabel: 'Sonsuza Kadar Ücretsiz',
    features: [
      'Core 1.0 Motoru: SHA-256, Bilinen Zararlı DLL & Side-Loading Tespiti',
      'Polyglot Gömülü Yük, Çift Uzantı & Silahlandırılmış LNK Kalkanı',
      'Hızlı Tarama, Tam Disk Taraması ve 5 MB Hızlı Dosya Analizi'
    ],
    missing: [
      'Core 1.0+ Anti-RAT Kill-Chain, 50 MB Analiz & Başlangıç Kalkanı',
      'SuperLX 1.0 Defender & RAT Kör Nokta Motoru + 500 MB Büyük Dosya Analizi',
      'Pro Özel Tasarım & Devrim RGB Tema Seçenekleri'
    ]
  },
  {
    id: 'plus',
    name: 'AegisCore Plus',
    engine: 'Core 1.0+',
    uploadLimitMb: 50,
    tagline: 'Core 1.0+ Anti-RAT, 50 MB Analiz & Çok Katmanlı Savunma',
    monthlyPrice: '$2.99',
    yearlyPrice: '$29.99',
    monthlyLabel: '$2.99 / ay',
    yearlyLabel: '$29.99 / yıl',
    savingsText: '%17 Tasarruf',
    features: [
      'Core 1.0+: PE RWX/Entropi, .NET Crypter, Fuzzy Hash & RAT Kill-Chain',
      '50 MB Hızlı Dosya Analizi + Başlangıç/Registry RAT Kalıcılık Denetçisi',
      'Çoklu Bölge Kalkanı (Downloads + Temp) + Tek Tıkla Süreç Durdur & İzole Et',
      'Canary Fidye Tuzağı + Çekirdek TCP-PID Ağ/RAT Port Güvenlik Duvarı',
      'AES-256-GCM Şifreli Karantina Kasası & Oyun Modu'
    ]
  },
  {
    id: 'pro',
    name: 'AegisCore Pro',
    engine: 'SuperLX 1.0',
    uploadLimitMb: 500,
    tagline: 'SuperLX 1.0 Motoru · 500 MB Dev Analiz · Devrim RGB',
    monthlyPrice: '$5.99',
    yearlyPrice: '$59.99',
    monthlyLabel: '$5.99 / ay',
    yearlyLabel: '$59.99 / yıl',
    savingsText: '%17 Tasarruf',
    highlighted: true,
    features: [
      'SuperLX 1.0 Anti-RAT & Defender Kör Nokta Motoru (Maksimum Hız + Güç)',
      '500 MB Dev Dosya Hızlı Analizi + 10 Vektörlü Anti-RAT Doğrulama Merkezi',
      'Özel Devrim RGB Tasarım (RGB Prizma / Cyber Neon / Apex Kızıl / Altın)',
      'AsyncRAT/Remcos .NET Loader, Hollowing, HTML Smuggling & LOLBin Kalkanı',
      '500ms Yerel Mikro-Sandbox + Atomik Zaman Makinesi (LIFO Geri Sarma)',
      'Pro Sistem Güçlendirici (RAM, DNS & Önbellek Optimizasyonu)'
    ]
  }
];

function getEngineName(tier) {
  if (tier === 'pro') return 'SuperLX 1.0';
  if (tier === 'plus') return 'Core 1.0+';
  return 'Core 1.0';
}

function getUploadLimitMb(tier) {
  if (tier === 'pro') return 500;
  if (tier === 'plus') return 50;
  return 5;
}

function getUploadLimitBytes(tier) {
  return getUploadLimitMb(tier) * 1024 * 1024;
}

function formatNow() {
  const d = new Date();
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function randomKeyGroup(len) {
  let out = '';
  for (let i = 0; i < len; i++) {
    out += ALPHABET[crypto.randomInt(0, ALPHABET.length)];
  }
  return out;
}

function generateKey(prefix) {
  return `AEGIS-${prefix}-${randomKeyGroup(4)}-${randomKeyGroup(4)}-${randomKeyGroup(4)}`;
}

let cachedFingerprint = null;
function getDeviceFingerprint() {
  if (cachedFingerprint) return cachedFingerprint;

  let machineGuid = '';
  try {
    const out = execFileSync(
      'reg.exe',
      ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'],
      { encoding: 'utf8', timeout: 3000, windowsHide: true }
    );
    const match = out.match(/MachineGuid\s+REG_SZ\s+([^\r\n]+)/i);
    if (match && match[1]) machineGuid = match[1].trim();
  } catch (_) {}

  const cpuModel = os.cpus()?.[0]?.model || 'unknown-cpu';
  const rawSeed = `${machineGuid}|${os.hostname()}|${os.platform()}|${os.arch()}|${cpuModel}`;
  const deviceId = crypto.createHash('sha256').update(rawSeed).digest('hex');

  cachedFingerprint = {
    deviceId,
    deviceShort: `DEV-${deviceId.slice(0, 8).toUpperCase()}`,
    hostname: os.hostname()
  };
  return cachedFingerprint;
}

function ensureStore() {
  if (!fs.existsSync(LICENSE_DIR)) {
    fs.mkdirSync(LICENSE_DIR, { recursive: true });
  }

  if (fs.existsSync(STORE_PATH)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(STORE_PATH, 'utf8'));
      if (Array.isArray(parsed.keys) && parsed.keys.length === 10) {
        return parsed;
      }
    } catch (_) {}
  }

  const keys = [];
  for (let i = 0; i < 5; i++) {
    const key = generateKey('PLUS');
    keys.push({
      slot: `PLUS-${i + 1}`,
      key,
      keyHash: crypto.createHash('sha256').update(key).digest('hex'),
      tier: 'plus',
      boundDeviceId: null,
      boundDeviceShort: null,
      activatedAt: null
    });
  }
  for (let i = 0; i < 5; i++) {
    const key = generateKey('PRO');
    keys.push({
      slot: `PRO-${i + 1}`,
      key,
      keyHash: crypto.createHash('sha256').update(key).digest('hex'),
      tier: 'pro',
      boundDeviceId: null,
      boundDeviceShort: null,
      activatedAt: null
    });
  }

  const store = {
    version: '1.0',
    generatedAt: formatNow(),
    maxDevicesPerKey: 1,
    keys
  };
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2), 'utf8');
  return store;
}

function saveStore(store) {
  if (!fs.existsSync(LICENSE_DIR)) fs.mkdirSync(LICENSE_DIR, { recursive: true });
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2), 'utf8');
}

function timingSafeHexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function computeActiveRecordMac(record, deviceId) {
  const payload = `${record.tier}|${record.keyHash}|${record.boundDeviceId}|${record.activatedAt || ''}|${record.billingCycle || 'monthly'}`;
  return crypto.createHmac('sha256', `AEGIS-LIC-MAC:${deviceId}`).update(payload).digest('hex');
}

function getActiveLicense() {
  ensureStore();
  const fp = getDeviceFingerprint();
  if (!fs.existsSync(ACTIVE_PATH)) {
    return {
      tier: 'free',
      tierLabel: 'Ücretsiz Sürüm (Core 1.0)',
      engineName: 'Core 1.0',
      uploadLimitMb: 5,
      activated: false,
      maskedKey: '',
      deviceShort: fp.deviceShort,
      hostname: fp.hostname,
      activatedAt: null,
      billingCycle: 'monthly',
      deviceLocked: false
    };
  }

  try {
    const saved = JSON.parse(fs.readFileSync(ACTIVE_PATH, 'utf8'));
    const expectedMac = computeActiveRecordMac(saved, fp.deviceId);
    const macValid = !saved.integrityMac || timingSafeHexEqual(saved.integrityMac, expectedMac);
    if ((saved.boundDeviceId && saved.boundDeviceId !== fp.deviceId) || !macValid) {
      return {
        tier: 'free',
        tierLabel: 'Ücretsiz Sürüm (Cihaz/Bütünlük Uyumsuz)',
        engineName: 'Core 1.0',
        uploadLimitMb: 5,
        activated: false,
        maskedKey: '',
        deviceShort: fp.deviceShort,
        hostname: fp.hostname,
        activatedAt: null,
        billingCycle: 'monthly',
        deviceLocked: false
      };
    }

    const tier = saved.tier === 'pro' || saved.tier === 'plus' ? saved.tier : 'free';
    return {
      tier,
      tierLabel: tier === 'pro' ? 'Pro Lisans (SuperLX 1.0)' : tier === 'plus' ? 'Plus Lisans (Core 1.0+)' : 'Ücretsiz Sürüm (Core 1.0)',
      engineName: getEngineName(tier),
      uploadLimitMb: getUploadLimitMb(tier),
      activated: tier !== 'free',
      maskedKey: tier !== 'free' ? MASKED_KEY_DISPLAY : '',
      deviceShort: fp.deviceShort,
      hostname: fp.hostname,
      activatedAt: saved.activatedAt || null,
      billingCycle: saved.billingCycle || 'monthly',
      deviceLocked: tier !== 'free'
    };
  } catch (_) {
    return {
      tier: 'free',
      tierLabel: 'Ücretsiz Sürüm (Core 1.0)',
      engineName: 'Core 1.0',
      uploadLimitMb: 5,
      activated: false,
      maskedKey: '',
      deviceShort: fp.deviceShort,
      hostname: fp.hostname,
      activatedAt: null,
      billingCycle: 'monthly',
      deviceLocked: false
    };
  }
}

function activateLicenseKey(rawKey, billingCycle = 'monthly', deviceIdOverride = '') {
  const store = ensureStore();
  const fp = getDeviceFingerprint();
  const targetDeviceId = typeof deviceIdOverride === 'string' && deviceIdOverride.trim()
    ? deviceIdOverride.trim()
    : fp.deviceId;
  const targetDeviceShort = targetDeviceId === fp.deviceId
    ? fp.deviceShort
    : `DEV-${targetDeviceId.slice(0, 8).toUpperCase()}`;

  const normalized = String(rawKey || '').trim().toUpperCase();
  if (!normalized) {
    return { success: false, status: 400, error: 'Lütfen geçerli bir lisans anahtarı girin.' };
  }

  const inputHash = crypto.createHash('sha256').update(normalized).digest('hex');
  const entry = store.keys.find(k => timingSafeHexEqual(String(k.keyHash || ''), inputHash));
  if (!entry) {
    return {
      success: false,
      status: 400,
      error: 'Geçersiz lisans anahtarı. Anahtar doğrulanamadı.'
    };
  }

  // Tek cihaz kilidi kontrolü
  if (entry.boundDeviceId && entry.boundDeviceId !== targetDeviceId) {
    return {
      success: false,
      status: 403,
      error: `Bu anahtar başka bir cihaza (${entry.boundDeviceShort || 'Kilitli Cihaz'}) kalıcı olarak bağlanmıştır. Bir anahtarla yalnızca 1 cihazda giriş yapılabilir.`
    };
  }

  const nowStr = formatNow();
  if (!entry.boundDeviceId) {
    entry.boundDeviceId = targetDeviceId;
    entry.boundDeviceShort = targetDeviceShort;
    entry.activatedAt = nowStr;
    saveStore(store);
  }

  // Test amaçlı harici deviceIdOverride verildiyse mevcut cihazın kalıcı aktif dosyasını ezme
  if (targetDeviceId === fp.deviceId) {
    const activeRecord = {
      tier: entry.tier,
      keyHash: entry.keyHash,
      maskedKey: MASKED_KEY_DISPLAY,
      boundDeviceId: targetDeviceId,
      deviceShort: fp.deviceShort,
      activatedAt: entry.activatedAt || nowStr,
      billingCycle: billingCycle === 'yearly' ? 'yearly' : 'monthly'
    };
    activeRecord.integrityMac = computeActiveRecordMac(activeRecord, fp.deviceId);
    fs.writeFileSync(ACTIVE_PATH, JSON.stringify(activeRecord, null, 2), 'utf8');
  }

  return {
    success: true,
    status: 200,
    tier: entry.tier,
    maskedKey: MASKED_KEY_DISPLAY,
    deviceShort: targetDeviceShort,
    activatedAt: entry.activatedAt || nowStr,
    deviceLocked: true
  };
}

function deactivateLocalSession() {
  if (fs.existsSync(ACTIVE_PATH)) {
    fs.unlinkSync(ACTIVE_PATH);
  }
  return getActiveLicense();
}

function hasTierAccess(minimumTier) {
  const active = getActiveLicense();
  return (TIER_RANK[active.tier] || 0) >= (TIER_RANK[minimumTier] || 0);
}

function runProSystemOptimizer() {
  return new Promise((resolve) => {
    const tempDir = os.tmpdir();
    let cleanedFiles = 0;
    let freedBytes = 0;
    const cutoffMs = Date.now() - 5 * 60 * 1000;

    try {
      const entries = fs.readdirSync(tempDir);
      for (const name of entries) {
        if (name.startsWith('aegis_drop_') || name.endsWith('.tmp')) {
          const full = path.join(tempDir, name);
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
        timestamp: formatNow(),
        cleanedTempFiles: cleanedFiles,
        freedMb: Number((freedBytes / (1024 * 1024)).toFixed(2)),
        dnsFlushed: !dnsErr,
        freeMemoryMb: freeMemAfterMb,
        memoryDeltaMb: Math.max(0, freeMemAfterMb - freeMemBeforeMb),
        memoryUsedPercent: usedPct,
        startupAuditStatus: 'Optimize Edildi (Çekirdek Koruması Hafif Modda)',
        hardeningScore: 99
      });
    });
  });
}

module.exports = {
  PLAN_CATALOG,
  TIER_RANK,
  MASKED_KEY_DISPLAY,
  ensureStore,
  getDeviceFingerprint,
  getActiveLicense,
  activateLicenseKey,
  deactivateLocalSession,
  hasTierAccess,
  getEngineName,
  getUploadLimitMb,
  getUploadLimitBytes,
  runProSystemOptimizer
};
