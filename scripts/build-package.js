#!/usr/bin/env node
/**
 * AegisCore Endpoint Security - Windows Standalone & Installer Packager
 * Zero external npm dependencies.
 *
 * Usage:
 *   node scripts/build-package.js          # Full self-contained portable + Setup.exe (if Inno Setup is installed)
 *   node scripts/build-package.js --lite   # Lightweight package without bundled Node.js / Python runtimes
 */

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const PKG = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const VERSION = PKG.version || '6.0.0';
const LITE_MODE = process.argv.includes('--lite');

const PYTHON_EMBED_VER = '3.10.11';
const PYTHON_EMBED_URL = `https://www.python.org/ftp/python/${PYTHON_EMBED_VER}/python-${PYTHON_EMBED_VER}-embed-amd64.zip`;

const DIST_DIR = path.join(ROOT, 'dist');
const CACHE_DIR = path.join(DIST_DIR, '.cache');
const STAGE_NAME = LITE_MODE
  ? `AegisCore-v${VERSION}-win-x64-lite`
  : `AegisCore-v${VERSION}-win-x64`;
const STAGE_DIR = path.join(DIST_DIR, STAGE_NAME);
const ZIP_PATH = path.join(DIST_DIR, `${STAGE_NAME}-portable.zip`);
const SETUP_PATH = path.join(DIST_DIR, `AegisCore-v${VERSION}-Setup.exe`);
const CHECKSUMS_PATH = path.join(DIST_DIR, 'SHA256SUMS.txt');

function log(msg) {
  console.log(`[AegisCore Packager] ${msg}`);
}

function run(cmd, args, opts = {}) {
  log(`> ${cmd} ${args.join(' ')}`);
  execFileSync(cmd, args, {
    cwd: ROOT,
    stdio: 'inherit',
    windowsHide: true,
    ...opts
  });
}

function copyFileSafe(src, dst) {
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  fs.copyFileSync(src, dst);
}

function copyTreeFiltered(srcDir, dstDir, filterFn) {
  if (!fs.existsSync(srcDir)) return;
  fs.mkdirSync(dstDir, { recursive: true });
  for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
    const srcPath = path.join(srcDir, entry.name);
    const dstPath = path.join(dstDir, entry.name);
    if (filterFn && !filterFn(srcPath, entry)) continue;
    if (entry.isDirectory()) {
      copyTreeFiltered(srcPath, dstPath, filterFn);
    } else if (entry.isFile()) {
      copyFileSafe(srcPath, dstPath);
    }
  }
}

function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    const tmpPath = destPath + '.part';
    const fetchUrl = (targetUrl, redirectsLeft = 5) => {
      https.get(targetUrl, { headers: { 'User-Agent': 'AegisCore-Packager/6.0' } }, (res) => {
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
          res.resume();
          if (redirectsLeft <= 0) return reject(new Error('Too many redirects'));
          return fetchUrl(res.headers.location, redirectsLeft - 1);
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} downloading ${targetUrl}`));
        }
        const out = fs.createWriteStream(tmpPath);
        res.pipe(out);
        out.on('finish', () => {
          out.close(() => {
            fs.renameSync(tmpPath, destPath);
            resolve(destPath);
          });
        });
        out.on('error', (err) => {
          try { fs.unlinkSync(tmpPath); } catch (_) {}
          reject(err);
        });
      }).on('error', (err) => {
        try { fs.unlinkSync(tmpPath); } catch (_) {}
        reject(err);
      });
    };
    fetchUrl(url);
  });
}

function extractZip(zipFile, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  const pyCode = [
    'import sys, zipfile',
    'with zipfile.ZipFile(sys.argv[1], "r") as zf:',
    '    zf.extractall(sys.argv[2])'
  ].join('\n');
  run('python', ['-c', pyCode, zipFile, destDir]);
}

function createZip(srcDir, outZip) {
  if (fs.existsSync(outZip)) fs.unlinkSync(outZip);
  const pyCode = [
    'import os, sys, zipfile',
    'src_dir, out_zip = sys.argv[1], sys.argv[2]',
    'base = os.path.dirname(os.path.abspath(src_dir))',
    'with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:',
    '    for dp, dns, fns in os.walk(src_dir):',
    '        dns.sort()',
    '        fns.sort()',
    '        for fn in fns:',
    '            fp = os.path.join(dp, fn)',
    '            arc = os.path.relpath(fp, base)',
    '            zf.write(fp, arc)'
  ].join('\n');
  run('python', ['-c', pyCode, srcDir, outZip]);
}

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  const fd = fs.openSync(filePath, 'r');
  const buf = Buffer.allocUnsafe(1024 * 1024);
  try {
    let bytesRead;
    while ((bytesRead = fs.readSync(fd, buf, 0, buf.length, null)) > 0) {
      hash.update(buf.subarray(0, bytesRead));
    }
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}

function findInnoSetupCompiler() {
  const envPath = process.env.ISCC_PATH;
  const candidates = [
    envPath,
    'C:\\Program Files (x86)\\Inno Setup 6\\ISCC.exe',
    'C:\\Program Files\\Inno Setup 6\\ISCC.exe'
  ].filter(Boolean);
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  try {
    const found = execFileSync('where.exe', ['iscc'], { encoding: 'utf8', windowsHide: true }).trim().split(/\r?\n/)[0];
    if (found && fs.existsSync(found)) return found;
  } catch (_) {}
  return null;
}

async function main() {
  log(`Building ${STAGE_NAME} (mode=${LITE_MODE ? 'lite' : 'standalone'})...`);
  fs.mkdirSync(DIST_DIR, { recursive: true });
  if (fs.existsSync(STAGE_DIR)) {
    fs.rmSync(STAGE_DIR, { recursive: true, force: true });
  }
  fs.mkdirSync(STAGE_DIR, { recursive: true });

  // 1. Publish native Windows Tray Launcher (AegisCore.exe)
  const launcherOut = path.join(DIST_DIR, '_build_launcher');
  if (fs.existsSync(launcherOut)) fs.rmSync(launcherOut, { recursive: true, force: true });
  run('dotnet', [
    'publish',
    path.join(ROOT, 'launcher', 'AegisCoreLauncher.csproj'),
    '-c', 'Release',
    '-r', 'win-x64',
    '--self-contained', 'true',
    '-p:PublishSingleFile=true',
    '-p:EnableCompressionInSingleFile=true',
    '-p:PublishTrimmed=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true',
    '-p:DebugType=none',
    '-p:DebugSymbols=false',
    '-o', launcherOut,
    '--nologo'
  ]);
  copyFileSafe(path.join(launcherOut, 'AegisCore.exe'), path.join(STAGE_DIR, 'AegisCore.exe'));
  fs.rmSync(launcherOut, { recursive: true, force: true });

  // 2. Publish C# .NET 8 Native Scanner Engine (AegisScanner.exe)
  const scannerOut = path.join(STAGE_DIR, 'engines', 'csharp-scanner', 'bin');
  run('dotnet', [
    'publish',
    path.join(ROOT, 'engines', 'csharp-scanner', 'AegisScanner.csproj'),
    '-c', 'Release',
    '-r', 'win-x64',
    '--self-contained', LITE_MODE ? 'false' : 'true',
    '-p:PublishSingleFile=true',
    '-p:EnableCompressionInSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true',
    '-p:DebugType=none',
    '-p:DebugSymbols=false',
    '-o', scannerOut,
    '--nologo'
  ]);

  // 3. Copy clean application files
  for (const rel of ['server.js', 'license_manager.js', 'package.json', 'README.md', 'Baslat_AegisCore.bat']) {
    copyFileSafe(path.join(ROOT, rel), path.join(STAGE_DIR, rel));
  }
  copyTreeFiltered(path.join(ROOT, 'public'), path.join(STAGE_DIR, 'public'));
  copyTreeFiltered(path.join(ROOT, 'signatures'), path.join(STAGE_DIR, 'signatures'));
  copyFileSafe(
    path.join(ROOT, 'engines', 'python-heuristics', 'analyzer.py'),
    path.join(STAGE_DIR, 'engines', 'python-heuristics', 'analyzer.py')
  );
  copyFileSafe(
    path.join(ROOT, 'engines', 'superlx', 'superlx_engine.py'),
    path.join(STAGE_DIR, 'engines', 'superlx', 'superlx_engine.py')
  );
  copyTreeFiltered(
    path.join(ROOT, 'vortex'),
    path.join(STAGE_DIR, 'vortex'),
    (srcPath, entry) => {
      if (entry.isDirectory() && ['__pycache__', 'native_cpp', 'rust_engine', 'tests'].includes(entry.name)) {
        return false;
      }
      if (entry.isFile() && /\.(pyc|pyo|log|db|key)$/i.test(entry.name)) {
        return false;
      }
      return true;
    }
  );

  // 4. Bundle portable Node.js + Embeddable Python 3.10.11 (standalone mode)
  if (!LITE_MODE) {
    const nodeDst = path.join(STAGE_DIR, 'runtime', 'node', 'node.exe');
    log(`Bundling Node.js runtime from ${process.execPath}`);
    copyFileSafe(process.execPath, nodeDst);

    const pyZipCache = path.join(CACHE_DIR, `python-${PYTHON_EMBED_VER}-embed-amd64.zip`);
    if (!fs.existsSync(pyZipCache) || fs.statSync(pyZipCache).size < 1_000_000) {
      log(`Downloading official Embeddable Python ${PYTHON_EMBED_VER}...`);
      await downloadFile(PYTHON_EMBED_URL, pyZipCache);
    } else {
      log(`Using cached Embeddable Python: ${pyZipCache}`);
    }

    const pyDst = path.join(STAGE_DIR, 'runtime', 'python');
    extractZip(pyZipCache, pyDst);

    // Ensure python310._pth includes script/app directories cleanly
    const pthFile = path.join(pyDst, 'python310._pth');
    if (fs.existsSync(pthFile)) {
      let pth = fs.readFileSync(pthFile, 'utf8');
      for (const relEntry of ['.', '..\\..\\vortex', '..\\..\\engines\\superlx']) {
        if (!pth.split(/\r?\n/).includes(relEntry)) {
          pth = pth.trimEnd() + '\r\n' + relEntry + '\r\n';
        }
      }
      fs.writeFileSync(pthFile, pth, 'utf8');
    }
  }

  // 5. Quick binary self-check
  run(path.join(STAGE_DIR, 'AegisCore.exe'), ['--check'], { cwd: STAGE_DIR });
  log('AegisCore.exe --check PASSED');

  // 6. Create portable ZIP archive
  log(`Creating portable ZIP: ${ZIP_PATH}`);
  createZip(STAGE_DIR, ZIP_PATH);

  const artifacts = [ZIP_PATH];

  // 7. Build Inno Setup installer (AegisCore-vX.Y.Z-Setup.exe) if ISCC.exe is installed
  const iscc = findInnoSetupCompiler();
  if (iscc && !LITE_MODE) {
    log(`Compiling Inno Setup installer with ${iscc}...`);
    run(iscc, [
      `/DMyAppVersion=${VERSION}`,
      `/DSourceDir=${STAGE_DIR}`,
      `/DOutputDir=${DIST_DIR}`,
      path.join(ROOT, 'installer', 'AegisCore.iss')
    ]);
    if (fs.existsSync(SETUP_PATH)) {
      artifacts.push(SETUP_PATH);
    }
  } else if (!LITE_MODE) {
    log('Inno Setup (ISCC.exe) not installed locally — skipping Setup.exe (GitHub Actions builds it automatically).');
  }

  // 8. Generate SHA-256 checksums
  const lines = artifacts.map((fp) => {
    const sizeMb = (fs.statSync(fp).size / (1024 * 1024)).toFixed(2);
    const digest = sha256File(fp);
    log(`ARTIFACT: ${path.basename(fp)} (${sizeMb} MB) SHA256=${digest}`);
    return `${digest}  ${path.basename(fp)}`;
  });
  fs.writeFileSync(CHECKSUMS_PATH, lines.join('\n') + '\n', 'utf8');
  log(`Done! Output directory: ${DIST_DIR}`);
}

main().catch((err) => {
  console.error('[AegisCore Packager] FAILED:', err);
  process.exit(1);
});
