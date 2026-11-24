#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SuperLX 1.0 :: AegisCore Next-Gen Autonomous & Anti-Evasion Security Engine
Çok katmanlı koruma:
  1. Tam Dosya Streaming SHA-256 + Bilinen Zararlı DLL / Side-Loading Kalkanı
  2. Çok Turlu Yinelemeli De-Obfuscator (Base64 x3, GZip/Zlib/Deflate, URL-Safe B64,
     Caret/Backtick, -f Format, Değişken Birleştirme, Ters Çevirme, XOR Brute-Force, Hex, Chr/Char, HTML-Entity)
  3. Deep PE Structural & IAT Analizörü (IAT Enjeksiyon Üçlüsü, Syscall Stubs, RWX, TLS, OEP Anomalisi, Boş IAT, Self-Signed Tamper)
  4. Streaming Polyglot Tarayıcısı (100 MB'a kadar resim/PDF içi gizli PE/Script), RTF/PDF/DDE/LNK/ZIP Müfettişi
  5. Modern LOLBin, UAC Bypass, Defender/Firewall Tamper, RAT & Stealer + Webhook Korelasyonu
"""

from __future__ import annotations
import base64
import ctypes
import gzip
import hashlib
import html as html_lib
import io
import json
import math
import os
import re
import struct
import sys
import tarfile
import urllib.parse
import zipfile
from collections import Counter
from typing import Dict, List, Optional, Set, Tuple

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.dirname(CURRENT_DIR))
DEFAULT_DB = os.path.join(ROOT_DIR, "signatures", "malware_db.json")

VORTEX_DIR = os.path.join(ROOT_DIR, "vortex")
if VORTEX_DIR not in sys.path:
    sys.path.insert(0, VORTEX_DIR)

try:
    from core.win32_native import verify_authenticode_catalog
except Exception:
    def verify_authenticode_catalog(_path: str) -> Tuple[bool, str]:
        return False, ""


_DB_CACHE: Dict[str, Tuple[float, dict]] = {}

_RTLO_CHARS = {"\u202e", "\u202d", "\u202a", "\u202b", "\u202c", "\u2066", "\u2067", "\u2068", "\u2069"}

_ALLOC_APIS = {"virtualallocex", "ntallocatevirtualmemory", "virtualallocexnuma", "zwallocatevirtualmemory", "heapcreate"}
_WRITE_APIS = {"writeprocessmemory", "ntwritevirtualmemory", "zwwritevirtualmemory"}
_EXEC_APIS = {"createremotethread", "createremotethreadex", "ntcreatethreadex", "queueuserapc", "ntqueueapcthread", "rtlcreateuserthread", "setthreadcontext", "ntsetcontextthread", "ntmapviewofsection"}
_SHELLCODE_MEM_APIS = {"virtualalloc", "virtualprotect", "ntprotectvirtualmemory", "virtualprotectex", "virtualallocex", "ntallocatevirtualmemory"}
_CALLBACK_EXEC_APIS = {
    "enumwindows", "enumchildwindows", "enumsystemlocalesa", "enumsystemlocalesw",
    "certenumsystemstore", "createtimerqueuetimer", "createfiber", "convertthreadtofiber",
    "callwindowproca", "callwindowprocw", "uuidfromstringa", "uuidfromstringw",
    "createthread", "enumfontfamiliesexa", "enumfontfamiliesexw", "graystringa", "graystringw",
}
_SPY_APIS = {"setwindowshookex", "setwindowshookexa", "setwindowshookexw", "getasynckeystate", "getkeystate", "capcreatecapturewindowa", "capcreatecapturewindoww", "registerrawinputdevices", "addclipboardformatlistener"}
_EXFIL_APIS = {"internetopenurla", "internetopenurlw", "httpsendrequesta", "httpsendrequestw", "winhttpsendrequest", "urldownloadtofilea", "urldownloadtofilew"}

_XOR_DOS_NEEDLE = b"This program cannot be run"
_XOR_DOS_VARIANTS = tuple((k, bytes(b ^ k for b in _XOR_DOS_NEEDLE)) for k in range(1, 256))


def _index_db(parsed: dict) -> dict:
    mal_dlls_map: Dict[str, str] = {}
    for item in parsed.get("malicious_dll_names", []):
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip().lower()
            threat_lbl = str(item.get("threat") or "")
        else:
            name = str(item).strip().lower()
            threat_lbl = ""
        if name:
            mal_dlls_map[name] = threat_lbl

    sha_bad: Dict[str, dict] = {}
    for k, v in (parsed.get("sha256_signatures") or {}).items():
        if isinstance(v, dict) and v.get("severity") != "SAFE":
            sha_bad[str(k).lower()] = v

    byte_pats_idx = []
    for pat in parsed.get("byte_patterns", []):
        p_s = str(pat.get("pattern", "")).lower()
        if p_s:
            byte_pats_idx.append((p_s, pat))

    parsed["_idx_mal_dlls"] = mal_dlls_map
    parsed["_idx_byovd_drivers"] = {str(d).strip().lower() for d in parsed.get("byovd_driver_names", []) if d}
    parsed["_idx_hijack_dlls"] = {str(d).strip().lower() for d in parsed.get("hijackable_system_dlls", []) if d}
    parsed["_idx_susp_exts"] = {str(e).strip().lower() for e in parsed.get("suspicious_extensions", []) if e}
    parsed["_idx_sha_bad"] = sha_bad
    parsed["_idx_byte_patterns"] = byte_pats_idx
    return parsed


def _load_db_cached(db_path: str) -> dict:
    if not os.path.isfile(db_path):
        return {}
    try:
        mtime = os.path.getmtime(db_path)
        cached = _DB_CACHE.get(db_path)
        if cached and cached[0] == mtime:
            return cached[1]
        with open(db_path, "r", encoding="utf-8") as df:
            parsed = _index_db(json.load(df))
        _DB_CACHE[db_path] = (mtime, parsed)
        return parsed
    except Exception:
        return {}


_MANAGED_CRYPTER_PARTS = (
    re.compile(r"(?:Assembly\]::Load|Assembly\.Load|\[Reflection\.Assembly\]|AppDomain\.CurrentDomain\.Load|DynamicInvoke|GetDelegateForFunctionPointer)", re.IGNORECASE),
    re.compile(r"(?:RijndaelManaged|AesCryptoServiceProvider|AesManaged|Aes\.Create|TripleDES|RC2CryptoServiceProvider|GZipStream|DeflateStream|FromBase64String|GetManifestResourceStream|ResourceManager|GetPixel|LockBits)", re.IGNORECASE),
    re.compile(r"(?:MethodInfo|EntryPoint\.Invoke|\.GetMethod\(|Invoke\s*\(|Activator\.CreateInstance|CallByName)", re.IGNORECASE),
)

_SUPERLX_COMPILED_RULES = [
    (
        ("mppreference", "disableantispyware", "disable", "ms-settings", "enablelua", "advfirewall", "firewallprofile", "wevtutil"),
        re.compile(
            r"(?:Add-MpPreference|Set-MpPreference|MpCmdRun)\s+.{0,350}?(?:-ExclusionPath|-ExclusionProcess|-ExclusionExtension|-DisableRealtimeMonitoring\s+(?:\$true|1)|-DisableBehaviorMonitoring\s+(?:\$true|1)|-DisableIOAVProtection\s+(?:\$true|1)|-DisableScriptScanning)"
            r"|(?:reg(?:\.exe)?\s+add|Set-ItemProperty).{0,300}?(?:DisableAntiSpyware|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableOnAccessProtection|ms-settings\\Shell\\Open\\command|EnableLUA)"
            r"|DisableAntiSpyware\s*(?:=|:|/d)\s*[\"']?1"
            r"|netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off"
            r"|Set-NetFirewallProfile\s+.{0,200}?-Enabled\s+False"
            r"|wevtutil(?:\.exe)?\s+cl\s+(?:Security|System|Application)",
            re.IGNORECASE | re.DOTALL,
        ),
        95,
        "DefenseEvasion.SecurityTamper.Bypass",
        "DefenderTamper",
        "Windows Defender, Firewall, UAC veya Olay Günlüğü körleştirme / dışlama girişimi",
    ),
    (
        ("blob", "atob", "createobjecturl", "mssaveoropenblob", "activexobject", "tvqqaamaaaaeaaaa", "<svg", "<hta:application", "webassembly"),
        re.compile(
            r"(?:(?:new\s+)?Blob\s*\(.{0,300}?(?:atob|Uint8Array|fromCharCode)|atob\s*\(\s*['\"][A-Za-z0-9+/=_-]{24,}|URL\.createObjectURL|msSaveOrOpenBlob"
            r"|ActiveXObject\s*\(\s*['\"](?:WScript\.Shell|ADODB\.Stream|Scripting\.FileSystemObject)|TVqQAAMAAAAEAAAA|<svg[^>]{0,200}?onload\s*=|<HTA:APPLICATION[^>]{0,200}?>|WebAssembly\.instantiate)",
            re.IGNORECASE | re.DOTALL,
        ),
        90,
        "Trojan.HTMLSmuggling.Dropper",
        "HTMLSmuggling",
        "HTML/SVG/HTA Smuggling veya tarayıcı belleğinde dosya oluşturma tekniği",
    ),
    (
        ("certutil", "mshta", "regsvr32", "rundll32", "bitsadmin", "iex", "invoke-expression", "webclient", "bitstransfer", "wmic", "msiexec", "forfiles", "pcalua", "cmstp", "odbcconf", "http://", "https://", "proxycommand", "codetaskfactory", "usingtask"),
        re.compile(
            r"(?:certutil(?:\.exe)?\s+.{0,250}?(?:-urlcache|-decode|-decodehex)"
            r"|mshta(?:\.exe)?\s+(?:https?://|vbscript:|javascript:)"
            r"|regsvr32(?:\.exe)?\s+.{0,200}?(?:/i:https?://|scrobj\.dll)"
            r"|rundll32(?:\.exe)?\s+(?:javascript:|vbscript:|comsvcs)"
            r"|bitsadmin(?:\.exe)?\s+/transfer"
            r"|(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\r\n]{0,260}?\|[^\r\n]{0,120}?(?:iex|Invoke-Expression)"
            r"|(?:New-Object\s+(?:System\.)?Net\.WebClient).{0,200}?(?:DownloadString|DownloadData|DownloadFile)\s*\(.{0,180}?http"
            r"|Start-BitsTransfer\s+.{0,200}?-Source\s+http"
            r"|wmic(?:\.exe)?\s+process\s+call\s+create"
            r"|msiexec(?:\.exe)?\s+/q\w*\s+/i\s+https?://"
            r"|forfiles(?:\.exe)?\s+.{0,220}?/c\s+[\"'].{0,180}?(?:cmd|powershell|pwsh|mshta|wscript)"
            r"|pcalua(?:\.exe)?\s+-a\s+"
            r"|cmstp(?:\.exe)?\s+.{0,160}?/s\b"
            r"|odbcconf(?:\.exe)?\s+.{0,160}?REGSVR"
            r"|hh(?:\.exe)?\s+https?://"
            r"|ssh(?:\.exe)?\s+.{0,180}?-o\s*ProxyCommand="
            r"|CodeTaskFactory|UsingTask.{0,180}?AssemblyFile)",
            re.IGNORECASE | re.DOTALL,
        ),
        88,
        "Execution.LOLBin.FilelessStager",
        "LOLBinLivingOffTheLand",
        "Windows yerleşik araçları (LOLBin) veya dosya çekme zinciriyle dosyasız yük çalıştırma",
    ),
    (
        ("amsiscanbuffer", "amsiinitfailed", "amsiutils", "etweventwrite", "nttraceevent"),
        re.compile(
            r"(?:AmsiScanBuffer|amsiInitFailed|AmsiUtils|EtwEventWrite|NtTraceEvent).{0,260}?(?:VirtualProtect|0x40|0xC3|0x31|Marshal\.Copy|Patch|WriteProcessMemory)",
            re.IGNORECASE | re.DOTALL,
        ),
        92,
        "Evasion.AMSI_ETW.MemoryPatch",
        "AMSI_ETW_Bypass",
        "Bellekte AMSI veya ETW olay telemetrisini yamayarak (Patch) görünmez olma saldırısı",
    ),
    (
        ("ntmapviewofsection", "virtualallocex", "reflectiveloader", "zwunmapviewofsection", "ntunmapviewofsection", "marshal.copy", "scriptblock", "hellsgate", "halosgate", "tartarusgate", "syswhispers"),
        re.compile(
            r"(?:NtMapViewOfSection.{0,350}?NtQueueApcThread|VirtualAllocEx.{0,350}?WriteProcessMemory.{0,350}?(?:CreateRemoteThread|QueueUserAPC)"
            r"|ReflectiveLoader|ZwUnmapViewOfSection.{0,350}?SetThreadContext|NtUnmapViewOfSection.{0,350}?ResumeThread"
            r"|Marshal\.Copy.{0,300}?CallWindowProc|\[ScriptBlock\]::Create\s*\("
            r"|HellsGate|HalosGate|TartarusGate|SysWhispers)",
            re.IGNORECASE | re.DOTALL,
        ),
        95,
        "Injection.EarlyBird_Hollowing.Crypter",
        "EarlyBird_ProcessHollowing",
        "Process Hollowing / Early-Bird APC / Doğrudan Syscall / Bellek içi kabuk enjeksiyonu",
    ),
    (
        ("comsvcs", "minidump", "physicalmemory", "mmmapiospace", "procdump"),
        re.compile(
            r"(?:comsvcs\.dll\s*,?\s*MiniDump|MiniDumpWriteDump.{0,220}?lsass|\\Device\\PhysicalMemory|MmMapIoSpace|procdump(?:\.exe)?\s+.{0,150}?lsass)",
            re.IGNORECASE | re.DOTALL,
        ),
        95,
        "CredentialAccess.LSASS_BYOVD.MemoryDump",
        "BYOVD_CredentialDump",
        "LSASS kimlik dökümü (Comsvcs/Procdump) veya fiziksel bellek sürücü istismarı (BYOVD)",
    ),
    (
        ("schtasks", "currentversion\\run", "image file execution options", "runpresetupcommandssection"),
        re.compile(
            r"(?:schtasks(?:\.exe)?\s+/create\s+.{0,260}?(?:/sc\s+(?:onlogon|onstart|minute)|powershell|pwsh|cmd\.exe|wscript|mshta|appdata|programdata)"
            r"|CurrentVersion\\Run(?:Once)?[^\r\n]{0,240}?\\(?:Temp|AppData|Public)"
            r"|\\Image File Execution Options\\[^\\\r\n]+\\?[^\r\n]{0,160}?Debugger"
            r"|RunPreSetupCommandsSection)",
            re.IGNORECASE | re.DOTALL,
        ),
        84,
        "RAT.Persistence.AutorunHijack",
        "RATPersistence",
        "Görev zamanlayıcı, Registry Run, IFEO Debugger veya CMSTP INF ile kalıcılık sağlama",
    ),
    (
        ("login data", "local state", "cookies.sqlite", "web data", "nkbihfbeogaeaoehlefnkodbefgpgknn", "exodus", "electrum", "webhooks/", "api.telegram.org", "transfer.sh"),
        re.compile(
            r"(?:(?:Login Data|Local State|cookies\.sqlite|Web Data|nkbihfbeogaeaoehlefnkodbefgpgknn|Exodus|Electrum).{0,400}?(?:CryptUnprotectData|webhook|api\.telegram\.org|HttpClient|WebClient|TcpClient|MultipartFormDataContent))"
            r"|(?:(?:discord\.com/api/webhooks/|api\.telegram\.org/bot|transfer\.sh).{0,400}?(?:Screenshot|Keylog|GetAsyncKeyState|CopyFromScreen|Password|Wallet|Token|Chrome))",
            re.IGNORECASE | re.DOTALL,
        ),
        92,
        "Stealer.Behavioral.BrowserCryptoExfil",
        "InfoStealer_Exfiltration",
        "Tarayıcı / Kripto cüzdan kimlik bilgisi hırsızlığı ve gizli dışa sızdırma zinciri",
    ),
    (
        ("ms-settings", "fodhelper", "computerdefaults"),
        re.compile(
            r"(?:Software\\Classes\\ms-settings\\Shell\\Open\\command|fodhelper\.exe|computerdefaults\.exe)",
            re.IGNORECASE,
        ),
        88,
        "PrivilegeEscalation.UAC.FodhelperBypass",
        "UACBypass",
        "Windows UAC yetki yükseltme atlatma tekniği (ms-settings / fodhelper)",
    ),
    (
        ("vssadmin", "shadowcopy", "wbadmin", "recoveryenabled"),
        re.compile(
            r"(?:vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)|bcdedit(?:\.exe)?\s+.{0,140}?recoveryenabled\s+no)",
            re.IGNORECASE | re.DOTALL,
        ),
        98,
        "Ransomware.ShadowCopy.RecoveryWipe",
        "ShadowCopyWipe",
        "Fidye yazılımı gölge kopya (VSS) veya Windows sistem kurtarma silme saldırısı",
    ),
    (
        ("invoke-cimmethod", "invoke-wmimethod", "commandlineeventconsumer", "__filtertoconsumerbinding"),
        re.compile(
            r"(?:(?:Invoke-CimMethod|Invoke-WmiMethod).{0,200}?Win32_Process.{0,120}?Create|CommandLineEventConsumer|__FilterToConsumerBinding)",
            re.IGNORECASE | re.DOTALL,
        ),
        90,
        "Execution.WMI_CIM.FilelessExec",
        "WMI_CIM_Abuse",
        "Modern WMI / CIM abonelik kalıcılığı veya dosyasız Win32_Process yürütme tekniği",
    ),
    (
        ("marshal.loads", "zlib.decompress", "lzma.decompress", "gzip.decompress", "buffer.from", "compile("),
        re.compile(
            r"(?:(?:exec|eval)\s*\(\s*(?:marshal\.loads|zlib\.decompress|lzma\.decompress|gzip\.decompress|compile\s*\(\s*base64)|eval\s*\(\s*Buffer\.from\s*\([^)]+,\s*['\"]base64['\"]\)\.toString)",
            re.IGNORECASE | re.DOTALL,
        ),
        90,
        "Trojan.Script.MarshaledLoader",
        "MarshaledScriptLoader",
        "Bellekte sıkıştırılmış veya Marshal/Base64 ile paketlenmiş zararlı Python/JS yükleyicisi",
    ),
    (
        ("<task", "<command>", "<exec>"),
        re.compile(
            r"<Task\b[^>]{0,200}>.{0,1200}?<Exec>.{0,400}?<Command>[^<]{0,260}?(?:powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|cmd(?:\.exe)?\s+/[ck])",
            re.IGNORECASE | re.DOTALL,
        ),
        88,
        "Persistence.TaskXML.MaliciousExec",
        "WeaponizedTaskXML",
        "Zamanlanmış görev XML tanımı içinde gizlenmiş zararlı çalıştırma komutu",
    ),
    (
        ("discord_desktop_core", "app.asar", "browserwindow", "webrequest"),
        re.compile(
            r"(?:discord_desktop_core|app\.asar|BrowserWindow).{0,450}?(?:webRequest\.onBeforeRequest|discord\.com/api/webhooks/|api/v\d+/users/@me|mfa\.[A-Za-z0-9_-]{10,}|Authorization)",
            re.IGNORECASE | re.DOTALL,
        ),
        94,
        "Trojan.Stealer.ElectronDiscordInject",
        "ElectronDiscordInjection",
        "Electron / Discord desktop_core istemci enjeksiyonu ve oturum/token hırsızlığı",
    ),
    (
        ("solana", "local extension settings", "bravesoftware", "phantom"),
        re.compile(
            r"(?:solana[/\\]id\.json|Local Extension Settings|Phantom|MetaMask|BraveSoftware.{0,140}?Login Data).{0,500}?(?:child_process|subprocess\.Popen|urllib\.request|requests\.post|fetch\s*\(|http\.request)",
            re.IGNORECASE | re.DOTALL,
        ),
        95,
        "APT.Lazarus.SupplyChainStealer",
        "DPRK_Lazarus_BeaverTail",
        "DPRK Lazarus / BeaverTail tarzı kripto cüzdan, tarayıcı eklenti ve anahtar sızdırma zinciri",
    ),
    # --- Website Virus & Web-Borne Threat Detection Rules ---
    (
        ("clipboard", "execcommand", "win + r", "windows + r", "verify you are human", "cloudflare"),
        re.compile(
            r"(?:(?:navigator\.clipboard\.writeText|document\.execCommand\s*\(\s*['\"]copy['\"]\)).{0,450}?(?:powershell|pwsh|mshta|cmd(?:\.exe)?|curl\s+|iex\b|irm\b|http://|https://)"
            r"|(?:Win\s*\+\s*R|Windows\s*\+\s*R).{0,350}?(?:Ctrl\s*\+\s*V|powershell|mshta|cmd))",
            re.IGNORECASE | re.DOTALL,
        ),
        96,
        "Web.ClickFix.ClipboardSocialEng",
        "WebVirus_ClickFix",
        "ClickFix / Sahte CAPTCHA pano enjeksiyonlu web virüsü saldırısı (Win+R / PowerShell / MSHTA)",
    ),
    (
        ("<svg", "data:application/octet-stream", "data:text/html;base64", "createobjecturl", "mssaveoropenblob"),
        re.compile(
            r"(?:<svg[^>]{0,200}(?:onload\s*=|<script\b|<foreignObject\b)"
            r"|data:(?:application/octet-stream|text/html|application/x-msdownload);base64,[A-Za-z0-9+/=]{24,}"
            r"|(?:URL\.createObjectURL\s*\(\s*new\s+Blob|msSaveOrOpenBlob).{0,300}?(?:atob|Uint8Array|fromCharCode|download\s*=))",
            re.IGNORECASE | re.DOTALL,
        ),
        94,
        "Web.HTMLSmuggling.SVGDropper",
        "WebVirus_HTMLSmuggling",
        "HTML / SVG Smuggling ile tarayıcı içi gizli zararlı dosya oluşturma ve indirme (Dropper)",
    ),
    (
        ("coinhive", "cryptoloot", "deepminer", "webminerpool", "stratum+tcp", "moneroocean", "cryptonight", "xmrig"),
        re.compile(
            r"(?:CoinHive\.Anonymous|CryptoLoot\.Anonymous|deepMiner|webminerpool|stratum\+tcp://|moneroocean|cryptonight\s*wasm|xmrig|WebAssembly\.instantiate.{0,250}?(?:miner|hashrate|nonce|stratum))",
            re.IGNORECASE | re.DOTALL,
        ),
        88,
        "Web.Cryptojacker.WasmMiner",
        "WebVirus_Cryptojacker",
        "Web sitesi kaynaklı gizli kripto madenciliği (Cryptojacking / WASM Miner) betiği",
    ),
    (
        ("cardnumber", "cc_number", "cvv", "creditcard", "billing_card", "exp_month"),
        re.compile(
            r"(?:cardnumber|cc_number|credit_?card|billing_card|card_?cvv|cvv2).{0,450}?(?:sendBeacon|XMLHttpRequest|fetch\s*\(|new\s+Image\s*\(|btoa\s*\(|discord\.com/api/webhooks|api\.telegram\.org)",
            re.IGNORECASE | re.DOTALL,
        ),
        93,
        "Web.Skimmer.MagecartCardTheft",
        "WebVirus_MagecartSkimmer",
        "Magecart / Web Skimmer ödeme formu ve kredi kartı bilgisi sızdırma virüsü",
    ),
    (
        ("eval(", "function(", "document.write(", "activexobject", "window.location"),
        re.compile(
            r"(?:(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\("
            r"|document\.write\s*\(\s*(?:unescape|atob|decodeURIComponent)\s*\("
            r"|new\s+ActiveXObject\s*\(\s*['\"](?:WScript\.Shell|MSXML2\.XMLHTTP|ADODB\.Stream|Shell\.Application)['\"]"
            r"|window\.location(?:\.replace|\.href)\s*[=(]\s*['\"]data:text/html;base64,)",
            re.IGNORECASE | re.DOTALL,
        ),
        88,
        "Web.ObfuscatedJS.Dropper",
        "WebVirus_ObfuscatedJS",
        "Gizlenmiş zararlı JavaScript yürütücüsü (eval/atob/unescape/ActiveX Dropper)",
    ),
    (
        ("api.telegram.org/bot", "discord.com/api/webhooks", "action=\"http://", "action='http://"),
        re.compile(
            r"(?:<form[^>]{0,250}?action\s*=\s*['\"]https?://(?:\d{1,3}\.){3}\d{1,3}[^\s'\"]{0,120}['\"]"
            r"|(?:password|passwd|card_?number|otp_?code|seed_?phrase).{0,400}?(?:api\.telegram\.org/bot|discord\.com/api/webhooks/))",
            re.IGNORECASE | re.DOTALL,
        ),
        89,
        "Web.PhishingKit.CredentialHarvest",
        "WebVirus_PhishingKit",
        "Oltalama (Phishing) formu: parola/kart verilerini doğrudan IP veya Telegram/Discord'a sızdırma",
    ),
    (
        ("webrequestblocking", "<all_urls>", "declarativenetrequest", "clipboardread"),
        re.compile(
            r"(?:<all_urls>.{0,450}?(?:webRequestBlocking|cookies|clipboardRead).{0,450}?(?:eval\s*\(|new\s+Function|discord\.com/api/webhooks|api\.telegram\.org|fetch\s*\(\s*['\"]https?://(?:\d{1,3}\.){3}\d{1,3}))",
            re.IGNORECASE | re.DOTALL,
        ),
        90,
        "Web.BrowserExt.MaliciousHijack",
        "WebVirus_MaliciousExtension",
        "Zararlı tarayıcı eklentisi: tüm sitelerde çerez/pano/ağ trafiği ele geçirme",
    ),
    (
        ("search-ms:", "crumb=location:", "iconfile=\\\\", "workingdirectory=\\\\"),
        re.compile(
            r"(?:search-ms:[^\r\n]{0,200}?crumb=location:\\\\|IconFile\s*=\s*\\\\[A-Za-z0-9_.-]+\\|WorkingDirectory\s*=\s*\\\\[A-Za-z0-9_.-]+\\)",
            re.IGNORECASE,
        ),
        94,
        "Web.SearchMS.NTLMDriveBy",
        "WebVirus_SearchMS_NTLM",
        "Web kaynaklı search-ms / URL dosyası üzerinden uzaktan SMB/NTLM kimlik avı ve sürücü yükleme",
    ),
    (
        ("clipboard", "settext", "gettext", "addclipboardformatlistener", "btc", "bc1", "monero", "trc20", "erc20"),
        re.compile(
            r"(?:(?:GetText|Clipboard\.Get|AddClipboardFormatListener|GetClipboardData).{0,450}?(?:SetText|Clipboard\.Set|SetClipboardData).{0,450}?(?:bc1[qpzry9x8gf2tvdw0s]|0x[a-fA-F0-9]{40}|T[A-Za-z1-9]{33}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}|wallet|btc|eth|xmr|usdt)"
            r"|(?:AddClipboardFormatListener|SetClipboardData).{0,400}?(?:bc1|TRC20|ERC20|Monero|Exodus))",
            re.IGNORECASE | re.DOTALL,
        ),
        90,
        "Trojan.ClipBanker.CryptoHijacker",
        "ClipBanker_Trojan",
        "Pano izleme ve kripto para cüzdan adresi değiştirme (ClipBanker) truva atı davranışı",
    ),
    (
        ("createdesktop", "opendesktop", "switchdesktop", "setthreaddesktop", "printwindow"),
        re.compile(
            r"(?:CreateDesktop[AW]?\s*.{0,450}?(?:SetThreadDesktop|OpenDesktop|SwitchDesktop|BitBlt|PrintWindow))",
            re.IGNORECASE | re.DOTALL,
        ),
        88,
        "Trojan.RAT.HiddenVNC",
        "HiddenVNC_RAT",
        "Gizli masaüstü (Hidden VNC / HVNC) oluşturma ve arka plan ekran kontrol API zinciri",
    ),
    (
        ("key4.db", "logins.json", "pk11sdr_decrypt", "tdata", "d877f783d5d3ef8c", "ielevator", "vaultenumerateitems", "filezilla", "recentservers.xml"),
        re.compile(
            r"(?:(?:key4\.db|logins\.json|PK11SDR_Decrypt|tdata[/\\]D877F783D5D3EF8C|IElevator|VaultEnumerateItems|FileZilla[/\\](?:recentservers|sitemanager)\.xml).{0,450}?(?:webhook|api\.telegram\.org|HttpClient|WebClient|MultipartFormData|requests\.post|fetch\s*\(|urllib|TcpClient|ZipArchive|CreateFromDirectory|CryptUnprotectData|NSS_Init))",
            re.IGNORECASE | re.DOTALL,
        ),
        93,
        "Trojan.Stealer.MultiAppHarvest",
        "MultiApp_InfoStealer",
        "Çoklu uygulama (Firefox/Telegram/Chrome App-Bound/FileZilla) kimlik bilgisi toplama ve sızdırma zinciri",
    ),
    (
        ("disabletaskmgr", "disableregistrytools", "windefend", "mpcmdrun", "taskkill", "mssense", "aegis"),
        re.compile(
            r"(?:(?:DisableTaskMgr|DisableRegistryTools|DisableCMD)\s*(?:=|:|/d)\s*[\"']?1"
            r"|(?:net(?:\.exe)?\s+stop|sc(?:\.exe)?\s+(?:stop|config|delete))\s+(?:WinDefend|WdNisSvc|Sense|SecurityHealthService|MpsSvc)"
            r"|MpCmdRun(?:\.exe)?\s+.{0,120}?-RemoveDefinitions"
            r"|taskkill(?:\.exe)?\s+/f\s+/im\s+(?:MsMpEng|MpDefenderCoreService|AegisScanner|Taskmgr|ProcessHacker|procexp))",
            re.IGNORECASE | re.DOTALL,
        ),
        94,
        "Trojan.DefenseEvasion.SecurityKiller",
        "Security_Tamper_Killer",
        "Güvenlik servislerini, Defender imzalarını veya Görev Yöneticisi/Kayıt Defterini devre dışı bırakma saldırısı",
    ),
    (
        ("tcpclient", "socket.socket", "net.createconnection", "redirectstandardinput", "dup2", "/c cmd", "cmd.exe"),
        re.compile(
            r"(?:(?:System\.Net\.Sockets\.TcpClient|New-Object\s+Net\.Sockets\.TcpClient).{0,450}?(?:GetStream|StreamReader|StreamWriter|cmd\.exe|powershell|RedirectStandardInput)"
            r"|(?:socket\.socket\s*\(|net\.createConnection\s*\(|net\.Socket\s*\().{0,450}?(?:subprocess|pty\.spawn|child_process|cmd\.exe|powershell|dup2))",
            re.IGNORECASE | re.DOTALL,
        ),
        90,
        "Trojan.Backdoor.ReverseShell",
        "ReverseShell_Backdoor",
        "Etkileşimli ters kabuk (Reverse Shell) TCP soket arka kapı kalıbı",
    ),
    (
        ("inprocserver32", "command processor", "appinit_dlls", "security packages", "treatas"),
        re.compile(
            r"(?:Software\\Classes\\CLSID\\\{[0-9a-fA-F-]{36}\}\\(?:InprocServer32|LocalServer32|TreatAs)"
            r"|Software\\Microsoft\\Command Processor[^\r\n]{0,160}?AutoRun"
            r"|Windows NT\\CurrentVersion\\Windows[^\r\n]{0,160}?AppInit_DLLs"
            r"|Control\\Lsa[^\r\n]{0,160}?(?:Security Packages|Notification Packages))",
            re.IGNORECASE,
        ),
        88,
        "Trojan.Persistence.COMOrAutoRunHijack",
        "COM_AutoRun_Persistence",
        "COM CLSID, Command Processor AutoRun, AppInit_DLLs veya LSA Paketi kalıcılık gaspı",
    ),
    (
        ("gcm", "get-command", "gal", "get-alias", "dir alias:"),
        re.compile(
            r"(?:&\s*\(\s*(?:gcm|Get-Command|gal|Get-Alias|dir\s+alias:)\s+[^\r\n\)]{1,80}\*[^\r\n\)]{0,80}\))",
            re.IGNORECASE,
        ),
        86,
        "Obfuscation.PowerShell.WildcardIEX",
        "PowerShell_Wildcard_Obfuscation",
        "PowerShell joker karakterli dinamik komut çözümleme (&(gcm *...*)) gizleme tekniği",
    ),
]


def _scan_corpus_rules(corpus_text: str, corpus_lower: Optional[str] = None) -> List[Tuple[int, str, str, str]]:
    """Fast prefiltered rule evaluator (O(N) Boyer-Moore C keyword check before regex compilation engine)."""
    low = corpus_lower if corpus_lower is not None else corpus_text.lower()
    hits: List[Tuple[int, str, str, str]] = []
    for kws, compiled_rx, r_score, t_name, cat, desc in _SUPERLX_COMPILED_RULES:
        if any(kw in low for kw in kws) and compiled_rx.search(corpus_text):
            hits.append((r_score, t_name, cat, desc))
    if ("assembly" in low or "dynamicinvoke" in low) and "invoke" in low:
        if all(rx.search(corpus_text) for rx in _MANAGED_CRYPTER_PARTS):
            hits.append((92, "RAT.MSIL.EncryptedReflectiveLoader", "AntiRAT_ManagedCrypter", ".NET Yönetimli Bellek İçi Şifreli RAT Yükleyici (AsyncRAT/DcRat/Remcos Crypter)"))
    return hits


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    if length >= 4096:
        inv = 1.0 / length
        entropy = 0.0
        log2 = math.log2
        count_fn = data.count
        for b in range(256):
            cnt = count_fn(b)
            if cnt:
                p = cnt * inv
                entropy -= p * log2(p)
        return round(entropy, 4)
    counts = Counter(data)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 4)


_MAX_DECOMP_BYTES = 2 * 1024 * 1024


def _is_plausible_decomp(raw_b: bytes) -> bool:
    if not raw_b:
        return False
    if raw_b.startswith(b"MZ") and b"PE\x00\x00" in raw_b[:1024]:
        return True
    sample = raw_b[:2048]
    if len(sample) >= 6:
        ascii_ratio = sum(32 <= b <= 126 or b in (9, 10, 13) for b in sample) / len(sample)
        if ascii_ratio >= 0.70:
            return True
        if b"\x00" in sample[:64]:
            u16 = sample.decode("utf-16le", errors="ignore")
            if len(u16) >= 4:
                u16_ratio = sum(32 <= ord(c) <= 126 or c in "\r\n\t" for c in u16) / len(u16)
                if u16_ratio >= 0.70:
                    return True
    return False


def _try_decompress_b64_payload(raw_b: bytes) -> Tuple[bytes, Optional[str]]:
    import zlib
    if raw_b.startswith(b"\x1f\x8b\x08"):
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = d.decompress(raw_b, _MAX_DECOMP_BYTES)
            if out:
                return out, "Base64+GZip"
        except Exception:
            pass
    if len(raw_b) >= 4 and raw_b[0] == 0x78 and raw_b[1] in (0x01, 0x5E, 0x9C, 0xDA):
        try:
            d = zlib.decompressobj(zlib.MAX_WBITS)
            out = d.decompress(raw_b, _MAX_DECOMP_BYTES)
            if out:
                return out, "Base64+Zlib"
        except Exception:
            pass
    if len(raw_b) >= 8 and not _is_plausible_decomp(raw_b):
        try:
            d = zlib.decompressobj(-zlib.MAX_WBITS)
            out = d.decompress(raw_b, _MAX_DECOMP_BYTES)
            if (d.eof or len(out) >= 12) and _is_plausible_decomp(out):
                return out, "Base64+RawDeflate"
        except Exception:
            pass
    return raw_b, None


def _decode_b64_tokens(text: str, budget: int = 240, min_token_len: int = 16) -> Tuple[List[str], List[str], bool]:
    """Decode up to `budget` unique Base64/URL-safe Base64 blobs, longest-first, without truncation blind spots."""
    decoded_texts: List[str] = []
    notes: List[str] = []
    found_pe = False

    # Rejoin wrapped Base64 split across quotes or line continuations before scanning
    cleaned = re.sub(r"['\"]\s*\+\s*['\"]", "", text)
    cands = re.findall(rf"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{{{min_token_len},}}={{0,2}})(?![A-Za-z0-9+/=_-])", cleaned)
    # Deduplicate and sort longest-first so large hidden payloads are never pushed out by small noise
    seen_cands: List[str] = sorted(set(cands), key=len, reverse=True)[:budget]

    for cand in seen_cands:
        norm = cand.replace("-", "+").replace("_", "/")
        pad = (-len(norm)) % 4
        if pad:
            norm += "=" * pad
        try:
            raw_b = base64.b64decode(norm, validate=True)
        except Exception:
            continue

        raw_b, comp_tag = _try_decompress_b64_payload(raw_b)
        if comp_tag:
            notes.append(f"{comp_tag} sıkıştırılmış gizli yük açıldı")

        if raw_b.startswith(b"MZ") and b"PE\x00\x00" in raw_b[:1024]:
            found_pe = True
            notes.append("Base64 içinde gizlenmiş çalıştırılabilir Windows PE (MZ) dosyası")
            continue

        for enc in ("utf-8", "utf-16le", "ascii"):
            try:
                dec = raw_b.decode(enc, errors="ignore")
            except Exception:
                continue
            if len(dec) >= 6:
                printable = sum(32 <= ord(c) <= 126 or c in "\r\n\t" for c in dec) / len(dec)
                if printable > 0.74:
                    decoded_texts.append(dec)
                    if not comp_tag:
                        notes.append("Gizli Base64 payload katmanı çözümlendi")
                    break

    return decoded_texts, list(dict.fromkeys(notes)), found_pe


_STANDARD_BATCH_VARS = {
    "temp", "tmp", "appdata", "localappdata", "comspec", "systemroot", "windir",
    "userprofile", "programdata", "programfiles", "programfiles(x86)", "public",
    "path", "username", "userdomain", "computername", "os", "cd", "homedrive",
    "homepath", "systemdrive", "pathext", "random", "date", "time", "errorlevel",
    "allusersprofile", "commonprogramfiles", "commonprogramfiles(x86)", "psmodulepath",
}

_SCRENC_PICK = (
    1, 2, 0, 1, 2, 0, 2, 0, 0, 2, 0, 2, 1, 0, 2, 0,
    1, 0, 2, 0, 1, 1, 2, 0, 0, 2, 1, 0, 2, 0, 0, 2,
    1, 1, 0, 2, 0, 2, 0, 1, 0, 1, 1, 2, 0, 1, 0, 2,
    1, 0, 2, 0, 1, 1, 2, 0, 0, 1, 1, 2, 0, 1, 0, 2,
)
_SCRENC_TABLES = (
    # Table 0 (ROW_2)
    {100:9,80:32,34:33,74:34,97:35,94:36,93:37,91:38,66:39,96:40,35:41,101:42,95:43,126:44,79:45,82:46,122:47,33:48,70:49,32:50,38:51,99:52,42:53,118:54,71:55,37:56,44:57,41:58,105:59,60:60,39:61,62:62,103:63,64:64,98:65,65:66,90:67,102:68,50:69,115:70,77:71,67:72,113:73,57:74,124:75,83:76,72:77,49:78,114:79,110:80,112:81,73:82,63:83,75:84,106:85,46:86,127:87,40:88,53:89,125:90,36:91,45:92,84:93,55:94,123:95,61:96,108:97,52:98,109:99,78:100,43:101,48:102,111:103,116:104,107:105,76:106,51:107,86:108,58:109,120:110,87:111,119:112,59:113,68:114,47:115,89:116,69:117,92:118,104:119,54:120,88:121,121:122,9:123,117:124,56:125,85:126},
    # Table 1 (ROW_0)
    {55:9,126:32,90:33,69:34,58:35,121:36,89:37,39:38,118:39,99:40,98:41,77:42,81:43,83:44,82:45,32:46,38:47,84:48,113:49,43:50,102:51,42:52,88:53,127:54,123:55,48:56,49:57,108:58,73:59,60:60,120:61,62:62,95:63,64:64,41:65,36:66,47:67,57:68,51:69,111:70,33:71,117:72,40:73,66:74,70:75,74:76,92:77,72:78,54:79,75:80,125:81,93:82,106:83,80:84,105:85,35:86,9:87,112:88,101:89,116:90,44:91,119:92,68:93,63:94,109:95,124:96,67:97,56:98,94:99,91:100,110:101,87:102,76:103,52:104,114:105,37:106,86:107,115:108,104:109,85:110,71:111,50:112,53:113,46:114,100:115,79:116,59:117,45:118,65:119,97:120,122:121,34:122,96:123,107:124,78:125,61:126},
    # Table 2 (ROW_1)
    {105:9,44:32,101:33,114:34,91:35,102:36,117:37,76:38,69:39,118:40,42:41,67:42,51:43,66:44,32:45,99:46,74:47,90:48,56:49,121:50,50:51,87:52,108:53,43:54,70:55,82:56,79:57,61:58,112:59,60:60,123:61,62:62,81:63,64:64,122:65,126:66,59:67,71:68,65:69,119:70,86:71,95:72,38:73,120:74,110:75,100:76,116:77,103:78,125:79,104:80,53:81,34:82,85:83,58:84,96:85,106:86,113:87,111:88,73:89,92:90,93:91,39:92,89:93,37:94,124:95,35:96,109:97,40:98,49:99,57:100,127:101,54:102,84:103,52:104,98:105,78:106,48:107,94:108,115:109,9:110,75:111,97:112,36:113,77:114,107:115,68:116,33:117,55:118,83:119,88:120,72:121,46:122,80:123,45:124,41:125,63:126},
)
_SCRENC_ESCAPES = {"#": "\r", "&": "\n", "!": "<", "*": ">", "$": "@"}


def _decode_ms_script_encode(text: str) -> Tuple[List[str], Optional[str]]:
    """Decode Microsoft Script Encoder (#@~^...^#~@) payloads used in .vbe / .jse / .hta trojans."""
    if "#@~^" not in text:
        return [], None
    decoded_blocks: List[str] = []
    pos = 0
    while len(decoded_blocks) < 8:
        start = text.find("#@~^", pos)
        if start == -1:
            break
        hdr_end = text.find("==", start + 4)
        if hdr_end == -1 or hdr_end - (start + 4) > 12:
            break
        body_start = hdr_end + 2
        end_marker = text.find("^#~@", body_start)
        if end_marker == -1:
            end_marker = min(len(text), body_start + 512 * 1024)
            payload_end = end_marker
        else:
            # Strip 6-char base64 CRC + '==' immediately before ^#~@
            payload_end = max(body_start, end_marker - 8)
            try:
                len_b64 = text[start + 4:hdr_end] + "=="
                decl_len = struct.unpack("<I", base64.b64decode(len_b64))[0]
            except Exception:
                decl_len = 0
            # Re-verify if payload uses plain text up to end_marker - 8
            if decl_len and body_start + decl_len <= end_marker:
                payload_end = max(payload_end, body_start + decl_len)

        encoded = text[body_start:payload_end]
        out_chars: List[str] = []
        i = 0
        key_pos = 0
        n = len(encoded)
        while i < n:
            ch = encoded[i]
            if ch == "@" and i + 1 < n and encoded[i + 1] in _SCRENC_ESCAPES:
                out_chars.append(_SCRENC_ESCAPES[encoded[i + 1]])
                i += 2
                key_pos += 1
                continue
            code = ord(ch)
            tbl = _SCRENC_TABLES[_SCRENC_PICK[key_pos & 63]]
            if code in tbl:
                out_chars.append(chr(tbl[code]))
                key_pos += 1
            elif ch in ("\r", "\n"):
                out_chars.append(ch)
            else:
                out_chars.append(ch)
                key_pos += 1
            i += 1
        dec_str = "".join(out_chars).strip()
        if len(dec_str) >= 6:
            decoded_blocks.append(dec_str)
        pos = end_marker + 4
    if decoded_blocks:
        return decoded_blocks, "Microsoft Script Encoder (.vbe/.jse) yükü çözüldü"
    return [], None


def _resolve_variables_and_format(text: str) -> Tuple[str, List[str]]:
    """Expand PowerShell $var='...', -f format, Batch set var=..., BatCloak %var:~pos,len% slicing, and reversed strings."""
    added: List[str] = []
    notes: List[str] = []

    # 1. PowerShell "{1}{0}" -f 'a','b' format strings
    fmt_rx = re.compile(r"['\"]([^{}'\"]*(?:\{\d+\}[^{}'\"]*)+)['\"]\s*-f\s*((?:['\"][^'\"]*['\"]\s*,?\s*)+)", re.IGNORECASE)
    for tmpl, arg_str in fmt_rx.findall(text)[:25]:
        args = re.findall(r"['\"]([^'\"]*)['\"]", arg_str)
        if args:
            try:
                expanded = re.sub(r"\{(\d+)\}", lambda m: args[int(m.group(1))] if int(m.group(1)) < len(args) else m.group(0), tmpl)
                if expanded != tmpl:
                    added.append(expanded)
                    notes.append("PowerShell -f format gizlemesi çözüldü")
            except Exception:
                pass

    # 2. PowerShell & Batch variable assignment + BatCloak %var:~start,len% substring slicing
    ps_vars: Dict[str, str] = {}
    batch_vars: Dict[str, str] = {}
    for vn, vv in re.findall(r"\$([A-Za-z_][A-Za-z0-9_]{0,32})\s*=\s*['\"]([^'\"\r\n]{1,260})['\"]", text)[:120]:
        ps_vars["$" + vn.lower()] = vv
    for vn, vv in re.findall(r"(?:^|\n|&)\s*(?:set|SET)\s+(?:/[aApP]\s+)?\"?([A-Za-z_][A-Za-z0-9_]{0,32})=([^\r\n&\"]{1,512})\"?", text)[:140]:
        batch_vars[vn.strip().lower()] = vv.rstrip("\r\n").rstrip('"')

    # Resolve %var:~start,len% and !var:~start,len! substring slicing (BatCloak)
    if batch_vars and (":~" in text):
        slice_rx = re.compile(r"[%!]([A-Za-z_][A-Za-z0-9_]{0,32}):~(-?\d+)(?:,(-?\d+))?[%!]")
        def _eval_slice(m: re.Match) -> str:
            val = batch_vars.get(m.group(1).lower())
            if val is None:
                return m.group(0)
            st = int(m.group(2))
            ln = int(m.group(3)) if m.group(3) is not None else None
            if st < 0:
                st = max(0, len(val) + st)
            if ln is None:
                return val[st:]
            if ln < 0:
                return val[st:len(val) + ln] if (len(val) + ln) > st else ""
            return val[st:st + ln]
        sliced = slice_rx.sub(_eval_slice, text)
        if sliced != text:
            # Also resolve plain %var% / !var! on the sliced result
            for bvn, bvv in batch_vars.items():
                ps_vars["%" + bvn + "%"] = bvv
                ps_vars["!" + bvn + "!"] = bvv
            added.append(sliced)
            notes.append("BatCloak (%var:~pos,len%) dilimleme gizlemesi çözüldü")
    else:
        for bvn, bvv in batch_vars.items():
            ps_vars["%" + bvn + "%"] = bvv
            ps_vars["!" + bvn + "!"] = bvv

    if ps_vars:
        max_expanded_len = min(2 * 1024 * 1024, max(65536, len(text) * 4))
        ordered_keys = sorted(ps_vars.keys(), key=len, reverse=True)
        combined_var_rx = re.compile("|".join(re.escape(k) for k in ordered_keys), re.IGNORECASE)
        base_for_sub = added[-1] if added else text
        sub_text = combined_var_rx.sub(lambda m: ps_vars.get(m.group(0).lower(), m.group(0)), base_for_sub)
        if len(sub_text) > max_expanded_len:
            sub_text = sub_text[:max_expanded_len]
        sub_text = re.sub(r"\s*\+\s*", "", sub_text)
        sub_text = sub_text.replace("''", "").replace('""', "")
        if sub_text != base_for_sub:
            added.append(sub_text)
            notes.append("Değişken birleştirme (Variable Substitution) gizlemesi çözüldü")

    # Strip undefined/junk Batch %junk% tokens (preserve real Windows env vars)
    if "%" in text:
        current_sub = added[-1] if added else text
        junk_rx = re.compile(r"%([A-Za-z0-9_@$-]{2,28})%")
        def _strip_junk(m: re.Match) -> str:
            tok = m.group(1).lower()
            if tok in _STANDARD_BATCH_VARS or tok in batch_vars:
                return m.group(0)
            return ""
        unjunked = junk_rx.sub(_strip_junk, current_sub)
        if unjunked != current_sub and len(current_sub) - len(unjunked) >= 6:
            added.append(unjunked)
            notes.append("Batch sahte/çöp değişken (%junk%) gizlemesi temizlendi")

    # 3. Simple .Replace('X','') / %var:X=% obfuscation stripping
    for lit, pat_s, rep_s in re.findall(r"['\"]([^'\"]{8,180})['\"]\s*\.Replace\(\s*['\"]([^'\"]{1,16})['\"]\s*,\s*['\"]([^'\"]*)['\"]\s*\)", text, re.IGNORECASE)[:15]:
        cleaned = lit.replace(pat_s, rep_s)
        if cleaned != lit:
            added.append(cleaned)
            notes.append(".Replace() karakter enjeksiyon gizlemesi çözüldü")

    # 4. String Reversal (PowerShell [-1..-n] / Array.Reverse / VBS StrReverse)
    if re.search(r"StrReverse|::Reverse\s*\(|\[\s*-1\s*\.\.", text, re.IGNORECASE):
        for s_lit in re.findall(r"['\"]([^'\"\r\n]{10,400})['\"]", text)[:25]:
            rev = s_lit[::-1]
            if any(k in rev.lower() for k in ("invoke", "powershell", "wscript", "http", "mshta", "certutil", "virtualalloc", "amsi", "download", "cmd.exe")):
                added.append(rev)
                notes.append("Ters çevrilmiş (String-Reverse) zararlı komut çözüldü")

    # 5. PowerShell array -join '' & [string]::Join('', (...)) reconstruction
    join_rx = re.compile(r"\(\s*((?:['\"][^'\"]{1,48}['\"]\s*,\s*){1,32}['\"][^'\"]{1,48}['\"])\s*\)\s*-join\s*['\"]{2}", re.IGNORECASE)
    for grp in join_rx.findall(text)[:20]:
        tokens = re.findall(r"['\"]([^'\"]*)['\"]", grp)
        if tokens:
            added.append("".join(tokens))
            notes.append("PowerShell -join dizi gizlemesi çözüldü")
    for grp in re.findall(r"\[string\]::Join\(\s*['\"]{2}\s*,\s*\(([^)]{4,800})\)\s*\)", text, re.IGNORECASE)[:15]:
        tokens = re.findall(r"['\"]([^'\"]*)['\"]", grp)
        if tokens:
            added.append("".join(tokens))
            notes.append("PowerShell -join dizi gizlemesi çözüldü")

    return ("\n".join(added) if added else ""), list(dict.fromkeys(notes))


def _decode_xor_and_encodings(text: str) -> Tuple[List[str], List[str]]:
    layers: List[str] = []
    notes: List[str] = []

    # [char]73+[char]69+[char]88 / [char]0x49
    for cm in re.findall(r"(?:\[char\]\s*(?:0x[0-9a-fA-F]+|\d+)(?:\s*\+\s*)?){3,}", text, re.IGNORECASE)[:12]:
        nums: List[int] = []
        for tok in re.findall(r"0x[0-9a-fA-F]+|\d+", cm):
            val = int(tok, 16) if tok.lower().startswith("0x") else int(tok)
            if 9 <= val <= 126:
                nums.append(val)
        if nums:
            layers.append("".join(chr(n) for n in nums))
            notes.append(f"[char] dizisi çözüldü ({len(nums)} karakter)")

    # [char[]]@(73,69,88...) or Chr(112)+Chr(111)... or String.fromCharCode(112,111,...)
    for group_rx, tag in (
        (r"@\(\s*((?:(?:0x[0-9a-fA-F]{1,2}|\d{2,3})\s*,\s*){3,}(?:0x[0-9a-fA-F]{1,2}|\d{2,3}))\s*\)", "Sayısal char dizisi"),
        (r"(?:ChrW?\(\s*\d{2,3}\s*\)\s*(?:\+|&)\s*){3,}ChrW?\(\s*\d{2,3}\s*\)", "VBS Chr() dizisi"),
        (r"String\.fromCharCode\s*\(\s*((?:\d{2,3}\s*,\s*){4,}\d{2,3})\s*\)", "JS fromCharCode()"),
    ):
        for gm in re.findall(group_rx, text, re.IGNORECASE)[:10]:
            nums = []
            for tok in re.findall(r"0x[0-9a-fA-F]+|\d+", gm):
                val = int(tok, 16) if tok.lower().startswith("0x") else int(tok)
                if 9 <= val <= 126:
                    nums.append(val)
            if len(nums) >= 4:
                layers.append("".join(chr(n) for n in nums))
                notes.append(f"{tag} çözüldü ({len(nums)} karakter)")

    # Hex sequences: \x4d\x5a..., 0x4d,0x5a..., or continuous FromHexString('496e76...')
    for hs in re.findall(r"(?:\\x[0-9a-fA-F]{2}){6,}", text)[:10]:
        try:
            raw_b = bytes.fromhex(hs.replace("\\x", ""))
            txt = raw_b.decode("utf-8", errors="ignore")
            if raw_b.startswith(b"MZ") or any(32 <= b <= 126 for b in raw_b):
                layers.append(txt if txt.strip() else f"HEX_BIN:{raw_b[:8].hex()}")
                notes.append("Hex (\\x) kodlu yük çözüldü")
        except Exception:
            pass

    for hx_blob in re.findall(r"FromHexString\s*\(\s*['\"]([0-9a-fA-F]{16,})['\"]\s*\)", text, re.IGNORECASE)[:10]:
        try:
            raw_b = bytes.fromhex(hx_blob)
            layers.append(raw_b.decode("utf-8", errors="ignore"))
            notes.append("Continuous Hex String payload çözüldü")
        except Exception:
            pass

    # Single-byte XOR brute force when file uses -bxor / xor / ^ over integer arrays OR Base64 blobs
    if re.search(r"-bxor\b|\bxor\b", text, re.IGNORECASE):
        keywords = ("http", "iex", "invoke", "powershell", "virtualalloc", "wscript", "cmd", "download", "amsi", "frombase64", "system.")
        byte_arrays = re.findall(r"(?:(?:0x[0-9a-fA-F]{1,2}|\d{1,3})\s*,\s*){10,}(?:0x[0-9a-fA-F]{1,2}|\d{1,3})", text)
        for arr in byte_arrays[:6]:
            raw_ints = []
            for tok in re.findall(r"0x[0-9a-fA-F]+|\d+", arr)[:400]:
                v = int(tok, 16) if tok.lower().startswith("0x") else int(tok)
                if 0 <= v <= 255:
                    raw_ints.append(v)
            if len(raw_ints) >= 12:
                for key in range(1, 256):
                    cand_bytes = bytes(b ^ key for b in raw_ints)
                    printable = sum(32 <= c <= 126 or c in (10, 13, 9) for c in cand_bytes) / len(cand_bytes)
                    if printable >= 0.85:
                        decoded = cand_bytes.decode("ascii", errors="ignore")
                        if any(kw in decoded.lower() for kw in keywords):
                            layers.append(decoded)
                            notes.append(f"Tek-bayt XOR şifre kırıldı (Anahtar 0x{key:02x})")
                            break

        for b64_cand in re.findall(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])", text)[:12]:
            try:
                raw_b = base64.b64decode(b64_cand, validate=True)[:1024]
            except Exception:
                continue
            if len(raw_b) >= 12:
                for key in range(1, 256):
                    cand_bytes = bytes(b ^ key for b in raw_b)
                    printable = sum(32 <= c <= 126 or c in (10, 13, 9) for c in cand_bytes) / len(cand_bytes)
                    if printable >= 0.85:
                        decoded = cand_bytes.decode("ascii", errors="ignore")
                        if any(kw in decoded.lower() for kw in keywords):
                            layers.append(decoded)
                            notes.append(f"Base64+XOR katmanlı şifre kırıldı (Anahtar 0x{key:02x})")
                            break

    # HTML/URL percent & entity decode for smuggling pages
    if "%" in text and re.search(r"%[0-9a-fA-F]{2}", text):
        unq = urllib.parse.unquote(text)
        if unq != text and any(k in unq.lower() for k in ("<script", "atob(", "powershell", "activexobject", "blob(")):
            layers.append(unq)
            notes.append("URL (%XX) kodlu HTML/JS gizlemesi çözüldü")
    if "&#" in text:
        unesc = html_lib.unescape(text)
        if unesc != text and any(k in unesc.lower() for k in ("<script", "atob(", "powershell", "wscript", "mshta")):
            layers.append(unesc)
            notes.append("HTML Entity (&#...) gizlemesi çözüldü")

    # JS / JSON \uXXXX Unicode escape decoding
    if "\\u00" in text or re.search(r"(?:\\u[0-9a-fA-F]{4}){4,}", text):
        try:
            u_dec = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)
            if u_dec != text:
                layers.append(u_dec)
                notes.append("Unicode \\uXXXX kaçış gizlemesi çözüldü")
        except Exception:
            pass

    return layers, list(dict.fromkeys(notes))


def deobfuscate_layers(raw_text: str, is_binary: bool = False) -> Tuple[str, List[str]]:
    """Çok turlu, özyinelemeli (recursive) obfuscation kırıcı."""
    all_notes: List[str] = []
    layers: List[str] = [raw_text]

    if not is_binary and "#@~^" in raw_text:
        sc_blocks, sc_note = _decode_ms_script_encode(raw_text)
        if sc_blocks:
            layers.extend(sc_blocks)
            if sc_note:
                all_notes.append(sc_note)

    if is_binary:
        joined = raw_text
    else:
        # Pre-pass: collapse PowerShell line continuation backticks & strip caret/backtick escapes & string concats
        work_text = "\n".join(layers)
        normalized = re.sub(r"`\r?\n\s*", "", work_text)
        # Solve simple arithmetic [char](100+5) before char decoding
        normalized = re.sub(
            r"\[char\]\s*\(\s*(\d+)\s*\+\s*(\d+)\s*\)",
            lambda m: f"[char]{int(m.group(1)) + int(m.group(2))}",
            normalized,
            flags=re.IGNORECASE,
        )
        # Strip Batch caret (^) before any non-newline char AND PowerShell backtick before alphanumeric/symbol
        stripped = re.sub(r"\^([^\r\n])", r"\1", normalized)
        stripped = re.sub(r"`([A-Za-z0-9_\-\.\:/=,\|\(\)'\"%$])", r"\1", stripped)
        joined = re.sub(r"['\"]\s*\+\s*['\"]", "", stripped)
        if joined != work_text:
            layers.append(joined)
            all_notes.append("Caret/Backtick/String-Concat gizlemesi çözüldü")

    resolved_vars, var_notes = _resolve_variables_and_format(joined)
    if resolved_vars:
        layers.append(resolved_vars)
        all_notes.extend(var_notes)

    enc_layers, enc_notes = _decode_xor_and_encodings(joined + "\n" + resolved_vars)
    if enc_layers:
        layers.extend(enc_layers)
        all_notes.extend(enc_notes)

    # Multi-round recursive Base64/GZip/Zlib unwrap (catches B64(B64(GZip(...))) up to 3 layers deep)
    frontier = "\n".join(layers)
    min_b64_len = 40 if is_binary else 16
    total_layer_chars = sum(len(x) for x in layers)
    max_total_layer_chars = 8 * 1024 * 1024
    for _depth in range(3):
        if total_layer_chars >= max_total_layer_chars:
            break
        b64_texts, b64_notes, found_pe = _decode_b64_tokens(frontier, budget=240, min_token_len=min_b64_len)
        all_notes.extend(b64_notes)
        if found_pe:
            layers.append("__EMBEDDED_PE_HEADER__")
        if not b64_texts:
            break
        capped_texts: List[str] = []
        for t in b64_texts:
            rem = max_total_layer_chars - total_layer_chars
            if rem <= 0:
                break
            chunk = t[:rem]
            capped_texts.append(chunk)
            total_layer_chars += len(chunk)
        layers.extend(capped_texts)
        next_vars, next_vnotes = _resolve_variables_and_format("\n".join(capped_texts))
        if next_vars and total_layer_chars < max_total_layer_chars:
            rem = max_total_layer_chars - total_layer_chars
            layers.append(next_vars[:rem])
            total_layer_chars += min(len(next_vars), rem)
            all_notes.extend(next_vnotes)
        frontier = "\n".join(capped_texts) + "\n" + next_vars

    return "\n".join(layers), list(dict.fromkeys(all_notes))


def _rva_to_offset(rva: int, sections: List[Tuple[int, int, int, int]]) -> Optional[int]:
    for vaddr, vsize, rptr, rsize in sections:
        span = max(vsize, rsize)
        if vaddr <= rva < vaddr + span:
            return rptr + (rva - vaddr)
    return None


def _read_cstr(data: bytes, offset: int, max_len: int = 256) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(len(data), offset + max_len))
    if end == -1:
        end = min(len(data), offset + max_len)
    return data[offset:end].decode("ascii", errors="ignore")


def _parse_der_outer_len(buf: bytes, offset: int) -> Optional[int]:
    """Return total byte length of an ASN.1 DER TLV element starting at `offset`."""
    if offset + 2 > len(buf) or buf[offset] != 0x30:
        return None
    b1 = buf[offset + 1]
    if b1 < 0x80:
        return 2 + b1
    num_len = b1 & 0x7F
    if num_len == 0 or num_len > 4 or offset + 2 + num_len > len(buf):
        return None
    content_len = int.from_bytes(buf[offset + 2:offset + 2 + num_len], "big")
    return 2 + num_len + content_len


def _inspect_pe_cert_table_padding(file_path: str, data: bytes, cert_file_off: int, cert_size: int) -> bool:
    """Detect CVE-2013-3900 trailing trojan payloads smuggled inside WIN_CERTIFICATE padding."""
    if cert_file_off <= 0 or cert_size <= 256:
        return False
    try:
        read_len = min(cert_size, 2 * 1024 * 1024)
        if cert_file_off + read_len <= len(data):
            cert_blob = data[cert_file_off:cert_file_off + read_len]
        elif file_path and os.path.isfile(file_path):
            with open(file_path, "rb") as f:
                f.seek(cert_file_off)
                cert_blob = f.read(read_len)
        else:
            return False

        if len(cert_blob) < 16:
            return False
        dw_len, _w_rev, _w_type = struct.unpack_from("<IHH", cert_blob, 0)
        der_len = _parse_der_outer_len(cert_blob, 8)
        if der_len is None:
            return False

        pad_start = 8 + der_len
        if cert_size <= pad_start + 256:
            return False

        trailing = cert_blob[pad_start:min(len(cert_blob), cert_size)]
        if cert_size > len(cert_blob) and file_path and os.path.isfile(file_path):
            extra_len = min(2 * 1024 * 1024, cert_size - pad_start)
            with open(file_path, "rb") as f:
                f.seek(cert_file_off + pad_start)
                trailing = f.read(extra_len)

        nonzero = trailing.replace(b"\x00", b"")
        if len(nonzero) <= 64:
            return False

        low_nz = nonzero.lower()
        if b"MZ" in nonzero and b"PE\x00\x00" in nonzero:
            return True
        if any(tok in low_nz for tok in (b"http://", b"https://", b"powershell", b"<script", b"wscript", b"invoke-", b"frombase64", b"createobject", b"cmd.exe")):
            return True
        if re.search(b"[A-Za-z0-9+/]{36,}={0,2}", nonzero):
            return True
        if len(nonzero) > 1024 and shannon_entropy(nonzero[:65536]) > 5.8:
            return True
    except Exception:
        return False
    return False


def _find_embedded_or_xor_pe(buf: bytes) -> Optional[Tuple[int, int]]:
    """Detect an embedded PE or single-byte XOR'd PE payload inside a buffer. Returns (offset, xor_key)."""
    if len(buf) < 128:
        return None
    # 1. Plaintext embedded PE (strict e_lfanew + PE header check to avoid random 'MZ' false hits)
    pos = 0
    lim = len(buf) - 68
    while pos < lim:
        idx = buf.find(b"MZ", pos)
        if idx == -1 or idx + 64 >= len(buf):
            break
        e_lfa = struct.unpack_from("<I", buf, idx + 0x3C)[0]
        if 0x40 <= e_lfa <= 0x800 and idx + e_lfa + 24 <= len(buf):
            if buf[idx + e_lfa:idx + e_lfa + 4] == b"PE\x00\x00":
                sec_cnt = struct.unpack_from("<H", buf, idx + e_lfa + 6)[0]
                if 1 <= sec_cnt <= 32:
                    return idx, 0
        pos = idx + 2

    # 2. Single-byte XOR'd PE (DOS stub marker across keys 1..255 at C speed)
    scan_slice = buf[:1024 * 1024]
    for k, needle in _XOR_DOS_VARIANTS:
        hit = scan_slice.find(needle)
        if hit != -1:
            return hit, k
    return None


def inspect_pe_metadata(data: bytes, file_path: str = "", file_size: int = 0) -> Dict[str, object]:
    info: Dict[str, object] = {
        "is_pe": False,
        "is_dll": False,
        "is_dotnet": False,
        "architecture": "",
        "sections": [],
        "has_rwx": False,
        "high_entropy_sections": [],
        "packer_sections": [],
        "entry_outside_text": False,
        "has_tls_callbacks": False,
        "has_embedded_cert": False,
        "cert_padding_trojan": False,
        "empty_imports": False,
        "iat_injection_triple": False,
        "shellcode_callback_iat": False,
        "has_reflective_export": False,
        "syscall_stubs": 0,
        "indirect_syscall_stubs": 0,
        "binary_pumping_overlay": False,
        "overlay_offset": 0,
        "overlay_size": 0,
        "embedded_xor_pe": None,
        "imported_apis": [],
        "extra_section_strings": "",
    }
    if len(data) < 64 or data[:2] != b"MZ":
        return info
    try:
        pe_off = struct.unpack("<I", data[0x3C:0x40])[0]
        if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return info
        info["is_pe"] = True
        machine, num_sec = struct.unpack_from("<HH", data, pe_off + 4)
        characteristics_pe = struct.unpack_from("<H", data, pe_off + 22)[0]
        info["is_dll"] = bool(characteristics_pe & 0x2000)
        opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
        opt_off = pe_off + 24
        if opt_off + 24 > len(data):
            return info

        magic = struct.unpack_from("<H", data, opt_off)[0]
        is_pe64 = (magic == 0x20B)
        info["architecture"] = "x64 (64-bit)" if is_pe64 else ("x86 (32-bit)" if magic == 0x10B else hex(machine))
        ep_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
        image_base = (
            struct.unpack_from("<Q", data, opt_off + 24)[0]
            if is_pe64 and opt_off + 32 <= len(data)
            else (struct.unpack_from("<I", data, opt_off + 28)[0] if opt_off + 32 <= len(data) else 0)
        )

        dd_base = opt_off + (112 if is_pe64 else 96)
        exp_rva = exp_size = imp_rva = imp_size = cert_file_off = cert_size = tls_rva = tls_size = delay_rva = delay_size = clr_rva = clr_size = 0
        if dd_base + 80 <= opt_off + opt_size and dd_base + 80 <= len(data):
            exp_rva, exp_size = struct.unpack_from("<II", data, dd_base)
            imp_rva, imp_size = struct.unpack_from("<II", data, dd_base + 8)
            cert_file_off, cert_size = struct.unpack_from("<II", data, dd_base + 4 * 8)
            tls_rva, tls_size = struct.unpack_from("<II", data, dd_base + 9 * 8)
        if dd_base + 112 <= opt_off + opt_size and dd_base + 112 <= len(data):
            delay_rva, delay_size = struct.unpack_from("<II", data, dd_base + 13 * 8)
        if dd_base + 120 <= opt_off + opt_size and dd_base + 120 <= len(data):
            clr_rva, clr_size = struct.unpack_from("<II", data, dd_base + 14 * 8)

        info["has_embedded_cert"] = (cert_file_off > 0 and cert_size > 0)
        info["has_tls_callbacks"] = (tls_rva > 0 and tls_size > 0)
        info["is_dotnet"] = (clr_rva > 0 and clr_size >= 72)

        if info["has_embedded_cert"]:
            info["cert_padding_trojan"] = _inspect_pe_cert_table_padding(file_path, data, cert_file_off, cert_size)

        sec_start = opt_off + opt_size
        packers = ("upx", ".vmp", ".themida", ".enigma", ".aspack", ".nsp", ".mpress", ".petite", ".rlpack")
        sec_coords: List[Tuple[int, int, int, int]] = []
        has_text_sec = False
        ep_in_text = False
        max_pe_end = sec_start + min(num_sec, 32) * 40
        extra_strings: List[str] = []
        deep_read_budget = 4 * 1024 * 1024

        for i in range(min(num_sec, 24)):
            off = sec_start + i * 40
            if off + 40 > len(data):
                break
            name = data[off:off + 8].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
            v_size, v_addr, r_size, r_ptr = struct.unpack_from("<IIII", data, off + 8)
            chars = struct.unpack_from("<I", data, off + 36)[0]
            sec_coords.append((v_addr, v_size, r_ptr, r_size))
            if r_ptr + r_size > max_pe_end:
                max_pe_end = r_ptr + r_size

            lower_sec = name.lower()
            if lower_sec in (".text", "code"):
                has_text_sec = True
            span = max(v_size, r_size)
            if ep_rva > 0 and v_addr <= ep_rva < v_addr + span and lower_sec in (".text", "code"):
                ep_in_text = True

            sec_bytes = data[r_ptr:r_ptr + min(r_size, 524288)] if r_ptr < len(data) else b""
            # Deep section past head buffer: read directly from disk to eliminate >4MB section blind spot
            if not sec_bytes and r_ptr >= len(data) and r_size > 0 and file_path and deep_read_budget > 0 and os.path.isfile(file_path):
                try:
                    to_read = min(r_size, 1024 * 1024, deep_read_budget)
                    with open(file_path, "rb") as df:
                        df.seek(r_ptr)
                        sec_bytes = df.read(to_read)
                    deep_read_budget -= len(sec_bytes)
                    if sec_bytes:
                        asc = b"\n".join(re.findall(b"[ -~]{5,}", sec_bytes)).decode("ascii", errors="ignore")
                        u16 = b"\n".join(re.findall(b"(?:[ -~]\x00){5,}", sec_bytes)).decode("utf-16le", errors="ignore")
                        if asc:
                            extra_strings.append(asc)
                        if u16:
                            extra_strings.append(u16)
                        if info["embedded_xor_pe"] is None and lower_sec != ".text":
                            emb_hit = _find_embedded_or_xor_pe(sec_bytes)
                            if emb_hit:
                                info["embedded_xor_pe"] = {"offset": r_ptr + emb_hit[0], "xor_key": emb_hit[1], "section": name}
                except Exception:
                    pass

            ent = shannon_entropy(sec_bytes)
            rwx = bool((chars & 0x80000000) and (chars & 0x20000000))
            info["sections"].append({"name": name, "size": r_size, "entropy": ent, "rwx": rwx})
            if rwx:
                info["has_rwx"] = True
            if lower_sec and any(lower_sec.startswith(p) for p in packers):
                info["packer_sections"].append(name)
            if ent > 7.45 and r_size > 2048 and lower_sec != ".rsrc":
                info["high_entropy_sections"].append(f"{name} ({ent})")
            if info["embedded_xor_pe"] is None and lower_sec in (".rsrc", ".data", ".rdata") and len(sec_bytes) >= 256:
                emb_hit = _find_embedded_or_xor_pe(sec_bytes)
                if emb_hit:
                    info["embedded_xor_pe"] = {"offset": r_ptr + emb_hit[0], "xor_key": emb_hit[1], "section": name}

        if extra_strings:
            info["extra_section_strings"] = "\n".join(extra_strings)[:1024 * 1024]

        if cert_file_off > 0 and cert_file_off + cert_size > max_pe_end:
            max_pe_end = cert_file_off + cert_size

        eff_size = file_size if file_size > 0 else len(data)
        if max_pe_end > 0 and eff_size > max_pe_end:
            overlay_size = eff_size - max_pe_end
            info["overlay_offset"] = max_pe_end
            info["overlay_size"] = overlay_size
            # Binary Pumping check (>= 5 MB overlay filled with low-entropy padding)
            if overlay_size >= 5 * 1024 * 1024 and file_path and os.path.isfile(file_path):
                try:
                    samples: List[float] = []
                    with open(file_path, "rb") as pf:
                        for pos in (max_pe_end, max_pe_end + overlay_size // 2, max(max_pe_end, eff_size - 131072)):
                            pf.seek(pos)
                            blk = pf.read(131072)
                            if blk:
                                samples.append(shannon_entropy(blk))
                    if samples and (sum(samples) / len(samples)) < 1.2:
                        info["binary_pumping_overlay"] = True
                except Exception:
                    pass
            # Check overlay for embedded / XOR'd PE
            if info["embedded_xor_pe"] is None and overlay_size >= 256:
                ov_slice = b""
                if max_pe_end < len(data):
                    ov_slice = data[max_pe_end:max_pe_end + min(overlay_size, 1024 * 1024)]
                elif file_path and os.path.isfile(file_path):
                    try:
                        with open(file_path, "rb") as pf:
                            pf.seek(max_pe_end)
                            ov_slice = pf.read(min(overlay_size, 1024 * 1024))
                    except Exception:
                        ov_slice = b""
                if ov_slice:
                    emb_hit = _find_embedded_or_xor_pe(ov_slice)
                    if emb_hit:
                        info["embedded_xor_pe"] = {"offset": max_pe_end + emb_hit[0], "xor_key": emb_hit[1], "section": "overlay"}

        if has_text_sec and ep_rva > 0 and not ep_in_text:
            info["entry_outside_text"] = True

        # Parse IAT Imports natively inside SuperLX 1.0
        imported_lower: Set[str] = set()
        if imp_rva > 0 and imp_size >= 20:
            idt_off = _rva_to_offset(imp_rva, sec_coords)
            if idt_off is not None:
                guard_dll = 0
                while idt_off + 20 <= len(data) and guard_dll < 64:
                    oft, _ts, _fwd, _n_rva, ft = struct.unpack_from("<IIIII", data, idt_off)
                    if oft == 0 and ft == 0:
                        break
                    thunk_off = _rva_to_offset(oft if oft != 0 else ft, sec_coords)
                    if thunk_off is not None:
                        step = 8 if is_pe64 else 4
                        fmt = "<Q" if is_pe64 else "<I"
                        ord_flag = (1 << 63) if is_pe64 else (1 << 31)
                        guard_api = 0
                        while thunk_off + step <= len(data) and guard_api < 512:
                            val = struct.unpack_from(fmt, data, thunk_off)[0]
                            if val == 0:
                                break
                            if not (val & ord_flag):
                                hn_off = _rva_to_offset(val & 0x7FFFFFFF, sec_coords)
                                if hn_off is not None and hn_off + 2 < len(data):
                                    api_n = _read_cstr(data, hn_off + 2)
                                    if api_n:
                                        imported_lower.add(api_n.lower())
                            thunk_off += step
                            guard_api += 1
                    idt_off += 20
                    guard_dll += 1
        elif ep_rva > 0 and not info["is_dll"] and not info["is_dotnet"] and delay_rva == 0:
            info["empty_imports"] = True

        # Parse Delay-Load Import Directory (DataDirectory[13]) to defeat Delay-Load API hiding
        if delay_rva > 0 and delay_size >= 32:
            d_off = _rva_to_offset(delay_rva, sec_coords)
            if d_off is not None:
                guard_dl = 0
                while d_off + 32 <= len(data) and guard_dl < 48:
                    gr_attrs, sz_name, _phmod, _piat, p_int = struct.unpack_from("<IIIII", data, d_off)
                    if sz_name == 0 and p_int == 0:
                        break
                    # Bit 0 of grAttrs == 1 means RVAs; 0 means VAs (minus image_base)
                    int_rva = p_int if (gr_attrs & 1) or p_int < image_base else (p_int - image_base)
                    thunk_off = _rva_to_offset(int_rva, sec_coords)
                    if thunk_off is not None:
                        step = 8 if is_pe64 else 4
                        fmt = "<Q" if is_pe64 else "<I"
                        ord_flag = (1 << 63) if is_pe64 else (1 << 31)
                        guard_api = 0
                        while thunk_off + step <= len(data) and guard_api < 256:
                            val = struct.unpack_from(fmt, data, thunk_off)[0]
                            if val == 0:
                                break
                            if not (val & ord_flag):
                                raw_hn = val & 0x7FFFFFFF
                                hn_rva = raw_hn if (gr_attrs & 1) or raw_hn < image_base else (raw_hn - image_base)
                                hn_off = _rva_to_offset(hn_rva, sec_coords)
                                if hn_off is not None and hn_off + 2 < len(data):
                                    api_n = _read_cstr(data, hn_off + 2)
                                    if api_n:
                                        imported_lower.add(api_n.lower())
                            thunk_off += step
                            guard_api += 1
                    d_off += 32
                    guard_dl += 1
        elif imp_rva == 0 and delay_rva > 0 and not imported_lower and ep_rva > 0 and not info["is_dll"] and not info["is_dotnet"]:
            info["empty_imports"] = True

        # Parse PE Export Directory (DataDirectory[0]) for ReflectiveLoader / Malicious DLL exports
        if exp_rva > 0 and exp_size >= 40:
            exp_off = _rva_to_offset(exp_rva, sec_coords)
            if exp_off is not None and exp_off + 40 <= len(data):
                num_names = struct.unpack_from("<I", data, exp_off + 24)[0]
                names_rva = struct.unpack_from("<I", data, exp_off + 32)[0]
                names_off = _rva_to_offset(names_rva, sec_coords)
                if names_off is not None:
                    for ni in range(min(num_names, 256)):
                        if names_off + ni * 4 + 4 > len(data):
                            break
                        fn_rva = struct.unpack_from("<I", data, names_off + ni * 4)[0]
                        fn_off = _rva_to_offset(fn_rva, sec_coords)
                        if fn_off is not None:
                            fn_name = _read_cstr(data, fn_off).lower()
                            if any(tok in fn_name for tok in ("reflectiveloader", "reflective_loader", "voidfunc")):
                                info["has_reflective_export"] = True
                                break

        info["imported_apis"] = sorted(imported_lower)[:100]
        if (imported_lower & _ALLOC_APIS) and (imported_lower & _WRITE_APIS) and (imported_lower & _EXEC_APIS):
            info["iat_injection_triple"] = True

        # Shellcode Callback Execution IAT combo (VirtualAlloc/Protect + Callback API + resolver/entropy/RWX)
        if (imported_lower & _SHELLCODE_MEM_APIS) and (imported_lower & _CALLBACK_EXEC_APIS):
            has_resolver_or_packed = (
                "getprocaddress" in imported_lower
                or "loadlibrarya" in imported_lower
                or "loadlibraryw" in imported_lower
                or "rtlmovememory" in imported_lower
                or info["has_rwx"]
                or bool(info["high_entropy_sections"])
            )
            if has_resolver_or_packed:
                info["shellcode_callback_iat"] = True

        # Detect Hell's Gate / SysWhispers direct syscall stubs + indirect syscall jump stubs
        code_slice = data[:524288]
        syscall_matches = len(re.findall(b"\x4c\x8b\xd1\xb8.{4,16}\x0f\x05\xc3", code_slice, re.DOTALL))
        indirect_matches = len(re.findall(b"\x4c\x8b\xd1\xb8..\x00\x00.{0,18}?(?:\xff\x25|\x41\xff[\xe0-\xe7]|\xff[\xe0-\xe7])", code_slice, re.DOTALL))
        info["syscall_stubs"] = syscall_matches + indirect_matches
        info["indirect_syscall_stubs"] = indirect_matches
    except Exception:
        pass
    return info


def _inspect_pyinstaller_overlay(file_path: str, file_size: int, db: Optional[dict] = None) -> Tuple[int, List[str], Optional[str]]:
    """Inspect PyInstaller CArchive overlays for packed Python stealers/RATs without executing them."""
    import zlib
    if file_size < 128 or not file_path or not os.path.isfile(file_path):
        return 0, [], None
    cookie_magic = b"MEI\x0c\x0b\x0a\x0b\x0e"
    try:
        tail_read = min(file_size, 8192)
        tail_start = file_size - tail_read
        with open(file_path, "rb") as f:
            f.seek(tail_start)
            tail = f.read(tail_read)
            idx = tail.rfind(cookie_magic)
            if idx == -1:
                return 0, [], None

            cookie_abs = tail_start + idx
            rem = file_size - cookie_abs
            pkg_len = toc_off = toc_len = 0
            cookie_sz = 0
            # Try v21+ 88-byte cookie first, then v20 24-byte cookie
            if rem >= 88:
                _m, pl, to, tl, _pv, _plb = struct.unpack_from("<8sIiIi64s", tail, idx)
                if 64 <= pl <= file_size and 0 < to < pl and 18 <= tl <= 10 * 1024 * 1024:
                    pkg_len, toc_off, toc_len, cookie_sz = pl, to, tl, 88
            if cookie_sz == 0 and rem >= 24:
                _m, pl, to, tl, _pv = struct.unpack_from("<8sIIII", tail, idx)
                if 64 <= pl <= file_size and 0 < to < pl and 18 <= tl <= 10 * 1024 * 1024:
                    pkg_len, toc_off, toc_len, cookie_sz = pl, to, tl, 24
            if cookie_sz == 0:
                return 0, [], None

            pkg_start = (cookie_abs + cookie_sz) - pkg_len
            toc_abs = pkg_start + toc_off
            if pkg_start < 0 or toc_abs + toc_len > file_size:
                return 0, [], None

            f.seek(toc_abs)
            toc_bytes = f.read(min(toc_len, 2 * 1024 * 1024))

            risk = 0
            findings: List[str] = []
            threat: Optional[str] = None
            db = db or {}
            byte_pats = db.get("byte_patterns", [])
            corpus_chunks: List[str] = []

            pos = 0
            entries = 0
            while pos + 18 <= len(toc_bytes) and entries < 60:
                entry_size, dpos, dlen, ulen, cflag, typecd = struct.unpack_from("<IIIIBc", toc_bytes, pos)
                if entry_size < 18 or pos + entry_size > len(toc_bytes):
                    break
                name_bytes = toc_bytes[pos + 18:pos + entry_size].split(b"\x00", 1)[0]
                entry_name = name_bytes.decode("utf-8", errors="ignore")
                pos += entry_size
                entries += 1

                if typecd in (b"s", b"m", b"M", b"x", b"b", b"X") and 0 < dlen <= 512 * 1024:
                    entry_abs = pkg_start + dpos
                    if entry_abs + dlen > file_size:
                        continue
                    f.seek(entry_abs)
                    blob = f.read(dlen)
                    if cflag == 1:
                        try:
                            blob = zlib.decompressobj().decompress(blob, 1024 * 1024)
                        except Exception:
                            continue
                    runs = b"\n".join(re.findall(b"[ -~\\r\\n\\t]{5,}", blob))
                    txt = runs.decode("ascii", errors="ignore")
                    if txt:
                        corpus_chunks.append(f"# [{entry_name}]\n{txt}")

            if corpus_chunks:
                combined_py, _ = deobfuscate_layers("\n".join(corpus_chunks), is_binary=False)
                low_py = combined_py.lower()
                for r_score, t_name, _cat, desc in _scan_corpus_rules(combined_py, low_py):
                    risk = max(risk, r_score)
                    threat = threat or t_name
                    findings.append(f"[SuperLX 1.0 PyInstaller Kalkanı] {desc}")
                for pat in byte_pats:
                    p_s = pat.get("pattern", "")
                    if p_s and p_s.lower() in low_py:
                        risk = min(100, max(risk, int(pat.get("score", 35))))
                        threat = threat or pat.get("name", "Trojan.PyInstaller.Stealer")
                        findings.append(f"[SuperLX 1.0 PyInstaller İmza] {pat.get('description')}")
            return risk, findings, threat
    except Exception:
        return 0, [], None


def _stream_polyglot_scan(file_path: str, file_size: int) -> Optional[Tuple[int, str]]:
    """Stream across the ENTIRE non-PE media file (up to 100 MB) to catch deep-offset polyglots (zero blind offset)."""
    scan_limit = min(file_size, 100 * 1024 * 1024)
    chunk_size = 2 * 1024 * 1024
    overlap = 1024
    offset = 0
    prev_tail = b""

    try:
        with open(file_path, "rb") as f:
            while offset < scan_limit:
                chunk = f.read(min(chunk_size, scan_limit - offset))
                if not chunk:
                    break
                buf = prev_tail + chunk
                base_off = max(0, offset - len(prev_tail))

                start_pos = 8 if base_off == 0 else 0
                idx = buf.find(b"MZ", start_pos)
                while idx != -1:
                    if idx + 24 <= len(buf) and buf[idx:idx + 1024].find(b"PE\x00\x00", 8) != -1:
                        return base_off + idx, "PE"
                    idx = buf.find(b"MZ", idx + 2)

                lower_buf = buf.lower()
                if b"<script" in lower_buf and (b"atob(" in lower_buf or b"wscript.shell" in lower_buf or b"blob(" in lower_buf):
                    return base_off, "SCRIPT_POLYGLOT"

                prev_tail = buf[-overlap:] if len(buf) > overlap else buf
                offset += len(chunk)
    except Exception:
        pass
    return None


def _read_motw_metadata(file_path: str) -> Dict[str, object]:
    """Read NTFS Zone.Identifier ADS (Mark of the Web) to trace browser/Internet download origin."""
    motw: Dict[str, object] = {"zone_id": 0, "from_internet": False, "host_url": "", "referrer_url": ""}
    ads_path = f"{file_path}:Zone.Identifier"
    try:
        with open(ads_path, "r", encoding="utf-8", errors="ignore") as af:
            content = af.read(4096)
        for line in content.splitlines():
            s = line.strip()
            low = s.lower()
            if low.startswith("zoneid="):
                try:
                    zid = int(s.split("=", 1)[1].strip())
                    motw["zone_id"] = zid
                    motw["from_internet"] = zid >= 3
                except ValueError:
                    pass
            elif low.startswith("hosturl="):
                motw["host_url"] = s.split("=", 1)[1].strip()[:300]
            elif low.startswith("referrerurl="):
                motw["referrer_url"] = s.split("=", 1)[1].strip()[:300]
    except Exception:
        pass
    return motw


def _inspect_zip_source(zf: zipfile.ZipFile, db: Optional[dict] = None, _depth: int = 0, _cum_bytes: int = 0) -> Tuple[int, List[str], Optional[str]]:
    risk = 0
    findings: List[str] = []
    threat: Optional[str] = None
    db = db or {}
    dangerous_exts = {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".psm1", ".ps1xml", ".vbs", ".vbe",
        ".js", ".jse", ".hta", ".lnk", ".sct", ".wsf", ".wsh", ".pif", ".com", ".cpl",
        ".inf", ".msi", ".msix", ".appx", ".iso", ".img", ".cab", ".xll", ".one", ".chm", ".reg", ".url"
    }
    doc_spoof = (".pdf.", ".doc.", ".docx.", ".xls.", ".xlsx.", ".jpg.", ".png.", ".txt.")
    mal_dlls = db.get("_idx_mal_dlls")
    if mal_dlls is None:
        mal_dlls = {
            (it.get("name", "") if isinstance(it, dict) else str(it)).strip().lower(): ""
            for it in db.get("malicious_dll_names", [])
        }
    sha_sigs = db.get("_idx_sha_bad")
    if sha_sigs is None:
        sha_sigs = db.get("sha256_signatures", {})
    byte_pats_idx = db.get("_idx_byte_patterns")
    if byte_pats_idx is None:
        byte_pats_idx = [(str(p.get("pattern", "")).lower(), p) for p in db.get("byte_patterns", []) if p.get("pattern")]

    all_infos = zf.infolist()
    total_uncomp = sum(max(0, zi.file_size) for zi in all_infos[:500])
    total_comp = sum(max(1, zi.compress_size) for zi in all_infos[:500])

    # Prioritize dangerous, nested archive, and manifest entries so decoy-file flooding cannot evade inspection
    priority_infos: List[zipfile.ZipInfo] = []
    other_infos: List[zipfile.ZipInfo] = []
    for zi in all_infos:
        nl = zi.filename.lower().replace("\\", "/")
        ex = os.path.splitext(nl)[1]
        bn = os.path.basename(nl)
        if ex in dangerous_exts or ex in {".zip", ".jar", ".class", ".java", ".ts", ".mjs"} or bn in {"appxmanifest.xml", "manifest.json", "config.json"} or ".." in nl or any(c in _RTLO_CHARS for c in zi.filename):
            if len(priority_infos) < 250:
                priority_infos.append(zi)
        elif len(other_infos) < 100:
            other_infos.append(zi)
    infos = priority_infos + other_infos

    for zi in infos:
        name_l = zi.filename.lower().replace("\\", "/")
        base_entry = os.path.basename(name_l)

        if ".." in name_l.split("/") or name_l.startswith("/"):
            risk = max(risk, 92)
            findings.append(f"[SuperLX 1.0 Arşiv Kalkanı] Zip-Slip yol atlama (Path Traversal) girişi: {zi.filename}")
            threat = threat or "Exploit.Archive.ZipSlipTraversal"

        for ch in zi.filename:
            if ch in _RTLO_CHARS:
                risk = max(risk, 95)
                findings.append(f"[SuperLX 1.0 Arşiv Kalkanı] Arşiv içi Unicode RTLO gizlenmiş dosya: {zi.filename}")
                threat = threat or "Trojan.Archive.UnicodeRTLO"
                break

        if base_entry and base_entry in mal_dlls:
            risk = max(risk, 100)
            findings.append(f"[SuperLX 1.0 Arşiv] Bilinen zararlı DLL bulundu: {zi.filename}")
            threat = threat or f"Trojan.Archive.KnownMaliciousDLL.{base_entry}"

        ext_i = os.path.splitext(name_l)[1]
        is_encrypted = bool(zi.flag_bits & 0x1)

        # Handle password-protected/encrypted ZIP entries safely without throwing RuntimeError
        if is_encrypted:
            if (base_entry in mal_dlls) or (ext_i in dangerous_exts and any(d in name_l for d in doc_spoof)) or ext_i in {".scr", ".hta", ".lnk", ".cpl", ".pif", ".sct", ".jse", ".vbe"}:
                risk = max(risk, 88)
                threat = threat or "Trojan.Archive.EncryptedDropper"
                findings.append(f"[SuperLX 1.0 Şifreli Arşiv] Parola korumalı ZIP içinde yüksek riskli zararlı yük: {zi.filename}")
            elif ext_i in dangerous_exts or ext_i == ".zip":
                risk = max(risk, 72)
                threat = threat or "Trojan.Archive.PasswordProtectedExec"
                findings.append(f"[SuperLX 1.0 Şifreli Arşiv] Analizi atlatmak için şifrelenmiş çalıştırılabilir arşiv öğesi: {zi.filename}")
            continue

        # Matryoshka up to 4-level nested ZIP-in-ZIP inspection with cumulative 24 MB byte cap against Zip Bombs
        if ext_i == ".zip" and _depth < 3 and 0 < zi.file_size <= 8 * 1024 * 1024 and _cum_bytes + zi.file_size <= 24 * 1024 * 1024:
            try:
                with zf.open(zi, "r") as zstream:
                    nested_bytes = zstream.read(8 * 1024 * 1024 + 1)
                if len(nested_bytes) <= 8 * 1024 * 1024:
                    with zipfile.ZipFile(io.BytesIO(nested_bytes), "r") as nested_zf:
                        n_risk, n_findings, n_threat = _inspect_zip_source(nested_zf, db, _depth + 1, _cum_bytes + len(nested_bytes))
                        if n_risk > 0:
                            risk = max(risk, n_risk)
                            findings.extend(n_findings)
                            threat = threat or n_threat
                else:
                    risk = max(risk, 88)
                    findings.append(f"[SuperLX 1.0 Arşiv Kalkanı] Sahte boyutlu iç içe Zip Bomb anomalisi: {zi.filename}")
                    threat = threat or "DoS.Archive.ZipBomb"
            except Exception:
                pass
            continue

        # MSIX / APPX / Browser Extension Manifest Inspection
        if base_entry in {"appxmanifest.xml", "manifest.json", "config.json"} and 0 < zi.file_size <= 1024 * 1024:
            try:
                with zf.open(zi, "r") as zstream:
                    m_txt = zstream.read(512 * 1024).decode("utf-8", errors="ignore")
                m_low = m_txt.lower()
                if base_entry in {"appxmanifest.xml", "config.json"} and re.search(r"(?:StartScript|PsfLauncher|powershell|pwsh|cmd\.exe|mshta|wscript)", m_txt, re.IGNORECASE):
                    if re.search(r"(?:-enc|-e\s|iex|downloadstring|http://|https://|FromBase64String|-w\s+hidden|ps1|bat|vbs)", m_low):
                        risk = max(risk, 92)
                        threat = threat or "Trojan.MSIX.MaliciousStartScript"
                        findings.append(f"[SuperLX 1.0 MSIX Kalkanı] Paket manifestinde ({zi.filename}) zararlı StartScript/PowerShell yükü")
                for r_score, t_name, _cat, desc in _scan_corpus_rules(m_txt, m_low):
                    risk = max(risk, r_score)
                    threat = threat or t_name
                    findings.append(f"[SuperLX 1.0 Paket Manifesti: {zi.filename}] {desc}")
            except Exception:
                pass
            continue

        if ext_i in dangerous_exts:
            if any(d in name_l for d in doc_spoof):
                risk = max(risk, 95)
                findings.append(f"[SuperLX 1.0 Arşiv] Çift uzantılı truva atı yükü: {zi.filename}")
                threat = threat or "Trojan.Archive.DoubleExtDropper"
            if zi.file_size > 0:
                try:
                    with zf.open(zi, "r") as zstream:
                        inner_bytes = zstream.read(2 * 1024 * 1024)
                except Exception:
                    continue
                if zi.file_size <= 2 * 1024 * 1024:
                    inner_sha = hashlib.sha256(inner_bytes).hexdigest().lower()
                    if inner_sha in sha_sigs and sha_sigs[inner_sha].get("severity") != "SAFE":
                        sig = sha_sigs[inner_sha]
                        risk = 100
                        findings.append(f"[SuperLX 1.0 Arşiv SHA-256: {zi.filename}] {sig.get('name')}")
                        threat = sig.get("name", "Known.Archive.Malware")
                        continue

                inner_pe = inspect_pe_metadata(inner_bytes)
                if inner_pe.get("is_pe"):
                    if inner_pe.get("cert_padding_trojan"):
                        risk = max(risk, 96)
                        findings.append(f"[SuperLX 1.0 Arşiv PE Cert: {zi.filename}] CVE-2013-3900 Sertifika tablosu gizli yükü")
                        threat = threat or "Trojan.Archive.CertPaddingPE"
                    if inner_pe.get("has_reflective_export"):
                        risk = max(risk, 92)
                        findings.append(f"[SuperLX 1.0 Arşiv PE Export: {zi.filename}] ReflectiveLoader dışa aktarım imzası")
                        threat = threat or "Trojan.Archive.ReflectiveLoaderDLL"
                    if inner_pe.get("iat_injection_triple"):
                        risk = max(risk, 92)
                        findings.append(f"[SuperLX 1.0 Arşiv PE IAT: {zi.filename}] Enjeksiyon API üçlüsü")
                        threat = threat or "Trojan.Archive.IATProcessInjection"
                    if inner_pe.get("shellcode_callback_iat"):
                        risk = max(risk, 86)
                        findings.append(f"[SuperLX 1.0 Arşiv PE IAT: {zi.filename}] Shellcode Callback yürütme API kombinasyonu")
                        threat = threat or "Trojan.Archive.ShellcodeCallbackLoader"
                    if inner_pe.get("syscall_stubs", 0) >= 3:
                        risk = max(risk, 88)
                        findings.append(f"[SuperLX 1.0 Arşiv Çekirdek: {zi.filename}] Doğrudan/Dolaylı Syscall stub imzası")
                        threat = threat or "Evasion.Archive.DirectSyscall"
                    if inner_pe.get("has_rwx") or inner_pe.get("packer_sections"):
                        risk = max(risk, 75)
                        findings.append(f"[SuperLX 1.0 Arşiv PE: {zi.filename}] RWX/Packer anomalisi")
                        threat = threat or "Heuristic.Archive.PackedPE"

                inner_txt_raw = inner_bytes.decode("utf-8", errors="ignore")
                if b"\x00" in inner_bytes[:4096]:
                    inner_txt_raw += "\n" + inner_bytes.decode("utf-16le", errors="ignore")
                inner_txt, _ = deobfuscate_layers(inner_txt_raw, is_binary=bool(inner_pe.get("is_pe")))
                inner_low = inner_txt.lower()
                for r_score, t_name, _cat, desc in _scan_corpus_rules(inner_txt, inner_low):
                    risk = max(risk, r_score)
                    findings.append(f"[SuperLX 1.0 Arşiv İç Tarama: {zi.filename}] {desc}")
                    threat = threat or t_name

                for p_low, pat in byte_pats_idx:
                    if p_low in inner_low:
                        risk = min(100, max(risk, int(pat.get("score", 35))))
                        findings.append(f"[SuperLX 1.0 Arşiv İmza: {zi.filename}] {pat.get('description')}")
                        threat = threat or pat.get("name", "Trojan.Archive.EmbeddedMalware")

                if ext_i == ".lnk" and re.search(r"(?:powershell|pwsh|cmd|mshta|wscript|certutil)", inner_low) and re.search(r"(?:-enc|-e\s|iex|iwr|http|downloadstring)", inner_low):
                    risk = max(risk, 92)
                    findings.append(f"[SuperLX 1.0 Arşiv LNK: {zi.filename}] Silahlandırılmış kısayol komutu")
                    threat = threat or "Trojan.Archive.WeaponizedLNK"

                if risk < 70 and ext_i in {".exe", ".scr", ".bat", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".lnk", ".iso", ".img", ".msix"}:
                    risk = max(risk, 45)
                    findings.append(f"[SuperLX 1.0 Arşiv Uyarısı] ZIP içinde riskli yük bulundu: {zi.filename}")
                    threat = threat or "Heuristic.Archive.ExecutablePayload"

        elif ext_i in {".class", ".java", ".ts", ".mjs"} and 0 < zi.file_size <= 2 * 1024 * 1024:
            try:
                with zf.open(zi, "r") as zstream:
                    j_bytes = zstream.read(2 * 1024 * 1024)
                if ext_i == ".class":
                    j_txt = b"\n".join(re.findall(b"[ -~]{4,}", j_bytes)).decode("ascii", errors="ignore")
                else:
                    j_txt = j_bytes.decode("utf-8", errors="ignore")
                j_low = j_txt.lower()
                if re.search(r"(?:Runtime.{0,40}getRuntime.{0,40}exec|ProcessBuilder)", j_txt, re.DOTALL) and re.search(
                    r"(?:powershell|pwsh|cmd\.exe|mshta|certutil|curl|http://|https://|-enc)", j_low
                ):
                    risk = max(risk, 90)
                    findings.append(f"[SuperLX 1.0 JAR Kalkanı: {zi.filename}] Zararlı Java süreç çalıştırma (Runtime.exec/ProcessBuilder)")
                    threat = threat or "Trojan.Java.MaliciousJarDropper"
                for r_score, t_name, _cat, desc in _scan_corpus_rules(j_txt, j_low):
                    risk = max(risk, r_score)
                    findings.append(f"[SuperLX 1.0 Paket İç Tarama: {zi.filename}] {desc}")
                    threat = threat or t_name
            except Exception:
                pass

    if total_comp > 0 and total_uncomp > 50 * 1024 * 1024 and (total_uncomp / total_comp) > 120:
        risk = max(risk, 88)
        findings.append(f"[SuperLX 1.0 Arşiv Kalkanı] Zip Bomb sıkıştırma anomalisi (Oran {total_uncomp // total_comp}x)")
        threat = threat or "DoS.Archive.ZipBomb"

    return risk, findings, threat


def _inspect_zip_container(file_path: str, db: Optional[dict] = None) -> Tuple[int, List[str], Optional[str]]:
    """Inspect .zip archives deeply against Encrypted bypass, Matryoshka ZIPs, Zip-Slip, Zip-Bombs, inner PE IAT/RWX & RAT scripts."""
    try:
        if not zipfile.is_zipfile(file_path):
            return 0, [], None
        with zipfile.ZipFile(file_path, "r") as zf:
            return _inspect_zip_source(zf, db, 0)
    except Exception:
        return 0, [], None


def _inspect_office_container(file_path: str, data: bytes, ext: str) -> Tuple[int, List[str], Optional[str]]:
    """Inspect OpenXML (.docx/.docm/.xlsx/.xlsm/.pptx...) and OLE2 (.doc/.xls/.ppt) against Follina/RemoteTemplate and malicious VBA macros."""
    risk = 0
    findings: List[str] = []
    threat: Optional[str] = None
    macro_auto_rx = re.compile(r"\b(?:AutoOpen|Auto_Open|Document_Open|Workbook_Open|AutoExec|AutoClose)\b", re.IGNORECASE)
    macro_evil_rx = re.compile(
        r"(?:WScript\.Shell|Shell\s*\(|CreateObject|powershell|pwsh|mshta|URLDownloadToFile|VirtualAlloc|CreateThread|RtlMoveMemory|FromBase64String|ADODB\.Stream|XMLHTTP)",
        re.IGNORECASE,
    )

    openxml_exts = {".docx", ".docm", ".dotm", ".xlsx", ".xlsm", ".xltx", ".pptx", ".pptm"}
    if ext in openxml_exts and zipfile.is_zipfile(file_path):
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                for zi in zf.infolist()[:60]:
                    name_l = zi.filename.lower().replace("\\", "/")
                    if name_l.endswith(".rels") and 0 < zi.file_size <= 262144:
                        with zf.open(zi, "r") as zstream:
                            rel_txt = zstream.read(262144).decode("utf-8", errors="ignore")
                        if re.search(r"ms-msdt:", rel_txt, re.IGNORECASE) or (
                            re.search(r'TargetMode\s*=\s*["\']External["\']', rel_txt, re.IGNORECASE)
                            and re.search(r"(?:attachedTemplate|oleObject|frame|subDocument|externalLink)", rel_txt, re.IGNORECASE)
                            and re.search(r"(?:https?://|file://|\\\\[A-Za-z0-9_.-]+\\|mhtml:|ms-msdt:)", rel_txt, re.IGNORECASE)
                        ):
                            risk = max(risk, 94)
                            threat = threat or "Exploit.Office.RemoteTemplateFollina"
                            findings.append(f"[SuperLX 1.0 Office Kalkanı] Harici şablon / Follina (ms-msdt) uzak yükleme ilişkisi: {zi.filename}")
                    elif "vbaproject.bin" in name_l and 0 < zi.file_size <= 4 * 1024 * 1024:
                        with zf.open(zi, "r") as zstream:
                            vba_bytes = zstream.read(4 * 1024 * 1024)
                        vba_txt = vba_bytes.decode("latin-1", errors="ignore") + "\n" + vba_bytes.decode("utf-16le", errors="ignore")
                        if macro_auto_rx.search(vba_txt) and macro_evil_rx.search(vba_txt):
                            risk = max(risk, 92)
                            threat = threat or "Trojan.Office.WeaponizedMacro"
                            findings.append(f"[SuperLX 1.0 Office Makro] Otomatik tetiklenen zararlı VBA makro yükü: {zi.filename}")
        except Exception:
            pass
    elif ext in {".doc", ".xls", ".ppt"} and data[:4] == b"\xd0\xcf\x11\xe0":
        ole_txt = data[: 2 * 1024 * 1024].decode("latin-1", errors="ignore") + "\n" + data[: 1024 * 1024].decode("utf-16le", errors="ignore")
        if macro_auto_rx.search(ole_txt) and macro_evil_rx.search(ole_txt):
            risk = max(risk, 92)
            threat = threat or "Trojan.Office.WeaponizedMacro"
            findings.append("[SuperLX 1.0 OLE2 Makro] Klasik Office belgesinde otomatik tetiklenen zararlı VBA makrosu")

    return risk, findings, threat


def _inspect_tar_container(file_path: str, db: Optional[dict] = None) -> Tuple[int, List[str], Optional[str]]:
    """Inspect .tar / .tar.gz / .tgz archives in-memory without writing extracted contents to disk."""
    risk = 0
    findings: List[str] = []
    threat: Optional[str] = None
    db = db or {}
    dangerous_exts = {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
        ".js", ".jse", ".hta", ".lnk", ".sct", ".wsf", ".pif", ".msi", ".py", ".reg"
    }
    doc_spoof = (".pdf.", ".doc.", ".docx.", ".xls.", ".xlsx.", ".jpg.", ".png.", ".txt.")
    mal_dlls = db.get("_idx_mal_dlls")
    if mal_dlls is None:
        mal_dlls = {
            (it.get("name", "") if isinstance(it, dict) else str(it)).strip().lower(): ""
            for it in db.get("malicious_dll_names", [])
        }
    sha_sigs = db.get("_idx_sha_bad")
    if sha_sigs is None:
        sha_sigs = db.get("sha256_signatures", {})
    byte_pats_idx = db.get("_idx_byte_patterns")
    if byte_pats_idx is None:
        byte_pats_idx = [(str(p.get("pattern", "")).lower(), p) for p in db.get("byte_patterns", []) if p.get("pattern")]

    try:
        with tarfile.open(file_path, mode="r:*") as tf:
            seen_members = 0
            while seen_members < 60:
                member = tf.next()
                if member is None:
                    break
                seen_members += 1
                name_l = member.name.lower().replace("\\", "/")
                base_entry = os.path.basename(name_l)
                ext_i = os.path.splitext(name_l)[1]

                if ".." in name_l.split("/") or name_l.startswith("/"):
                    risk = max(risk, 92)
                    threat = threat or "Exploit.Archive.TarSlipTraversal"
                    findings.append(f"[SuperLX 1.0 TAR Kalkanı] Tar-Slip yol atlama (Path Traversal) girişi: {member.name}")

                if any(ch in _RTLO_CHARS for ch in member.name):
                    risk = max(risk, 95)
                    threat = threat or "Trojan.Archive.UnicodeRTLO"
                    findings.append(f"[SuperLX 1.0 TAR Kalkanı] Arşiv içi Unicode RTLO gizlenmiş dosya: {member.name}")

                if base_entry and base_entry in mal_dlls:
                    risk = max(risk, 100)
                    threat = f"Trojan.Archive.KnownMaliciousDLL.{base_entry}"
                    findings.append(f"[SuperLX 1.0 TAR Arşiv] Bilinen zararlı DLL bulundu: {member.name}")

                if ext_i in dangerous_exts and any(d in name_l for d in doc_spoof):
                    risk = max(risk, 95)
                    threat = threat or "Trojan.Archive.DoubleExtDropper"
                    findings.append(f"[SuperLX 1.0 TAR Arşiv] Çift uzantılı aldatıcı yük: {member.name}")

                if member.isfile() and ext_i in dangerous_exts and 0 < member.size <= 2 * 1024 * 1024:
                    f_obj = tf.extractfile(member)
                    if f_obj is None:
                        continue
                    inner_bytes = f_obj.read(2 * 1024 * 1024)
                    inner_sha = hashlib.sha256(inner_bytes).hexdigest().lower()
                    if inner_sha in sha_sigs and sha_sigs[inner_sha].get("severity") != "SAFE":
                        risk = 100
                        threat = sha_sigs[inner_sha].get("name", "Known.Archive.Malware")
                        findings.append(f"[SuperLX 1.0 TAR SHA-256: {member.name}] {threat}")
                        continue

                    inner_pe = inspect_pe_metadata(inner_bytes)
                    if inner_pe.get("is_pe") and (inner_pe.get("iat_injection_triple") or inner_pe.get("has_reflective_export") or inner_pe.get("syscall_stubs", 0) >= 3):
                        risk = max(risk, 92)
                        threat = threat or "Trojan.Archive.EmbeddedPE"
                        findings.append(f"[SuperLX 1.0 TAR PE: {member.name}] Zararlı yürütücü / IAT / Syscall anomalisi")

                    inner_txt_raw = inner_bytes.decode("utf-8", errors="ignore")
                    inner_txt, _ = deobfuscate_layers(inner_txt_raw, is_binary=inner_pe.get("is_pe", False))
                    inner_low = inner_txt.lower()
                    for r_score, t_name, _cat, desc in _scan_corpus_rules(inner_txt, inner_low):
                        risk = max(risk, r_score)
                        threat = threat or t_name
                        findings.append(f"[SuperLX 1.0 TAR İç Tarama: {member.name}] {desc}")
                    for p_low, pat in byte_pats_idx:
                        if p_low in inner_low:
                            risk = min(100, max(risk, int(pat.get("score", 35))))
                            threat = threat or pat.get("name", "Trojan.Archive.EmbeddedMalware")
                            findings.append(f"[SuperLX 1.0 TAR İmza: {member.name}] {pat.get('description')}")
    except Exception:
        pass
    return risk, findings, threat


def _inspect_other_archive(data: bytes, ext: str, db: Optional[dict] = None) -> Tuple[int, List[str], Optional[str]]:
    """Inspect .7z / .rar / .cab / .tar headers, embedded PE slices, path traversal, malicious DLLs & double-extensions."""
    risk = 0
    findings: List[str] = []
    threat: Optional[str] = None
    db = db or {}
    mal_dlls = db.get("_idx_mal_dlls")
    if mal_dlls is None:
        mal_dlls = {
            (it.get("name", "") if isinstance(it, dict) else str(it)).strip().lower(): ""
            for it in db.get("malicious_dll_names", [])
        }

    txt = data[: 2 * 1024 * 1024].decode("utf-8", errors="ignore") + "\n" + data[: 2 * 1024 * 1024].decode("utf-16le", errors="ignore")
    low = txt.lower()

    if re.search(r"(?:\.\./|\.\.\\)", txt):
        risk = max(risk, 90)
        threat = threat or "Exploit.Archive.PathTraversal"
        findings.append(f"[SuperLX 1.0 Arşiv ({ext or 'archive'})] Yol atlama (Path Traversal) girişimi")

    for mdll in mal_dlls:
        if mdll and mdll in low:
            risk = max(risk, 100)
            threat = threat or f"Trojan.Archive.KnownMaliciousDLL.{mdll}"
            findings.append(f"[SuperLX 1.0 Arşiv ({ext or 'archive'})] Bilinen zararlı DLL referansı: {mdll}")
            break

    if re.search(r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\.(?:exe|scr|bat|cmd|ps1|vbs|vbe|js|hta|lnk|pif)", low):
        risk = max(risk, 92)
        threat = threat or "Trojan.Archive.DoubleExtDropper"
        findings.append(f"[SuperLX 1.0 Arşiv ({ext or 'archive'})] Çift uzantılı aldatıcı dosya yükü tespit edildi")

    # Search embedded unencrypted MZ->PE headers inside .cab/.tar/.7z/.rar stream
    pos = 32
    limit = min(len(data), 4 * 1024 * 1024)
    while pos < limit - 68:
        idx = data.find(b"MZ", pos, limit)
        if idx == -1 or idx + 64 >= limit:
            break
        e_lfanew = struct.unpack_from("<I", data, idx + 0x3C)[0]
        if 0x20 <= e_lfanew <= 0x1000 and idx + e_lfanew + 4 <= len(data):
            if data[idx + e_lfanew: idx + e_lfanew + 4] == b"PE\x00\x00":
                inner_pe = inspect_pe_metadata(data[idx: min(len(data), idx + 1024 * 1024)])
                if ext == ".cab" or data[:4] == b"MSCF" or inner_pe.get("iat_injection_triple") or inner_pe.get("has_rwx") or inner_pe.get("has_reflective_export") or inner_pe.get("syscall_stubs", 0) >= 3:
                    risk = max(risk, 88)
                    threat = threat or "Trojan.Archive.EmbeddedPE"
                    findings.append(f"[SuperLX 1.0 Arşiv ({ext or 'CAB'})] Konteyner içinde gömülü Windows PE ikilisi (offset {idx})")
                break
        pos = idx + 2

    return risk, findings, threat


def _inspect_disk_image(file_path: str, file_size: int) -> Tuple[int, List[str], Optional[str]]:
    """Inspect ISO/IMG/VHD/VHDX disk images (MOTW bypass vector) up to first 8 MB for embedded PE/LNK/autorun payloads."""
    risk = 0
    findings: List[str] = []
    threat: Optional[str] = None
    max_scan = min(file_size, 8 * 1024 * 1024)
    try:
        with open(file_path, "rb") as f:
            buf = f.read(max_scan)
        if not buf:
            return 0, [], None

        # 1. Search sector offsets > 2048 for valid PE/MZ binaries embedded in ISO/IMG image
        search_from = 2048 if len(buf) > 2048 else 0
        pos = search_from
        while pos < len(buf) - 68:
            idx = buf.find(b"MZ", pos)
            if idx == -1 or idx + 64 >= len(buf):
                break
            e_lfanew = struct.unpack_from("<I", buf, idx + 0x3C)[0]
            if 0x20 <= e_lfanew <= 0x1000 and idx + e_lfanew + 4 <= len(buf):
                if buf[idx + e_lfanew: idx + e_lfanew + 4] == b"PE\x00\x00":
                    risk = 92
                    threat = "Trojan.DiskImage.SmuggledPayload"
                    findings.append(f"[SuperLX 1.0 Disk İmajı Kalkanı] İmaj içinde gömülü Windows PE yürütücüsü (offset {idx})")
                    return risk, findings, threat
            pos = idx + 2

        # 2. Check for autorun.inf or weaponized LNK/script commands embedded in disk image
        low_txt = (buf.decode("utf-8", errors="ignore") + "\n" + buf.decode("utf-16le", errors="ignore")).lower()
        if re.search(r"\[autorun\].{0,250}?(?:open|shellexecute)\s*=", low_txt, re.DOTALL):
            risk = max(risk, 88)
            threat = threat or "Trojan.DiskImage.AutorunDropper"
            findings.append("[SuperLX 1.0 Disk İmajı Kalkanı] İmaj içinde otomatik çalıştırma (autorun.inf) komutu")
        elif re.search(r"(?:powershell|pwsh|mshta|rundll32|cmd(?:\.exe)?\s+/[ck])", low_txt) and re.search(r"(?:-enc|-e\s|iex|invoke-expression|downloadstring|frombase64|https?://)", low_txt):
            risk = max(risk, 90)
            threat = threat or "Trojan.DiskImage.WeaponizedScript"
            findings.append("[SuperLX 1.0 Disk İmajı Kalkanı] İmaj içinde gizlenmiş kabuk/indirici betiği")
    except Exception:
        pass
    return risk, findings, threat


def analyze_superlx(file_path: str, db_path: str = DEFAULT_DB, tier: str = "pro", precomputed: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    """
    Birleşik SuperLX 1.0 Derin Güvenlik Motoru (Lisans kısıtı olmadan herkes için maksimum koruma).
    """
    result: Dict[str, object] = {
        "engine": "SuperLX 1.0",
        "path": file_path,
        "file_name": os.path.basename(file_path),
        "exists": os.path.isfile(file_path),
        "size_bytes": 0,
        "sha256": "",
        "entropy": 0.0,
        "is_signed": False,
        "signer": "",
        "pe_analysis": {},
        "risk_score": 0,
        "status": "CLEAN",
        "severity": "SAFE",
        "threat_name": "",
        "detection_stage": "Temiz (SuperLX 1.0 Tüm Katmanlar Geçildi)",
        "blind_spots_caught": [],
        "findings": [],
    }

    if not result["exists"]:
        return result

    file_size = os.path.getsize(file_path)
    result["size_bytes"] = file_size

    # Full SHA-256 stream (or reuse precomputed buffer/hash from daemon static analyzer) + 4 MB head + 512 KB overlay tail
    pre = precomputed or {}
    max_head = 4 * 1024 * 1024
    pre_sha = str(pre.get("sha256") or "").lower()
    pre_data = pre.get("data")
    if isinstance(pre_data, (bytes, bytearray)):
        data = bytes(pre_data)
        if pre_sha:
            result["sha256"] = pre_sha
        else:
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(131072)
                    if not chunk:
                        break
                    hasher.update(chunk)
            result["sha256"] = hasher.hexdigest().lower()
    elif pre_sha:
        with open(file_path, "rb") as f:
            data = f.read(max_head)
            if file_size > max_head + 65536:
                try:
                    f.seek(max(0, file_size - 524288))
                    data = data + f.read(524288)
                except Exception:
                    pass
        result["sha256"] = pre_sha
    else:
        hasher = hashlib.sha256()
        head_chunks: List[bytes] = []
        head_collected = 0
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(131072)
                if not chunk:
                    break
                hasher.update(chunk)
                if head_collected < max_head:
                    take = chunk[: max_head - head_collected]
                    head_chunks.append(take)
                    head_collected += len(take)
            data = b"".join(head_chunks)
            if file_size > max_head + 65536:
                try:
                    f.seek(max(0, file_size - 524288))
                    data = data + f.read(524288)
                except Exception:
                    pass
        result["sha256"] = hasher.hexdigest().lower()

    if isinstance(pre.get("entropy"), (int, float)):
        result["entropy"] = float(pre["entropy"])
    else:
        result["entropy"] = shannon_entropy(data[: 1024 * 1024])
    file_name = result["file_name"]
    lower_name = file_name.lower()
    lower_path = os.path.abspath(file_path).lower()
    ext = os.path.splitext(lower_name)[1]

    db = _load_db_cached(db_path)

    # 0. Unicode RTLO Spoofing Check
    if any(ch in _RTLO_CHARS for ch in file_name):
        result.update({
            "status": "INFECTED",
            "severity": "CRITICAL",
            "risk_score": 95,
            "threat_name": "Trojan.Masquerade.UnicodeRTLO",
            "detection_stage": "SuperLX 1.0 İsim Gizleme Kalkanı",
        })
        result["findings"].append("[SuperLX 1.0] Dosya adında sahte uzantı gösteren Unicode RTLO karakteri tespit edildi")
        return result

    # 1. AŞAMA 1: Bilinen Zararlı DLL + SHA-256 DB (ön-indeksli O(1))
    mal_dlls_map = db.get("_idx_mal_dlls")
    if mal_dlls_map is None:
        mal_dlls_map = {
            (it.get("name", "") if isinstance(it, dict) else str(it)).strip().lower(): (str(it.get("threat") or "") if isinstance(it, dict) else "")
            for it in db.get("malicious_dll_names", [])
        }
    if lower_name in mal_dlls_map:
        threat_label = mal_dlls_map[lower_name] or f"Trojan.KnownMaliciousDLL.{file_name}"
        result.update({
            "status": "INFECTED",
            "severity": "CRITICAL",
            "risk_score": 100,
            "threat_name": threat_label,
            "detection_stage": "Aşama 1: Bilinen Zararlı DLL Veritabanı",
        })
        result["findings"].append(f"[Aşama 1] Veritabanındaki bilinen zararlı DLL: {file_name}")
        return result

    sha_sigs = db.get("_idx_sha_bad")
    if sha_sigs is None:
        sha_sigs = db.get("sha256_signatures", {})
    if result["sha256"] in sha_sigs and sha_sigs[result["sha256"]].get("severity") != "SAFE":
        sig = sha_sigs[result["sha256"]]
        result.update({
            "status": "INFECTED",
            "severity": sig.get("severity", "CRITICAL"),
            "risk_score": 100,
            "threat_name": sig.get("name", "Known.Malware"),
            "detection_stage": "Aşama 1: SHA-256 İmza Veritabanı",
        })
        result["findings"].append(f"[Aşama 1] Exact SHA-256 eşleşmesi: {sig.get('description')}")
        return result

    # 2. PE Yapısı & WinVerifyTrust Gerçek İmza Doğrulaması
    byovd_drivers = db.get("_idx_byovd_drivers")
    if byovd_drivers is None:
        byovd_drivers = {str(d).strip().lower() for d in db.get("byovd_driver_names", []) if d}
    if lower_name in byovd_drivers:
        result.update({
            "status": "INFECTED",
            "severity": "CRITICAL",
            "risk_score": 95,
            "threat_name": f"Rootkit.BYOVD.VulnerableDriver.{file_name}",
            "detection_stage": "Aşama 1: BYOVD Kötüye Kullanılan Sürücü Kalkanı",
            "blind_spots_caught": ["BYOVD_VulnerableDriver"],
        })
        result["findings"].append(f"[SuperLX 1.0 Çekirdek Koruması] İmzalı olsa bile EDR/AV körleştirmede kullanılan bilinen zafiyetli sürücü (BYOVD): {file_name}")
        return result

    pe_info = inspect_pe_metadata(data, file_path=file_path, file_size=file_size)
    result["pe_analysis"] = pe_info
    if precomputed is not None and "is_signed" in precomputed:
        is_signed = bool(precomputed.get("is_signed"))
        signer = str(precomputed.get("signer") or "")
    else:
        is_signed, signer = (
            verify_authenticode_catalog(file_path)
            if pe_info["is_pe"] or ext in {".exe", ".dll", ".sys", ".ps1", ".cat"}
            else (False, "")
        )
    result["is_signed"] = is_signed
    result["signer"] = signer

    has_signed_pe_tamper = bool(
        pe_info.get("cert_padding_trojan")
        or pe_info.get("has_reflective_export")
        or pe_info.get("syscall_stubs", 0) >= 3
        or pe_info.get("binary_pumping_overlay")
    )
    if is_signed and pe_info.get("is_pe") and not has_signed_pe_tamper:
        result["detection_stage"] = "Temiz (Doğrulanmış İmza + SuperLX 1.0 Geçildi)"
        return result

    hijack_dlls = db.get("_idx_hijack_dlls")
    if hijack_dlls is None:
        hijack_dlls = {d.lower() for d in db.get("hijackable_system_dlls", [])}
    if lower_name in hijack_dlls:
        in_win = any(p in lower_path for p in ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\"))
        in_user_write = any(p in lower_path for p in ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\", "\\desktop\\", "\\programdata\\", "\\documents\\", "\\onedrive\\"))
        if not in_win and in_user_write:
            result.update({
                "status": "INFECTED",
                "severity": "CRITICAL",
                "risk_score": 95,
                "threat_name": f"Trojan.DLLSideLoading.{file_name}",
                "detection_stage": "Aşama 1: Zararlı DLL Side-Loading Tespiti",
            })
            result["findings"].append(f"[Aşama 1] İmzasız sistem DLL taklidi kullanıcı dizininde: {file_name}")
            return result

    score = 0
    findings: List[str] = []
    blind_spots: List[str] = []
    threat = ""

    if pe_info.get("cert_padding_trojan"):
        score = min(100, score + 96)
        threat = "Trojan.PE.CertTablePaddingCVE2013_3900"
        blind_spots.append("CertTablePadding_CVE2013_3900")
        findings.append("[SuperLX 1.0 İmza Bütünlüğü] CVE-2013-3900: İmzalı PE sertifika tablosu (WIN_CERTIFICATE) sonuna gizlenmiş trojan yükü")

    # 3. Polyglot & Magic-Byte Spoofing (Streaming zero-blind scan up to 100 MB!)
    safe_media_exts = {
        ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".txt", ".doc", ".docx", ".xls", ".xlsx",
        ".mp3", ".mp4", ".wav", ".avi", ".bmp", ".webp", ".ico", ".csv", ".pptx"
    }
    if pe_info["is_pe"] and ext in safe_media_exts:
        score += 92
        threat = "Trojan.SpoofedExtension.PE"
        findings.append(f"[SuperLX 1.0 Magic-Byte] {ext} uzantısı altına gizlenmiş çalıştırılabilir Windows PE ikilisi")
    elif ext in {".pdf", ".jpg", ".jpeg", ".png", ".gif"} and not pe_info["is_pe"]:
        poly_hit = _stream_polyglot_scan(file_path, file_size)
        if poly_hit:
            off_hit, p_kind = poly_hit
            score += 92
            threat = "Trojan.Polyglot.EmbeddedPE" if p_kind == "PE" else "Trojan.Polyglot.EmbeddedScript"
            blind_spots.append("PolyglotPayloads")
            findings.append(f"[SuperLX 1.0 Polyglot] Temiz {ext} dosyası arkasında gizli {p_kind} yükü (offset {off_hit})")

    # 3B. ZIP / JAR / VSIX / MSIX / CRX Dropper Container Inspection
    if ext in {".zip", ".jar", ".vsix", ".msix", ".appx", ".crx", ".xpi"}:
        z_risk, z_findings, z_threat = _inspect_zip_container(file_path, db)
        if z_risk > 0:
            score = min(100, score + z_risk)
            findings.extend(z_findings)
            blind_spots.append("ArchiveContainerScan")
            if not threat and z_threat:
                threat = z_threat

    # 3B0. Office OpenXML (.docx/.docm/.xlsm...) & Legacy OLE2 (.doc/.xls/.ppt) Inspection
    if ext in {".docx", ".docm", ".dotm", ".xlsx", ".xlsm", ".xltx", ".pptx", ".pptm", ".doc", ".xls", ".ppt"}:
        off_risk, off_findings, off_threat = _inspect_office_container(file_path, data, ext)
        if off_risk > 0:
            score = min(100, score + off_risk)
            findings.extend(off_findings)
            blind_spots.append("WeaponizedOffice")
            if not threat and off_threat:
                threat = off_threat

    # 3B1. Disk Images (ISO/IMG/VHD/VHDX) & Office/Help/OneNote/MSI/TAR/7z Delivery Vectors
    if ext in {".iso", ".img", ".vhd", ".vhdx"}:
        d_risk, d_findings, d_threat = _inspect_disk_image(file_path, file_size)
        if d_risk > 0:
            score = min(100, score + d_risk)
            findings.extend(d_findings)
            blind_spots.append("DiskImageSmuggling")
            threat = threat or d_threat or "Trojan.DiskImage.SmuggledPayload"
    elif ext == ".xll" and pe_info.get("is_pe") and not is_signed:
        score = min(100, score + 88)
        findings.append("[SuperLX 1.0 XLL Kalkanı] İmzasız Excel (.xll) yerel C/C++ eklentisi")
        blind_spots.append("MaliciousXLL")
        threat = threat or "Trojan.Office.UnsignedXLLAddIn"
    elif ext == ".one" or data[:8] == b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d":
        one_pe_hit = False
        idx = 64
        while idx < len(data) - 68:
            pos = data.find(b"MZ", idx)
            if pos == -1 or pos + 64 >= len(data):
                break
            e_lfa = struct.unpack_from("<I", data, pos + 0x3C)[0]
            if 0x20 <= e_lfa <= 0x800 and pos + e_lfa + 4 <= len(data) and data[pos + e_lfa: pos + e_lfa + 4] == b"PE\x00\x00":
                one_pe_hit = True
                break
            idx = pos + 2
        one_low = (data.decode("utf-8", errors="ignore") + "\n" + data.decode("utf-16le", errors="ignore")).lower()
        if one_pe_hit or re.search(r"<hta:application|wscript\.shell|mshta\s+http|powershell\s+.{0,300}?(?:-enc|iex|downloadstring)|cmd\.exe\s+/[ck]", one_low, re.IGNORECASE):
            score = min(100, score + 92)
            findings.append("[SuperLX 1.0 OneNote Kalkanı] OneNote (.one) notu içine gömülü çalıştırılabilir/betik yükü")
            blind_spots.append("WeaponizedOneNote")
            threat = threat or "Trojan.OneNote.EmbeddedPayload"
    elif ext == ".chm" or data[:4] == b"ITSF":
        chm_txt = data.decode("utf-8", errors="ignore") + "\n" + data.decode("utf-16le", errors="ignore")
        if re.search(r"(?:mshta|powershell|pwsh|cmd\.exe|regsvr32|rundll32|wscript\.shell|ActiveXObject)", chm_txt, re.IGNORECASE):
            score = min(100, score + 90)
            findings.append("[SuperLX 1.0 CHM Kalkanı] Derlenmiş Yardım (.chm) içinde zararlı komut/ActiveX çalıştırma")
            blind_spots.append("WeaponizedCHM")
            threat = threat or "Trojan.CHM.CompiledHelpExploit"
    elif ext == ".msi" and data[:4] == b"\xd0\xcf\x11\xe0" and not is_signed:
        msi_txt = data.decode("ascii", errors="ignore") + "\n" + data.decode("utf-16le", errors="ignore")
        if "customaction" in msi_txt.lower() and re.search(r"(?:powershell|pwsh|-enc|Invoke-Expression|DownloadString|FromBase64String|mshta|wscript\.shell|cmd(?:\.exe)?\s+/[ck])", msi_txt, re.IGNORECASE):
            score = min(100, score + 88)
            findings.append("[SuperLX 1.0 MSI Kalkanı] İmzasız .msi paketinde şüpheli CustomAction kabuk/betik yürütmesi")
            blind_spots.append("WeaponizedMSI")
            threat = threat or "Trojan.MSI.MaliciousCustomAction"
    elif ext in {".tar", ".tgz"} or lower_name.endswith((".tar.gz", ".tar.bz2", ".tbz2", ".tar.xz")):
        t_risk, t_findings, t_threat = _inspect_tar_container(file_path, db)
        if t_risk == 0 and ext == ".tar":
            t_risk, t_findings, t_threat = _inspect_other_archive(data, ext, db)
        if t_risk > 0:
            score = min(100, score + t_risk)
            findings.extend(t_findings)
            blind_spots.append("ArchiveContainerScan")
            if not threat and t_threat:
                threat = t_threat
    elif ext in {".7z", ".rar", ".cab"} or data[:6] == b"7z\xbc\xaf\x27\x1c" or data[:5] == b"Rar!\x1a" or data[:4] == b"MSCF":
        oa_risk, oa_findings, oa_threat = _inspect_other_archive(data, ext, db)
        if oa_risk > 0:
            score = min(100, score + oa_risk)
            findings.extend(oa_findings)
            blind_spots.append("ArchiveContainerScan")
            if not threat and oa_threat:
                threat = oa_threat

    # 3B2. NTFS Mark-of-the-Web (Zone.Identifier) Download Origin Analysis
    motw = _read_motw_metadata(file_path)
    result["motw"] = motw
    if motw.get("from_internet"):
        blind_spots.append("InternetDownloadMotW")
        if (pe_info.get("is_pe") and (pe_info.get("has_tls_callbacks") or result["entropy"] > 7.15 or pe_info.get("empty_imports"))) or ext in {".hta", ".sct", ".wsf", ".jse", ".vbe", ".iso", ".img", ".vhd", ".vhdx"}:
            score = min(100, score + 35)
            origin_hint = motw.get("host_url") or motw.get("referrer_url") or "İnternet Kaynağı (ZoneId=3)"
            findings.append(f"[SuperLX 1.0 İndirme Kalkanı (MotW)] İnternetten indirilen imzasız/yüksek riskli dosya ({origin_hint})")
            threat = threat or "Heuristic.Download.SuspiciousInternetDrop"

    # 3B3. PyInstaller CArchive Overlay Inspection
    if pe_info.get("is_pe") and not is_signed:
        pyi_risk, pyi_findings, pyi_threat = _inspect_pyinstaller_overlay(file_path, file_size, db)
        if pyi_risk > 0:
            score = min(100, score + pyi_risk)
            findings.extend(pyi_findings)
            blind_spots.append("PyInstallerOverlay")
            threat = threat or pyi_threat or "Trojan.PyInstaller.PackedStealer"

    # 3C. Weaponized LNK Shortcut Detector
    if ext == ".lnk":
        lnk_text = data.decode("utf-16le", errors="ignore") + "\n" + data.decode("ascii", errors="ignore")
        if re.search(r"(?:powershell|pwsh|cmd(?:\.exe)?\s+/[ck]|mshta|wscript|cscript|certutil|bitsadmin|forfiles|cmstp|%comspec%)", lnk_text, re.IGNORECASE) and re.search(r"(?:-enc|-e\s|iex|iwr|irm|http|downloadstring|\\.sct|scrobj|frombase64|curl|regsvr)", lnk_text, re.IGNORECASE):
            score += 92
            threat = threat or "Trojan.LNK.WeaponizedShortcut"
            blind_spots.append("WeaponizedLNK")
            findings.append("[SuperLX 1.0 LNK Kalkanı] Kısayol (.lnk) hedefinde gizlenmiş kabuk/indirici komutu")

    # 4. Binary-Safe Metin Çıkarma + UTF-8/UTF-16LE/UTF-16BE + Çok Turlu De-Obfuscation
    is_binary_container = pe_info["is_pe"] or ext in {
        ".png", ".jpg", ".jpeg", ".gif", ".zip", ".jar", ".vsix", ".msix", ".appx", ".crx", ".xpi",
        ".docx", ".docm", ".dotm", ".xlsx", ".xlsm", ".xltx", ".pptx", ".pptm", ".tar", ".tgz", ".gz",
        ".7z", ".rar", ".cab", ".pdf", ".exe", ".dll", ".sys"
    }
    if is_binary_container and len(data) > 512 * 1024:
        # Extract printable ASCII and UTF-16LE strings cleanly in O(N) ms without regex noise on 4MB pixel/padding bytes
        ascii_runs = b"\n".join(re.findall(b"[ -~\\r\\n\\t]{5,}", data[: 2 * 1024 * 1024]))
        utf16_runs = b"\n".join(re.findall(b"(?:[ -~]\\x00){5,}", data[: 2 * 1024 * 1024]))
        raw_text = ascii_runs.decode("ascii", errors="ignore") + "\n" + utf16_runs.decode("utf-16le", errors="ignore")
    else:
        decoded_parts: List[str] = [data.decode("utf-8", errors="ignore")]
        bom_u16_idx = data[:64].find(b"\xff\xfe")
        if bom_u16_idx != -1:
            decoded_parts.append(data[bom_u16_idx + 2:].decode("utf-16le", errors="ignore"))
        elif b"\x00" in data[:4096]:
            decoded_parts.append(data.decode("utf-16le", errors="ignore"))
        if data[:2] == b"\xfe\xff" or (len(data) > 10 and data[0] == 0 and data[2] == 0):
            decoded_parts.append(data.decode("utf-16be", errors="ignore"))
        raw_text = "\n".join(decoded_parts)

    if pe_info.get("extra_section_strings"):
        raw_text = raw_text + "\n" + str(pe_info["extra_section_strings"])

    combined_text, deobf_notes = deobfuscate_layers(raw_text, is_binary=is_binary_container)
    if "__EMBEDDED_PE_HEADER__" in combined_text:
        score = min(100, score + 92)
        threat = threat or "Trojan.Smuggling.Base64PE"
        blind_spots.append("EmbeddedBase64PE")

    if deobf_notes:
        lower_comb = combined_text.lower()
        strong_deobf_indicators = (
            "invoke-expression", "downloadstring", "downloadfile", "invoke-webrequest", "invoke-restmethod",
            "virtualalloc", "amsiscanbuffer", "add-mppreference", "set-mppreference", "comsvcs", "frombase64string",
            "asyncmutex", "setwindowshookex", "wscript.shell", "adodb.stream", "certutil",
            "mshta", "regsvr32", "schtasks", "url.createobjecturl", "activexobject",
        )
        has_iex_token = bool(re.search(r"\biex\b", lower_comb))
        has_script_net_stager = (
            not pe_info["is_pe"]
            and bool(re.search(r"https?://", lower_comb))
            and bool(re.search(r"\b(?:powershell|pwsh|cmd|wscript|cscript|mshta|curl|wget|certutil|bitsadmin|rundll32)\b", lower_comb))
        )
        if any(ind in lower_comb for ind in strong_deobf_indicators) or has_iex_token or has_script_net_stager:
            score = min(100, score + 72)
            threat = threat or "Trojan.SuperLX.DeobfuscatedEvader"
            blind_spots.append("MultiLayerDeobfuscation")
            findings.append(f"[SuperLX 1.0 Çözücü] {', '.join(deobf_notes)} -> Gizli zararlı yük ortaya çıkarıldı")

    # 5. SuperLX 1.0 Özel Kurallar (O(N) Boyer-Moore önbakışlı kural motoru)
    lower_combined = combined_text.lower()
    for r_score, t_name, cat, desc in _scan_corpus_rules(combined_text, lower_combined):
        score = min(100, score + r_score)
        if not threat:
            threat = t_name
        if cat not in blind_spots:
            blind_spots.append(cat)
        findings.append(f"[SuperLX 1.0] {desc}")

    # 5B. PDF Active Scripting, Office DDE & NTLM/SMB UNC Leak (.url / .scf) & .REG Hijack
    if ext == ".pdf" and re.search(r"/OpenAction|/Launch\b|/(?:JS|JavaScript)\b", raw_text, re.IGNORECASE):
        if re.search(r"powershell|cmd\.exe|mshta|wscript|certutil|http://|https://|launchurl|eval\s*\(", combined_text, re.IGNORECASE):
            score = min(100, score + 90)
            threat = threat or "Exploit.PDF.WeaponizedAction"
            blind_spots.append("WeaponizedPDF")
            findings.append("[SuperLX 1.0 PDF Kalkanı] PDF içinde otomatik tetiklenen zararlı eylem (/OpenAction /Launch)")

    if ext in {".iqy", ".slk", ".csv"} and re.search(r"(?:^|\n|\t|,)\s*[=@+\-]?(?:cmd|powershell|mshta|wscript|cscript)\s*[|!]", raw_text, re.IGNORECASE):
        score = min(100, score + 90)
        threat = threat or "Trojan.Office.DDEInjection"
        blind_spots.append("OfficeDDE")
        findings.append("[SuperLX 1.0 DDE Kalkanı] Elektronik tabloda dinamik veri değişimi (DDE) komut çalıştırma")

    if ext == ".rtf" and "\\objdata" in raw_text.lower() and re.search(r"Equation\.3|d0cf11e0|90909090", raw_text, re.IGNORECASE):
        score = min(100, score + 88)
        threat = threat or "Exploit.RTF.OLEEquation"
        blind_spots.append("RTFExploit")
        findings.append("[SuperLX 1.0 RTF Kalkanı] RTF içinde gömülü OLE/Equation istismar nesnesi")

    if ext in {".url", ".scf"} and re.search(r"(?:IconFile|URL)\s*=\s*(?:file://)?\\\\(?!(?:127\.0\.0\.1|localhost)\\)[A-Za-z0-9_.-]+\\", raw_text, re.IGNORECASE):
        score = min(100, score + 86)
        threat = threat or "CredentialAccess.SMB.NTLMHashLeak"
        blind_spots.append("UNC_NTLM_Leak")
        findings.append("[SuperLX 1.0 Ağ Kalkanı] Dış SMB/WebDAV UNC yoluyla NTLMv2 kimlik sızdırma tuzağı")

    if ext == ".reg" and re.search(
        r"Image File Execution Options\\.{0,240}?\"?Debugger\"?\s*=|SilentProcessExit\\.{0,240}?\"?MonitorProcess\"?\s*=|DisableAntiSpyware|DisableRealtimeMonitoring|CurrentVersion\\Run.{0,220}?\\(?:Temp|AppData|Public)",
        raw_text,
        re.IGNORECASE | re.DOTALL,
    ):
        score = min(100, score + 90)
        threat = threat or "DefenseEvasion.Registry.MaliciousImport"
        blind_spots.append("MaliciousREG")
        findings.append("[SuperLX 1.0 Kayıt Kalkanı] .reg dosyasıyla IFEO Debugger, kalıcılık veya güvenlik körleştirme")

    # 5C. Env-var slicing / ClickFix / WMIC XSL / APT Kernel Driver Service checks
    if re.search(r"\$(?:env:ComSpec|PSHome|ShellId)\[\s*\d+\s*,\s*\d+", combined_text, re.IGNORECASE):
        score = min(100, score + 82)
        threat = threat or "Obfuscation.PowerShell.EnvCharSlicing"
        blind_spots.append("EnvCharSlicing")
        findings.append("[SuperLX 1.0 Gizleme] Ortam değişkeni indeks dilimleme ($env:ComSpec[...]) ile iex gizlemesi")

    if re.search(r"navigator\.clipboard\.writeText\s*\(.{0,220}?(?:powershell|pwsh|mshta|cmd\s+/c|curl)|wmic(?:\.exe)?\s+.{0,160}?/format\s*:\s*[\"']?https?://|sc(?:\.exe)?\s+create\s+.{0,180}?type=\s*kernel", combined_text, re.IGNORECASE | re.DOTALL):
        score = min(100, score + 92)
        threat = threat or "Execution.ClickFix_APT_Stager"
        blind_spots.append("APT_ClickFix_LOLBin")
        findings.append("[SuperLX 1.0 APT Kalkanı] ClickFix Pano Tuzağı / WMIC XSL / Çekirdek Sürücü Enjeksiyonu")

    # 5D. Middle-File Padding Evasion Defense for large scripts (> 4 MB up to 25 MB)
    text_script_exts = {".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".html", ".htm", ".hta", ".svg", ".sct", ".wsf", ".py", ".reg", ".inf"}
    if not pe_info["is_pe"] and ext in text_script_exts and 4 * 1024 * 1024 < file_size <= 25 * 1024 * 1024 and score < 70:
        try:
            with open(file_path, "rb") as sf:
                sf.seek(3_800_000)
                while sf.tell() < max(3_800_000, file_size - 400_000):
                    blk = sf.read(1024 * 1024)
                    if not blk:
                        break
                    mid_txt, mid_notes = deobfuscate_layers(blk.decode("utf-8", errors="ignore"))
                    mid_low = mid_txt.lower()
                    for sc_m, tn_m, cat_m, d_m in _scan_corpus_rules(mid_txt, mid_low):
                        score = min(100, score + sc_m)
                        threat = threat or tn_m
                        if cat_m not in blind_spots:
                            blind_spots.append(cat_m)
                        findings.append(f"[SuperLX 1.0 Orta-Bölge Koruması] Büyük betik orta dolgusundaki gizli yük: {d_m}")
                    if mid_notes and any(k in mid_low for k in ("invoke-expression", "iex", "downloadstring", "virtualalloc", "http://", "https://")):
                        score = min(100, score + 75)
                        threat = threat or "Trojan.SuperLX.PaddedScriptEvader"
                        blind_spots.append("MiddlePaddingBypass")
                        findings.append("[SuperLX 1.0 Orta-Bölge Koruması] Milyonlarca baytlık dolgu arkasına gizlenmiş zararlı yük")
                    if score >= 70:
                        break
        except Exception:
            pass

    # 6. Byte Patterns & Anti-RAT Kill-Chain Correlation
    cats_hit: Set[str] = set()
    inj_hits = 0
    byte_pats_idx = db.get("_idx_byte_patterns")
    if byte_pats_idx is None:
        byte_pats_idx = [(str(p.get("pattern", "")).lower(), p) for p in db.get("byte_patterns", []) if p.get("pattern")]
    for p_low, pat in byte_pats_idx:
        if p_low in lower_combined:
            score = min(100, score + int(pat.get("score", 35)))
            findings.append(f"[{pat.get('id')}] {pat.get('description')}")
            cat = pat.get("category")
            if cat:
                cats_hit.add(cat)
                if cat in ("ProcessInjection", "ProcessHollowing"):
                    inj_hits += 1
            if not threat:
                threat = pat.get("name", "")

    if inj_hits >= 2:
        score = min(100, score + 30)
        findings.append("[SuperLX 1.0 Davranış] Çoklu Bellek Enjeksiyonu / Process Hollowing API zinciri")

    if "Spyware" in cats_hit and ({"Backdoor", "Exfiltration", "CredentialAccess"} & cats_hit):
        score = min(100, score + 50)
        findings.append("[SuperLX 1.0 Anti-RAT] Casus izleme (Keylogger/Ekran/Kamera) + C2/Webhook sızdırma korelasyonu")
        if "AntiRAT_KillChain" not in blind_spots:
            blind_spots.append("AntiRAT_KillChain")
        if not threat or threat.startswith("Backdoor.") or threat.startswith("Spyware."):
            threat = "RAT.Behavioral.KillChain"

    # 7. PE Structural + IAT + Syscall + Untrusted Self-Signed + Pumping + Callback + AutoIt/Go/Rust Analysis
    if pe_info.get("is_pe"):
        if pe_info.get("binary_pumping_overlay"):
            score = min(100, score + 55)
            blind_spots.append("BinaryPumpingOverlay")
            findings.append(f"[SuperLX 1.0 PE Şişirme] Boyut atlatma amacıyla aşırı düşük entropili dev overlay dolgusu ({round(pe_info.get('overlay_size', 0) / (1024 * 1024), 1)} MB)")
            threat = threat or "Evasion.Trojan.BinaryPumping"
        if pe_info.get("embedded_xor_pe"):
            emb_meta = pe_info["embedded_xor_pe"]
            score = min(100, score + 88)
            blind_spots.append("EmbeddedOrXorPE")
            xk = emb_meta.get("xor_key", 0)
            findings.append(f"[SuperLX 1.0 Gömülü Yük] PE ({emb_meta.get('section')}) içinde {'XOR (0x%02x) şifreli ' % xk if xk else ''}ikincil Windows PE yürütücüsü")
            threat = threat or "Trojan.PE.EmbeddedOrXorPayload"
        if pe_info.get("has_embedded_cert") and not is_signed and not pe_info.get("cert_padding_trojan"):
            score = min(100, score + 45)
            findings.append("[SuperLX 1.0 İmza] Doğrulanamayan / Self-Signed (sahte güvenilir) Authenticode sertifikası")
            threat = threat or "Heuristic.UntrustedSignature.PE"
        if pe_info.get("has_reflective_export"):
            score = min(100, score + 92)
            blind_spots.append("PE_ReflectiveExport")
            findings.append("[SuperLX 1.0 PE Export] Bellek içi ReflectiveLoader DLL dışa aktarım tablosu")
            threat = threat or "Trojan.DLL.ReflectiveLoaderExport"
        if pe_info.get("iat_injection_triple"):
            score = min(100, score + 80)
            blind_spots.append("PE_IAT_Injection")
            findings.append("[SuperLX 1.0 PE IAT] İçe Aktarma Tablosunda (IAT) Bellek Enjeksiyonu API üçlüsü (Alloc+Write+Exec)")
            threat = threat or "Trojan.PE.IATProcessInjection"
        if pe_info.get("shellcode_callback_iat"):
            score = min(100, score + 82)
            blind_spots.append("PE_ShellcodeCallbackIAT")
            findings.append("[SuperLX 1.0 PE IAT] Geri çağrı (Callback) üzerinden bellek içi Shellcode çalıştırma API kombinasyonu")
            threat = threat or "Trojan.PE.ShellcodeCallbackLoader"
        if pe_info.get("syscall_stubs", 0) >= 3:
            score = min(100, score + 65)
            blind_spots.append("DirectOrIndirectSyscalls")
            findings.append(f"[SuperLX 1.0 Çekirdek] Doğrudan/Dolaylı Windows Syscall / SysWhispers EDR atlatma stub'ları ({pe_info['syscall_stubs']} adet)")
            threat = threat or "Evasion.Syscall.EDRHookBypass"
        pe_apis = set(pe_info.get("imported_apis") or [])
        if (pe_apis & _SPY_APIS) and ((pe_apis & _EXFIL_APIS) or "cryptunprotectdata" in pe_apis):
            score = min(100, score + 75)
            blind_spots.append("PE_IAT_RATStealer")
            findings.append("[SuperLX 1.0 PE IAT RAT] Casus kancası + Ağ/DPAPI sızdırma API kombinasyonu")
            threat = threat or "RAT.PE.SpywareExfilIAT"
        has_svc_create = any(k in pe_apis for k in ("createservicea", "createservicew")) and any(k in pe_apis for k in ("openscmanagera", "openscmanagerw"))
        if has_svc_create and ("deviceiocontrol" in pe_apis or any(k in pe_apis for k in ("startservicea", "startservicew"))):
            score = min(100, score + 75)
            blind_spots.append("PE_BYOVD_DriverLoader")
            findings.append("[SuperLX 1.0 Çekirdek Koruması] İmzasız BYOVD Sürücü / Servis Yükleyici IAT (OpenSCManager+CreateService)")
            threat = threat or "Rootkit.PE.BYOVDDriverLoader"
        if pe_info.get("has_rwx"):
            score = min(100, score + 45)
            findings.append("[SuperLX 1.0 PE Bellek] İmzasız PE içinde RWX (Yazılabilir+Çalıştırılabilir) bölüm")
            threat = threat or "Heuristic.PE.RWXSection"
        if pe_info.get("packer_sections"):
            score = min(100, score + 38)
            findings.append(f"[SuperLX 1.0 PE Packer] Şüpheli packer bölümleri: {', '.join(pe_info['packer_sections'])}")
            threat = threat or "Heuristic.PE.Packed"
        if pe_info.get("entry_outside_text"):
            score = min(100, score + 35)
            findings.append("[SuperLX 1.0 PE OEP] Program giriş noktası (EntryPoint) standart .text bölümü dışında")
            threat = threat or "Heuristic.PE.AnomalousEntryPoint"
        if pe_info.get("has_tls_callbacks"):
            score = min(100, score + 10)
            findings.append("[SuperLX 1.0 PE TLS] TLS Callback erken kod yürütme / Anti-Debug tablosu")
        if pe_info.get("empty_imports") and (result["entropy"] > 6.8 or pe_info.get("high_entropy_sections")):
            score = min(100, score + 50)
            findings.append("[SuperLX 1.0 PE IAT] Yüksek entropili ikilide boş Import Tablosu (Dinamik API Hashing / Shellcode)")
            threat = threat or "Heuristic.PE.HiddenAPIImports"
        if pe_info.get("high_entropy_sections") and result["entropy"] > 7.35:
            score = min(100, score + 45)
            findings.append(f"[SuperLX 1.0 Entropi] Yüksek entropili PE bölümü: {', '.join(pe_info['high_entropy_sections'])}")
            threat = threat or "Heuristic.PE.HighEntropy"

        # AutoIt3 / AutoHotkey & Go/Rust unsigned multi-indicator correlation
        if not is_signed:
            has_autoit = (b"AU3!EA06" in data) or (b"AU3!EA05" in data) or (b">AUTOHOTKEY SCRIPT<" in data)
            if has_autoit:
                au_signals = sum(1 for tok in (
                    "virtualalloc", "writeprocessmemory", "createprocess", "shellexecute",
                    "currentversion\\run", "cryptunprotectdata", "http://", "https://",
                    "discord.com/api/webhooks", "api.telegram.org", "setwindowshookex",
                ) if tok in lower_combined)
                if au_signals >= 2 or motw.get("from_internet"):
                    score = min(100, score + 75)
                    blind_spots.append("AutoItTrojanLoader")
                    findings.append("[SuperLX 1.0 AutoIt/AHK] Derlenmiş AutoIt/AutoHotkey ikilisinde şüpheli trojan davranış göstergeleri")
                    threat = threat or "Trojan.AutoIt.CompiledLoader"

            is_go_rust = (b"go.buildid" in data[:131072]) or (b".gopclntab" in data[:262144]) or ("rustc/" in lower_combined)
            if is_go_rust:
                gr_hits = sum(1 for tok in (
                    "virtualallocex", "writeprocessmemory", "createremotethread", "ntallocatevirtualmemory",
                    "discord.com/api/webhooks", "api.telegram.org/bot", "cryptunprotectdata",
                    "login data", "currentversion\\run", "vssadmin delete", "amsiscanbuffer",
                ) if tok in lower_combined)
                if gr_hits >= 2:
                    score = min(100, score + 75)
                    blind_spots.append("GoRustImplant")
                    findings.append("[SuperLX 1.0 Go/Rust] İmzasız Go/Rust ikilisinde çoklu trojan/implant API ve C2 izleri")
                    threat = threat or "Trojan.GoRust.ImplantLoader"

    # 8. Çift Uzantı Kontrolü
    doc_exts = (".pdf.", ".doc.", ".docx.", ".xls.", ".xlsx.", ".jpg.", ".png.", ".txt.")
    susp_exts = db.get("_idx_susp_exts")
    if susp_exts is None:
        susp_exts = set(db.get("suspicious_extensions", []))
    if ext in susp_exts and any(d in lower_name for d in doc_exts):
        score = min(100, score + 70)
        findings.append(f"[SuperLX 1.0 Çift Uzantı] Sahte belge uzantılı çalıştırılabilir dosya ({file_name})")
        threat = threat or "Heuristic.Trojan.DoubleExtension"

    if score >= 70:
        result["status"] = "INFECTED"
        result["severity"] = "CRITICAL"
    elif score >= 35:
        result["status"] = "SUSPICIOUS"
        result["severity"] = "MEDIUM"
    else:
        result["status"] = "CLEAN"
        result["severity"] = "SAFE"

    result["risk_score"] = min(100, score)
    result["threat_name"] = threat
    result["blind_spots_caught"] = blind_spots
    result["findings"] = findings

    if result["status"] != "CLEAN":
        if blind_spots:
            result["detection_stage"] = f"SuperLX 1.0 Derin Kalkan ({', '.join(blind_spots[:2])})"
        else:
            result["detection_stage"] = "SuperLX 1.0 Sezgisel & Yapısal Analiz"
    else:
        result["detection_stage"] = "Temiz (SuperLX 1.0 Doğrulaması Geçildi)"

    return result


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    target_path = sys.argv[1] if len(sys.argv) > 1 else ""
    tier_arg = sys.argv[2].lower() if len(sys.argv) > 2 else "pro"
    db_arg = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_DB
    print(json.dumps(analyze_superlx(target_path, db_arg, tier_arg), ensure_ascii=False))
