#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MODÜL 3 :: "Soy Ağacı" ve Süreç Zinciri Niyet Okuyucu (Process Lineage & Behavioral Graph)
PID/PPID canlı ağaç grafiği, Kural A (LOLBins), Kural B (Masquerading/Hollowing) ve
Registry Run / Startup / Zamanlanmış Görev kalıcılık kancalarını yönetir.
"""

from __future__ import annotations
import base64
import gzip
import hashlib
import os
import re
import threading
import time
import winreg
from typing import Callable, Dict, List, Optional, Set, Tuple

from core.event_bus import EventBus
from core.win32_native import (
    enumerate_process_modules,
    enumerate_processes_fast,
    enumerate_processes_incremental,
    inspect_process_memory_anomalies,
    suspend_process,
    terminate_process,
    verify_authenticode_catalog,
)

_EXPECTED_SCANNER_PATH = os.path.normcase(
    os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "engines",
            "csharp-scanner",
            "bin",
            "AegisScanner.exe",
        )
    )
)


_ENC_CMD_RX = re.compile(
    r"(?:^|[\s\"'])[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)(?:\s+|\s*:\s*)['\"]?([A-Za-z0-9+/=_-]{16,})['\"]?",
    re.IGNORECASE,
)
_FROM_B64_CMD_RX = re.compile(
    r"FromBase64String\s*\(\s*['\"]([A-Za-z0-9+/=_-]{16,})['\"]\s*\)",
    re.IGNORECASE,
)

_CMDLINE_FAST_MARKERS = (
    "-enc", "/enc", "-ec ", "/ec ", "-e ", "/e ", "encodedcommand", "downloadstring", "invoke-expression",
    "amsiscanbuffer", "virtualallocex", "vssadmin", "shadowcopy", "scrobj.dll",
    "comsvcs.dll", "ms-settings", "advfirewall", "invoke-cimmethod",
    "installutil", "msbuild", "schtasks", "curl", "tar.exe", "frombase64string",
    "taskkill", "windefend", "mpcmdrun", "ntdsutil", "esentutl", "reg save",
    "command processor", "appinit_dlls", "winlogon", "disabletaskmgr",
    "disableregistrytools", "syncappvpublishingserver", "pcalua", "bitsadmin",
    "certreq", "child_process", "subprocess", "socket.socket", "urllib",
)

_CMDLINE_THREAT_RULES: Tuple[Tuple[re.Pattern, str], ...] = (
    (
        re.compile(
            r"(?:(?:invoke-expression|\biex\b).{0,260}?(?:downloadstring|downloaddata|downloadfile|net\.webclient|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b|frombase64string)"
            r"|(?:downloadstring|downloaddata|downloadfile|net\.webclient|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b|frombase64string).{0,260}?(?:invoke-expression|\biex\b|\|)"
            r"|powershell(?:\.exe)?\s+.{0,180}?-(?:ep|executionpolicy)\s+bypass.{0,180}?-w(?:indowstyle)?\s+hidden.{0,220}?(?:https?://|\\temp\\|\\public\\|\\appdata\\|frombase64|-e(?:nc|c)?\b))",
            re.IGNORECASE | re.DOTALL,
        ),
        "Fileless.PowerShell.MemoryStager",
    ),
    (
        re.compile(
            r"(?:(?:System\.Net\.Sockets\.TcpClient|New-Object\s+Net\.Sockets\.TcpClient).{0,260}?(?:GetStream|cmd\.exe|powershell|RedirectStandardInput)"
            r"|(?:pythonw?(?:\.exe)?\s+.*?-c\b.{0,280}?(?:socket|subprocess|urllib|exec\s*\(|eval\s*\(|pty\.spawn|base64))"
            r"|(?:node(?:\.exe)?\s+.*?-e\b.{0,280}?(?:child_process|net\.connect|createConnection|eval\s*\(|http\.get|fetch\s*\()))",
            re.IGNORECASE | re.DOTALL,
        ),
        "Fileless.Interpreter.ReverseShellOrStager",
    ),
    (
        re.compile(
            r"(?:virtualallocex.{0,220}?writeprocessmemory|amsiscanbuffer|amsiutils|amsiinitfailed|etweventwrite)",
            re.IGNORECASE | re.DOTALL,
        ),
        "Fileless.AMSI_Injection.Stager",
    ),
    (
        re.compile(
            r"(?:vssadmin(?:\.exe)?\s+(?:delete\s+shadows|resize\s+shadowstorage)|wmic(?:\.exe)?\s+shadowcopy\s+delete|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)|bcdedit(?:\.exe)?\s+.{0,140}?recoveryenabled\s+no)",
            re.IGNORECASE | re.DOTALL,
        ),
        "Ransomware.ShadowCopy.RecoveryWipe",
    ),
    (
        re.compile(
            r"(?:reg(?:\.exe)?\s+save\s+hklm\\(?:sam|system|security)\b|ntdsutil(?:\.exe)?\s+.{0,160}?(?:ifm|ntds)|esentutl(?:\.exe)?\s+/y\s+/vss)",
            re.IGNORECASE | re.DOTALL,
        ),
        "CredentialAccess.LiveCmd.SAMOrNTDSDump",
    ),
    (
        re.compile(
            r"(?:mshta(?:\.exe)?\s+(?:https?://|javascript:|vbscript:)|regsvr32(?:\.exe)?\s+.{0,180}?(?:/i:https?://|scrobj\.dll|\\temp\\|\\appdata\\|\\users\\public\\|\\downloads\\)|rundll32(?:\.exe)?\s+.{0,220}?(?:javascript:|vbscript:|comsvcs\.dll.{0,80}?minidump|url\.dll,OpenURL|advpack\.dll|pcwutl\.dll|syssetup\.dll|\\temp\\|\\appdata\\|\\users\\public\\|\\downloads\\)|certutil(?:\.exe)?\s+.{0,180}?-urlcache.{0,120}?https?://|certreq(?:\.exe)?\s+-Post|bitsadmin(?:\.exe)?\s+/transfer|forfiles(?:\.exe)?\s+.{0,180}?/c\s+|cmstp(?:\.exe)?\s+/s|odbcconf(?:\.exe)?\s+.{0,140}?REGSVR|msiexec(?:\.exe)?\s+.{0,120}?/i\s+https?://|pcalua(?:\.exe)?\s+-a\s+|wmic(?:\.exe)?\s+.{0,160}?/format\s*:\s*[\"']?https?://|syncappvpublishingserver(?:\.exe)?\s+|Invoke-CimMethod.{0,180}?Win32_Process.{0,80}?Create)",
            re.IGNORECASE | re.DOTALL,
        ),
        "Fileless.LOLBin.RemoteExecution",
    ),
    (
        re.compile(
            r"(?:(?:Add-MpPreference|Set-MpPreference).{0,200}?(?:-Exclusion|-DisableRealtimeMonitoring|-DisableIOAVProtection|-DisableBehaviorMonitoring)"
            r"|MpCmdRun(?:\.exe)?\s+.{0,120}?-RemoveDefinitions"
            r"|(?:net(?:\.exe)?\s+stop|sc(?:\.exe)?\s+(?:stop|config|delete))\s+(?:WinDefend|WdNisSvc|Sense|SecurityHealthService)"
            r"|taskkill(?:\.exe)?\s+/f\s+/im\s+(?:MsMpEng|MpDefenderCoreService|AegisScanner|Taskmgr|ProcessHacker)"
            r"|reg(?:\.exe)?\s+add\s+.{0,240}?(?:DisableAntiSpyware|DisableRealtimeMonitoring|DisableTaskMgr|DisableRegistryTools|ms-settings\\Shell\\Open\\command|Image File Execution Options\\.{0,120}?Debugger|Winlogon\\.{0,80}?(?:Shell|Userinit)|Command Processor.{0,80}?AutoRun|AppInit_DLLs|Policies\\Explorer\\Run|WOW6432Node\\.{0,120}?\\Run)"
            r"|netsh(?:\.exe)?\s+advfirewall\s+set\s+allprofiles\s+state\s+off"
            r"|wevtutil(?:\.exe)?\s+cl\s+(?:Security|System|Application)"
            r"|sc(?:\.exe)?\s+create\s+.{0,160}?type=\s*kernel)",
            re.IGNORECASE | re.DOTALL,
        ),
        "DefenseEvasion.LiveCmd.SecurityTamper",
    ),
    (
        re.compile(
            r"(?:installutil(?:\.exe)?\s+.{0,160}?/logfile=.{0,200}?(?:/u\b|/uninstall)"
            r"|msbuild(?:\.exe)?\s+.{0,180}?(?:\\Temp\\|\\Public\\|\\AppData\\|\\Downloads\\).{0,160}?\.(?:xml|csproj|proj|targets))",
            re.IGNORECASE | re.DOTALL,
        ),
        "Fileless.DotNetLOLBin.Exec",
    ),
    (
        re.compile(
            r"(?:(?:curl|tar)(?:\.exe)?\s+.{0,200}?https?://[^\r\n]{0,160}?\|\s*(?:powershell|pwsh|cmd|iex\b))",
            re.IGNORECASE | re.DOTALL,
        ),
        "Fileless.PipedDownloader.Exec",
    ),
    (
        re.compile(
            r"schtasks(?:\.exe)?\s+/create\s+.{0,240}?(?:powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|\\temp\\|\\users\\public\\|\\appdata\\|\\downloads\\)",
            re.IGNORECASE | re.DOTALL,
        ),
        "Persistence.LiveCmd.ScheduledTask",
    ),
    (
        re.compile(
            r"(?:conhost(?:\.exe)?\s+--headless\s+.{0,180}?(?:powershell|pwsh|cmd|mshta|wscript|curl)"
            r"|finger(?:\.exe)?\s+[^\r\n]{0,120}@[^\r\n]{0,120}\|\s*(?:cmd|powershell|pwsh)"
            r"|hh(?:\.exe)?\s+https?://"
            r"|ssh(?:\.exe)?\s+.{0,160}?\s-(?:R|D)\s+\d{2,5}"
            r"|(?:cloudflared|ngrok|chisel|frpc)(?:\.exe)?\s+.{0,160}?(?:tunnel|tcp|client|--url))",
            re.IGNORECASE | re.DOTALL,
        ),
        "C2.LiveCmd.CovertTunnelOrClickFix",
    ),
)

_HOSTS_PATH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\drivers\etc\hosts")
_TASKS_DIR = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\Tasks")
_PAYLOAD_ARG_RX = re.compile(
    r"(?:\"([^\r\n\"]+\.(?:ps1|psm1|bat|cmd|vbs|vbe|js|jse|hta|py|dll|cpl|sct|wsf|msi|msix|jar|lnk|xml|chm))\"|([^\s\"']+\.(?:ps1|psm1|bat|cmd|vbs|vbe|js|jse|hta|py|dll|cpl|sct|wsf|msi|msix|jar|lnk|xml|chm)))",
    re.IGNORECASE,
)


def _file_sha256_small(path: str) -> str:
    try:
        if os.path.isfile(path) and os.path.getsize(path) <= 2 * 1024 * 1024:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        pass
    return ""


class ProcessLineageMonitor:
    """Canlı Ebeveyn-Çocuk süreç ağacını, dosyasız komut satırlarını ve kalıcılık kancalarını izler."""

    RULE_A_OFFICE_PARENTS = {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe",
        "eqnedt32.exe", "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe",
    }
    RULE_A_BROWSER_PARENTS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe"}
    RULE_A_LOLBINS = {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe",
        "msiexec.exe", "forfiles.exe", "pcalua.exe", "cmstp.exe", "odbcconf.exe",
        "msbuild.exe", "installutil.exe", "hh.exe", "wmic.exe",
    }
    RULE_A_HIGH_RISK_BROWSER_CHILDREN = {
        "mshta.exe", "certutil.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
        "powershell.exe", "pwsh.exe", "bitsadmin.exe", "forfiles.exe", "cmstp.exe",
        "odbcconf.exe", "hh.exe",
    }
    RULE_C_CMDLINE_TARGETS = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe",
        "regsvr32.exe", "certutil.exe", "wmic.exe", "bitsadmin.exe", "vssadmin.exe",
        "wbadmin.exe", "bcdedit.exe", "wscript.exe", "cscript.exe", "forfiles.exe",
        "cmstp.exe", "odbcconf.exe", "msiexec.exe", "reg.exe", "netsh.exe",
        "wevtutil.exe", "sc.exe", "schtasks.exe", "curl.exe", "ssh.exe",
        "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
        "python.exe", "pythonw.exe", "node.exe", "java.exe", "javaw.exe",
        "dotnet.exe", "conhost.exe", "pcalua.exe", "hh.exe", "certreq.exe",
        "esentutl.exe", "ftp.exe", "taskkill.exe", "syncappvpublishingserver.exe",
        "explorer.exe",
    }
    _INTERPRETER_PAYLOAD_EXES = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "python.exe", "pythonw.exe",
        "node.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
        "regsvr32.exe", "msiexec.exe", "java.exe", "javaw.exe", "hh.exe",
    }
    _HOLLOWING_OR_LOLBIN_MEM_TARGETS = {
        "svchost.exe", "notepad.exe", "regasm.exe", "vbc.exe", "applaunch.exe",
        "msbuild.exe", "installutil.exe", "cvtres.exe", "dllhost.exe",
        "rundll32.exe", "powershell.exe", "pwsh.exe", "explorer.exe",
    }
    _JIT_RUNTIMES = {
        "node.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
        "opera.exe", "vivaldi.exe", "python.exe", "pythonw.exe", "dotnet.exe",
        "code.exe", "antigravity.exe", "discord.exe",
    }
    _RISKY_RUN_DIRS = (
        "\\downloads\\", "\\indirilenler\\", "\\appdata\\local\\temp\\", "\\temp\\",
        "\\desktop\\", "\\masaüstü\\", "\\users\\public\\", "\\appdata\\roaming\\",
        "\\appdata\\local\\", "\\programdata\\", "\\onedrive\\", "\\documents\\",
        "\\belgeler\\", "\\music\\", "\\videos\\", "\\windows\\temp\\", "\\windows\\tasks\\",
    )
    _TRUSTED_SYSTEM_ROOT_PREFIXES = (
        "c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\windows\\winsxs\\",
        "c:\\program files\\", "c:\\program files (x86)\\",
    )

    RULE_B_EXPECTED_PARENTS = {
        "svchost.exe": {"services.exe", "svchost.exe"},
        "lsass.exe": {"wininit.exe"},
        "services.exe": {"wininit.exe"},
        "wininit.exe": {"smss.exe"},
        "csrss.exe": {"smss.exe"},
        "smss.exe": {"system"},
        "winlogon.exe": {"smss.exe"},
        "spoolsv.exe": {"services.exe"},
        "dwm.exe": {"winlogon.exe"},
        "taskhostw.exe": {"svchost.exe", "services.exe"},
        "sihost.exe": {"svchost.exe"},
        "runtimebroker.exe": {"svchost.exe"},
        "explorer.exe": {"userinit.exe", "explorer.exe", "winlogon.exe"},
        "conhost.exe": {"csrss.exe"},
        "ctfmon.exe": {"svchost.exe", "winlogon.exe"},
        "dllhost.exe": {"svchost.exe", "services.exe"},
        "searchindexer.exe": {"services.exe"},
        "msmpeng.exe": {"services.exe"},
    }

    RUN_KEYS = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        (winreg.HKEY_CURRENT_USER, r"Environment"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Command Processor"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Command Processor"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
        (winreg.HKEY_CURRENT_USER, r"Software\Classes\ms-settings\Shell\Open\command"),
        (winreg.HKEY_CURRENT_USER, r"Software\Classes\mscfile\Shell\Open\command"),
    ]

    def __init__(
        self,
        event_bus: EventBus,
        poll_interval_sec: float = 0.12,
        auto_freeze_on_rule_a: bool = False,
        auto_block: bool = True,
        exempt_pids: Optional[Set[int]] = None,
        on_untrusted_exec: Optional[Callable[[int, str, str], None]] = None,
        malicious_dlls: Optional[Set[str]] = None,
        hijackable_dlls: Optional[Set[str]] = None,
        on_persistence_event: Optional[Callable[[Dict[str, object]], None]] = None,
    ) -> None:
        self._bus = event_bus
        self._poll_interval = poll_interval_sec
        self._auto_freeze_on_rule_a = auto_freeze_on_rule_a
        self._auto_block = auto_block
        self._realtime_enabled = True
        self._on_untrusted_exec = on_untrusted_exec
        self._on_persistence_event = on_persistence_event
        self._malicious_dlls: Set[str] = {d.lower() for d in (malicious_dlls or set()) if d}
        self._hijackable_dlls: Set[str] = {d.lower() for d in (hijackable_dlls or set()) if d}
        self._aegis_root = os.path.normcase(os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
        self._exempt_pids: Set[int] = {os.getpid(), os.getppid()} | set(exempt_pids or set())
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._mem_sem = threading.Semaphore(2)
        self._scan_tick = 0
        self._mem_rotate_idx = 0

        self._pid_map: Dict[int, Dict[str, object]] = {}
        self._children_map: Dict[int, Set[int]] = {}
        self._last_new_pids: List[int] = []
        self._seen_alerts: Set[Tuple[int, str]] = set()
        self._registry_baseline: Dict[Tuple[int, str], Dict[str, str]] = {}
        self._startup_baseline: Dict[str, Set[str]] = {}
        self._tasks_baseline: Dict[str, float] = {}
        self._hosts_sha256: str = ""
        self._hosts_stat_sig: Optional[Tuple[int, int]] = None

        self._capture_persistence_baseline()
        self._baseline_pids: Set[int] = set(self.build_lineage_graph().keys())

    def configure_databases(
        self,
        malicious_dlls: Optional[Set[str]] = None,
        hijackable_dlls: Optional[Set[str]] = None,
        on_persistence_event: Optional[Callable[[Dict[str, object]], None]] = None,
    ) -> None:
        with self._lock:
            if malicious_dlls is not None:
                self._malicious_dlls = {d.lower() for d in malicious_dlls if d}
            if hijackable_dlls is not None:
                self._hijackable_dlls = {d.lower() for d in hijackable_dlls if d}
            if on_persistence_event is not None:
                self._on_persistence_event = on_persistence_event

    def set_policy(self, realtime_enabled: bool, auto_block: bool) -> None:
        with self._lock:
            self._realtime_enabled = bool(realtime_enabled)
            self._auto_block = bool(auto_block)

    def _is_exempt(self, pid: int, ppid: int, proc_name: str, proc_path: str = "") -> bool:
        if pid <= 4 or pid in self._exempt_pids:
            return True
        name_low = proc_name.lower()
        if name_low == "aegisscanner.exe" and proc_path:
            if os.path.normcase(os.path.abspath(proc_path)) == _EXPECTED_SCANNER_PATH:
                return True
        if ppid in self._exempt_pids and name_low == "conhost.exe":
            return True
        return False

    def _read_reg_dict(self, hive: int, subkey: str) -> Dict[str, str]:
        values: Dict[str, str] = {}
        sub_low = subkey.lower()
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                idx = 0
                while True:
                    try:
                        name, val, _rtype = winreg.EnumValue(key, idx)
                        n_low = str(name).lower()
                        if sub_low == "environment" and n_low != "userinitmprlogonscript":
                            idx += 1
                            continue
                        if sub_low.endswith(r"\command processor") and n_low != "autorun":
                            idx += 1
                            continue
                        if sub_low.endswith(r"\winlogon") and n_low not in {"shell", "userinit"}:
                            idx += 1
                            continue
                        if sub_low.endswith(r"\currentversion\windows") and n_low != "appinit_dlls":
                            idx += 1
                            continue
                        values[name] = str(val)
                        idx += 1
                    except OSError:
                        break
        except OSError:
            pass
        return values

    @staticmethod
    def _startup_dirs() -> List[str]:
        dirs = [
            os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), r"Microsoft\Windows\Start Menu\Programs\Startup"),
        ]
        return [d for d in dirs if d and os.path.isdir(d)]

    @staticmethod
    def _enumerate_non_ms_tasks() -> Dict[str, float]:
        out: Dict[str, float] = {}
        if not os.path.isdir(_TASKS_DIR):
            return out
        try:
            for root, dirs, files in os.walk(_TASKS_DIR):
                # Skip Microsoft inbox tasks tree to avoid Windows Update noise
                if os.path.normcase(root) == os.path.normcase(_TASKS_DIR):
                    dirs[:] = [d for d in dirs if d.lower() != "microsoft"]
                for fn in files:
                    fp = os.path.join(root, fn)
                    try:
                        out[fp] = os.path.getmtime(fp)
                    except OSError:
                        pass
                if len(out) >= 300:
                    break
        except OSError:
            pass
        return out

    def _capture_persistence_baseline(self) -> None:
        for hive, subkey in self.RUN_KEYS:
            self._registry_baseline[(hive, subkey)] = self._read_reg_dict(hive, subkey)

        for sdir in self._startup_dirs():
            try:
                self._startup_baseline[sdir] = set(os.listdir(sdir))
            except OSError:
                self._startup_baseline[sdir] = set()

        self._tasks_baseline = self._enumerate_non_ms_tasks()

        try:
            st = os.stat(_HOSTS_PATH)
            self._hosts_stat_sig = (st.st_size, st.st_mtime_ns)
        except OSError:
            self._hosts_stat_sig = None
        self._hosts_sha256 = _file_sha256_small(_HOSTS_PATH)

    def build_lineage_graph(self, snapshot: Optional[List[Dict[str, object]]] = None) -> Dict[int, Dict[str, object]]:
        """PID ve PPID üzerinden canlı ağaç grafiği kurar (değişiklik yoksa sıfır tahsis)."""
        if snapshot is None:
            with self._lock:
                prev_map = self._pid_map
            pid_map, new_pids, dead_pids = enumerate_processes_incremental(prev_map)
            with self._lock:
                if not new_pids and not dead_pids:
                    self._last_new_pids = []
                    return self._pid_map
                if dead_pids:
                    for dpid in dead_pids:
                        old_p = self._pid_map.get(dpid)
                        if old_p is not None:
                            old_ppid = int(old_p["ppid"])
                            ch = self._children_map.get(old_ppid)
                            if ch is not None:
                                ch.discard(dpid)
                                if not ch:
                                    del self._children_map[old_ppid]
                    self._baseline_pids -= dead_pids
                    self._seen_alerts = {item for item in self._seen_alerts if item[0] not in dead_pids}
                for npid in new_pids:
                    np = pid_map[npid]
                    self._children_map.setdefault(int(np["ppid"]), set()).add(npid)
                self._pid_map = pid_map
                self._last_new_pids = new_pids
            return pid_map

        pid_map: Dict[int, Dict[str, object]] = {}
        children_map: Dict[int, Set[int]] = {}
        for p in snapshot:
            pid = int(p["pid"])
            ppid = int(p["ppid"])
            pid_map[pid] = p
            children_map.setdefault(ppid, set()).add(pid)

        with self._lock:
            dead_pids = set(self._pid_map.keys()) - set(pid_map.keys())
            if dead_pids:
                self._baseline_pids -= dead_pids
                self._seen_alerts = {item for item in self._seen_alerts if item[0] not in dead_pids}
            self._pid_map = pid_map
            self._children_map = children_map
            self._last_new_pids = list(pid_map.keys())
        return pid_map

    def get_child_tree_pids(self, root_pid: int, rescan: bool = True) -> List[int]:
        """Verilen PID'nin tüm alt çocuk süreç ağaçlarını (BFS) döndürür."""
        if rescan:
            self.build_lineage_graph()
        with self._lock:
            visited: List[int] = []
            queue = [root_pid]
            seen = {root_pid}
            while queue:
                curr = queue.pop(0)
                for child in self._children_map.get(curr, set()):
                    if child not in seen:
                        seen.add(child)
                        visited.append(child)
                        queue.append(child)
            return visited

    def terminate_process_tree(self, root_pid: int, rescan: bool = False) -> bool:
        """Hedef süreci ve tüm alt çocuklarını askıya alıp sonlandırır."""
        if root_pid <= 4 or root_pid in self._exempt_pids:
            return False
        targets = [root_pid] + [c for c in self.get_child_tree_pids(root_pid, rescan=rescan) if c not in self._exempt_pids]
        for tpid in targets:
            suspend_process(tpid)
        any_killed = False
        for tpid in reversed(targets):
            if terminate_process(tpid):
                any_killed = True
        return any_killed

    @staticmethod
    def _normalize_cmdline(raw_cmdline: str) -> str:
        """Komut satırındaki caret (^), backtick (`), birleştirme ve Base64/GZip yüklerini normalleştirir."""
        parts = [raw_cmdline]
        caret_stripped = re.sub(r"\^([^\r\n])", r"\1", raw_cmdline)
        backtick_stripped = re.sub(r"`([^\r\n])", r"\1", caret_stripped)
        concat_collapsed = re.sub(r"['\"]\s*\+\s*['\"]", "", backtick_stripped)
        if concat_collapsed != raw_cmdline:
            parts.append(concat_collapsed)

        for rx in (_ENC_CMD_RX, _FROM_B64_CMD_RX):
            for m in rx.finditer(concat_collapsed):
                b64_tok = m.group(1).replace("-", "+").replace("_", "/")
                padded = b64_tok + ("=" * ((4 - len(b64_tok) % 4) % 4))
                try:
                    raw_bytes = base64.b64decode(padded, validate=False)
                    if raw_bytes.startswith(b"\x1f\x8b\x08"):
                        try:
                            raw_bytes = gzip.decompress(raw_bytes)
                        except Exception:
                            pass
                    for enc in ("utf-16le", "utf-8"):
                        dec = raw_bytes.decode(enc, errors="ignore").replace("\x00", "").strip()
                        if len(dec) >= 6:
                            parts.append(dec)
                except Exception:
                    pass
        return "\n".join(parts)

    @staticmethod
    def _decode_b64_command(raw_cmdline: str) -> str:
        return ProcessLineageMonitor._normalize_cmdline(raw_cmdline)

    def _extract_cmdline_payload_paths(self, cmdline: str) -> List[str]:
        """Yorumlayıcı/LOLBin komut satırı argümanlarındaki gerçek dosya yollarını ayıklar."""
        if not cmdline:
            return []
        found: List[str] = []
        seen_low: Set[str] = set()
        for m in _PAYLOAD_ARG_RX.finditer(cmdline):
            cand = (m.group(1) or m.group(2) or "").strip().strip("'\"")
            if not cand or cand.lower().startswith(("http://", "https://")):
                continue
            expanded = os.path.expandvars(cand)
            if not os.path.isabs(expanded):
                continue
            norm = os.path.normcase(os.path.abspath(expanded))
            if norm in seen_low or "\\node_modules\\" in norm or norm.startswith(self._aegis_root + os.sep):
                continue
            if norm.startswith("c:\\windows\\system32\\") or norm.startswith("c:\\windows\\syswow64\\"):
                continue
            if os.path.isfile(expanded):
                seen_low.add(norm)
                found.append(expanded)
        return found[:4]

    def evaluate_command_line(self, parent_name: str, child_name: str, child_pid: int, parent_pid: int, cmdline: str) -> Optional[Dict[str, object]]:
        """Kural C: Dosyasız LOLBin / -EncodedCommand / yorumlayıcı stager denetimi."""
        if not cmdline:
            return None
        name_low = child_name.lower()
        inspected_cmd = self._normalize_cmdline(cmdline)
        if name_low not in self.RULE_C_CMDLINE_TARGETS:
            cmd_low = inspected_cmd.lower()
            if not any(m in cmd_low for m in _CMDLINE_FAST_MARKERS):
                return None
        if (child_pid, "CMDLINE_INSPECTED") in self._seen_alerts:
            return None
        self._seen_alerts.add((child_pid, "CMDLINE_INSPECTED"))

        matched_threat = ""
        for rx, threat_label in _CMDLINE_THREAT_RULES:
            if rx.search(inspected_cmd):
                matched_threat = threat_label
                break
        if not matched_threat:
            return None

        terminated = False
        if self._auto_block and not self._is_exempt(child_pid, parent_pid, child_name):
            terminated = self.terminate_process_tree(child_pid, rescan=False)

        finding = {
            "rule": "RULE_C_FILELESS_CMDLINE",
            "pid": child_pid,
            "ppid": parent_pid,
            "parent_name": parent_name,
            "child_name": child_name,
            "cmdline": cmdline[:260],
            "threat_name": matched_threat,
            "terminated": terminated,
            "score_delta": 95,
            "description": f"Dosyasız Komut Satırı Saldırısı Engellendi: {child_name} ({matched_threat})",
        }
        self._bus.emit(
            "MOD3_LINEAGE_GRAPH",
            "FILELESS_CMDLINE_BLOCKED",
            severity="CRITICAL",
            **finding,
        )
        return finding

    def evaluate_process_pair(self, parent_name: str, child_name: str, child_pid: int, child_path: str = "", parent_pid: int = 0) -> List[Dict[str, object]]:
        """Kural A ve Kural B denetimlerini tek bir süreç çifti üzerinde değerlendirir."""
        findings: List[Dict[str, object]] = []
        p_low = parent_name.lower()
        c_low = child_name.lower()
        c_path_low = child_path.lower()

        # Kural A: Belge uygulamasından LOLBin veya tarayıcıdan yüksek riskli betik motoru başlatma
        is_office_lolbin = (p_low in self.RULE_A_OFFICE_PARENTS and c_low in self.RULE_A_LOLBINS)
        is_browser_dropper = (p_low in self.RULE_A_BROWSER_PARENTS and c_low in self.RULE_A_HIGH_RISK_BROWSER_CHILDREN)

        if (is_office_lolbin or is_browser_dropper) and (child_pid, "RULE_A_LOLBIN_SPAWN") not in self._seen_alerts:
            self._seen_alerts.add((child_pid, "RULE_A_LOLBIN_SPAWN"))
            if (self._auto_freeze_on_rule_a or self._auto_block) and not self._is_exempt(child_pid, parent_pid, child_name):
                suspend_process(child_pid)

            finding = {
                "rule": "RULE_A_LOLBIN_SPAWN",
                "pid": child_pid,
                "ppid": parent_pid,
                "parent_name": parent_name,
                "child_name": child_name,
                "child_path": child_path,
                "score_delta": 35,
                "description": f"Anormal Soy Ağacı (Kural A): {parent_name} -> {child_name} başlattı",
            }
            findings.append(finding)
            self._bus.emit(
                "MOD3_LINEAGE_GRAPH",
                "SUSPICIOUS_LINEAGE_DETECTED",
                severity="CRITICAL",
                **finding,
            )

        # Kural B: Kritik sistem sürecinin gerçek Windows dizini dışından veya şüpheli ebeveynle çalışması
        if c_low in self.RULE_B_EXPECTED_PARENTS and (child_pid, "RULE_B_SYSTEM_MASQUERADE") not in self._seen_alerts:
            if c_low == "explorer.exe":
                in_sys_dir = (
                    (not c_path_low)
                    or c_path_low == "c:\\windows\\explorer.exe"
                    or c_path_low.startswith("c:\\windows\\system32\\")
                    or c_path_low.startswith("c:\\windows\\syswow64\\")
                )
            elif c_low == "msmpeng.exe":
                in_sys_dir = (
                    (not c_path_low)
                    or c_path_low.startswith("c:\\programdata\\microsoft\\windows defender\\")
                    or c_path_low.startswith("c:\\program files\\windows defender\\")
                )
            else:
                in_sys_dir = (
                    (not c_path_low)
                    or c_path_low.startswith("c:\\windows\\system32\\")
                    or c_path_low.startswith("c:\\windows\\syswow64\\")
                )

            bad_path = bool(c_path_low) and not in_sys_dir
            suspicious_spawners = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "winword.exe", "excel.exe"}
            bad_parent = (p_low in suspicious_spawners) and not (c_low == "conhost.exe")

            if bad_path or bad_parent:
                self._seen_alerts.add((child_pid, "RULE_B_SYSTEM_MASQUERADE"))
                terminated = False
                if bad_path and self._auto_block and not self._is_exempt(child_pid, parent_pid, child_name, child_path):
                    terminated = self.terminate_process_tree(child_pid, rescan=False)
                finding = {
                    "rule": "RULE_B_SYSTEM_MASQUERADE",
                    "pid": child_pid,
                    "ppid": parent_pid,
                    "parent_name": parent_name,
                    "child_name": child_name,
                    "child_path": child_path,
                    "file_path": child_path if bad_path else "",
                    "should_quarantine": bool(bad_path),
                    "terminated": terminated,
                    "score_delta": 95 if bad_path else 35,
                    "description": f"Sistem Süreci Taklidi (Kural B): {child_name} (Ebeveyn: {parent_name or 'Bilinmiyor'}, Yol: {child_path or 'Gizli'})",
                }
                findings.append(finding)
                self._bus.emit(
                    "MOD3_LINEAGE_GRAPH",
                    "SYSTEM_MASQUERADE_DETECTED",
                    severity="CRITICAL",
                    **finding,
                )

        return findings

    def scan_process_memory_now(self, pid: int, proc_name: str = "", exe_path: str = "") -> Dict[str, object]:
        """Tek bir PID üzerinde canlı DLL side-loading + Process Hollowing + kabuk kodu denetimi."""
        if pid <= 4 or pid in self._exempt_pids:
            return {}
        c_low = (proc_name or os.path.basename(exe_path or "")).lower()
        p_low = (exe_path or "").lower()
        is_jit = c_low in self._JIT_RUNTIMES
        is_hollow_target = (c_low in self._HOLLOWING_OR_LOLBIN_MEM_TARGETS) or bool(
            p_low and not p_low.startswith(self._TRUSTED_SYSTEM_ROOT_PREFIXES)
        )

        # 1. Live DLL Side-Loading / Malicious Loaded Module Detection
        mods = enumerate_process_modules(pid)
        for mod in mods:
            m_name = str(mod.get("name") or "").lower()
            m_path = str(mod.get("path") or "")
            m_path_low = m_path.lower()
            if not m_name or not m_path:
                continue

            if m_name in self._malicious_dlls:
                terminated = False
                if self._auto_block:
                    terminated = self.terminate_process_tree(pid, rescan=False)
                self._bus.emit(
                    "MOD3_LINEAGE_GRAPH",
                    "DLL_INJECTION_DETECTED",
                    severity="CRITICAL",
                    pid=pid,
                    child_name=proc_name,
                    file_path=m_path,
                    dll_path=m_path,
                    threat_name=f"Trojan.LiveModule.{m_name}",
                    terminated=terminated,
                    score_delta=95,
                    description=f"Canlı Süreç İçinde Bilinen Zararlı DLL Yüklendi: {m_name} (PID {pid})",
                )
                return {"dll_injection": m_path, "terminated": terminated}

            is_risky_dll_dir = any(z in m_path_low for z in self._RISKY_RUN_DIRS)
            is_in_win = any(m_path_low.startswith(p) for p in ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\windows\\winsxs\\"))
            if not is_in_win and ((m_name in self._hijackable_dlls and is_risky_dll_dir) or (c_low in self._HOLLOWING_OR_LOLBIN_MEM_TARGETS and is_risky_dll_dir)):
                signed, _signer = verify_authenticode_catalog(m_path)
                if not signed:
                    terminated = False
                    if self._auto_block:
                        terminated = self.terminate_process_tree(pid, rescan=False)
                    self._bus.emit(
                        "MOD3_LINEAGE_GRAPH",
                        "DLL_INJECTION_DETECTED",
                        severity="CRITICAL",
                        pid=pid,
                        child_name=proc_name,
                        file_path=m_path,
                        dll_path=m_path,
                        threat_name=f"Trojan.LiveDLLSideLoading.{m_name}",
                        terminated=terminated,
                        score_delta=95,
                        description=f"Canlı DLL Side-Loading / İmzasız Modül Enjeksiyonu: {proc_name} <- {m_name}",
                    )
                    return {"dll_sideloading": m_path, "terminated": terminated}

        # 2. Live Process Hollowing & Unbacked Executable Memory Inspection
        mem_rep = inspect_process_memory_anomalies(
            pid,
            exe_path=exe_path,
            check_hollowing=is_hollow_target,
            is_jit_runtime=is_jit,
        )
        if mem_rep.get("hollowing_detected"):
            terminated = False
            if self._auto_block:
                terminated = self.terminate_process_tree(pid, rescan=False)
            self._bus.emit(
                "MOD3_LINEAGE_GRAPH",
                "PROCESS_HOLLOWING_DETECTED",
                severity="CRITICAL",
                pid=pid,
                child_name=proc_name,
                file_path=exe_path,
                threat_name="Trojan.Memory.ProcessHollowing",
                terminated=terminated,
                score_delta=95,
                description=f"Canlı Process Hollowing Saldırısı Durduruldu: {proc_name} (PID {pid})",
                findings=mem_rep.get("findings") or [],
            )
            return mem_rep
        if mem_rep.get("unbacked_shellcode_detected"):
            terminated = False
            if self._auto_block:
                terminated = self.terminate_process_tree(pid, rescan=False)
            self._bus.emit(
                "MOD3_LINEAGE_GRAPH",
                "MEMORY_INJECTION_DETECTED",
                severity="CRITICAL",
                pid=pid,
                child_name=proc_name,
                file_path=exe_path,
                threat_name="Trojan.Memory.FilelessShellcode",
                terminated=terminated,
                score_delta=95,
                description=f"Bellekte Yedeklenmemiş Shellcode / Reflective Yük Tespit Edildi: {proc_name} (PID {pid})",
                findings=mem_rep.get("findings") or [],
            )
            return mem_rep
        return mem_rep

    def _run_memory_worker(self, pid: int, proc_name: str, exe_path: str) -> None:
        if not self._mem_sem.acquire(blocking=False):
            return
        try:
            self.scan_process_memory_now(pid, proc_name=proc_name, exe_path=exe_path)
        except Exception:
            pass
        finally:
            self._mem_sem.release()

    def _poll_persistence_and_hijacks(self) -> None:
        # Kalıcılık & UAC Bypass & AutoRun anahtarları kontrolü
        for hive, subkey in self.RUN_KEYS:
            current = self._read_reg_dict(hive, subkey)
            prev = self._registry_baseline.get((hive, subkey), {})
            for val_name, val_data in current.items():
                if val_name not in prev or prev[val_name] != val_data:
                    old_val = prev.get(val_name)
                    self._registry_baseline[(hive, subkey)][val_name] = val_data
                    evt_payload = {
                        "kind": "registry",
                        "hive": hive,
                        "subkey": subkey,
                        "value_name": val_name,
                        "new_value": val_data,
                        "old_value": old_val,
                        "score_delta": 25,
                        "description": f"Kayıt Defteri Kalıcılık / Kanca Değişimi: {subkey} ({val_name})",
                    }
                    self._bus.emit(
                        "MOD3_LINEAGE_GRAPH",
                        "PERSISTENCE_MODIFICATION_DETECTED",
                        severity="HIGH",
                        **evt_payload,
                    )
                    if self._on_persistence_event is not None:
                        try:
                            self._on_persistence_event(evt_payload)
                        except Exception:
                            pass

        # Kullanıcı & Ortak Startup klasörleri değişimi
        for sdir in self._startup_dirs():
            try:
                curr_files = set(os.listdir(sdir))
            except OSError:
                continue
            prev_files = self._startup_baseline.setdefault(sdir, set())
            for new_f in (curr_files - prev_files):
                prev_files.add(new_f)
                full_fp = os.path.join(sdir, new_f)
                evt_payload = {
                    "kind": "startup_file",
                    "location": "StartupFolder",
                    "file_path": full_fp,
                    "score_delta": 25,
                    "description": f"Başlangıç Klasörüne Yeni Öğe Eklendi: {new_f}",
                }
                self._bus.emit(
                    "MOD3_LINEAGE_GRAPH",
                    "PERSISTENCE_MODIFICATION_DETECTED",
                    severity="HIGH",
                    **evt_payload,
                )
                if self._on_persistence_event is not None:
                    try:
                        self._on_persistence_event(evt_payload)
                    except Exception:
                        pass

        # Non-Microsoft Scheduled Tasks XML değişiklikleri
        curr_tasks = self._enumerate_non_ms_tasks()
        for tpath, tmtime in curr_tasks.items():
            prev_m = self._tasks_baseline.get(tpath)
            if prev_m is None or tmtime != prev_m:
                self._tasks_baseline[tpath] = tmtime
                evt_payload = {
                    "kind": "scheduled_task",
                    "location": "ScheduledTasks",
                    "file_path": tpath,
                    "score_delta": 35,
                    "description": f"Yeni veya Değiştirilmiş Zamanlanmış Görev XML: {os.path.basename(tpath)}",
                }
                self._bus.emit(
                    "MOD3_LINEAGE_GRAPH",
                    "PERSISTENCE_MODIFICATION_DETECTED",
                    severity="HIGH",
                    **evt_payload,
                )
                if self._on_persistence_event is not None:
                    try:
                        self._on_persistence_event(evt_payload)
                    except Exception:
                        pass

        # Windows hosts dosyası bütünlük değişimi (stat önbellekli)
        try:
            st = os.stat(_HOSTS_PATH)
            curr_sig: Optional[Tuple[int, int]] = (st.st_size, st.st_mtime_ns)
        except OSError:
            curr_sig = None

        if curr_sig != self._hosts_stat_sig:
            self._hosts_stat_sig = curr_sig
            curr_hosts = _file_sha256_small(_HOSTS_PATH)
            if curr_hosts and self._hosts_sha256 and curr_hosts != self._hosts_sha256:
                self._hosts_sha256 = curr_hosts
                self._bus.emit(
                    "MOD3_LINEAGE_GRAPH",
                    "PERSISTENCE_MODIFICATION_DETECTED",
                    severity="HIGH",
                    location="HostsFile",
                    file_path=_HOSTS_PATH,
                    score_delta=35,
                    description="Windows hosts (DNS Yönlendirme) Dosyası Değiştirildi",
                )

    def scan_once(self) -> List[Dict[str, object]]:
        """Anlık süreç ağacını (yalnızca yeni PID'ler), dosyasız komut satırlarını, bellek/DLL enjeksiyonlarını ve kalıcılık anahtarlarını tarar."""
        if not self._realtime_enabled:
            return []

        pid_map = self.build_lineage_graph()
        all_findings: List[Dict[str, object]] = []
        self._scan_tick += 1

        target_pids = list(pid_map.keys()) if self._scan_tick == 1 else list(self._last_new_pids)
        for pid in target_pids:
            proc = pid_map.get(pid)
            if proc is None:
                continue
            ppid = int(proc["ppid"])
            parent = pid_map.get(ppid)
            parent_name = str(parent["name"]) if parent else ""
            child_name = str(proc["name"])
            child_path = str(proc.get("path", ""))
            cmdline = str(proc.get("cmdline", ""))

            if pid not in self._baseline_pids and not self._is_exempt(pid, ppid, child_name, child_path):
                cmd_finding = self.evaluate_command_line(parent_name, child_name, pid, ppid, cmdline)
                if cmd_finding:
                    all_findings.append(cmd_finding)

                c_name_low = child_name.lower()
                c_path_norm = os.path.normcase(os.path.abspath(child_path)) if child_path else ""
                is_outside_trusted_dirs = bool(
                    c_path_norm
                    and not c_path_norm.startswith(self._TRUSTED_SYSTEM_ROOT_PREFIXES)
                    and not c_path_norm.startswith(self._aegis_root + os.sep)
                )

                # Extract & inspect script/DLL/MSI payload arguments passed to interpreters/LOLBins
                if self._on_untrusted_exec is not None and c_name_low in self._INTERPRETER_PAYLOAD_EXES and cmdline and (pid, "ARG_PAYLOAD_INSPECTED") not in self._seen_alerts:
                    self._seen_alerts.add((pid, "ARG_PAYLOAD_INSPECTED"))
                    for payload_path in self._extract_cmdline_payload_paths(cmdline):
                        if threading.active_count() < 28:
                            threading.Thread(target=self._on_untrusted_exec, args=(pid, payload_path, cmdline), daemon=True).start()

                # Inspect any new process running outside Windows/Program Files/AegisCore
                if (
                    self._on_untrusted_exec is not None
                    and child_path
                    and (pid, "EXEC_INSPECTED") not in self._seen_alerts
                    and (is_outside_trusted_dirs or any(z in c_path_norm for z in self._RISKY_RUN_DIRS))
                ):
                    self._seen_alerts.add((pid, "EXEC_INSPECTED"))
                    if threading.active_count() < 28:
                        threading.Thread(target=self._on_untrusted_exec, args=(pid, child_path, cmdline), daemon=True).start()

                # Async live DLL side-loading + Process Hollowing / unbacked memory check for risky or hollow-prone targets
                if (
                    (pid, "MEM_INSPECTED") not in self._seen_alerts
                    and (is_outside_trusted_dirs or c_name_low in self._HOLLOWING_OR_LOLBIN_MEM_TARGETS)
                ):
                    self._seen_alerts.add((pid, "MEM_INSPECTED"))
                    if threading.active_count() < 28:
                        threading.Thread(target=self._run_memory_worker, args=(pid, child_name, child_path), daemon=True).start()

            pair_findings = self.evaluate_process_pair(parent_name, child_name, pid, child_path, ppid)
            all_findings.extend(pair_findings)

        if self._scan_tick % 20 == 0:
            self._poll_persistence_and_hijacks()

        # Periodic rotation sweep (8 processes every ~3s) to catch late DLL injection or delayed hollowing
        if self._scan_tick % 25 == 0 and pid_map:
            rot_cands = [
                (p_id, p_info) for p_id, p_info in pid_map.items()
                if p_id > 4 and p_id not in self._exempt_pids and (
                    str(p_info.get("name", "")).lower() in self._HOLLOWING_OR_LOLBIN_MEM_TARGETS
                    or (p_info.get("path") and not str(p_info.get("path", "")).lower().startswith(self._TRUSTED_SYSTEM_ROOT_PREFIXES))
                )
            ]
            if rot_cands:
                start_i = self._mem_rotate_idx % len(rot_cands)
                batch = (rot_cands[start_i:] + rot_cands[:start_i])[:8]
                self._mem_rotate_idx = (start_i + 8) % len(rot_cands)
                for p_id, p_info in batch:
                    if threading.active_count() < 28:
                        threading.Thread(
                            target=self._run_memory_worker,
                            args=(p_id, str(p_info.get("name", "")), str(p_info.get("path", ""))),
                            daemon=True,
                        ).start()

        return all_findings

    def start(self) -> None:
        if self._running:
            return
        self._running = True

        def _loop() -> None:
            while self._running:
                try:
                    self.scan_once()
                except Exception:
                    pass
                time.sleep(self._poll_interval)

        self._thread = threading.Thread(target=_loop, name="AegisLineageMonitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.5)
            self._thread = None


_normalize_cmdline_for_inspection = ProcessLineageMonitor._normalize_cmdline
