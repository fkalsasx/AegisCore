#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MODÜL 2 :: "Gölge Kafes" – Sıfır-İnfazlı Statik & AST Davranış Emülatörü
Zararlı dosyaları gerçek işletim sisteminde çalıştırmadan (Zero-RCE Sandbox) AST,
uyku atlatma (Sleep-Evasion), Anti-VM yoklaması, dosya bırakma ve süreç başlatma niyetini analiz eder.
"""

from __future__ import annotations
import ast
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from core.event_bus import EventBus

_SUPERLX_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "engines", "superlx"))
if _SUPERLX_DIR not in sys.path:
    sys.path.insert(0, _SUPERLX_DIR)
try:
    from superlx_engine import deobfuscate_layers as _deobfuscate_layers
except Exception:
    _deobfuscate_layers = None


@dataclass
class DetonationReport:
    session_id: str
    target_path: str
    pid: Optional[int]
    observation_ms: float
    sleep_calls_patched: int
    anti_vm_profile_injected: bool
    files_created: List[str] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    child_processes_spawned: int = 0
    verdict: str = "CLEAN"
    risk_delta: int = 0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


class ShadowCageSandbox:
    """
    Şüpheli betik ve yürütülebilir dosyaları konak OS üzerinde ASLA çalıştırmadan
    statik + AST tabanlı izole davranışsal emülasyonla değerlendirir.
    """

    SLEEP_PATTERNS = (
        re.compile(r"\bStart-Sleep\s+(?:-Seconds|-s|-Milliseconds|-m)?\s*\d+", re.IGNORECASE),
        re.compile(r"\btime\.sleep\s*\(\s*[\d.]+\s*\)"),
        re.compile(r"\bWScript\.Sleep\s*\(?\s*\d+\s*\)?", re.IGNORECASE),
        re.compile(r"\bSleep\s*\(\s*\d+\s*\)", re.IGNORECASE),
        re.compile(r"\btimeout\s+/t\s+\d+(?:\s+/nobreak)?", re.IGNORECASE),
    )

    ANTI_VM_RX = re.compile(
        r"\b(?:Win32_BIOS|Win32_ComputerSystem|VirtualBox|VMware|QEMU|SbieDll|IsDebuggerPresent|CheckRemoteDebuggerPresent|GetCursorPos|GetTickCount)\b",
        re.IGNORECASE,
    )
    FILE_DROP_RX = re.compile(
        r"(?:WriteAllBytes|WriteAllText|Out-File|Copy-Item|Remove-Item.{0,120}?-Recurse|\bdel\s+/[fq]|shutil\.rmtree|os\.remove|os\.unlink|open\s*\([^)\r\n]+,\s*['\"](?:wb|w|ab)['\"])",
        re.IGNORECASE,
    )
    PROC_NET_RX = re.compile(
        r"(?:subprocess\.(?:Popen|run|call)|os\.system|os\.popen|Start-Process|WScript\.Shell|ShellExecute|urllib\.request|requests\.(?:post|get)|System\.Net\.(?:WebClient|Http|Sockets)|XMLHTTP|WinHttpRequest)",
        re.IGNORECASE,
    )
    PERSISTENCE_INTENT_RX = re.compile(
        r"(?:CurrentVersion\\Run(?:Once)?|\bschtasks\b|New-ScheduledTask|\\Start Menu\\Programs\\Startup|Winlogon\\|ms-settings\\Shell\\Open\\command)",
        re.IGNORECASE,
    )
    CRED_STEAL_RX = re.compile(
        r"(?:Login Data|Local State|cookies\.sqlite|CryptUnprotectData|MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn|tdata|\\lsass\b|MiniDumpWriteDump|key4\.db)",
        re.IGNORECASE,
    )
    INJECT_C2_RX = re.compile(
        r"(?:VirtualAlloc(?:Ex)?|WriteProcessMemory|CreateRemoteThread|Assembly\]::Load|Assembly\.Load|TcpClient|discord\.com/api/webhooks/|api\.telegram\.org/bot|SetWindowsHookEx|GetAsyncKeyState)",
        re.IGNORECASE,
    )

    def __init__(self, event_bus: EventBus, cage_root: str) -> None:
        self._bus = event_bus
        self._cage_root = os.path.abspath(cage_root)
        os.makedirs(self._cage_root, exist_ok=True)

    @staticmethod
    def _extract_path_hint(node: ast.AST) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Call):
            parts = [str(a.value) for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            if parts:
                return os.path.join(*parts)
        return ""

    @classmethod
    def _inspect_python_ast(cls, text: str) -> Dict[str, object]:
        stats: Dict[str, object] = {"file_ops": 0, "proc_net_ops": 0, "write_targets": []}
        try:
            tree = ast.parse(text)
        except Exception:
            return stats

        file_funcs = {"open", "rmtree", "remove", "unlink", "write_bytes", "write_text"}
        proc_funcs = {"Popen", "run", "call", "system", "popen", "urlopen", "post", "get", "exec", "eval"}
        var_paths: Dict[str, str] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                hint = cls._extract_path_hint(node.value)
                if hint:
                    var_paths[node.targets[0].id] = hint
            elif isinstance(node, ast.Call):
                name = ""
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name in file_funcs:
                    if name == "open":
                        mode_s = ""
                        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                            mode_s = str(node.args[1].value)
                        for kw in node.keywords:
                            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                                mode_s = str(kw.value.value)
                        if any(m in mode_s for m in ("w", "a", "+")):
                            stats["file_ops"] = int(stats["file_ops"]) + 1
                            if node.args:
                                target_hint = cls._extract_path_hint(node.args[0])
                                if not target_hint and isinstance(node.args[0], ast.Name):
                                    target_hint = var_paths.get(node.args[0].id, "")
                                if target_hint:
                                    stats["write_targets"].append(target_hint)
                    else:
                        stats["file_ops"] = int(stats["file_ops"]) + 1
                        if node.args:
                            target_hint = cls._extract_path_hint(node.args[0])
                            if target_hint:
                                stats["write_targets"].append(target_hint)
                elif name in proc_funcs:
                    stats["proc_net_ops"] = int(stats["proc_net_ops"]) + 1
        return stats

    def detonate(self, target_path: str, observation_ms: int = 500) -> DetonationReport:
        """Hedef dosyayı gerçek sistemde çalıştırmadan Sıfır-İnfaz emülasyonuyla çözümler."""
        session_id = str(uuid.uuid4())[:12]
        t_start = time.perf_counter()

        report = DetonationReport(
            session_id=session_id,
            target_path=target_path,
            pid=None,
            observation_ms=0.0,
            sleep_calls_patched=0,
            anti_vm_profile_injected=True,
        )

        ext = os.path.splitext(target_path)[1].lower()
        content = ""
        try:
            if os.path.isfile(target_path):
                with open(target_path, "rb") as f:
                    raw = f.read(2 * 1024 * 1024)
                content = raw.decode("utf-8", errors="ignore")
                if b"\x00" in raw[:4096]:
                    content += "\n" + raw.decode("utf-16le", errors="ignore")
        except Exception as exc:
            report.notes.append(f"Emülasyon okuma notu: {exc}")

        if content:
            emulated_text = content
            if _deobfuscate_layers is not None:
                try:
                    deobf_txt, deobf_notes = _deobfuscate_layers(content, is_binary=False)
                    if deobf_txt and len(deobf_txt) > len(content):
                        emulated_text = deobf_txt
                    if deobf_notes:
                        report.notes.append(f"Emülatör çözme katmanı: {', '.join(deobf_notes[:2])}")
                except Exception:
                    pass

            for rx in self.SLEEP_PATTERNS:
                report.sleep_calls_patched += len(rx.findall(emulated_text))

            anti_vm_hits = self.ANTI_VM_RX.findall(emulated_text)
            file_hits = self.FILE_DROP_RX.findall(emulated_text)
            proc_hits = self.PROC_NET_RX.findall(emulated_text)
            persist_hits = self.PERSISTENCE_INTENT_RX.findall(emulated_text)
            cred_hits = self.CRED_STEAL_RX.findall(emulated_text)
            inject_hits = self.INJECT_C2_RX.findall(emulated_text)
            ast_stats = self._inspect_python_ast(content) if ext == ".py" else {"file_ops": 0, "proc_net_ops": 0, "write_targets": []}

            if anti_vm_hits:
                report.risk_delta += 25
                report.notes.append(f"Anti-VM / Sandbox atlatma yoklaması tespit edildi ({len(anti_vm_hits)} referans)")

            write_targets = list(ast_stats.get("write_targets") or [])
            for m in re.findall(r"(?:Out-File|WriteAllText|WriteAllBytes)\s+['\"]?([^'\"\r\n,;\)]+)", emulated_text, re.IGNORECASE)[:5]:
                write_targets.append(m.strip())

            total_file_intent = len(file_hits) + int(ast_stats["file_ops"])
            if total_file_intent > 0:
                if write_targets:
                    for wt in write_targets[:6]:
                        report.files_modified.append(wt)
                        report.files_created.append(wt)
                else:
                    report.files_created.extend([f"emulated_write_{i+1}" for i in range(min(5, total_file_intent))])
                if re.search(r"(?:Remove-Item|rmtree|os\.remove|os\.unlink|\bdel\s+/[fq])", emulated_text, re.IGNORECASE):
                    report.files_modified.append("simulated_delete_attempt")
                report.risk_delta += 30
                report.notes.append(f"Sıfır-İnfaz emülasyonu: Dosya yazma/silme niyeti ({total_file_intent} çağrı)")

            total_proc_net = len(proc_hits) + int(ast_stats["proc_net_ops"])
            if total_proc_net > 0:
                report.child_processes_spawned = total_proc_net
                report.risk_delta += 30
                report.notes.append(f"Sıfır-İnfaz emülasyonu: Alt süreç veya C2 ağ niyeti ({total_proc_net} çağrı)")

            if persist_hits:
                report.risk_delta += 30
                report.notes.append(f"Sıfır-İnfaz emülasyonu: Kalıcılık (Run/ScheduledTask/Startup) niyeti ({len(persist_hits)} iz)")

            if cred_hits:
                report.risk_delta += 35
                report.notes.append(f"Sıfır-İnfaz emülasyonu: Tarayıcı/Cüzdan/LSASS kimlik bilgisi hedefleme ({len(cred_hits)} iz)")

            if inject_hits:
                report.risk_delta += 35
                report.notes.append(f"Sıfır-İnfaz emülasyonu: Bellek enjeksiyonu veya C2 kanalı niyeti ({len(inject_hits)} iz)")

            if report.sleep_calls_patched > 0 and (report.risk_delta > 0 or report.sleep_calls_patched >= 1):
                if report.risk_delta > 0:
                    report.risk_delta += 15
                    report.notes.append(f"Uyku atlatma (Sleep-Evasion) tespit edildi: {report.sleep_calls_patched} çağrı")

        report.risk_delta = min(75, report.risk_delta)
        report.verdict = "MALICIOUS" if report.risk_delta >= 55 else ("SUSPICIOUS" if report.risk_delta >= 25 else "CLEAN")
        report.observation_ms = round((time.perf_counter() - t_start) * 1000.0, 2)

        self._bus.emit(
            "MOD2_SHADOW_CAGE",
            "SHADOW_CAGE_DETONATION_REPORT",
            severity="HIGH" if report.risk_delta >= 40 else "INFO",
            pid=None,
            report=report.to_dict(),
        )
        return report
