#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MODÜL 5 :: "Bilişsel Risk Barometresi" – Dinamik Skorlama Motoru (0-100 Risk Matrix)
Her aktif PID için 0-100 arası canlı tehdit puanı hesaplar ve eşik değerlere
(30+, 50+, 80+) göre Zaman Makinesi, Kısıtlama ve İnfaz + Rollback aksiyonlarını yürütür.
"""

from __future__ import annotations
import json
import os
import subprocess
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set

from core.event_bus import EventBus, TelemetryPacket
from core.win32_native import lower_process_priority, suspend_process, terminate_process
from modules.m3_process_lineage import ProcessLineageMonitor
from modules.m6_time_machine import AtomicTimeMachine
from modules.m7_self_defense_vault import SelfDefenseVault


class RiskSignal(Enum):
    UNSIGNED_EXECUTABLE = ("UNSIGNED_EXECUTABLE", 15, "Dijital imzasız çalıştırılabilir dosya")
    TEMP_OR_DOWNLOADS_EXECUTION = ("TEMP_OR_DOWNLOADS_EXECUTION", 15, "Geçici klasörlerden (Temp/Downloads) doğrudan çalışma")
    HIGH_ENTROPY = ("HIGH_ENTROPY", 25, "Yüksek Entropi (> 7.2) paketlenmiş/şifreli yapı")
    PERSISTENCE_ATTEMPT = ("PERSISTENCE_ATTEMPT", 25, "Kalıcılık (Registry Run / Zamanlanmış Görev) girişimi")
    SUSPICIOUS_LINEAGE = ("SUSPICIOUS_LINEAGE", 35, "Şüpheli Soy Ağacı (LOLBins / Masquerading)")
    MEMORY_INJECTION_OR_HOOK = ("MEMORY_INJECTION_OR_HOOK", 45, "Başka bir sürecin belleğine müdahale / API Hooking")
    C2_SUSPICIOUS_NETWORK = ("C2_SUSPICIOUS_NETWORK", 45, "Şüpheli C2 / RAT Ağ Soketi Bağlantısı")
    DLL_SIDELOADING_OR_MALICIOUS_MODULE = ("DLL_SIDELOADING_OR_MALICIOUS_MODULE", 65, "Canlı Süreç İçinde İmzasız / Zararlı DLL Side-Loading")
    PROCESS_HOLLOWING_OR_INJECTION = ("PROCESS_HOLLOWING_OR_INJECTION", 85, "Canlı Process Hollowing veya Yedeklenmemiş Bellek Kabuk Kodu")
    SYSTEM_BINARY_MASQUERADE = ("SYSTEM_BINARY_MASQUERADE", 80, "Windows Sistem Süreci İsim Taklidi")
    FILELESS_CMDLINE_ATTACK = ("FILELESS_CMDLINE_ATTACK", 85, "Dosyasız Komut Satırı / Encoded Yük Saldırısı")
    WATCHLIST_SUSPICIOUS_EXEC = ("WATCHLIST_SUSPICIOUS_EXEC", 40, "İzleme Listesindeki Şüpheli İkilinin Çalıştırılması")

    def __init__(self, code: str, points: int, description: str) -> None:
        self.code = code
        self.points = points
        self.description = description


@dataclass
class ProcessRiskProfile:
    pid: int
    executable_path: str = ""
    score: int = 0
    tier: str = "CLEAN"  # CLEAN, MONITORED, RESTRICTED, CRITICAL
    signals: List[str] = field(default_factory=list)
    actions_taken: List[str] = field(default_factory=list)
    network_blocked: bool = False
    priority_lowered: bool = False
    terminated: bool = False
    rollback_summary: Optional[Dict[str, object]] = None
    quarantine_record: Optional[Dict[str, object]] = None

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


class CognitiveRiskBarometer:
    """0-100 Dinamik Risk Puanlama ve Otonom Müdahale Motoru."""

    def __init__(
        self,
        event_bus: EventBus,
        lineage_monitor: ProcessLineageMonitor,
        time_machine: AtomicTimeMachine,
        vault: SelfDefenseVault,
        dump_dir: str,
        enable_firewall_block: bool = False,
    ) -> None:
        self._bus = event_bus
        self._lineage = lineage_monitor
        self._time_machine = time_machine
        self._vault = vault
        self._dump_dir = os.path.abspath(dump_dir)
        self._enable_firewall_block = enable_firewall_block
        self._lock = threading.RLock()
        self._profiles: Dict[int, ProcessRiskProfile] = {}
        self._signal_dedup: Dict[int, Set[str]] = {}

        os.makedirs(self._dump_dir, exist_ok=True)
        self._subscribe_telemetry()

    def _subscribe_telemetry(self) -> None:
        self._bus.subscribe("SUSPICIOUS_LINEAGE_DETECTED", self._on_lineage_event)
        self._bus.subscribe("SYSTEM_MASQUERADE_DETECTED", self._on_lineage_event)
        self._bus.subscribe("CANARY_TRIPWIRE_TRIGGERED", self._on_canary_event)
        self._bus.subscribe("MEMORY_INJECTION_DETECTED", self._on_memory_or_dll_event)
        self._bus.subscribe("PROCESS_HOLLOWING_DETECTED", self._on_memory_or_dll_event)
        self._bus.subscribe("DLL_INJECTION_DETECTED", self._on_dll_event)

    def _on_lineage_event(self, pkt: TelemetryPacket) -> None:
        if pkt.pid:
            self.add_signal(pkt.pid, RiskSignal.SUSPICIOUS_LINEAGE, executable_path=str(pkt.payload.get("child_path", "")))

    def _on_memory_or_dll_event(self, pkt: TelemetryPacket) -> None:
        if pkt.pid:
            self.add_signal(pkt.pid, RiskSignal.PROCESS_HOLLOWING_OR_INJECTION, executable_path=str(pkt.payload.get("file_path", "") or pkt.payload.get("child_path", "")))

    def _on_dll_event(self, pkt: TelemetryPacket) -> None:
        if pkt.pid:
            self.add_signal(pkt.pid, RiskSignal.DLL_SIDELOADING_OR_MALICIOUS_MODULE, executable_path=str(pkt.payload.get("file_path", "")))

    def _on_canary_event(self, pkt: TelemetryPacket) -> None:
        if pkt.pid:
            # Canary tetiklendiğinde skoru anında 100 yap ve Rollback/İnfaz uygula
            self.force_critical_score(pkt.pid, reason="CANARY_TRIPWIRE_TRIGGERED")

    def get_profile(self, pid: int, executable_path: str = "") -> ProcessRiskProfile:
        with self._lock:
            existing = self._profiles.get(pid)
            if existing is None:
                self._profiles[pid] = ProcessRiskProfile(pid=pid, executable_path=executable_path)
                self._signal_dedup[pid] = set()
            elif executable_path:
                if existing.executable_path and existing.executable_path.lower() != executable_path.lower():
                    # PID reused by a different binary: reset stale risk state
                    self._profiles[pid] = ProcessRiskProfile(pid=pid, executable_path=executable_path)
                    self._signal_dedup[pid] = set()
                elif not existing.executable_path:
                    existing.executable_path = executable_path
            return self._profiles[pid]

    def _block_network_firewall(self, exe_path: str, pid: int) -> bool:
        if not self._enable_firewall_block or not exe_path or not os.path.isfile(exe_path):
            return False
        rule_name = f"AEGIS_BLOCK_PID_{pid}"
        try:
            netsh_exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "netsh.exe")
            res = subprocess.run(
                [
                    netsh_exe, "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=out", "action=block", f"program={exe_path}", "enable=yes",
                ],
                capture_output=True,
                timeout=3,
            )
            return res.returncode == 0
        except Exception:
            return False

    def _write_forensic_dump_metadata(self, profile: ProcessRiskProfile, child_pids: List[int]) -> str:
        dump_path = os.path.join(self._dump_dir, f"forensic_pid_{profile.pid}.json")
        dump_data = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "pid": profile.pid,
            "child_pids": child_pids,
            "executable_path": profile.executable_path,
            "risk_score": profile.score,
            "signals": profile.signals,
        }
        with open(dump_path, "w", encoding="utf-8") as f:
            json.dump(dump_data, f, ensure_ascii=False, indent=2)
        return dump_path

    def _evaluate_thresholds(self, profile: ProcessRiskProfile) -> None:
        score = profile.score

        # 30 - 49 Puan (İzleniyor): Modül 6 Zaman Makinesi aktif edilir
        if score >= 30 and "TIME_MACHINE_ENABLED" not in profile.actions_taken:
            self._time_machine.enable_journaling(profile.pid)
            profile.actions_taken.append("TIME_MACHINE_ENABLED")
            if score < 50:
                profile.tier = "MONITORED"

        # 50 - 79 Puan (Kısıtlandı / Gri Liste): Ağ kısıtla + CPU önceliğini düşür
        if 50 <= score < 80:
            profile.tier = "RESTRICTED"
            if "PRIORITY_LOWERED" not in profile.actions_taken:
                profile.priority_lowered = lower_process_priority(profile.pid)
                profile.actions_taken.append("PRIORITY_LOWERED")
            if "NETWORK_RESTRICTED" not in profile.actions_taken:
                fw_ok = self._block_network_firewall(profile.executable_path, profile.pid)
                profile.network_blocked = True
                profile.actions_taken.append("NETWORK_RESTRICTED" if fw_ok else "NETWORK_POLICY_MARKED")

        # 80 - 100 Puan (Kritik Tehdit / İnfaz)
        if score >= 80 and "CRITICAL_EXECUTION_COMPLETED" not in profile.actions_taken:
            profile.tier = "CRITICAL"
            child_pids = self._lineage.get_child_tree_pids(profile.pid)
            all_targets = [profile.pid] + child_pids

            # 1. Tüm ağacı dondur (NtSuspendProcess)
            for t_pid in all_targets:
                suspend_process(t_pid)
            profile.actions_taken.append(f"FROZEN_PROCESS_TREE({len(all_targets)})")

            # 2. Adli bellek/durum dökümünü kaydet
            dump_path = self._write_forensic_dump_metadata(profile, child_pids)
            profile.actions_taken.append(f"FORENSIC_DUMP({os.path.basename(dump_path)})")

            # 3. Tüm alt süreçleri ve ana süreci sonlandır
            for t_pid in reversed(all_targets):
                terminate_process(t_pid)
            profile.terminated = True
            profile.actions_taken.append("TERMINATED_TREE")

            # 4. Çalıştırılabilir dosyayı .aegis_q kasasına taşı
            if profile.executable_path and os.path.isfile(profile.executable_path):
                q_rec = self._vault.quarantine_file(
                    profile.executable_path,
                    threat_name="AegisCore.Autonomous.CriticalThreat",
                    risk_score=profile.score,
                )
                profile.quarantine_record = q_rec
                if q_rec:
                    profile.actions_taken.append("QUARANTINED_EXECUTABLE")

            # 5. Modül 6 Atomik Geri Sarma (Rollback)
            rb_summary = self._time_machine.rollback(profile.pid)
            profile.rollback_summary = rb_summary
            profile.actions_taken.append("ATOMIC_ROLLBACK_TRIGGERED")
            profile.actions_taken.append("CRITICAL_EXECUTION_COMPLETED")

            self._bus.emit(
                "MOD5_RISK_BAROMETER",
                "AUTONOMOUS_EXECUTION_AND_ROLLBACK",
                severity="CRITICAL",
                pid=profile.pid,
                profile=profile.to_dict(),
            )

    def add_signal(self, pid: int, signal: RiskSignal, executable_path: str = "") -> ProcessRiskProfile:
        """Canlı sürece yeni bir risk sinyali ekler ve otonom eşikleri tetikler."""
        with self._lock:
            profile = self.get_profile(pid, executable_path)
            seen = self._signal_dedup[pid]
            if signal.code not in seen:
                seen.add(signal.code)
                profile.score = min(100, profile.score + signal.points)
                profile.signals.append(f"[{signal.code} +{signal.points}] {signal.description}")

            # Konum bazlı otomatik kontrol (AppData\Local\Temp, Downloads, Public, Roaming, ProgramData, Windows\Temp)
            if profile.executable_path:
                low_p = profile.executable_path.lower()
                risky_zones = (
                    "\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\",
                    "\\appdata\\roaming\\", "\\programdata\\", "\\windows\\temp\\",
                )
                if any(rz in low_p for rz in risky_zones) and RiskSignal.TEMP_OR_DOWNLOADS_EXECUTION.code not in seen:
                    seen.add(RiskSignal.TEMP_OR_DOWNLOADS_EXECUTION.code)
                    profile.score = min(100, profile.score + RiskSignal.TEMP_OR_DOWNLOADS_EXECUTION.points)
                    profile.signals.append(f"[{RiskSignal.TEMP_OR_DOWNLOADS_EXECUTION.code} +{RiskSignal.TEMP_OR_DOWNLOADS_EXECUTION.points}] {RiskSignal.TEMP_OR_DOWNLOADS_EXECUTION.description}")

        self._bus.emit(
            "MOD5_RISK_BAROMETER",
            "RISK_SCORE_UPDATED",
            severity="CRITICAL" if profile.score >= 80 else "HIGH" if profile.score >= 50 else "MEDIUM" if profile.score >= 30 else "INFO",
            pid=pid,
            score=profile.score,
            signal=signal.code,
        )
        self._evaluate_thresholds(profile)
        return profile

    def force_critical_score(self, pid: int, reason: str, executable_path: str = "") -> ProcessRiskProfile:
        with self._lock:
            profile = self.get_profile(pid, executable_path)
            profile.score = 100
            profile.signals.append(f"[INSTANT_CRITICAL] {reason}")
        self._evaluate_thresholds(profile)
        return profile
