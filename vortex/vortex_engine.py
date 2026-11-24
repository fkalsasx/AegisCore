#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AEGIS-VORTEX :: 6 Katmanlı Otonom Savunma ve Geri Sarma Motoru (Ana Orkestratör)
Tüm modülleri merkezi EventBus üzerinden çok iş parçacıklı ve asenkron şekilde koordine eder.
"""

from __future__ import annotations
import asyncio
import os
import sys
from typing import Dict, List, Optional

# Paket yolunu güvenli ekle
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from core.event_bus import EventBus
from modules.m1_static_pe_analyzer import StaticAnalysisReport, StaticPEAnalyzer
from modules.m2_shadow_cage import DetonationReport, ShadowCageSandbox
from modules.m3_process_lineage import ProcessLineageMonitor
from modules.m4_canary_honeypot import CanaryHoneypotGrid
from modules.m5_risk_barometer import CognitiveRiskBarometer, ProcessRiskProfile, RiskSignal
from modules.m6_time_machine import AtomicTimeMachine
from modules.m7_self_defense_vault import SelfDefenseVault


class AegisVortexEngine:
    """AEGIS-VORTEX 6+1 Katmanlı Otonom Savunma Çekirdek Sınıfı."""

    def __init__(self, workspace_root: str, canary_dirs: Optional[List[str]] = None) -> None:
        self.workspace_root = os.path.abspath(workspace_root)
        self.vault_dir = os.path.join(self.workspace_root, "AEGIS_Vault")
        self.shadow_dir = os.path.join(self.workspace_root, "AEGIS_ShadowStore")
        self.cage_dir = os.path.join(self.workspace_root, "AEGIS_ShadowCage")
        self.dump_dir = os.path.join(self.vault_dir, "dumps")

        self.bus = EventBus(max_history=200)

        # Modül 7: Öz-Koruma & Şifreli Karantina Kasası
        self.vault = SelfDefenseVault(self.bus, vault_dir=self.vault_dir, shadow_dir=self.shadow_dir)

        # Modül 6: Atomik Zaman Makinesi
        self.time_machine = AtomicTimeMachine(self.bus, shadow_store_dir=self.shadow_dir)

        # Modül 1: Statik, Fuzzy Hash, Entropi, PE IAT & AST/Regex Dekoderi
        self.static_analyzer = StaticPEAnalyzer(self.bus)

        # Modül 2: Gölge Kafes Mikro-Sanallaştırma
        self.shadow_cage = ShadowCageSandbox(self.bus, cage_root=self.cage_dir)

        # Modül 3: Soy Ağacı & Süreç Zinciri İzleyicisi
        self.lineage_monitor = ProcessLineageMonitor(self.bus, poll_interval_sec=0.5, auto_block=True)

        # Modül 4: Yem Tuzakları (Canary Honeypot Grid)
        self.canary_grid = CanaryHoneypotGrid(self.bus, protected_dirs=canary_dirs)

        # Modül 5: Bilişsel Risk Barometresi (0-100 Risk Matrix)
        self.risk_barometer = CognitiveRiskBarometer(
            event_bus=self.bus,
            lineage_monitor=self.lineage_monitor,
            time_machine=self.time_machine,
            vault=self.vault,
            dump_dir=self.dump_dir,
        )

    def start(self, deploy_canaries: bool = True) -> None:
        try:
            loop = asyncio.get_running_loop()
            self.bus.attach_event_loop(loop)
        except RuntimeError:
            pass

        if deploy_canaries:
            self.canary_grid.deploy_canaries()
        self.canary_grid.start()
        self.lineage_monitor.start()
        self.bus.emit("AEGIS_VORTEX", "ENGINE_STARTED", severity="INFO", workspace=self.workspace_root)

    def stop(self) -> None:
        self.lineage_monitor.stop()
        self.canary_grid.stop()
        self.bus.emit("AEGIS_VORTEX", "ENGINE_STOPPED", severity="INFO")

    def inspect_and_detonate(self, file_path: str, assigned_pid: Optional[int] = None, run_sandbox: bool = True) -> Dict[str, object]:
        """
        Çalıştırma öncesi tam 6 katmanlı boru hattı:
        1. Modül 1 Statik + Fuzzy + PE IAT + Entropi + AST/Regex analizi
        2. Şüpheli/imzasızsa Modül 2 Gölge Kafes 500ms ön-infazı
        3. Modül 5 Risk Barometresi üzerinden otonom değerlendirme
        """
        static_rep: StaticAnalysisReport = self.static_analyzer.analyze_file(file_path)
        detonation_rep: Optional[DetonationReport] = None

        needs_sandbox = run_sandbox and ((not static_rep.is_signed) or static_rep.risk_contribution >= 15)
        if needs_sandbox:
            detonation_rep = self.shadow_cage.detonate(file_path, observation_ms=500)

        risk_profile: Optional[ProcessRiskProfile] = None
        if assigned_pid is not None:
            if static_rep.is_pe and not static_rep.is_signed:
                risk_profile = self.risk_barometer.add_signal(assigned_pid, RiskSignal.UNSIGNED_EXECUTABLE, file_path)
            if static_rep.packed_or_obfuscated:
                risk_profile = self.risk_barometer.add_signal(assigned_pid, RiskSignal.HIGH_ENTROPY, file_path)
            if static_rep.process_injection_flag:
                risk_profile = self.risk_barometer.add_signal(assigned_pid, RiskSignal.MEMORY_INJECTION_OR_HOOK, file_path)

        return {
            "static_analysis": static_rep.to_dict(),
            "shadow_cage_detonation": detonation_rep.to_dict() if detonation_rep else None,
            "risk_profile": risk_profile.to_dict() if risk_profile else None,
        }
