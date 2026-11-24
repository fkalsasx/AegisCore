#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AegisCore Otonom Çekirdek :: Sürekli Çalışan Gerçek Zamanlı Savunma Daemon'ı (NDJSON IPC)
Modül 1-7 arasında çok aşamalı anlık dosya denetimi, Canary Honeypot izleme, Canlı Süreç Soy Ağacı
ve Risk Barometresi olaylarını Node.js orkestratöre akıtır.
"""

import gc
import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import time
import winreg

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
SUPERLX_DIR = os.path.join(ROOT_DIR, "engines", "superlx")
for _p in (CURRENT_DIR, SUPERLX_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core.event_bus import TelemetryPacket
from core.win32_native import (
    find_pids_by_executable_path,
    suspend_process,
    terminate_process,
    trim_working_set,
)
from modules.m1_static_pe_analyzer import FuzzyHasher
from modules.m3_process_lineage import _CMDLINE_THREAT_RULES, _normalize_cmdline_for_inspection
from modules.m5_risk_barometer import RiskSignal
from vortex_engine import AegisVortexEngine
try:
    from superlx_engine import analyze_superlx
except Exception:
    analyze_superlx = None

stdout_lock = threading.Lock()
_SCRIPT_EXTS_EXEC = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".py", ".hta", ".wsf", ".sct", ".html", ".svg"}
_SAFE_AUTOREVERT_SUBKEYS = {
    r"software\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\runonce",
    r"software\wow6432node\microsoft\windows\currentversion\run",
    r"software\wow6432node\microsoft\windows\currentversion\runonce",
    r"software\microsoft\windows\currentversion\policies\explorer\run",
    r"software\microsoft\command processor",
    r"software\classes\ms-settings\shell\open\command",
    r"software\classes\mscfile\shell\open\command",
}
_TASK_CMD_RX = re.compile(r"<Command>\s*([^<]{1,400})\s*</Command>", re.IGNORECASE)
_TASK_ARGS_RX = re.compile(r"<Arguments>\s*([^<]{1,800})\s*</Arguments>", re.IGNORECASE)
_REG_PATH_EXTRACT_RX = re.compile(
    r"\"([^\r\n\"]{3,320}\.(?:exe|dll|ps1|psm1|vbs|vbe|js|jse|bat|cmd|hta|wsf|sct|sys))\"|([A-Za-z]:\\[^\s\"']{3,320}\.(?:exe|dll|ps1|psm1|vbs|vbe|js|jse|bat|cmd|hta|wsf|sct|sys))",
    re.IGNORECASE,
)


def emit_ndjson(obj: dict) -> None:
    line = json.dumps(obj, ensure_ascii=False)
    with stdout_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def load_malware_db(engine: AegisVortexEngine, workspace_root: str) -> dict:
    db_path = os.path.join(workspace_root, "signatures", "malware_db.json")
    malicious_dlls = {}
    hijackable_dlls = set()
    byovd_drivers = set()
    sha256_sigs = {}

    if os.path.isfile(db_path):
        try:
            with open(db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data.get("malicious_dll_names", []):
                if isinstance(item, dict):
                    name = str(item.get("name", "")).strip().lower()
                    if name:
                        malicious_dlls[name] = item
                else:
                    name = str(item).strip().lower()
                    if name:
                        malicious_dlls[name] = {"name": name, "threat": f"Trojan.KnownMaliciousDLL.{name}", "risk_score": 100}
            for item in data.get("hijackable_system_dlls", []):
                name = str(item).strip().lower()
                if name:
                    hijackable_dlls.add(name)
            for item in data.get("byovd_driver_names", []):
                name = str(item).strip().lower()
                if name:
                    byovd_drivers.add(name)
            for sha, info in data.get("sha256_signatures", {}).items():
                if info.get("severity") != "SAFE":
                    sha256_sigs[sha.lower()] = info
                    engine.static_analyzer.register_known_malware(
                        info.get("name", "Known.Malware"),
                        sha256=sha.lower(),
                    )
        except Exception:
            pass

    return {
        "malicious_dlls": malicious_dlls,
        "hijackable_dlls": hijackable_dlls,
        "byovd_drivers": byovd_drivers,
        "sha256_sigs": sha256_sigs,
    }


def main() -> None:
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")

    workspace_root = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(CURRENT_DIR)
    canary_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(workspace_root, "realtime_protected_zone")

    engine = AegisVortexEngine(workspace_root=workspace_root, canary_dirs=[canary_dir])
    db_cache = load_malware_db(engine, workspace_root)

    # Bilinen temel test/zararlı fuzzy imzalarını kaydet
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    engine.static_analyzer.register_known_malware(
        "EICAR-Standard-Antivirus-Test-File",
        sha256=hashlib.sha256(eicar_bytes).hexdigest(),
        fuzzy_sig=FuzzyHasher.compute(eicar_bytes),
    )

    watchlist_lock = threading.Lock()
    watchlist_paths: dict[str, dict] = {}
    watchlist_hashes: dict[str, dict] = {}

    def add_to_watchlist(path: str = "", sha256: str = "", score: int = 45, threat: str = "") -> None:
        info = {"score": int(score), "threat": str(threat or "Suspicious.WatchlistItem"), "added_at": time.time()}
        with watchlist_lock:
            if path:
                norm_p = os.path.normcase(os.path.abspath(path))
                watchlist_paths[norm_p] = info
                if len(watchlist_paths) > 2000:
                    watchlist_paths.pop(next(iter(watchlist_paths)))
            if sha256:
                watchlist_hashes[sha256.lower()] = info
                if len(watchlist_hashes) > 2000:
                    watchlist_hashes.pop(next(iter(watchlist_hashes)))

    def get_watchlist_hit(path: str = "", sha256: str = "") -> dict | None:
        with watchlist_lock:
            if sha256 and sha256.lower() in watchlist_hashes:
                return watchlist_hashes[sha256.lower()]
            if path:
                norm_p = os.path.normcase(os.path.abspath(path))
                return watchlist_paths.get(norm_p)
        return None

    def on_untrusted_exec(pid: int, exe_path: str, cmdline: str = "") -> None:
        if analyze_superlx is None or not exe_path or not os.path.isfile(exe_path):
            return
        try:
            rep = analyze_superlx(exe_path, tier="pro")
            risk = int(rep.get("risk_score", 0))
            sha256 = str(rep.get("sha256") or "").lower()
            base_name = os.path.basename(exe_path).lower()
            ext_low = os.path.splitext(exe_path)[1].lower()
            blind_spots = list(rep.get("blind_spots_caught") or [])
            is_signed = bool(rep.get("is_signed"))
            is_byovd_or_tamper = (
                base_name in db_cache["byovd_drivers"]
                or any(b in blind_spots for b in ("SIGNED_CERT_PADDING_HIJACK", "BYOVD_VULNERABLE_DRIVER"))
            )
            wl_hit = get_watchlist_hit(exe_path, sha256)

            if risk >= 70 and (not is_signed or is_byovd_or_tamper or ext_low in _SCRIPT_EXTS_EXEC):
                if engine.lineage_monitor._auto_block:
                    engine.lineage_monitor.terminate_process_tree(pid, rescan=False)
                threat = str(rep.get("threat_name") or "Execution.UntrustedZone.Malware")
                engine.risk_barometer.force_critical_score(pid, threat, executable_path=exe_path)
                engine.bus.emit(
                    "MOD3_LINEAGE_GRAPH",
                    "ON_EXECUTE_THREAT_BLOCKED",
                    severity="CRITICAL",
                    pid=pid,
                    file_path=exe_path,
                    cmdline=cmdline[:200],
                    threat_name=threat,
                    score_delta=risk,
                    should_quarantine=True,
                    description=f"Çalıştırma Anında Zararlı Dosya Durduruldu: {os.path.basename(exe_path)} ({threat})",
                )
            elif (45 <= risk < 70) or wl_hit is not None:
                add_to_watchlist(exe_path, sha256, max(risk, 45), str(rep.get("threat_name") or "Execution.Watchlist.Suspicious"))
                engine.risk_barometer.add_signal(
                    pid,
                    RiskSignal.WATCHLIST_SUSPICIOUS_EXEC if wl_hit else RiskSignal.RAPID_CHILD_SPAWNING,
                    executable_path=exe_path,
                )
                if wl_hit and risk >= 45 and engine.lineage_monitor._auto_block:
                    engine.lineage_monitor.terminate_process_tree(pid, rescan=False)
                    threat = str(rep.get("threat_name") or wl_hit.get("threat") or "Execution.Watchlist.Blocked")
                    engine.bus.emit(
                        "MOD3_LINEAGE_GRAPH",
                        "ON_EXECUTE_THREAT_BLOCKED",
                        severity="CRITICAL",
                        pid=pid,
                        file_path=exe_path,
                        cmdline=cmdline[:200],
                        threat_name=threat,
                        score_delta=85,
                        should_quarantine=True,
                        description=f"İzleme Listesindeki Şüpheli Dosya Çalışırken Durduruldu: {os.path.basename(exe_path)}",
                    )
        except Exception:
            pass

    def _inspect_command_threat(cmd_text: str) -> tuple[int, str, str]:
        if not cmd_text:
            return 0, "", ""
        norm_cmd = _normalize_cmdline_for_inspection(cmd_text)
        for rx, tname in _CMDLINE_THREAT_RULES:
            if rx.search(norm_cmd) or rx.search(cmd_text):
                return 90, tname, ""
        m = _REG_PATH_EXTRACT_RX.search(cmd_text)
        payload_path = ""
        if m:
            payload_path = next((g for g in m.groups() if g), "")
            if payload_path and os.path.isfile(payload_path) and analyze_superlx is not None:
                try:
                    p_rep = analyze_superlx(payload_path, tier="pro")
                    p_risk = int(p_rep.get("risk_score", 0))
                    if p_risk >= 65 and not p_rep.get("is_signed"):
                        return p_risk, str(p_rep.get("threat_name") or "Persistence.MaliciousPayload"), payload_path
                except Exception:
                    pass
        return 0, "", payload_path

    def on_persistence_event(evt_payload: dict) -> None:
        try:
            kind = str(evt_payload.get("kind", ""))
            if kind == "registry":
                hive = evt_payload.get("hive")
                subkey = str(evt_payload.get("subkey") or "")
                sub_low = subkey.lower()
                val_name = str(evt_payload.get("value_name") or "")
                val_str = str(evt_payload.get("new_value") or "")
                risk, threat, payload_path = _inspect_command_threat(val_str)

                high_risk_hook = (
                    "command processor" in sub_low
                    or "appinit_dlls" in sub_low
                    or "ms-settings\\shell\\open\\command" in sub_low
                    or "mscfile\\shell\\open\\command" in sub_low
                    or "image file execution options" in sub_low
                    or ("environment" == sub_low and val_name.lower() == "userinitmprlogonscript")
                )
                if high_risk_hook and risk < 85:
                    risk = 85
                    threat = threat or ("Persistence.RegistryHook." + sub_low.rsplit("\\", 1)[-1])

                if risk >= 65:
                    reverted = False
                    val_low = val_name.lower()
                    is_cmd_proc = "command processor" in sub_low
                    can_delete = (
                        (sub_low in _SAFE_AUTOREVERT_SUBKEYS and (not is_cmd_proc or val_low == "autorun"))
                        or (sub_low == "environment" and val_low == "userinitmprlogonscript")
                    )
                    if engine.lineage_monitor._auto_block and can_delete and hive is not None:
                        try:
                            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as wk:
                                winreg.DeleteValue(wk, val_name)
                            reverted = True
                        except OSError:
                            reverted = False
                    engine.bus.emit(
                        "MOD3_LINEAGE_GRAPH",
                        "PERSISTENCE_BLOCKED_AND_REVERTED",
                        severity="CRITICAL",
                        kind="registry",
                        subkey=subkey,
                        value_name=val_name,
                        new_value=val_str[:240],
                        reverted=reverted,
                        threat_name=threat,
                        file_path=payload_path if (payload_path and os.path.isfile(payload_path)) else "",
                        should_quarantine=bool(payload_path and os.path.isfile(payload_path)),
                        score_delta=risk,
                        description=f"Zararlı Kalıcılık Mekanizması {'Otomatik Temizlendi' if reverted else 'Tespit Edildi'}: {val_name} ({threat})",
                    )
            elif kind in ("startup_file", "scheduled_task"):
                fpath = str(evt_payload.get("file_path") or "")
                if not fpath or not os.path.isfile(fpath):
                    return
                risk = 0
                threat = ""
                payload_path = ""
                if kind == "scheduled_task":
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as tf:
                            xml_txt = tf.read(65536)
                        cmd_m = _TASK_CMD_RX.search(xml_txt)
                        arg_m = _TASK_ARGS_RX.search(xml_txt)
                        combined_task_cmd = f"{cmd_m.group(1) if cmd_m else ''} {arg_m.group(1) if arg_m else ''}".strip()
                        risk, threat, payload_path = _inspect_command_threat(combined_task_cmd)
                    except OSError:
                        pass
                elif analyze_superlx is not None:
                    ext_l = os.path.splitext(fpath)[1].lower()
                    s_rep = analyze_superlx(fpath, tier="pro")
                    s_risk = int(s_rep.get("risk_score", 0))
                    if s_risk >= 65 and (not s_rep.get("is_signed") or s_risk >= 80 or ext_l in _SCRIPT_EXTS_EXEC):
                        risk = s_risk
                        threat = str(s_rep.get("threat_name") or "Persistence.Startup.Malware")
                if risk >= 65:
                    engine.bus.emit(
                        "MOD3_LINEAGE_GRAPH",
                        "PERSISTENCE_BLOCKED_AND_REVERTED",
                        severity="CRITICAL",
                        kind=kind,
                        file_path=fpath,
                        payload_path=payload_path if (payload_path and os.path.isfile(payload_path)) else "",
                        threat_name=threat or "Persistence.ScheduledOrStartup",
                        reverted=False,
                        should_quarantine=True,
                        score_delta=risk,
                        description=f"Zararlı Başlangıç/Görev Kalıcılığı Yakalandı: {os.path.basename(fpath)} ({threat})",
                    )
        except Exception:
            pass

    engine.lineage_monitor.configure_databases(
        malicious_dlls=set(db_cache["malicious_dlls"].keys()),
        hijackable_dlls=db_cache["hijackable_dlls"],
        on_persistence_event=on_persistence_event,
    )
    engine.lineage_monitor._on_untrusted_exec = on_untrusted_exec

    # EventBus'tan canlı kritik olayları Node.js orkestratöre ilet
    def on_bus_event(pkt: TelemetryPacket) -> None:
        if pkt.event_type in {
            "SUSPICIOUS_LINEAGE_DETECTED",
            "SYSTEM_MASQUERADE_DETECTED",
            "FILELESS_CMDLINE_BLOCKED",
            "ON_EXECUTE_THREAT_BLOCKED",
            "PERSISTENCE_MODIFICATION_DETECTED",
            "PERSISTENCE_BLOCKED_AND_REVERTED",
            "MEMORY_INJECTION_DETECTED",
            "PROCESS_HOLLOWING_DETECTED",
            "DLL_INJECTION_DETECTED",
            "C2_NETWORK_CONTAINED",
            "CANARY_TRIPWIRE_TRIGGERED",
            "AUTONOMOUS_EXECUTION_AND_ROLLBACK",
            "TAMPER_ATTEMPT_BLOCKED",
        }:
            emit_ndjson({"kind": "bus_event", "packet": pkt.to_dict()})

    engine.bus.subscribe("*", on_bus_event)
    engine.start(deploy_canaries=True)

    # Başlangıç canlı durum bilgisini gönder
    emit_ndjson({
        "kind": "ready",
        "canary_count": len(engine.canary_grid._canaries),
        "monitored_processes": len(engine.lineage_monitor.build_lineage_graph()),
    })
    gc.collect()
    trim_working_set()

    # Periyodik Canary stat kontrolü + hafif nabız (ReadDirectoryChangesW anlık izler; 10s aralık, değişim/30s emit)
    def telemetry_heartbeat() -> None:
        canary_stats: dict[str, tuple[int, int]] = {}
        last_procs = -1
        last_canaries = -1
        hb_tick = 0
        while True:
            time.sleep(10.0)
            hb_tick += 1
            try:
                canary_changed = False
                with engine.canary_grid._lock:
                    canary_paths = list(engine.canary_grid._canaries.keys())
                for cp in canary_paths:
                    try:
                        st = os.stat(cp)
                        sig = (st.st_size, st.st_mtime_ns)
                    except OSError:
                        sig = (-1, -1)
                    if canary_stats.get(cp) != sig:
                        canary_stats[cp] = sig
                        canary_changed = True

                if canary_changed or (hb_tick % 3 == 0):
                    engine.canary_grid.verify_integrity_once()

                procs_count = len(engine.lineage_monitor._pid_map)
                c_count = len(canary_paths)
                if procs_count != last_procs or c_count != last_canaries or (hb_tick % 3 == 0):
                    last_procs = procs_count
                    last_canaries = c_count
                    emit_ndjson({
                        "kind": "heartbeat",
                        "monitored_processes": procs_count,
                        "canary_count": c_count,
                    })

                if hb_tick % 6 == 0:
                    gc.collect()
                    trim_working_set()
            except Exception:
                pass

    hb_thread = threading.Thread(target=telemetry_heartbeat, daemon=True)
    hb_thread.start()

    # Stdin üzerinden çok aşamalı anlık analiz isteklerini işle
    sys_root_norm = os.path.normcase(os.path.abspath(os.environ.get("SystemRoot", r"C:\Windows")))
    sys32_prefix = os.path.join(sys_root_norm, "system32") + os.sep
    syswow_prefix = os.path.join(sys_root_norm, "syswow64") + os.sep
    inspect_counter = 0

    def _is_unc_path(p: str) -> bool:
        return isinstance(p, str) and (p.startswith("\\\\") or p.startswith("//") or p.lower().startswith("\\\\?\\unc\\"))

    for raw_line in sys.stdin:
        if len(raw_line) > 2 * 1024 * 1024:
            emit_ndjson({"kind": "reply", "id": None, "error": "IPC request too large"})
            continue
        line = raw_line.strip()
        if not line:
            continue
        req_id = None
        try:
            req = json.loads(line)
            req_id = req.get("id")
            cmd = req.get("cmd")

            if cmd == "inspect_file":
                target = str(req.get("path", "") or "")
                req_tier = str(req.get("tier", "plus")).lower()
                if not target or _is_unc_path(target) or not os.path.isfile(target):
                    emit_ndjson({"kind": "reply", "id": req_id, "error": "File not found or blocked path"})
                    continue

                base_name = os.path.basename(target).lower()
                ext_low = os.path.splitext(target)[1].lower()
                lower_path = os.path.abspath(target).lower()
                stage_findings = []
                blind_spots = []
                detected_stage = "Temiz (Çok Aşamalı Kontrol Geçildi)"
                stage_score = 0
                stage_threat = ""

                # AŞAMA 1A: Bilinen Zararlı Virüs DLL Veritabanı + BYOVD Sürücü Kontrolü
                if base_name in db_cache["malicious_dlls"]:
                    dll_info = db_cache["malicious_dlls"][base_name]
                    stage_score = int(dll_info.get("risk_score", 95))
                    stage_threat = str(dll_info.get("threat", "Trojan.DLL.KnownMalicious"))
                    detected_stage = "Aşama 1: Bilinen Zararlı DLL Veritabanı"
                    stage_findings.append(f"[Aşama 1] Bilinen zararlı DLL modülü: {base_name} ({stage_threat})")
                elif base_name in db_cache["byovd_drivers"]:
                    stage_score = 90
                    stage_threat = f"Trojan.BYOVD.VulnerableDriver.{base_name}"
                    detected_stage = "Aşama 1: Bilinen İstismar Edilebilir Sürücü (BYOVD)"
                    blind_spots.append("BYOVD_VULNERABLE_DRIVER")
                    stage_findings.append(f"[Aşama 1] Güvenlik kırıcı BYOVD sürücüsü: {base_name}")

                # AŞAMA 1B-2-3-4: Tek okuma + önbellekli/önceden hesaplanmış SHA-256 & İmza
                raw_pre = req.get("precomputed")
                pre_arg = raw_pre if isinstance(raw_pre, dict) else None
                rep, head_bytes = engine.static_analyzer.analyze_file_with_buffer(target, precomputed=pre_arg)

                # SHA-256 eşleşmesi varsa Aşama 1 önceliği ver
                if rep.sha256.lower() in db_cache["sha256_sigs"]:
                    sig = db_cache["sha256_sigs"][rep.sha256.lower()]
                    stage_score = max(stage_score, 100)
                    stage_threat = sig.get("name", "Malware.SHA256.Signature")
                    detected_stage = "Aşama 1: Virüs İmza Veritabanı"
                    stage_findings.append(f"[Aşama 1] Exact SHA-256 eşleşmesi: {stage_threat}")

                wl_hit = get_watchlist_hit(target, rep.sha256)
                if wl_hit and stage_score < 55:
                    stage_score = 55
                    stage_threat = stage_threat or str(wl_hit.get("threat") or "Suspicious.WatchlistMatch")
                    stage_findings.append(f"[İzleme Listesi] Şüpheli dosya kaydı eşleşti ({stage_threat})")

                superlx_rep = None
                det_rep = None

                if stage_score < 100:
                    # Hijackable System DLL dış konum kontrolü (imzasızsa)
                    norm_target_path = os.path.normcase(os.path.abspath(target))
                    if (
                        stage_score == 0
                        and base_name in db_cache["hijackable_dlls"]
                        and not norm_target_path.startswith(sys32_prefix)
                        and not norm_target_path.startswith(syswow_prefix)
                        and not rep.is_signed
                    ):
                        suspicious_loc = any(z in lower_path for z in ("\\downloads\\", "\\temp\\", "\\appdata\\", "\\users\\public\\"))
                        if suspicious_loc:
                            stage_score = 80
                            stage_threat = f"Trojan.DLL.SideLoading.{base_name}"
                            detected_stage = "Aşama 1: Zararlı DLL Side-Loading Tespiti"
                            stage_findings.append(f"[Aşama 1] İmzasız sistem DLL taklidi / Side-Loading şüphesi: {base_name}")

                    # SuperLX 1.0 Birleşik Kör Nokta & De-Obfuscation Katmanı (imzasız, script, BYOVD veya imzalı PE padding/pumping kontrolü)
                    should_run_superlx = (
                        analyze_superlx is not None
                        and (
                            not rep.is_signed
                            or ext_low in _SCRIPT_EXTS_EXEC
                            or base_name in db_cache["byovd_drivers"]
                            or rep.is_pe
                        )
                    )
                    if should_run_superlx:
                        superlx_rep = analyze_superlx(
                            target,
                            tier="pro",
                            precomputed={
                                "sha256": rep.sha256,
                                "is_signed": rep.is_signed,
                                "signer": rep.signer,
                                "data": head_bytes,
                                "entropy": rep.overall_entropy,
                            },
                        )
                        for b in (superlx_rep.get("blind_spots_caught") or []):
                            if b not in blind_spots:
                                blind_spots.append(b)
                        sx_score = int(superlx_rep.get("risk_score", 0))
                        if sx_score > stage_score:
                            stage_score = sx_score
                            if superlx_rep.get("threat_name"):
                                stage_threat = str(superlx_rep["threat_name"])
                        elif not stage_threat and superlx_rep.get("threat_name"):
                            stage_threat = str(superlx_rep["threat_name"])
                        for f in (superlx_rep.get("findings") or []):
                            if f not in stage_findings:
                                stage_findings.append(f)

                    if req.get("detonate") and (not rep.is_signed or ext_low in _SCRIPT_EXTS_EXEC) and max(stage_score, rep.risk_contribution) >= 25:
                        if ext_low in _SCRIPT_EXTS_EXEC:
                            det_rep = engine.shadow_cage.detonate(target, observation_ms=350)

                del head_bytes

                total_score = min(100, max(stage_score, rep.risk_contribution) + (det_rep.risk_delta if det_rep else 0))
                if 40 <= total_score < 70:
                    add_to_watchlist(target, rep.sha256, total_score, stage_threat or "Suspicious.MonitorWatchlist")
                findings = stage_findings + [f for f in (list(rep.flags) + list(rep.script_findings)) if f not in stage_findings]
                if det_rep and det_rep.notes:
                    findings.extend(det_rep.notes)
                    detected_stage = "SuperLX 1.0 · Mikro-Sandbox Davranış Analizi"
                elif blind_spots and stage_score < 100:
                    detected_stage = f"SuperLX 1.0 Derin Kalkan ({', '.join(blind_spots[:2])})"
                elif not stage_findings and total_score >= 30:
                    detected_stage = "SuperLX 1.0 · Çok Katmanlı Analiz"

                engine_label = "SuperLX 1.0"
                emit_ndjson({
                    "kind": "reply",
                    "id": req_id,
                    "result": {
                        "engine_name": engine_label,
                        "motw": superlx_rep.get("motw") if superlx_rep else None,
                        "static_analysis": rep.to_dict(),
                        "shadow_cage": det_rep.to_dict() if det_rep else None,
                        "blind_spots_caught": blind_spots,
                        "engine_score": total_score,
                        "detection_stage": detected_stage,
                        "threat_name": stage_threat,
                        "findings": findings,
                    },
                })
                inspect_counter += 1
                if inspect_counter % 50 == 0:
                    gc.collect()
            elif cmd == "batch_inspect":
                paths = list(req.get("paths") or [])
                results = []
                if analyze_superlx is not None:
                    for fp in paths[:100]:
                        try:
                            if isinstance(fp, str) and not _is_unc_path(fp) and os.path.isfile(fp):
                                results.append(analyze_superlx(fp, tier="pro"))
                        except Exception:
                            pass
                emit_ndjson({"kind": "reply", "id": req_id, "results": results})
                gc.collect()
            elif cmd == "startup_audit":
                entries = []
                reg_targets = [
                    ("HKCU\\Run", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    ("HKCU\\RunOnce", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                    ("HKLM\\Run", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    ("HKLM\\RunOnce", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                    ("HKLM\\WOW6432Node\\Run", winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
                    ("HKLM\\WOW6432Node\\RunOnce", winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
                    ("HKCU\\Policies\\Run", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
                    ("HKLM\\Policies\\Run", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
                    ("HKCU\\CmdAutoRun", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Command Processor"),
                    ("HKLM\\CmdAutoRun", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Command Processor"),
                    ("HKLM\\AppInit_DLLs", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
                    ("HKCU\\LogonScript", winreg.HKEY_CURRENT_USER, r"Environment"),
                ]
                susp_kw = (
                    "powershell", "pwsh", "-enc", "-ec ", "mshta", "wscript", "cscript", "\\temp\\",
                    "\\users\\public\\", "appdata\\roaming", "\\programdata\\", "cmd /c", "cmd.exe",
                    "regsvr32", "rundll32", "certutil", "bitsadmin", "forfiles", "cmstp",
                    "odbcconf", "frombase64", "downloadstring", "http://", "https://", "pcalua",
                )
                for hive_name, hive, subkey in reg_targets:
                    try:
                        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as k:
                            i = 0
                            while True:
                                try:
                                    v_name, v_val, _ = winreg.EnumValue(k, i)
                                    i += 1
                                    vn_low = str(v_name).lower()
                                    if hive_name == "HKCU\\LogonScript" and vn_low != "userinitmprlogonscript":
                                        continue
                                    if hive_name.endswith("\\CmdAutoRun") and vn_low != "autorun":
                                        continue
                                    if hive_name == "HKLM\\AppInit_DLLs" and vn_low != "appinit_dlls":
                                        continue
                                    val_str = str(v_val).strip()
                                    if hive_name == "HKLM\\AppInit_DLLs" and not val_str:
                                        continue
                                    is_susp = (
                                        any(kw in val_str.lower() for kw in susp_kw)
                                        or hive_name in ("HKCU\\LogonScript", "HKCU\\CmdAutoRun", "HKLM\\CmdAutoRun", "HKLM\\AppInit_DLLs")
                                    )
                                    entries.append({
                                        "source": hive_name,
                                        "name": str(v_name),
                                        "command": val_str,
                                        "riskLevel": "SUSPICIOUS" if is_susp else "SAFE",
                                        "reason": (
                                            f"Yüksek Riskli Kalıcılık Kancası ({hive_name})"
                                            if hive_name in ("HKCU\\LogonScript", "HKCU\\CmdAutoRun", "HKLM\\CmdAutoRun", "HKLM\\AppInit_DLLs")
                                            else ("Şüpheli komut/dizin kalıcılığı" if is_susp else "Standart başlangıç öğesi")
                                        ),
                                    })
                                except OSError:
                                    break
                    except OSError:
                        pass

                # Winlogon Shell / Userinit kontrolü
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", 0, winreg.KEY_READ) as wk:
                        for wn in ("Shell", "Userinit"):
                            try:
                                wval, _ = winreg.QueryValueEx(wk, wn)
                                w_s = str(wval).strip()
                                w_low = w_s.lower().rstrip(",")
                                is_ok = (wn == "Shell" and w_low in ("explorer.exe", r"c:\windows\explorer.exe")) or (
                                    wn == "Userinit" and w_low in (r"c:\windows\system32\userinit.exe", "userinit.exe")
                                )
                                entries.append({
                                    "source": "HKLM\\Winlogon",
                                    "name": wn,
                                    "command": w_s,
                                    "riskLevel": "SAFE" if is_ok else "SUSPICIOUS",
                                    "reason": "Standart Winlogon kabuğu" if is_ok else "Standart dışı Winlogon Shell/Userinit değişikliği",
                                })
                            except OSError:
                                pass
                except OSError:
                    pass

                # Image File Execution Options (IFEO) Debugger yönlendirmeleri
                try:
                    ifeo_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ifeo_path, 0, winreg.KEY_READ) as ik:
                        si = 0
                        while si < 400:
                            try:
                                sub_name = winreg.EnumKey(ik, si)
                                si += 1
                                try:
                                    with winreg.OpenKey(ik, sub_name, 0, winreg.KEY_READ) as sk:
                                        dbg_val, _ = winreg.QueryValueEx(sk, "Debugger")
                                        dbg_str = str(dbg_val).strip()
                                        if dbg_str:
                                            entries.append({
                                                "source": "HKLM\\IFEO",
                                                "name": sub_name,
                                                "command": dbg_str,
                                                "riskLevel": "SUSPICIOUS",
                                                "reason": "IFEO Debugger yönlendirmesi (Hata Ayıklayıcı Gaspı)",
                                            })
                                except OSError:
                                    pass
                            except OSError:
                                break
                except OSError:
                    pass

                # UAC Bypass (ms-settings / mscfile) anahtarları
                for uac_label, uac_sub in (
                    ("HKCU\\UAC_ms-settings", r"Software\Classes\ms-settings\Shell\Open\command"),
                    ("HKCU\\UAC_mscfile", r"Software\Classes\mscfile\Shell\Open\command"),
                ):
                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, uac_sub, 0, winreg.KEY_READ) as uk:
                            u_val, _ = winreg.QueryValueEx(uk, "")
                            if str(u_val).strip():
                                entries.append({
                                    "source": uac_label,
                                    "name": "(Default)",
                                    "command": str(u_val).strip(),
                                    "riskLevel": "SUSPICIOUS",
                                    "reason": "UAC Bypass Hijack komutu",
                                })
                    except OSError:
                        pass

                startup_dirs = [
                    ("Startup Folder", os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")),
                    ("Common Startup", os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), r"Microsoft\Windows\Start Menu\Programs\Startup")),
                ]
                for src_lbl, startup_dir in startup_dirs:
                    if startup_dir and os.path.isdir(startup_dir):
                        for fn in os.listdir(startup_dir):
                            full = os.path.join(startup_dir, fn)
                            if os.path.isfile(full) and fn.lower() != "desktop.ini":
                                ext_l = os.path.splitext(fn)[1].lower()
                                is_susp = ext_l in {".vbs", ".ps1", ".bat", ".js", ".hta", ".scr", ".wsf", ".sct"}
                                rsn = "Başlangıç klasöründe çalıştırılabilir betik" if is_susp else "Standart başlangıç kısayolu"
                                if ext_l == ".lnk" and analyze_superlx is not None:
                                    try:
                                        lnk_r = analyze_superlx(full, tier="pro")
                                        if lnk_r.get("status") != "CLEAN":
                                            is_susp = True
                                            rsn = str(lnk_r.get("threat_name") or "Silahlandırılmış başlangıç kısayolu")
                                    except Exception:
                                        pass
                                entries.append({
                                    "source": src_lbl,
                                    "name": fn,
                                    "command": full,
                                    "riskLevel": "SUSPICIOUS" if is_susp else "SAFE",
                                    "reason": rsn,
                                })

                # Non-Microsoft Scheduled Tasks (System32\Tasks)
                tasks_map = engine.lineage_monitor._enumerate_non_ms_tasks()
                for t_idx, tpath in enumerate(list(tasks_map.keys())[:120]):
                    try:
                        with open(tpath, "r", encoding="utf-8", errors="replace") as tf:
                            xml_txt = tf.read(32768)
                        cm = _TASK_CMD_RX.search(xml_txt)
                        am = _TASK_ARGS_RX.search(xml_txt)
                        task_cmd = f"{cm.group(1) if cm else ''} {am.group(1) if am else ''}".strip()
                        t_risk, t_threat, _ = _inspect_command_threat(task_cmd)
                        entries.append({
                            "source": "ScheduledTasks",
                            "name": os.path.basename(tpath),
                            "command": task_cmd[:260] or tpath,
                            "riskLevel": "SUSPICIOUS" if t_risk >= 65 else "SAFE",
                            "reason": t_threat or "Üçüncü taraf zamanlanmış görev",
                        })
                    except OSError:
                        pass
                emit_ndjson({"kind": "reply", "id": req_id, "entries": entries})
            elif cmd == "kill_process_tree":
                req_pid = int(req.get("pid") or 0)
                req_path = str(req.get("path") or "")
                pids_to_kill: list[int] = []
                if req_pid > 4:
                    pids_to_kill.append(req_pid)
                if req_path and not _is_unc_path(req_path):
                    for found_p in find_pids_by_executable_path(req_path):
                        if found_p not in pids_to_kill:
                            pids_to_kill.append(found_p)
                killed_pids: list[int] = []
                for kp in pids_to_kill:
                    if kp not in engine.lineage_monitor._exempt_pids:
                        if engine.lineage_monitor.terminate_process_tree(kp, rescan=False):
                            killed_pids.append(kp)
                emit_ndjson({"kind": "reply", "id": req_id, "killed_pids": killed_pids})
            elif cmd == "register_watchlist":
                wl_path = str(req.get("path") or "")
                wl_sha = str(req.get("sha256") or "").lower()
                wl_score = int(req.get("risk_score") or 45)
                wl_threat = str(req.get("threat_name") or "Suspicious.WatchlistItem")
                add_to_watchlist(wl_path, wl_sha, wl_score, wl_threat)
                emit_ndjson({"kind": "reply", "id": req_id, "ok": True})
            elif cmd == "report_network_threat":
                n_pid = int(req.get("pid") or 0)
                n_proc = str(req.get("process_name") or "")
                n_path = str(req.get("exe_path") or "")
                n_ip = str(req.get("remote_address") or "")
                n_port = int(req.get("remote_port") or 0)
                n_reason = str(req.get("reason") or f"Şüpheli C2 Soket İletişimi ({n_ip}:{n_port})")
                n_score = int(req.get("risk_score") or 0)
                file_risk = 0
                file_threat = ""
                is_signed_exe = False
                if n_path and os.path.isfile(n_path) and not _is_unc_path(n_path) and analyze_superlx is not None:
                    try:
                        f_rep = analyze_superlx(n_path, tier="pro")
                        file_risk = int(f_rep.get("risk_score", 0))
                        file_threat = str(f_rep.get("threat_name") or "")
                        is_signed_exe = bool(f_rep.get("is_signed"))
                    except Exception:
                        pass
                eff_score = max(n_score, file_risk)
                contained = False
                should_q = False
                if n_pid > 4 and n_pid not in engine.lineage_monitor._exempt_pids:
                    prof = engine.risk_barometer.add_signal(n_pid, RiskSignal.C2_SUSPICIOUS_NETWORK, executable_path=n_path)
                    if eff_score >= 80 or (file_risk >= 70 and not is_signed_exe) or prof.score >= 85:
                        if file_risk >= 70 and not is_signed_exe:
                            should_q = True
                        if engine.lineage_monitor._auto_block:
                            contained = engine.lineage_monitor.terminate_process_tree(n_pid, rescan=False)
                        engine.risk_barometer.force_critical_score(n_pid, n_reason, executable_path=n_path)
                        engine.bus.emit(
                            "MOD3_LINEAGE_GRAPH",
                            "C2_NETWORK_CONTAINED",
                            severity="CRITICAL",
                            pid=n_pid,
                            process_name=n_proc,
                            file_path=n_path,
                            remote_address=n_ip,
                            remote_port=n_port,
                            threat_name=file_threat or f"Trojan.C2.{n_port}",
                            terminated=contained,
                            should_quarantine=should_q,
                            score_delta=max(eff_score, 85),
                            description=f"Aktif C2 Ağ İletişimi İzole Edildi: {n_proc} -> {n_ip}:{n_port} ({n_reason})",
                        )
                emit_ndjson({
                    "kind": "reply",
                    "id": req_id,
                    "contained": contained,
                    "should_quarantine": should_q,
                    "file_path": n_path,
                    "effective_score": eff_score,
                    "threat_name": file_threat or "Trojan.C2.NetworkActivity",
                })
            elif cmd == "scan_process_memory":
                m_pid = int(req.get("pid") or 0)
                m_proc = str(req.get("process_name") or "")
                m_path = str(req.get("exe_path") or "")
                m_res = {}
                if m_pid > 4:
                    m_res = engine.lineage_monitor.scan_process_memory_now(m_pid, proc_name=m_proc, exe_path=m_path)
                emit_ndjson({"kind": "reply", "id": req_id, "result": m_res})
            elif cmd == "lineage_snapshot":
                graph = engine.lineage_monitor.build_lineage_graph()
                emit_ndjson({"kind": "reply", "id": req_id, "process_count": len(graph)})
            elif cmd == "redeploy_canaries":
                deployed = engine.canary_grid.deploy_canaries()
                emit_ndjson({"kind": "reply", "id": req_id, "canary_count": len(deployed)})
            elif cmd == "set_policy":
                rt_en = bool(req.get("realtime_enabled", True))
                auto_q = bool(req.get("auto_quarantine", True))
                engine.lineage_monitor.set_policy(rt_en, auto_q)
                emit_ndjson({"kind": "reply", "id": req_id, "realtime_enabled": rt_en, "auto_quarantine": auto_q})
            elif cmd == "timemachine_snapshot":
                with engine.time_machine._lock:
                    conn = sqlite3.connect(engine.time_machine._db_path)
                    try:
                        rows = conn.execute(
                            "SELECT seq_id, timestamp, pid, op_type, original_path, rolled_back FROM shadow_journal ORDER BY seq_id DESC LIMIT 25"
                        ).fetchall()
                    finally:
                        conn.close()
                entries = [
                    {
                        "seqId": r[0],
                        "timestamp": r[1],
                        "pid": r[2],
                        "opType": r[3],
                        "path": r[4],
                        "rolledBack": bool(r[5]),
                    }
                    for r in rows
                ]
                emit_ndjson({"kind": "reply", "id": req_id, "entries": entries})
            elif cmd == "timemachine_rollback":
                target_pid = int(req.get("pid", 0))
                if target_pid <= 0:
                    with engine.time_machine._lock:
                        conn = sqlite3.connect(engine.time_machine._db_path)
                        try:
                            row = conn.execute("SELECT pid FROM shadow_journal WHERE rolled_back = 0 ORDER BY seq_id DESC LIMIT 1").fetchone()
                        finally:
                            conn.close()
                    target_pid = int(row[0]) if row else 0
                if target_pid > 0:
                    summary = engine.time_machine.rollback(target_pid)
                    emit_ndjson({"kind": "reply", "id": req_id, "summary": summary})
                else:
                    emit_ndjson({"kind": "reply", "id": req_id, "summary": {"pid": 0, "entries_processed": 0, "files_deleted": [], "files_restored": [], "registry_reverted": [], "errors": []}})
        except Exception as exc:
            emit_ndjson({"kind": "reply", "id": req_id, "error": str(exc)})


if __name__ == "__main__":
    main()
