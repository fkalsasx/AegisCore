#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AegisCore - Python 3.10 İleri Seviye Sezgisel (Heuristic), PE Yapısal (RWX/Hollow),
Base64 Deobfuscation ve Magic-Byte Analiz Motoru
"""

import sys
import os
import json
import math
import hashlib
import struct
import re
import base64
from collections import Counter

def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)

def analyze_pe_header(data: bytes) -> dict:
    pe_info = {
        "is_pe": False,
        "architecture": "Unknown",
        "sections": [],
        "suspicious_sections": [],
        "has_high_entropy_section": False,
        "has_rwx_section": False,
        "has_overlay": False,
        "overlay_size": 0
    }
    if len(data) < 64 or data[:2] != b"MZ":
        return pe_info

    try:
        pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
        if pe_offset + 24 > len(data) or data[pe_offset:pe_offset+4] != b"PE\x00\x00":
            return pe_info

        pe_info["is_pe"] = True
        machine = struct.unpack("<H", data[pe_offset+4:pe_offset+6])[0]
        num_sections = struct.unpack("<H", data[pe_offset+6:pe_offset+8])[0]
        size_of_optional_header = struct.unpack("<H", data[pe_offset+20:pe_offset+22])[0]

        if machine == 0x8664:
            pe_info["architecture"] = "x64 (64-bit)"
        elif machine == 0x014c:
            pe_info["architecture"] = "x86 (32-bit)"
        else:
            pe_info["architecture"] = f"0x{machine:04x}"

        section_table_offset = pe_offset + 24 + size_of_optional_header
        standard_sections = {
            ".text", ".rdata", ".data", ".rsrc", ".reloc", ".idata", ".edata",
            ".pdata", ".bss", ".tls", ".didat", ".00cfg", ".gfids", ".mrdata",
            ".sxdata", ".retplne", ".crt", ".imrsiv", ".voltbl", ".orpc", ".rodata"
        }
        known_packers = ("upx", ".vmp", ".themida", ".enigma", ".aspack", ".nsp", ".mpress", ".petite")
        max_pe_end = 0

        for i in range(min(num_sections, 16)):
            sec_offset = section_table_offset + (i * 40)
            if sec_offset + 40 > len(data):
                break
            raw_name = data[sec_offset:sec_offset+8].split(b"\x00")[0].decode("ascii", errors="ignore")
            virtual_size = struct.unpack("<I", data[sec_offset+8:sec_offset+12])[0]
            raw_size = struct.unpack("<I", data[sec_offset+16:sec_offset+20])[0]
            raw_ptr = struct.unpack("<I", data[sec_offset+20:sec_offset+24])[0]
            characteristics = struct.unpack("<I", data[sec_offset+36:sec_offset+40])[0]

            if raw_ptr + raw_size > max_pe_end:
                max_pe_end = raw_ptr + raw_size

            sec_data = data[raw_ptr:raw_ptr+min(raw_size, 524288)] if raw_ptr < len(data) else b""
            sec_entropy = calculate_shannon_entropy(sec_data)

            is_write = (characteristics & 0x80000000) != 0
            is_exec = (characteristics & 0x20000000) != 0
            is_rwx = is_write and is_exec

            pe_info["sections"].append({
                "name": raw_name,
                "size": raw_size,
                "virtual_size": virtual_size,
                "entropy": sec_entropy,
                "rwx": is_rwx
            })

            if is_rwx:
                pe_info["has_rwx_section"] = True
                pe_info["suspicious_sections"].append(f"Yazılabilir + Çalıştırılabilir (RWX) bellek bölümü: {raw_name}")

            lower_sec = raw_name.lower()
            if lower_sec and any(lower_sec.startswith(pk) for pk in known_packers):
                pe_info["suspicious_sections"].append(f"Bilinen Packer/Crypter bölümü tespit edildi: {raw_name}")
            elif lower_sec and lower_sec not in standard_sections and sec_entropy > 7.1:
                pe_info["suspicious_sections"].append(f"Standart dışı yüksek entropili PE bölümü: {raw_name} ({sec_entropy})")

            if raw_size == 0 and virtual_size > 4096 and lower_sec not in {".bss"}:
                pe_info["suspicious_sections"].append(f"Diskte 0-byte fakat bellekte geniş (Packer açıcı) bölüm: {raw_name}")

            if sec_entropy > 7.45 and raw_size > 2048 and lower_sec not in {".rsrc"}:
                pe_info["has_high_entropy_section"] = True
                pe_info["suspicious_sections"].append(f"Yüksek entropili şifreli/paketlenmiş bölüm: {raw_name} ({sec_entropy})")

        if max_pe_end > 0 and len(data) > max_pe_end + 65536:
            pe_info["has_overlay"] = True
            pe_info["overlay_size"] = len(data) - max_pe_end
            if pe_info["overlay_size"] >= 5 * 1024 * 1024:
                ov_sample = data[max_pe_end:max_pe_end + 262144]
                ov_ent = calculate_shannon_entropy(ov_sample)
                if ov_ent < 1.5:
                    pe_info.setdefault("suspicious_sections", []).append(
                        f"Binary Pumping Dolgu Saldırısı (Büyük Düşük Entropili Overlay: {pe_info['overlay_size'] // (1024 * 1024)} MB, Entropi={ov_ent:.2f})"
                    )

    except Exception:
        pass

    return pe_info

def deobfuscate_embedded_base64(text: str) -> str:
    """Betik veya ikililer içindeki gizlenmiş Base64 bloklarını çözerek içerik taraması yapar."""
    decoded_fragments = []
    candidates = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text)
    for cand in candidates[:20]:
        try:
            raw = base64.b64decode(cand, validate=True)
            for enc in ("utf-8", "utf-16le", "ascii"):
                decoded = raw.decode(enc, errors="ignore")
                printable_ratio = sum(32 <= ord(c) <= 126 or c in "\r\n\t" for c in decoded) / max(1, len(decoded))
                if len(decoded) >= 10 and printable_ratio > 0.75:
                    decoded_fragments.append(decoded)
                    break
        except Exception:
            continue
    return "\n".join(decoded_fragments)

def deep_heuristic_scan(file_path: str, db_path: str) -> dict:
    result = {
        "engine": "AegisCore Python 3.10 Deep Heuristic, PE & Script Deobfuscation Engine",
        "path": file_path,
        "file_name": os.path.basename(file_path),
        "exists": False,
        "size_bytes": 0,
        "sha256": "",
        "md5": "",
        "entropy": 0.0,
        "pe_analysis": {},
        "risk_score": 0,
        "status": "CLEAN",
        "severity": "SAFE",
        "threat_name": "",
        "heuristic_findings": []
    }

    if not os.path.isfile(file_path):
        return result

    try:
        result["exists"] = True
        result["size_bytes"] = os.path.getsize(file_path)

        with open(file_path, "rb") as f:
            data = f.read(4 * 1024 * 1024)

        result["sha256"] = hashlib.sha256(data).hexdigest()
        result["md5"] = hashlib.md5(data).hexdigest()
        result["entropy"] = calculate_shannon_entropy(data)
        result["pe_analysis"] = analyze_pe_header(data)

        db = {}
        if os.path.isfile(db_path):
            with open(db_path, "r", encoding="utf-8") as dbf:
                db = json.load(dbf)

        # 1. Exact SHA-256 signature match
        sha_sigs = db.get("sha256_signatures", {})
        if result["sha256"] in sha_sigs:
            sig = sha_sigs[result["sha256"]]
            if sig.get("severity") != "SAFE":
                result["risk_score"] = 100
                result["threat_name"] = sig.get("name", "Known.Malware")
                result["severity"] = sig.get("severity", "CRITICAL")
                result["heuristic_findings"].append(f"[SHA-256 İmza Motoru] {sig.get('description')}")

        # 2. Magic-Byte Spoofing Check
        ext = os.path.splitext(result["file_name"])[1].lower()
        doc_media_exts = {".pdf", ".jpg", ".jpeg", ".png", ".gif", ".txt", ".doc", ".docx", ".xls", ".xlsx"}
        if result["pe_analysis"].get("is_pe") and ext in doc_media_exts:
            result["risk_score"] = min(100, result["risk_score"] + 90)
            result["heuristic_findings"].append(f"[Magic-Byte Sahtekarlığı] {ext} uzantısı altında gizlenmiş Windows MZ yürütülebilir dosya")
            if not result["threat_name"]:
                result["threat_name"] = "Trojan.SpoofedExtension.Executable"

        # 3. Combine plain text + Deobfuscated Base64 fragments
        text_content = data.decode("utf-8", errors="ignore")
        deobfuscated = deobfuscate_embedded_base64(text_content)
        combined_text = text_content + ("\n" + deobfuscated if deobfuscated else "")

        if deobfuscated and any(kw in deobfuscated.lower() for kw in ("powershell", "iex", "invoke-", "http", "cmd.exe", "vssadmin", "virtualalloc", "downloadstring")):
            result["risk_score"] = min(100, result["risk_score"] + 65)
            result["heuristic_findings"].append("[Betik Çözücü] Gizlenmiş Base64 yükü içinde şüpheli komutlar çözümlendi")
            if not result["threat_name"]:
                result["threat_name"] = "Trojan.Script.DeobfuscatedPayload"

        # 4. Byte / Behavioral Patterns
        categories_hit = set()
        combined_lower = combined_text.lower()
        for pat in db.get("byte_patterns", []):
            pattern_str = pat.get("pattern", "")
            if pattern_str and pattern_str.lower() in combined_lower:
                result["risk_score"] = min(100, result["risk_score"] + pat.get("score", 40))
                result["heuristic_findings"].append(f"[{pat.get('id')}] {pat.get('description')}")
                if pat.get("category"):
                    categories_hit.add(pat["category"])
                if not result["threat_name"]:
                    result["threat_name"] = pat.get("name")

        # 5. Advanced Regex Behavioral Heuristics
        advanced_rules = [
            (r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/", 55, "Heuristic.C2.DirectIPUrl", "Doğrudan IP adresine bağlanan Komuta Kontrol (C2) URL kalıbı"),
            (r"(?:cmd\.exe\s+/c|powershell(?:\.exe)?\s+-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+[A-Za-z0-9+/=]{12,})", 85, "Trojan.Script.EncodedCommand", "Gizlenmiş/Base64 şifreli kabuk komutu çalıştırma"),
            (r"(?:YOUR\s+FILES\s+HAVE\s+BEEN\s+ENCRYPTED|bitcoin\s+wallet|decrypt\s+your\s+files)", 80, "Ransomware.Heuristic.NotePattern", "Fidye yazılımı (Ransomware) şifreleme/fidye notu metin kalıbı"),
            (r"(?:WScript\.Shell|Scripting\.FileSystemObject|ADODB\.Stream)", 50, "Heuristic.Dropper.WScriptCOM", "Zararlı betik yükleyicilerinde sık kullanılan Windows COM nesnesi"),
            (r"Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?", 50, "Heuristic.Persistence.RegistryRun", "Sistem başlangıcına kalıcılık (Persistence Run/RunOnce) ekleme anahtarı"),
            (r"(?:Invoke-Expression|IEX\s*\(|DownloadString\s*\()", 55, "Trojan.PowerShell.InMemoryExec", "Bellek içi uzaktan kod indirip çalıştırma (Fileless Execution) kalıbı"),
            (r"(?:/bin/(?:ba)?sh\s+-i|/dev/tcp/|TcpClient.{0,120}?GetStream|RedirectStandard(?:Input|Output|Error).{0,120}?cmd\.exe)", 85, "Trojan.Generic.ReverseShell", "Ters kabuk (Reverse Shell) / uzaktan etkileşimli komut akışı kalıbı"),
            (r"(?:GetClipboardData|SetClipboardData|Clipboard\.SetText).{0,220}?(?:\bbc1q[0-9a-z]{20,60}|\b0x[a-fA-F0-9]{40}\b|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b)", 85, "Trojan.ClipBanker.CryptoHijack", "Pano (Clipboard) kripto cüzdan adresi değiştirme kalıbı"),
            (r"(?:(?:Add-MpPreference|Set-MpPreference).{0,160}?(?:-Exclusion|-DisableRealtimeMonitoring|-DisableIOAVProtection)|netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off|AmsiScanBuffer.{0,100}?VirtualProtect|EtwEventWrite.{0,100}?VirtualProtect)", 85, "Trojan.DefenseEvasion.SecurityKiller", "Güvenlik duvarı / Windows Defender / AMSI-ETW devre dışı bırakma girişimi"),
            (r"(?:Login Data|Local State|cookies\.sqlite|wallet\.dat|Exodus|Electrum|tdata).{0,240}?(?:CryptUnprotectData|NSS_Init|DPAPI|master_key|AES-GCM)", 85, "Trojan.Stealer.MultiAppHarvest", "Tarayıcı, kripto cüzdan ve mesajlaşma oturum verisi çalma (InfoStealer) kalıbı")
        ]

        for regex, score, t_name, desc in advanced_rules:
            if re.search(regex, combined_text, re.IGNORECASE):
                result["risk_score"] = min(100, result["risk_score"] + score)
                result["heuristic_findings"].append(f"[Python Derin Analiz] {desc}")
                if not result["threat_name"]:
                    result["threat_name"] = t_name

        # 6. PE Structural Anomalies
        if result["pe_analysis"].get("suspicious_sections"):
            for sec_warn in result["pe_analysis"]["suspicious_sections"]:
                result["risk_score"] = min(100, result["risk_score"] + 35)
                result["heuristic_findings"].append(f"[PE Yapısal Analiz] {sec_warn}")
                if not result["threat_name"]:
                    result["threat_name"] = "Heuristic.PE.PackedOrModified"

        # 7. Kill-Chain Bonus
        if len(categories_hit) >= 2:
            result["risk_score"] = min(100, result["risk_score"] + 25)
            result["heuristic_findings"].append(f"[Kill-Chain Korelasyonu] Birden fazla saldırı tekniği bir arada ({', '.join(sorted(categories_hit))})")

        # 8. Overall Verdict
        if result["risk_score"] >= 70:
            result["status"] = "INFECTED"
            result["severity"] = "CRITICAL"
        elif result["risk_score"] >= 35:
            result["status"] = "SUSPICIOUS"
            result["severity"] = "MEDIUM"
        else:
            result["status"] = "CLEAN"
            result["severity"] = "SAFE"

    except Exception as e:
        result["error"] = str(e)

    return result

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    default_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "signatures", "malware_db.json")
    db_file = sys.argv[2] if len(sys.argv) > 2 else default_db
    output = deep_heuristic_scan(target, db_file)
    print(json.dumps(output, ensure_ascii=False))
