#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MODÜL 1 :: Çok Katmanlı Statik, Fuzzy Hash, Shannon Entropi, PE IAT ve Betik Dekoderi
(Pre-Execution Scanner)
"""

from __future__ import annotations
import ast
import base64
import hashlib
import math
import os
import re
import struct
from collections import Counter
from dataclasses import dataclass, field, asdict
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Set, Tuple

from core.event_bus import EventBus
from core.win32_native import verify_authenticode_catalog

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def shannon_entropy(data: bytes) -> float:
    """H(X) = -sum(P(x_i) * log2(P(x_i))) formülü ile 0.0 - 8.0 arası entropi."""
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
    entropy = 0.0
    for cnt in counts.values():
        p = cnt / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class FuzzyHasher:
    """
    CTPH (Context-Triggered Piecewise Hashing / SSDEEP mantığı) ile
    mutasyona uğramış zararlı yazılım varyantlarını yüzde benzerlik ile tespit eder.
    """

    WINDOW_SIZE = 7
    FNV_PRIME = 0x01000193
    FNV_OFFSET = 0x811C9DC5

    @classmethod
    def _compute_for_block(cls, data: bytes, block_size: int) -> Tuple[str, str]:
        chunks_primary: List[str] = []
        chunks_secondary: List[str] = []

        h1 = 0
        h2 = 0
        h3 = 0
        win_size = cls.WINDOW_SIZE
        window = bytearray(win_size)
        win_idx = 0

        fnv_prime = cls.FNV_PRIME
        fnv_offset = cls.FNV_OFFSET
        fnv_p = fnv_offset
        fnv_s = fnv_offset
        alphabet = B64_ALPHABET

        is_pow2 = block_size > 0 and (block_size & (block_size - 1)) == 0
        mask_p = block_size - 1
        block_size2 = block_size * 2
        mask_s = block_size2 - 1

        for b in data:
            old = window[win_idx]
            h2 -= h1
            h2 += win_size * b
            h1 += b - old
            h3 = ((h3 << 5) ^ b) & 0xFFFFFFFF
            window[win_idx] = b
            win_idx += 1
            if win_idx == win_size:
                win_idx = 0
            roll = (h1 + h2 + h3) & 0xFFFFFFFF

            fnv_p = ((fnv_p * fnv_prime) ^ b) & 0xFFFFFFFF
            fnv_s = ((fnv_s * fnv_prime) ^ b) & 0xFFFFFFFF

            if (roll & mask_p) == mask_p if is_pow2 else (roll % block_size) == mask_p:
                chunks_primary.append(alphabet[fnv_p & 63])
                fnv_p = fnv_offset
                if len(chunks_primary) >= 64:
                    break

            if (roll & mask_s) == mask_s if is_pow2 else (roll % block_size2) == mask_s:
                chunks_secondary.append(alphabet[fnv_s & 63])
                fnv_s = fnv_offset

        chunks_primary.append(alphabet[fnv_p & 63])
        chunks_secondary.append(alphabet[fnv_s & 63])
        return "".join(chunks_primary), "".join(chunks_secondary)

    @classmethod
    def compute(cls, data: bytes) -> str:
        if not data:
            return "3::"

        if len(data) > 131072:
            mid = len(data) // 2
            data = data[:65536] + data[mid:mid + 32768] + data[-32768:]

        # Resmi SSDEEP/CTPH adaptif blok boyutu belirleme
        block_size = 8
        while block_size * 64 < len(data) and block_size < 65536:
            block_size *= 2

        p1, p2 = cls._compute_for_block(data, block_size)
        while len(p1) < 20 and block_size > 4:
            block_size //= 2
            p1, p2 = cls._compute_for_block(data, block_size)

        return f"{block_size}:{p1}:{p2}"

    @staticmethod
    def similarity(sig_a: str, sig_b: str) -> float:
        """İki bulanık imzanın yüzde benzerlik oranını (0.0 - 100.0) hesaplar."""
        try:
            ba, p1a, p2a = sig_a.split(":", 2)
            bb, p1b, p2b = sig_b.split(":", 2)
            ba_i, bb_i = int(ba), int(bb)
        except ValueError:
            return 0.0

        if ba_i == bb_i:
            ratio = SequenceMatcher(None, p1a, p1b).ratio()
            return round(ratio * 100.0, 2)
        if ba_i * 2 == bb_i:
            ratio = SequenceMatcher(None, p2a, p1b).ratio()
            return round(ratio * 100.0, 2)
        if bb_i * 2 == ba_i:
            ratio = SequenceMatcher(None, p1a, p2b).ratio()
            return round(ratio * 100.0, 2)
        return 0.0


@dataclass
class StaticAnalysisReport:
    path: str
    file_name: str
    size_bytes: int
    sha256: str
    fuzzy_hash: str
    overall_entropy: float
    is_pe: bool = False
    pe_arch: str = ""
    is_signed: bool = False
    signer: str = ""
    sections: List[Dict[str, object]] = field(default_factory=list)
    packed_or_obfuscated: bool = False
    imported_dlls: Dict[str, List[str]] = field(default_factory=dict)
    process_injection_flag: bool = False
    fuzzy_match: Optional[Dict[str, object]] = None
    script_findings: List[str] = field(default_factory=list)
    decoded_payloads: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    risk_contribution: int = 0

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


class StaticPEAnalyzer:
    """
    MODÜL 1 Ana Sınıfı:
    Çalıştırma öncesi (Pre-Execution) statik, entropi, fuzzy hash, PE IAT ve AST/Regex betik analizi.
    """

    ALLOC_APIS = {"virtualallocex", "ntallocatevirtualmemory", "virtualallocexnuma", "zwallocatevirtualmemory", "virtualalloc", "ntprotectvirtualmemory", "virtualprotectex"}
    WRITE_APIS = {"writeprocessmemory", "ntwritevirtualmemory", "zwwritevirtualmemory", "ntunmapviewofsection", "zwunmapviewofsection"}
    EXEC_APIS = {
        "createremotethread", "createremotethreadex", "ntcreatethreadex",
        "queueuserapc", "ntqueueapcthread", "rtlcreateuserthread",
        "setthreadcontext", "ntsetcontextthread", "resumethread", "ntresumethread",
        "ntmapviewofsection",
    }

    def __init__(self, event_bus: EventBus) -> None:
        self._bus = event_bus
        self._known_sha256: Dict[str, str] = {}
        self._known_fuzzy: Dict[str, str] = {}

    def register_known_malware(self, name: str, sha256: Optional[str] = None, fuzzy_sig: Optional[str] = None) -> None:
        if sha256:
            self._known_sha256[sha256.lower()] = name
        if fuzzy_sig:
            self._known_fuzzy[fuzzy_sig] = name

    @staticmethod
    def _rva_to_offset(rva: int, sections: List[Tuple[int, int, int, int]]) -> Optional[int]:
        """(VirtualAddress, VirtualSize, PointerToRawData, SizeOfRawData) üzerinden RVA -> Disk Offset."""
        for vaddr, vsize, rptr, rsize in sections:
            span = max(vsize, rsize)
            if vaddr <= rva < vaddr + span:
                off = rptr + (rva - vaddr)
                return off
        return None

    @staticmethod
    def _read_cstring(data: bytes, offset: int, max_len: int = 256) -> str:
        if offset < 0 or offset >= len(data):
            return ""
        end = data.find(b"\x00", offset, min(len(data), offset + max_len))
        if end == -1:
            end = min(len(data), offset + max_len)
        return data[offset:end].decode("ascii", errors="ignore")

    def _parse_pe_and_iat(self, data: bytes, report: StaticAnalysisReport) -> None:
        if len(data) < 64 or data[:2] != b"MZ":
            return

        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return

            report.is_pe = True
            machine, num_sections = struct.unpack_from("<HH", data, pe_offset + 4)
            opt_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            opt_offset = pe_offset + 24

            if opt_offset + 2 > len(data):
                return
            magic = struct.unpack_from("<H", data, opt_offset)[0]
            is_pe64 = (magic == 0x20B)
            report.pe_arch = "x64 (PE32+)" if is_pe64 else "x86 (PE32)" if magic == 0x10B else f"0x{magic:04x}"

            # DataDirectory[1] = Import Directory
            import_dir_rva = 0
            import_dir_size = 0
            dd_offset = opt_offset + (112 if is_pe64 else 96)
            if dd_offset + 16 <= opt_offset + opt_size and dd_offset + 16 <= len(data):
                import_dir_rva, import_dir_size = struct.unpack_from("<II", data, dd_offset + 8)

            sec_table_offset = opt_offset + opt_size
            sec_coords: List[Tuple[int, int, int, int]] = []

            for i in range(min(num_sections, 32)):
                off = sec_table_offset + i * 40
                if off + 40 > len(data):
                    break
                name_raw = data[off:off + 8].split(b"\x00", 1)[0].decode("ascii", errors="ignore")
                vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
                sec_coords.append((vaddr, vsize, rptr, rsize))

                sec_bytes = data[rptr:rptr + rsize] if rptr < len(data) and rsize > 0 else b""
                sec_ent = shannon_entropy(sec_bytes)
                is_packed_sec = sec_ent > 7.2
                if is_packed_sec:
                    report.packed_or_obfuscated = True

                report.sections.append({
                    "name": name_raw,
                    "virtual_address": hex(vaddr),
                    "raw_size": rsize,
                    "entropy": sec_ent,
                    "packed_suspicious": is_packed_sec,
                })

            # IAT / Import Directory Ayrıştırma
            if import_dir_rva > 0 and import_dir_size >= 20:
                idt_off = self._rva_to_offset(import_dir_rva, sec_coords)
                if idt_off is not None:
                    idt_guard = 0
                    while idt_off + 20 <= len(data) and idt_guard < 512:
                        idt_guard += 1
                        orig_first_thunk, _ts, _fwd, name_rva, first_thunk = struct.unpack_from("<IIIII", data, idt_off)
                        if orig_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
                            break

                        dll_name_off = self._rva_to_offset(name_rva, sec_coords)
                        dll_name = self._read_cstring(data, dll_name_off) if dll_name_off is not None else "Unknown.dll"

                        thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
                        thunk_off = self._rva_to_offset(thunk_rva, sec_coords)
                        apis: List[str] = []

                        if thunk_off is not None:
                            step = 8 if is_pe64 else 4
                            fmt = "<Q" if is_pe64 else "<I"
                            ord_flag = 1 << 63 if is_pe64 else 1 << 31
                            guard = 0
                            while thunk_off + step <= len(data) and guard < 1024:
                                val = struct.unpack_from(fmt, data, thunk_off)[0]
                                if val == 0:
                                    break
                                if not (val & ord_flag):
                                    hint_name_off = self._rva_to_offset(val & 0x7FFFFFFF, sec_coords)
                                    if hint_name_off is not None and hint_name_off + 2 < len(data):
                                        api_name = self._read_cstring(data, hint_name_off + 2)
                                        if api_name:
                                            apis.append(api_name)
                                thunk_off += step
                                guard += 1

                        if dll_name:
                            report.imported_dlls[dll_name] = apis
                        idt_off += 20

            # Süreç Enjeksiyonu IAT API Üçlüsü Kontrolü
            all_apis_lower: Set[str] = {api.lower() for api_list in report.imported_dlls.values() for api in api_list}
            has_alloc = bool(all_apis_lower & self.ALLOC_APIS)
            has_write = bool(all_apis_lower & self.WRITE_APIS)
            has_exec = bool(all_apis_lower & self.EXEC_APIS)

            if has_alloc and has_write and has_exec:
                report.process_injection_flag = True
                report.flags.append("Yüksek Olasılıklı Süreç Enjeksiyonu (Process Injection IAT Üçlüsü)")
        except Exception:
            pass

    def _analyze_script(self, data: bytes, ext: str, report: StaticAnalysisReport) -> None:
        text = data.decode("utf-8", errors="ignore")
        decoded_texts: List[str] = []

        # Base64 bloklarını yakala ve hem UTF-8 hem UTF-16LE olarak çöz
        b64_candidates = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text)
        for cand in b64_candidates[:25]:
            try:
                raw = base64.b64decode(cand, validate=True)
                for enc in ("utf-8", "utf-16le", "ascii"):
                    s = raw.decode(enc, errors="ignore")
                    printable = sum(32 <= ord(c) <= 126 or c in "\r\n\t" for c in s) / max(1, len(s))
                    if len(s) >= 8 and printable > 0.78:
                        decoded_texts.append(s)
                        break
            except Exception:
                continue

        report.decoded_payloads = decoded_texts
        full_corpus = text + "\n" + "\n".join(decoded_texts)

        # Regex Davranış Kalıpları
        patterns = [
            (r"\b(?:Invoke-Expression|IEX)\b", "PowerShell dinamik kod çalıştırma (Invoke-Expression / IEX)"),
            (r"-e(?:nc|ncodedcommand)\b", "Gizlenmiş Base64 komut parametresi (-EncodedCommand)"),
            (r"-w(?:indowstyle)?\s+hidden\b", "Gizli pencere çalıştırma (-WindowStyle Hidden)"),
            (r"DownloadString\s*\(|Net\.WebClient", "Ağ üzerinden bellek içi yük indirme (DownloadString)"),
            (r"AmsiUtils|amsiInitFailed|AmsiScanBuffer", "AMSI koruma atlatma girişimi (AMSI Bypass)"),
            (r"WScript\.Shell|CreateObject\s*\(", "COM Script yürütme nesnesi"),
        ]
        for rx, desc in patterns:
            if re.search(rx, full_corpus, re.IGNORECASE):
                report.script_findings.append(f"[Regex] {desc}")

        # Yapısal AST Analizi (Python betikleri için gerçek ast.parse + genel betik token çağrı ağacı)
        if ext == ".py":
            try:
                tree = ast.parse(text)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        fn = ""
                        if isinstance(node.func, ast.Name):
                            fn = node.func.id
                        elif isinstance(node.func, ast.Attribute):
                            fn = node.func.attr
                        if fn in {"eval", "exec", "system", "Popen", "b64decode"}:
                            report.script_findings.append(f"[AST] Tehlikeli dinamik çağrı düğümü tespit edildi: {fn}()")
            except (SyntaxError, RecursionError, ValueError):
                pass
        else:
            # PowerShell / JS / VBS için hafif sözdizimi çağrı-ağacı çıkarıcı (Call AST)
            call_tokens = re.findall(r"([A-Za-z_][A-Za-z0-9_.\-:]+)\s*\(", full_corpus)
            suspicious_calls = [c for c in call_tokens if any(k in c.lower() for k in ("eval", "exec", "download", "frombase64", "shellexecute", "virtualalloc"))]
            if suspicious_calls:
                report.script_findings.append(f"[Script-AST] Şüpheli çağrı zinciri: {', '.join(sorted(set(suspicious_calls)))}")

    def analyze_file_with_buffer(
        self, file_path: str, precomputed: Optional[Dict[str, object]] = None
    ) -> Tuple[StaticAnalysisReport, bytes]:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Dosya bulunamadı: {file_path}")

        file_size = os.path.getsize(file_path)
        max_head = 4 * 1024 * 1024
        pre_sha = str((precomputed or {}).get("sha256") or "").lower()

        if pre_sha:
            with open(file_path, "rb") as f:
                data = f.read(max_head)
                if file_size > 4_500_000:
                    try:
                        f.seek(max(0, file_size - 262144))
                        data = data + f.read(262144)
                    except Exception:
                        pass
            sha256 = pre_sha
        else:
            hasher = hashlib.sha256()
            head_chunks: List[bytes] = []
            head_collected = 0
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(262144)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    if head_collected < max_head:
                        take = chunk[: max_head - head_collected]
                        head_chunks.append(take)
                        head_collected += len(take)
                data = b"".join(head_chunks)
                if file_size > 4_500_000:
                    try:
                        f.seek(max(0, file_size - 262144))
                        data = data + f.read(262144)
                    except Exception:
                        pass
            sha256 = hasher.hexdigest()

        overall_ent = shannon_entropy(data[: 1024 * 1024])

        report = StaticAnalysisReport(
            path=file_path,
            file_name=os.path.basename(file_path),
            size_bytes=file_size,
            sha256=sha256,
            fuzzy_hash="",
            overall_entropy=overall_ent,
        )

        if overall_ent > 7.2:
            report.packed_or_obfuscated = True
            report.flags.append(f"Şifrelenmiş / Paketlenmiş (Packed/Obfuscated) Şüpheli (Entropi: {overall_ent})")

        # 1. Tam SHA-256 Kontrolü
        known_sha_hit = sha256 in self._known_sha256
        if known_sha_hit:
            m_name = self._known_sha256[sha256]
            report.flags.append(f"Tam SHA-256 Zararlı İmzası: {m_name}")
            report.risk_contribution += 100

        # 2. PE + IAT + İmza Doğrulaması
        self._parse_pe_and_iat(data, report)
        if precomputed is not None and "is_signed" in precomputed:
            report.is_signed = bool(precomputed.get("is_signed"))
            report.signer = str(precomputed.get("signer") or "")
        elif report.is_pe:
            is_signed, signer = verify_authenticode_catalog(file_path)
            report.is_signed = is_signed
            report.signer = signer

        # 2B. Bulanık İmza (Fuzzy Hash) Kontrolü — imzalı veya tam SHA eşleşen dosyalarda atlanır
        if self._known_fuzzy and not known_sha_hit and not report.is_signed:
            fuzzy_sig = FuzzyHasher.compute(data)
            report.fuzzy_hash = fuzzy_sig
            best_fuzzy: Tuple[float, str] = (0.0, "")
            for k_fuzzy, m_name in self._known_fuzzy.items():
                sim = FuzzyHasher.similarity(fuzzy_sig, k_fuzzy)
                if sim > best_fuzzy[0]:
                    best_fuzzy = (sim, m_name)
            if best_fuzzy[0] >= 55.0:
                report.fuzzy_match = {"malware_name": best_fuzzy[1], "similarity_percent": best_fuzzy[0]}
                report.flags.append(f"Bulanık İmza Varyant Eşleşmesi: {best_fuzzy[1]} (%{best_fuzzy[0]} benzerlik)")
                report.risk_contribution += 75

        # 3. Betik Analizi
        ext = os.path.splitext(file_path)[1].lower()
        if ext in {".ps1", ".psm1", ".vbs", ".vbe", ".bat", ".cmd", ".js", ".jse", ".py", ".hta", ".wsf", ".sct"}:
            self._analyze_script(data, ext, report)

        # Risk katkısı hesaplama (Modül 5 kurallarıyla uyumlu)
        if report.is_pe and not report.is_signed:
            report.risk_contribution += 15
        if report.packed_or_obfuscated and not report.is_signed:
            report.risk_contribution += 25
        if report.process_injection_flag and not report.is_signed:
            report.risk_contribution += 45
        if report.script_findings:
            report.risk_contribution += min(65, 25 * len(report.script_findings))

        severity = "CRITICAL" if report.risk_contribution >= 80 else "HIGH" if report.risk_contribution >= 50 else "MEDIUM" if report.risk_contribution >= 30 else "INFO"
        self._bus.emit(
            "MOD1_STATIC_ANALYZER",
            "PRE_EXECUTION_SCAN_COMPLETE",
            severity=severity,
            report=report.to_dict(),
        )
        return report, data

    def analyze_file(self, file_path: str, precomputed: Optional[Dict[str, object]] = None) -> StaticAnalysisReport:
        report, _ = self.analyze_file_with_buffer(file_path, precomputed=precomputed)
        return report
