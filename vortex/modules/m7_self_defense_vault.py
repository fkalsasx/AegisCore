#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MODÜL 7 :: Öz-Koruma (Self-Defense) ve Şifreli Karantina Kasası (.aegis_q)
Yakalanan zararlıların PE başlığını bozar, AES-256-GCM (Windows bcrypt.dll) +
dinamik XOR katmanıyla şifreleyerek .aegis_q uzantısıyla izole eder ve SQLite
meta veri tabanında saklar. Anti-Tamper koruma uygular.
"""

from __future__ import annotations
import hashlib
import os
import sqlite3
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from core.event_bus import EventBus
from core.win32_native import (
    bcrypt_aes256_gcm_decrypt,
    bcrypt_aes256_gcm_encrypt,
    harden_process_dacl_self_defense,
    set_file_hidden_system,
)


class SelfDefenseVault:
    """PE Header bozma, AES-256-GCM karantina ve Anti-Tamper servis koruması."""

    CORRUPT_PE_MARKER = b"AEGIS_CORRUPTED_PE_HEADER_XXXX"

    def __init__(self, event_bus: EventBus, vault_dir: str, shadow_dir: str, master_secret: str = "AEGIS-VORTEX-MASTER-2026") -> None:
        self._bus = event_bus
        self._vault_dir = os.path.abspath(vault_dir)
        self._shadow_dir = os.path.abspath(shadow_dir)
        self._db_path = os.path.join(self._vault_dir, "vault_meta.db")
        self._legacy_aes_key = hashlib.sha256(master_secret.encode("utf-8")).digest()
        self._lock = threading.RLock()
        self._service_pid = os.getpid()

        os.makedirs(self._vault_dir, exist_ok=True)
        os.makedirs(self._shadow_dir, exist_ok=True)
        self._aes_key = self._load_or_create_machine_key()
        self._init_db()
        self.apply_anti_tamper()

    def _load_or_create_machine_key(self) -> bytes:
        key_path = os.path.join(self._vault_dir, ".vault_master.key")
        if os.path.isfile(key_path):
            try:
                with open(key_path, "rb") as kf:
                    raw = kf.read()
                if len(raw) == 32:
                    return raw
            except OSError:
                pass
        key = os.urandom(32)
        try:
            with open(key_path, "wb") as kf:
                kf.write(key)
            set_file_hidden_system(key_path, True)
            self._restrict_file_acl(key_path)
        except OSError:
            pass
        return key

    @staticmethod
    def _restrict_file_acl(file_path: str) -> None:
        try:
            user = os.environ.get("USERNAME", "")
            icacls_exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe")
            if user and os.path.isfile(icacls_exe):
                subprocess.run(
                    [icacls_exe, file_path, "/inheritance:r", "/grant:r", f"{user}:(R,W)"],
                    capture_output=True,
                    timeout=3,
                )
        except Exception:
            pass

    def _init_db(self) -> None:
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS quarantine_items (
                        id TEXT PRIMARY KEY,
                        original_path TEXT NOT NULL,
                        vault_path TEXT NOT NULL,
                        sha256 TEXT NOT NULL,
                        size_bytes INTEGER NOT NULL,
                        threat_name TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        pe_corrupted INTEGER NOT NULL,
                        quarantined_at TEXT NOT NULL
                    )
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def apply_anti_tamper(self) -> Dict[str, bool]:
        """
        AEGIS-VORTEX servis PID'ine ve kritik koruma dizinlerine (Vault & ShadowStore)
        dış müdahalelere karşı öz-koruma uygular.
        """
        proc_hardened = harden_process_dacl_self_defense()
        dirs_protected = True
        for d in (self._vault_dir, self._shadow_dir):
            try:
                set_file_hidden_system(d, True)
            except Exception:
                dirs_protected = False

        self._bus.emit(
            "MOD7_SELF_DEFENSE",
            "ANTI_TAMPER_ACTIVE",
            severity="INFO",
            pid=self._service_pid,
            process_hardened=proc_hardened,
            protected_dirs=[self._vault_dir, self._shadow_dir],
        )
        return {"process_hardened": proc_hardened, "dirs_protected": dirs_protected}

    def deny_external_tamper_attempt(self, actor_pid: int, target_path_or_pid: str) -> bool:
        """Dış süreçlerin servis PID'ine veya ShadowStore/Vault alanına müdahalesini tespit ve bloke eder."""
        raw_str = str(target_path_or_pid)
        has_path_sep = ("\\" in raw_str) or ("/" in raw_str)
        normalized = os.path.normcase(os.path.abspath(raw_str)) if has_path_sep else raw_str
        vault_norm = os.path.normcase(os.path.abspath(self._vault_dir))
        shadow_norm = os.path.normcase(os.path.abspath(self._shadow_dir))
        is_protected_target = (
            raw_str == str(self._service_pid)
            or normalized == vault_norm
            or normalized.startswith(vault_norm + os.sep)
            or normalized == shadow_norm
            or normalized.startswith(shadow_norm + os.sep)
        )
        if is_protected_target and actor_pid != self._service_pid:
            self._bus.emit(
                "MOD7_SELF_DEFENSE",
                "TAMPER_ATTEMPT_BLOCKED",
                severity="CRITICAL",
                pid=actor_pid,
                target=raw_str,
                action="DENIED",
            )
            return True
        return False

    def _is_inside_vault_dir(self, path_str: str) -> bool:
        try:
            base = os.path.normcase(os.path.abspath(self._vault_dir))
            cand = os.path.normcase(os.path.abspath(path_str))
            return cand.startswith(base + os.sep) and cand.endswith(".aegis_q")
        except Exception:
            return False

    def _is_protected_system_or_vault_path(self, path_str: str) -> bool:
        try:
            real_norm = os.path.normcase(os.path.realpath(path_str))
            sys_root = os.path.normcase(os.path.abspath(os.environ.get("SystemRoot", r"C:\Windows")))
            vault_norm = os.path.normcase(os.path.abspath(self._vault_dir))
            shadow_norm = os.path.normcase(os.path.abspath(self._shadow_dir))
            for pref in (sys_root, vault_norm, shadow_norm):
                if real_norm == pref or real_norm.startswith(pref + os.sep):
                    return True
            return False
        except Exception:
            return True

    @staticmethod
    def _dynamic_xor(data: bytes, seed_hex: str) -> bytes:
        key = hashlib.sha256(seed_hex.encode("utf-8")).digest()
        klen = len(key)
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = b ^ key[i % klen]
        return bytes(out)

    def quarantine_file(self, file_path: str, threat_name: str, risk_score: int) -> Optional[Dict[str, object]]:
        """
        Dosyanın PE başlığını bozar, dinamik XOR + bcrypt AES-256-GCM ile şifreler,
        .aegis_q olarak kaydeder, orijinali siler ve meta veriyi SQLite'a yazar.
        """
        abs_path = os.path.abspath(file_path)
        if not os.path.isfile(abs_path) or os.path.islink(abs_path):
            return None
        if self._is_protected_system_or_vault_path(abs_path):
            return None
        if os.path.getsize(abs_path) > 100 * 1024 * 1024:
            return None

        with open(abs_path, "rb") as f:
            raw_bytes = f.read()

        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        qid = str(uuid.uuid4())
        vault_path = os.path.join(self._vault_dir, f"{qid}.aegis_q")

        # 1. Orijinal PE başlığını (ilk 64 bayt) şifreli zarf içinde yedekleyip payload üzerindeki MZ/PE başlığını boz
        pe_corrupted = 0
        payload = bytearray(raw_bytes)
        original_header = bytes(raw_bytes[:64])
        if len(payload) >= 2 and payload[:2] == b"MZ":
            pe_corrupted = 1
            marker_len = min(len(self.CORRUPT_PE_MARKER), len(payload))
            payload[:marker_len] = self.CORRUPT_PE_MARKER[:marker_len]

        # 2. Çift Katmanlı Zarf: [4-byte header len][original_header][XOR(corrupted_payload)] -> AES-256-GCM
        hdr_len_bytes = len(original_header).to_bytes(4, "little")
        xored_body = self._dynamic_xor(bytes(payload), qid)
        envelope = hdr_len_bytes + original_header + xored_body
        encrypted_blob = bcrypt_aes256_gcm_encrypt(self._aes_key, envelope)

        with open(vault_path, "wb") as vf:
            vf.write(encrypted_blob)

        os.remove(abs_path)
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                conn.execute(
                    """
                    INSERT INTO quarantine_items
                    (id, original_path, vault_path, sha256, size_bytes, threat_name, risk_score, pe_corrupted, quarantined_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (qid, abs_path, vault_path, sha256, len(raw_bytes), threat_name, risk_score, pe_corrupted, now_iso),
                )
                conn.commit()
            finally:
                conn.close()

        record = {
            "id": qid,
            "original_path": abs_path,
            "vault_path": vault_path,
            "sha256": sha256,
            "size_bytes": len(raw_bytes),
            "threat_name": threat_name,
            "risk_score": risk_score,
            "pe_corrupted": bool(pe_corrupted),
            "quarantined_at": now_iso,
        }
        self._bus.emit("MOD7_SELF_DEFENSE", "FILE_QUARANTINED", severity="CRITICAL", **record)
        return record

    def restore_file(self, qid: str, restore_path: Optional[str] = None) -> Optional[str]:
        """Karantinadaki .aegis_q dosyasını çözüp PE başlığını onararak geri yükler."""
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                row = conn.execute(
                    "SELECT original_path, vault_path, pe_corrupted FROM quarantine_items WHERE id = ?",
                    (qid,),
                ).fetchone()
            finally:
                conn.close()

        if not row:
            return None

        orig_path, vault_path, pe_corrupted = row
        target_out = os.path.abspath(restore_path or orig_path)
        if not self._is_inside_vault_dir(vault_path) or not os.path.isfile(vault_path) or os.path.islink(vault_path):
            return None
        if os.path.islink(target_out) or self._is_protected_system_or_vault_path(target_out):
            return None

        with open(vault_path, "rb") as vf:
            blob = vf.read()

        envelope = bcrypt_aes256_gcm_decrypt(self._aes_key, blob)
        hdr_len = int.from_bytes(envelope[:4], "little")
        original_header = envelope[4:4 + hdr_len]
        xored_body = envelope[4 + hdr_len:]
        restored_body = bytearray(self._dynamic_xor(xored_body, qid))
        if pe_corrupted and len(restored_body) >= len(original_header):
            restored_body[:len(original_header)] = original_header

        os.makedirs(os.path.dirname(target_out), exist_ok=True)
        with open(target_out, "wb") as out_f:
            out_f.write(restored_body)

        os.remove(vault_path)
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                conn.execute("DELETE FROM quarantine_items WHERE id = ?", (qid,))
                conn.commit()
            finally:
                conn.close()

        self._bus.emit("MOD7_SELF_DEFENSE", "FILE_RESTORED_FROM_VAULT", severity="WARNING", id=qid, restored_path=target_out)
        return target_out

    def list_quarantine(self) -> List[Dict[str, object]]:
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                rows = conn.execute(
                    "SELECT id, original_path, vault_path, sha256, size_bytes, threat_name, risk_score, pe_corrupted, quarantined_at FROM quarantine_items ORDER BY quarantined_at DESC"
                ).fetchall()
            finally:
                conn.close()

        return [
            {
                "id": r[0],
                "original_path": r[1],
                "vault_path": r[2],
                "sha256": r[3],
                "size_bytes": r[4],
                "threat_name": r[5],
                "risk_score": r[6],
                "pe_corrupted": bool(r[7]),
                "quarantined_at": r[8],
            }
            for r in rows
        ]
