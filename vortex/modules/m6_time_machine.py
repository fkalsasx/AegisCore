#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MODÜL 6 :: "Atomik Zaman Makinesi" – Gölge Günlük ve Geri Sarma (Shadow Journal & Rollback)
Risk skoru >= 30 olan süreçler için Copy-on-Write yedekleme (AEGIS_ShadowStore) ve
SQLite işlem günlüğü tutar. Süreç >= 80 ile infaz edildiğinde LIFO (Son Giren İlk Çıkar)
sırayla dosyaları ve Kayıt Defteri değerlerini baytı baytına geri sarar.
"""

from __future__ import annotations
import hashlib
import json
import os
import sqlite3
import threading
import uuid
import winreg
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from core.event_bus import EventBus
from core.win32_native import bcrypt_aes256_gcm_decrypt, bcrypt_aes256_gcm_encrypt, set_file_hidden_system


class AtomicTimeMachine:
    """Copy-on-Write Gölge Günlük ve LIFO Atomik Geri Sarma Motoru."""

    MAX_SHADOW_FILE_BYTES = 100 * 1024 * 1024

    def __init__(self, event_bus: EventBus, shadow_store_dir: str, master_secret: Optional[str] = None) -> None:
        self._bus = event_bus
        self._shadow_dir = os.path.abspath(shadow_store_dir)
        self._db_path = os.path.join(self._shadow_dir, "shadow_journal.db")
        self._lock = threading.RLock()
        self._monitored_pids: Set[int] = set()

        os.makedirs(self._shadow_dir, exist_ok=True)
        self._aes_key = (
            hashlib.sha256(master_secret.encode("utf-8")).digest()
            if master_secret
            else self._load_or_create_shadow_key()
        )
        self._init_db()

    def _load_or_create_shadow_key(self) -> bytes:
        key_path = os.path.join(self._shadow_dir, ".shadow_master.key")
        if os.path.isfile(key_path) and not os.path.islink(key_path):
            try:
                with open(key_path, "rb") as kf:
                    raw = kf.read(32)
                if len(raw) == 32:
                    return raw
            except OSError:
                pass
        key = os.urandom(32)
        try:
            with open(key_path, "wb") as kf:
                kf.write(key)
            set_file_hidden_system(key_path, True)
        except OSError:
            pass
        return key

    def _is_inside_shadow_dir(self, path_str: str) -> bool:
        try:
            base = os.path.normcase(os.path.abspath(self._shadow_dir))
            cand = os.path.normcase(os.path.abspath(path_str))
            return cand.startswith(base + os.sep)
        except Exception:
            return False

    @staticmethod
    def _is_protected_os_path(path_str: str) -> bool:
        try:
            norm = os.path.normcase(os.path.realpath(path_str))
            sys_root = os.path.normcase(os.path.abspath(os.environ.get("SystemRoot", r"C:\Windows")))
            return norm == sys_root or norm.startswith(sys_root + os.sep)
        except Exception:
            return True

    def _init_db(self) -> None:
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS shadow_journal (
                        seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        pid INTEGER NOT NULL,
                        op_type TEXT NOT NULL,
                        original_path TEXT NOT NULL,
                        backup_path TEXT,
                        reg_meta_json TEXT,
                        rolled_back INTEGER DEFAULT 0
                    )
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def enable_journaling(self, pid: int) -> None:
        with self._lock:
            is_new = pid not in self._monitored_pids
            self._monitored_pids.add(pid)
        if is_new:
            self._bus.emit("MOD6_TIME_MACHINE", "SHADOW_JOURNAL_ENABLED", severity="MEDIUM", pid=pid)

    def is_journaling_enabled(self, pid: int) -> bool:
        with self._lock:
            return pid in self._monitored_pids

    def record_file_operation(self, pid: int, op_type: str, original_path: str) -> Optional[int]:
        """
        İşlem Türleri: CREATE, MODIFY, DELETE
        MODIFY veya DELETE öncesinde orijinal dosya AEGIS_ShadowStore'a AES-256-GCM şifreli yedeklenir.
        """
        op = op_type.upper()
        abs_path = os.path.abspath(original_path)
        backup_path: Optional[str] = None

        if op in {"MODIFY", "DELETE"} and os.path.isfile(abs_path) and not os.path.islink(abs_path):
            if os.path.getsize(abs_path) <= self.MAX_SHADOW_FILE_BYTES:
                with open(abs_path, "rb") as f:
                    orig_bytes = f.read()
                encrypted = bcrypt_aes256_gcm_encrypt(self._aes_key, orig_bytes)
                backup_path = os.path.join(self._shadow_dir, f"{pid}_{uuid.uuid4().hex}.shadow")
                with open(backup_path, "wb") as bf:
                    bf.write(encrypted)

        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                cur = conn.execute(
                    """
                    INSERT INTO shadow_journal (timestamp, pid, op_type, original_path, backup_path, reg_meta_json)
                    VALUES (?, ?, ?, ?, ?, NULL)
                    """,
                    (now_iso, pid, op, abs_path, backup_path),
                )
                conn.commit()
                seq_id = int(cur.lastrowid)
            finally:
                conn.close()

        self._bus.emit(
            "MOD6_TIME_MACHINE",
            "SHADOW_ENTRY_RECORDED",
            severity="INFO",
            pid=pid,
            seq_id=seq_id,
            op_type=op,
            original_path=abs_path,
            backup_path=backup_path,
        )
        return seq_id

    def record_registry_operation(
        self,
        pid: int,
        hive: int,
        subkey: str,
        value_name: str,
        old_value: Optional[str],
        old_type: int = winreg.REG_SZ,
    ) -> int:
        """Kayıt Defteri değişikliğini geri sarma amacıyla günlüğe kaydeder."""
        now_iso = datetime.now(timezone.utc).isoformat()
        meta = json.dumps({
            "hive": hive,
            "subkey": subkey,
            "value_name": value_name,
            "old_value": old_value,
            "old_type": old_type,
        }, ensure_ascii=False)

        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                cur = conn.execute(
                    """
                    INSERT INTO shadow_journal (timestamp, pid, op_type, original_path, backup_path, reg_meta_json)
                    VALUES (?, ?, 'REGISTRY', ?, NULL, ?)
                    """,
                    (now_iso, pid, f"{subkey}\\{value_name}", meta),
                )
                conn.commit()
                return int(cur.lastrowid)
            finally:
                conn.close()

    def rollback(self, pid: int) -> Dict[str, object]:
        """
        LIFO (Son Giren İlk Çıkar) sırasıyla ilgili PID'nin tüm değişikliklerini geri sarar:
        1. CREATE edilen yeni dosyaları siler.
        2. MODIFY/DELETE edilen dosyaları AEGIS_ShadowStore'dan baytı baytına geri yükler.
        3. REGISTRY anahtarlarını eski haline döndürür.
        """
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                rows = conn.execute(
                    """
                    SELECT seq_id, op_type, original_path, backup_path, reg_meta_json
                    FROM shadow_journal
                    WHERE pid = ? AND rolled_back = 0
                    ORDER BY seq_id DESC
                    """,
                    (pid,),
                ).fetchall()
            finally:
                conn.close()

        files_deleted: List[str] = []
        files_restored: List[str] = []
        registry_reverted: List[str] = []
        errors: List[str] = []

        for seq_id, op_type, orig_path, backup_path, reg_meta_json in rows:
            try:
                if op_type == "CREATE":
                    if (
                        os.path.isfile(orig_path)
                        and not os.path.islink(orig_path)
                        and not self._is_protected_os_path(orig_path)
                    ):
                        os.remove(orig_path)
                        files_deleted.append(orig_path)

                elif op_type in {"MODIFY", "DELETE"}:
                    if (
                        backup_path
                        and self._is_inside_shadow_dir(backup_path)
                        and os.path.isfile(backup_path)
                        and not os.path.islink(backup_path)
                        and not os.path.islink(orig_path)
                        and not self._is_protected_os_path(orig_path)
                    ):
                        with open(backup_path, "rb") as bf:
                            blob = bf.read(self.MAX_SHADOW_FILE_BYTES + 1024)
                        restored_bytes = bcrypt_aes256_gcm_decrypt(self._aes_key, blob)
                        os.makedirs(os.path.dirname(orig_path), exist_ok=True)
                        with open(orig_path, "wb") as out_f:
                            out_f.write(restored_bytes)
                        files_restored.append(orig_path)
                        try:
                            os.remove(backup_path)
                        except OSError:
                            pass

                elif op_type == "REGISTRY" and reg_meta_json:
                    meta = json.loads(reg_meta_json)
                    hive = int(meta["hive"])
                    subkey = str(meta["subkey"])
                    val_name = str(meta["value_name"])
                    old_val = meta["old_value"]
                    old_type = int(meta.get("old_type", winreg.REG_SZ))

                    with winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                        if old_val is None:
                            try:
                                winreg.DeleteValue(key, val_name)
                            except FileNotFoundError:
                                pass
                        else:
                            winreg.SetValueEx(key, val_name, 0, old_type, old_val)
                    registry_reverted.append(f"{subkey}\\{val_name}")

                with self._lock:
                    conn = sqlite3.connect(self._db_path)
                    try:
                        conn.execute("UPDATE shadow_journal SET rolled_back = 1 WHERE seq_id = ?", (seq_id,))
                        conn.commit()
                    finally:
                        conn.close()
            except Exception as exc:
                errors.append(f"seq={seq_id}: {exc}")

        summary = {
            "pid": pid,
            "entries_processed": len(rows),
            "files_deleted": files_deleted,
            "files_restored": files_restored,
            "registry_reverted": registry_reverted,
            "errors": errors,
        }
        self._bus.emit("MOD6_TIME_MACHINE", "ATOMIC_ROLLBACK_COMPLETED", severity="HIGH", **summary)
        return summary
