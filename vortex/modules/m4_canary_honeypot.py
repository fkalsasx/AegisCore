#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MODÜL 4 :: "Yem Tuzakları" – Fidye Yazılımı Kapanı (Canary Honeypot Grid)
Kritik dizinlere gizli sistem niteliğinde !_00_* ve ~_zz_* yem tuzak dosyaları dağıtır;
ReadDirectoryChangesW ile sıfır-toleranslı izler ve 1 baytlık değişimde dahi
ilgili süreci NtSuspendProcess ile anında dondurur.
"""

from __future__ import annotations
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import os
import threading
import time
from typing import Callable, Dict, List, Optional

from core.event_bus import EventBus
from core.win32_native import (
    FILE_FLAG_BACKUP_SEMANTICS,
    FILE_LIST_DIRECTORY,
    FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE,
    FILE_NOTIFY_CHANGE_SIZE,
    FILE_SHARE_DELETE,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    INVALID_HANDLE_VALUE,
    OPEN_EXISTING,
    kernel32,
    set_file_hidden_system,
    suspend_process,
    terminate_process,
)


class FILE_NOTIFY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset", wintypes.DWORD),
        ("Action", wintypes.DWORD),
        ("FileNameLength", wintypes.DWORD),
        ("FileName", wintypes.WCHAR * 1),
    ]


class CanaryHoneypotGrid:
    """Fidye yazılımlarını ilk baytta yakalayan gizli Canary tuzak ağı."""

    CANARY_FILENAMES = (
        "!_00_aegis_vault.docx",
        "!_00_aegis_ledger.xlsx",
        "~_zz_aegis_backup.pdf",
    )

    def __init__(
        self,
        event_bus: EventBus,
        protected_dirs: Optional[List[str]] = None,
        secret_key: Optional[bytes] = None,
        suspect_pid_resolver: Optional[Callable[[str], Optional[int]]] = None,
    ) -> None:
        self._bus = event_bus
        self._secret = secret_key if secret_key is not None else os.urandom(32)
        self._suspect_resolver = suspect_pid_resolver
        self._protected_dirs = protected_dirs or self._default_user_dirs()
        self._canaries: Dict[str, str] = {}  # file_path -> expected_sha256
        self._running = False
        self._threads: List[threading.Thread] = []
        self._dir_handles: List[int] = []
        self._lock = threading.RLock()
        self._tripped_paths: set[str] = set()

    @staticmethod
    def _default_user_dirs() -> List[str]:
        home = os.path.expanduser("~")
        candidates = [
            os.path.join(home, "Desktop"),
            os.path.join(home, "Documents"),
            os.path.join(home, "Pictures"),
        ]
        return [d for d in candidates if os.path.isdir(d)]

    def _generate_canary_payload(self, file_path: str) -> bytes:
        token = hmac.new(self._secret, file_path.encode("utf-8"), hashlib.sha256).hexdigest()
        name_low = file_path.lower()
        if name_low.endswith(".pdf"):
            header = b"%PDF-1.7\n% AegisCore Protected Ledger\n"
        elif name_low.endswith(".docx") or name_low.endswith(".xlsx"):
            header = b"PK\x03\x04AEGIS_PROTECTED_CANARY_ARCHIVE\n"
        else:
            header = b"AEGIS_CANARY_HEADER\n"
        body = (
            f"CONFIDENTIAL FINANCIAL ARCHIVE RECORD\n"
            f"Canary-Token: {token}\n"
            f"Integrity-Anchor: AEGIS-VORTEX-ZERO-TRUST\n"
        ).encode("utf-8")
        return header + body

    def deploy_canaries(self) -> List[str]:
        """Hedef dizinlere alfabetik en üst ve en alt tuzak dosyalarını yerleştirir."""
        deployed: List[str] = []
        for directory in self._protected_dirs:
            os.makedirs(directory, exist_ok=True)
            for fname in self.CANARY_FILENAMES:
                fpath = os.path.abspath(os.path.join(directory, fname))
                if os.path.islink(fpath):
                    continue
                payload = self._generate_canary_payload(fpath)
                expected_hash = hashlib.sha256(payload).hexdigest()

                if os.path.exists(fpath):
                    set_file_hidden_system(fpath, False)
                with open(fpath, "wb") as f:
                    f.write(payload)
                set_file_hidden_system(fpath, True)

                with self._lock:
                    self._canaries[fpath.lower()] = expected_hash
                    self._tripped_paths.discard(fpath.lower())
                deployed.append(fpath)

        self._bus.emit(
            "MOD4_CANARY_HONEYPOT",
            "CANARY_GRID_DEPLOYED",
            severity="INFO",
            deployed_count=len(deployed),
            directories=self._protected_dirs,
        )
        return deployed

    def cleanup_canaries(self) -> None:
        with self._lock:
            paths = list(self._canaries.keys())
            self._canaries.clear()
        for p in paths:
            try:
                if os.path.exists(p) and not os.path.islink(p):
                    set_file_hidden_system(p, False)
                    os.remove(p)
            except OSError:
                pass

    def _on_canary_compromised(self, file_path: str, action: str, culprit_pid: Optional[int] = None) -> None:
        key = os.path.abspath(file_path).lower()
        with self._lock:
            if key in self._tripped_paths:
                return
            self._tripped_paths.add(key)

        pid = culprit_pid
        if pid is None and self._suspect_resolver:
            pid = self._suspect_resolver(file_path)

        frozen = False
        terminated = False
        if pid and pid > 4 and pid != os.getpid():
            frozen = suspend_process(pid)
            terminated = terminate_process(pid)

        self._bus.emit(
            "MOD4_CANARY_HONEYPOT",
            "CANARY_TRIPWIRE_TRIGGERED",
            severity="CRITICAL",
            pid=pid,
            canary_path=file_path,
            action=action,
            process_frozen=frozen,
            process_terminated=terminated,
            score_delta=100,
        )

    def verify_integrity_once(self, suspect_pid: Optional[int] = None) -> List[str]:
        """Tüm yem dosyalarının bütünlüğünü 1 bayt hassasiyetle doğrular."""
        compromised: List[str] = []
        with self._lock:
            items = list(self._canaries.items())

        for fpath_low, expected_hash in items:
            if not os.path.exists(fpath_low):
                compromised.append(fpath_low)
                self._on_canary_compromised(fpath_low, "DELETED_OR_RENAMED", suspect_pid)
                continue
            try:
                if os.path.islink(fpath_low):
                    compromised.append(fpath_low)
                    self._on_canary_compromised(fpath_low, "SYMLINK_TAMPERED", suspect_pid)
                    continue
                with open(fpath_low, "rb") as f:
                    curr_hash = hashlib.sha256(f.read(65536)).hexdigest()
                if curr_hash != expected_hash:
                    compromised.append(fpath_low)
                    self._on_canary_compromised(fpath_low, "MODIFIED_BYTES", suspect_pid)
            except OSError:
                compromised.append(fpath_low)
                self._on_canary_compromised(fpath_low, "LOCKED_OR_TAMPERED", suspect_pid)

        return compromised

    def _watch_directory_win32(self, directory: str) -> None:
        h_dir = kernel32.CreateFileW(
            directory,
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if h_dir == INVALID_HANDLE_VALUE or not h_dir:
            return

        with self._lock:
            self._dir_handles.append(h_dir)

        buf = ctypes.create_string_buffer(32768)
        bytes_returned = wintypes.DWORD(0)
        notify_filter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE

        try:
            while self._running:
                ok = kernel32.ReadDirectoryChangesW(
                    h_dir,
                    buf,
                    len(buf),
                    False,
                    notify_filter,
                    ctypes.byref(bytes_returned),
                    None,
                    None,
                )
                if not ok or bytes_returned.value == 0:
                    break

                offset = 0
                raw_bytes = buf.raw[:bytes_returned.value]
                while offset + 12 <= len(raw_bytes):
                    next_off = ctypes.c_uint32.from_buffer_copy(raw_bytes, offset).value
                    action = ctypes.c_uint32.from_buffer_copy(raw_bytes, offset + 4).value
                    name_len = ctypes.c_uint32.from_buffer_copy(raw_bytes, offset + 8).value
                    if offset + 12 + name_len > len(raw_bytes):
                        break
                    fname_bytes = raw_bytes[offset + 12: offset + 12 + name_len]
                    fname = fname_bytes.decode("utf-16-le", errors="ignore")
                    full_path = os.path.abspath(os.path.join(directory, fname)).lower()

                    if full_path in self._canaries:
                        action_label = {1: "CREATED", 2: "DELETED", 3: "MODIFIED", 4: "RENAMED_OLD", 5: "RENAMED_NEW"}.get(action, "CHANGED")
                        self._on_canary_compromised(full_path, action_label)

                    if next_off == 0:
                        break
                    offset += next_off
        except Exception:
            pass
        finally:
            kernel32.CloseHandle(h_dir)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        for d in self._protected_dirs:
            if os.path.isdir(d):
                t = threading.Thread(target=self._watch_directory_win32, args=(d,), name=f"CanaryWatch-{os.path.basename(d)}", daemon=True)
                t.start()
                self._threads.append(t)

    def stop(self) -> None:
        self._running = False
        with self._lock:
            handles = list(self._dir_handles)
            self._dir_handles.clear()
        for h in handles:
            try:
                kernel32.CancelIoEx(h, None)
            except Exception:
                pass
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads.clear()
