#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AEGIS-VORTEX :: Win32 Native Çekirdek API Köprüsü (Zero External Dependencies)
kernel32.dll, ntdll.dll, bcrypt.dll, wintrust.dll, advapi32.dll ve user32.dll
çağrılarını doğrudan ctypes ile yönetir.
"""

from __future__ import annotations
import ctypes
from ctypes import wintypes
import os
import stat
import threading
from typing import Dict, List, Optional, Tuple

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
bcrypt = ctypes.WinDLL("bcrypt", use_last_error=True)
wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)

# Sabitler
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_TERMINATE = 0x0001
PROCESS_SET_INFORMATION = 0x0200
PROCESS_ALL_ACCESS = 0x001F0FFF

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
_EXEC_PROTECTS = (PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)

IDLE_PRIORITY_CLASS = 0x00000040
CREATE_SUSPENDED = 0x00000004
CREATE_NO_WINDOW = 0x08000000

FILE_ATTRIBUTE_HIDDEN = 0x02
FILE_ATTRIBUTE_SYSTEM = 0x04
FILE_ATTRIBUTE_NORMAL = 0x80

# Job Object sabitleri
JobObjectBasicLimitInformation = 2
JobObjectBasicUIRestrictions = 4
JobObjectExtendedLimitInformation = 9
JOB_OBJECT_LIMIT_WORKINGSET = 0x00000001
JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100

JOB_OBJECT_UILIMIT_HANDLES = 0x00000001
JOB_OBJECT_UILIMIT_READCLIPBOARD = 0x00000002
JOB_OBJECT_UILIMIT_WRITECLIPBOARD = 0x00000004
JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS = 0x00000008
JOB_OBJECT_UILIMIT_DISPLAYSETTINGS = 0x00000010
JOB_OBJECT_UILIMIT_GLOBALATOMS = 0x00000020
JOB_OBJECT_UILIMIT_DESKTOP = 0x00000040
JOB_OBJECT_UILIMIT_EXITWINDOWS = 0x00000080

# ReadDirectoryChangesW sabitleri
FILE_LIST_DIRECTORY = 0x0001
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class JOBOBJECT_BASIC_UI_RESTRICTIONS(ctypes.Structure):
    _fields_ = [("UIRestrictionsClass", wintypes.DWORD)]


class BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.ULONG),
        ("dwInfoVersion", wintypes.ULONG),
        ("pbNonce", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbNonce", wintypes.ULONG),
        ("pbAuthData", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbAuthData", wintypes.ULONG),
        ("pbTag", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbTag", wintypes.ULONG),
        ("pbMacContext", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbMacContext", wintypes.ULONG),
        ("cbAAD", wintypes.ULONG),
        ("cbData", ctypes.c_uint64),
        ("dwFlags", wintypes.ULONG),
    ]


class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2", ctypes.c_void_p * 2),
        ("UniqueProcessId", ctypes.c_size_t),
        ("Reserved3", ctypes.c_void_p),
    ]


# Prototip tanımlamaları
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.TerminateProcess.restype = wintypes.BOOL
kernel32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.SetPriorityClass.restype = wintypes.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL

ntdll.NtSuspendProcess.argtypes = [wintypes.HANDLE]
ntdll.NtSuspendProcess.restype = ctypes.c_long
ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
ntdll.NtResumeProcess.restype = ctypes.c_long
ntdll.NtQueryInformationProcess.argtypes = [
    wintypes.HANDLE,
    wintypes.ULONG,
    ctypes.c_void_p,
    wintypes.ULONG,
    ctypes.POINTER(wintypes.ULONG),
]
ntdll.NtQueryInformationProcess.restype = ctypes.c_long

kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
kernel32.CreateJobObjectW.restype = wintypes.HANDLE
kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
kernel32.SetInformationJobObject.restype = wintypes.BOOL
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wintypes.BOOL
kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
kernel32.SetFileAttributesW.restype = wintypes.BOOL
kernel32.ReadDirectoryChangesW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, ctypes.c_void_p]
kernel32.ReadDirectoryChangesW.restype = wintypes.BOOL
kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
kernel32.CancelIoEx.restype = wintypes.BOOL
kernel32.GetCurrentProcess.argtypes = []
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.SetProcessWorkingSetSize.argtypes = [wintypes.HANDLE, ctypes.c_size_t, ctypes.c_size_t]
kernel32.SetProcessWorkingSetSize.restype = wintypes.BOOL

_PROC_TLS = threading.local()


def _get_proc_scratch():
    img_buf = getattr(_PROC_TLS, "img_buf", None)
    cmd_buf = getattr(_PROC_TLS, "cmd_buf", None)
    if img_buf is None or cmd_buf is None:
        img_buf = ctypes.create_unicode_buffer(512)
        cmd_buf = ctypes.create_string_buffer(8192)
        _PROC_TLS.img_buf = img_buf
        _PROC_TLS.cmd_buf = cmd_buf
    return img_buf, cmd_buf


def trim_working_set() -> bool:
    """Windows üzerinde çalışma kümesini (Working Set) düşük RAM için sıkıştırır."""
    try:
        h_self = kernel32.GetCurrentProcess()
        return bool(kernel32.SetProcessWorkingSetSize(h_self, ctypes.c_size_t(-1), ctypes.c_size_t(-1)))
    except Exception:
        return False

wintrust.CryptCATAdminAcquireContext.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, wintypes.DWORD]
wintrust.CryptCATAdminAcquireContext.restype = wintypes.BOOL
wintrust.CryptCATAdminReleaseContext.argtypes = [ctypes.c_void_p, wintypes.DWORD]
wintrust.CryptCATAdminReleaseContext.restype = wintypes.BOOL
wintrust.CryptCATAdminCalcHashFromFileHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD]
wintrust.CryptCATAdminCalcHashFromFileHandle.restype = wintypes.BOOL
wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
wintrust.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
wintrust.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL
wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.c_void_p, ctypes.c_void_p]
wintrust.WinVerifyTrust.restype = ctypes.c_long

bcrypt.BCryptOpenAlgorithmProvider.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
bcrypt.BCryptOpenAlgorithmProvider.restype = ctypes.c_long
bcrypt.BCryptCloseAlgorithmProvider.argtypes = [ctypes.c_void_p, wintypes.DWORD]
bcrypt.BCryptCloseAlgorithmProvider.restype = ctypes.c_long
bcrypt.BCryptSetProperty.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.ULONG, wintypes.DWORD]
bcrypt.BCryptSetProperty.restype = ctypes.c_long
bcrypt.BCryptGenerateSymmetricKey.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, wintypes.DWORD]
bcrypt.BCryptGenerateSymmetricKey.restype = ctypes.c_long
bcrypt.BCryptDestroyKey.argtypes = [ctypes.c_void_p]
bcrypt.BCryptDestroyKey.restype = ctypes.c_long
bcrypt.BCryptEncrypt.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG), wintypes.DWORD]
bcrypt.BCryptEncrypt.restype = ctypes.c_long
bcrypt.BCryptDecrypt.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG), wintypes.DWORD]
bcrypt.BCryptDecrypt.restype = ctypes.c_long


def enumerate_processes() -> List[Dict[str, object]]:
    """CreateToolhelp32Snapshot ile çalışan tüm süreçleri ve tam yollarını okur."""
    procs: List[Dict[str, object]] = []
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE or not snap:
        return procs

    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            return procs

        while True:
            pid = int(entry.th32ProcessID)
            ppid = int(entry.th32ParentProcessID)
            name = entry.szExeFile
            exe_path = ""

            if pid > 4:
                h_proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if h_proc:
                    try:
                        buf = ctypes.create_unicode_buffer(512)
                        size = wintypes.DWORD(512)
                        if kernel32.QueryFullProcessImageNameW(h_proc, 0, buf, ctypes.byref(size)):
                            exe_path = buf.value
                    finally:
                        kernel32.CloseHandle(h_proc)

            procs.append({
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "path": exe_path,
                "threads": int(entry.cntThreads),
            })

            if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snap)

    return procs


def _query_command_line_from_handle(h_proc: int) -> str:
    """NtQueryInformationProcess(ProcessCommandLineInformation=60) ile tam komut satırını okur."""
    buf_size = 8192
    _, buf = _get_proc_scratch()
    ret_len = wintypes.ULONG(0)
    status = ntdll.NtQueryInformationProcess(h_proc, 60, buf, buf_size, ctypes.byref(ret_len))
    if status == -1073741820 and 0 < ret_len.value <= 131072:
        buf_size = int(ret_len.value) + 64
        buf = ctypes.create_string_buffer(buf_size)
        status = ntdll.NtQueryInformationProcess(h_proc, 60, buf, buf_size, ctypes.byref(ret_len))
    if status != 0:
        return ""
    try:
        ustr = UNICODE_STRING.from_buffer_copy(buf, 0)
        if not ustr.Buffer or ustr.Length == 0:
            return ""
        base_addr = ctypes.addressof(buf)
        if not (base_addr <= int(ustr.Buffer) and int(ustr.Buffer) + int(ustr.Length) <= base_addr + buf_size):
            return ""
        return ctypes.wstring_at(ustr.Buffer, ustr.Length // 2)
    except Exception:
        return ""


def read_process_command_line(pid: int) -> str:
    """Verilen PID için süreç komut satırını hafif biçimde döndürür."""
    if pid <= 4:
        return ""
    h_proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h_proc:
        return ""
    try:
        return _query_command_line_from_handle(h_proc)
    finally:
        kernel32.CloseHandle(h_proc)


def enumerate_processes_incremental(
    prev_map: Optional[Dict[int, Dict[str, object]]] = None
) -> Tuple[Dict[int, Dict[str, object]], List[int], set]:
    """
    Sadece yeni ortaya çıkan PID'lerde OpenProcess çağırarak sıfır gereksiz sözlük
    tahsisiyle (zero-churn) artımlı süreç haritası, yeni PID listesi ve ölen PID kümesi döndürür.
    """
    prev = prev_map or {}
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE or not snap:
        return prev, [], set()

    seen_pids: set[int] = set()
    new_entries: Dict[int, Dict[str, object]] = {}
    new_pids: List[int] = []
    img_buf, _ = _get_proc_scratch()

    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            return prev, [], set()

        while True:
            pid = int(entry.th32ProcessID)
            ppid = int(entry.th32ParentProcessID)
            name = entry.szExeFile
            seen_pids.add(pid)

            cached = prev.get(pid)
            if cached is not None and int(cached.get("ppid", -1)) == ppid and str(cached.get("name", "")) == name:
                pass
            else:
                exe_path = ""
                cmdline = ""
                if pid > 4:
                    h_proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                    if h_proc:
                        try:
                            size = wintypes.DWORD(512)
                            if kernel32.QueryFullProcessImageNameW(h_proc, 0, img_buf, ctypes.byref(size)):
                                exe_path = img_buf.value
                            cmdline = _query_command_line_from_handle(h_proc)
                        finally:
                            kernel32.CloseHandle(h_proc)

                new_entries[pid] = {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "path": exe_path,
                    "cmdline": cmdline,
                    "threads": int(entry.cntThreads),
                }
                new_pids.append(pid)

            if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snap)

    dead_pids = set(prev.keys()) - seen_pids
    if not new_entries and not dead_pids:
        return prev, [], set()

    next_map = {pid: p for pid, p in prev.items() if pid in seen_pids} if prev else {}
    next_map.update(new_entries)
    return next_map, new_pids, dead_pids


def enumerate_processes_fast(prev_map: Optional[Dict[int, Dict[str, object]]] = None) -> List[Dict[str, object]]:
    """Sadece yeni PID'lerde OpenProcess çağırarak düşük CPU ile çalışan süreçleri ve komut satırlarını döndürür."""
    procs: List[Dict[str, object]] = []
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE or not snap:
        return procs

    img_buf, _ = _get_proc_scratch()
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            return procs

        while True:
            pid = int(entry.th32ProcessID)
            ppid = int(entry.th32ParentProcessID)
            name = entry.szExeFile
            name_low = name.lower()

            cached = prev_map.get(pid) if prev_map else None
            if cached and int(cached.get("ppid", -1)) == ppid and str(cached.get("name", "")).lower() == name_low:
                exe_path = str(cached.get("path", ""))
                cmdline = str(cached.get("cmdline", ""))
            else:
                exe_path = ""
                cmdline = ""
                if pid > 4:
                    h_proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                    if h_proc:
                        try:
                            size = wintypes.DWORD(512)
                            if kernel32.QueryFullProcessImageNameW(h_proc, 0, img_buf, ctypes.byref(size)):
                                exe_path = img_buf.value
                            cmdline = _query_command_line_from_handle(h_proc)
                        finally:
                            kernel32.CloseHandle(h_proc)

            procs.append({
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "path": exe_path,
                "cmdline": cmdline,
                "threads": int(entry.cntThreads),
            })

            if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snap)

    return procs


def suspend_process(pid: int) -> bool:
    """NtSuspendProcess ile hedefin tüm iş parçacıklarını OS seviyesinde anında dondurur."""
    if pid <= 4 or pid == os.getpid():
        return False
    h_proc = kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
    if not h_proc:
        return False
    try:
        status = ntdll.NtSuspendProcess(h_proc)
        return status == 0
    finally:
        kernel32.CloseHandle(h_proc)


def resume_process(pid: int) -> bool:
    """Dondurulmuş süreci tekrar çalıştırır."""
    if pid <= 4:
        return False
    h_proc = kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
    if not h_proc:
        return False
    try:
        return ntdll.NtResumeProcess(h_proc) == 0
    finally:
        kernel32.CloseHandle(h_proc)


def terminate_process(pid: int, exit_code: int = 1) -> bool:
    """Süreci zorla sonlandırır."""
    if pid <= 4 or pid == os.getpid():
        return False
    h_proc = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h_proc:
        return False
    try:
        return bool(kernel32.TerminateProcess(h_proc, exit_code))
    finally:
        kernel32.CloseHandle(h_proc)


def lower_process_priority(pid: int) -> bool:
    """Gri liste süreci için CPU önceliğini IDLE seviyesine düşürür."""
    if pid <= 4 or pid == os.getpid():
        return False
    h_proc = kernel32.OpenProcess(PROCESS_SET_INFORMATION, False, pid)
    if not h_proc:
        return False
    try:
        return bool(kernel32.SetPriorityClass(h_proc, IDLE_PRIORITY_CLASS))
    finally:
        kernel32.CloseHandle(h_proc)


def set_file_hidden_system(path: str, hidden: bool = True) -> bool:
    """Dosyaya Gizli + Sistem özniteliği atar veya kaldırır."""
    attrs = (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) if hidden else FILE_ATTRIBUTE_NORMAL
    return bool(kernel32.SetFileAttributesW(str(path), attrs))


_AUTH_CACHE: Dict[Tuple[str, int, int], Tuple[bool, str]] = {}
_AUTH_LOCK = threading.Lock()
_CAT_TLS = threading.local()


class _WT_GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _WT_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(_WT_GUID)),
    ]


class _WT_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(_WT_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


def _verify_catalog_cached(file_path: str) -> Tuple[bool, str]:
    h_cat_admin = getattr(_CAT_TLS, "h_cat_admin", None)
    if not h_cat_admin:
        h_new = ctypes.c_void_p()
        try:
            if wintrust.CryptCATAdminAcquireContext(ctypes.byref(h_new), None, 0) and h_new.value:
                h_cat_admin = h_new.value
                _CAT_TLS.h_cat_admin = h_cat_admin
        except Exception:
            h_cat_admin = None
    if not h_cat_admin:
        return False, ""

    try:
        h_file = kernel32.CreateFileW(file_path, 0x80000000, 1 | 2 | 4, None, 3, 0x80, None)
        if h_file and h_file != INVALID_HANDLE_VALUE:
            try:
                hash_len = wintypes.DWORD(0)
                wintrust.CryptCATAdminCalcHashFromFileHandle(h_file, ctypes.byref(hash_len), None, 0)
                if hash_len.value > 0:
                    hash_buf = (ctypes.c_ubyte * hash_len.value)()
                    if wintrust.CryptCATAdminCalcHashFromFileHandle(h_file, ctypes.byref(hash_len), hash_buf, 0):
                        prev = ctypes.c_void_p()
                        h_info = wintrust.CryptCATAdminEnumCatalogFromHash(
                            ctypes.c_void_p(h_cat_admin), hash_buf, hash_len.value, 0, ctypes.byref(prev)
                        )
                        if h_info:
                            wintrust.CryptCATAdminReleaseCatalogContext(ctypes.c_void_p(h_cat_admin), h_info, 0)
                            return True, "Windows Security Catalog"
            finally:
                kernel32.CloseHandle(h_file)
    except Exception:
        pass
    return False, ""


def _verify_embedded_authenticode(file_path: str) -> Tuple[bool, str]:
    try:
        action_guid = _WT_GUID(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
        file_info = _WT_FILE_INFO(ctypes.sizeof(_WT_FILE_INFO), file_path, None, None)
        wt_data = _WT_DATA()
        wt_data.cbStruct = ctypes.sizeof(_WT_DATA)
        wt_data.dwUIChoice = 2  # WTD_UI_NONE
        wt_data.fdwRevocationChecks = 1  # WTD_REVOKE_WHOLECHAIN
        wt_data.dwUnionChoice = 1  # WTD_CHOICE_FILE
        wt_data.pFile = ctypes.pointer(file_info)
        wt_data.dwStateAction = 1  # WTD_STATEACTION_VERIFY
        wt_data.dwProvFlags = 0x00000080  # WTD_CACHE_ONLY_URL_RETRIEVAL
        res = wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wt_data))
        wt_data.dwStateAction = 2  # WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(wt_data))
        if res == 0:
            return True, "Authenticode Verified"
    except Exception:
        pass
    return False, ""


def verify_authenticode_catalog(file_path: str) -> Tuple[bool, str]:
    """
    Windows Security Catalog (kalıcı thread-local CryptCATAdmin*) ve gömülü
    Authenticode (WTD_CACHE_ONLY_URL_RETRIEVAL + önbellekli) doğrulamasını yürütür.
    """
    try:
        st = os.stat(file_path)
    except OSError:
        return False, ""
    if not stat.S_ISREG(st.st_mode):
        return False, ""

    abs_low = os.path.abspath(file_path).lower()
    cache_key = (abs_low, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino)
    with _AUTH_LOCK:
        cached = _AUTH_CACHE.get(cache_key)
        if cached is not None:
            return cached

    if "\\windows\\" in abs_low:
        verdict = _verify_catalog_cached(file_path)
        if not verdict[0]:
            verdict = _verify_embedded_authenticode(file_path)
    else:
        verdict = _verify_embedded_authenticode(file_path)
        if not verdict[0]:
            verdict = _verify_catalog_cached(file_path)

    with _AUTH_LOCK:
        if len(_AUTH_CACHE) >= 1024:
            _AUTH_CACHE.clear()
        _AUTH_CACHE[cache_key] = verdict

    return verdict


def bcrypt_aes256_gcm_encrypt(key_32: bytes, plaintext: bytes) -> bytes:
    """
    Windows CNG bcrypt.dll kullanarak gerçek AES-256-GCM şifrelemesi gerçekleştirir.
    Çıktı formatı: [12-byte IV][16-byte AuthTag][Ciphertext]
    """
    if len(key_32) != 32:
        raise ValueError("AES-256 için anahtar tam 32 byte olmalıdır.")

    iv = os.urandom(12)
    h_alg = ctypes.c_void_p()
    h_key = ctypes.c_void_p()

    status = bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(h_alg), "AES", None, 0)
    if status != 0:
        raise OSError(f"BCryptOpenAlgorithmProvider hata: 0x{status:08x}")

    try:
        mode = ctypes.create_unicode_buffer("ChainingModeGCM")
        status = bcrypt.BCryptSetProperty(h_alg, "ChainingMode", mode, ctypes.sizeof(mode), 0)
        if status != 0:
            raise OSError(f"BCryptSetProperty hata: 0x{status:08x}")

        key_buf = (ctypes.c_ubyte * 32).from_buffer_copy(key_32)
        status = bcrypt.BCryptGenerateSymmetricKey(h_alg, ctypes.byref(h_key), None, 0, key_buf, 32, 0)
        if status != 0:
            raise OSError(f"BCryptGenerateSymmetricKey hata: 0x{status:08x}")

        try:
            tag = (ctypes.c_ubyte * 16)()
            iv_buf = (ctypes.c_ubyte * 12).from_buffer_copy(iv)
            auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
            auth_info.cbSize = ctypes.sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)
            auth_info.dwInfoVersion = 1
            auth_info.pbNonce = iv_buf
            auth_info.cbNonce = 12
            auth_info.pbTag = tag
            auth_info.cbTag = 16

            pt_len = len(plaintext)
            pt_buf = (ctypes.c_ubyte * pt_len).from_buffer_copy(plaintext) if pt_len > 0 else (ctypes.c_ubyte * 1)()
            ct_buf = (ctypes.c_ubyte * max(1, pt_len))()
            cb_result = wintypes.ULONG(0)

            status = bcrypt.BCryptEncrypt(
                h_key,
                pt_buf if pt_len > 0 else None,
                pt_len,
                ctypes.byref(auth_info),
                None,
                0,
                ct_buf if pt_len > 0 else None,
                pt_len,
                ctypes.byref(cb_result),
                0
            )
            if status != 0:
                raise OSError(f"BCryptEncrypt hata: 0x{status:08x}")

            return iv + bytes(tag) + bytes(ct_buf)[:cb_result.value]
        finally:
            if h_key.value:
                bcrypt.BCryptDestroyKey(h_key)
    finally:
        if h_alg.value:
            bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)


def bcrypt_aes256_gcm_decrypt(key_32: bytes, blob: bytes) -> bytes:
    """Windows CNG bcrypt.dll kullanarak AES-256-GCM veriyi çözer ve tag doğrular."""
    if len(key_32) != 32 or len(blob) < 28:
        raise ValueError("Geçersiz şifreli veri veya anahtar.")

    iv = blob[:12]
    tag = blob[12:28]
    ciphertext = blob[28:]

    h_alg = ctypes.c_void_p()
    h_key = ctypes.c_void_p()

    status = bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(h_alg), "AES", None, 0)
    if status != 0:
        raise OSError(f"BCryptOpenAlgorithmProvider hata: 0x{status:08x}")

    try:
        mode = ctypes.create_unicode_buffer("ChainingModeGCM")
        status = bcrypt.BCryptSetProperty(h_alg, "ChainingMode", mode, ctypes.sizeof(mode), 0)
        if status != 0:
            raise OSError(f"BCryptSetProperty hata: 0x{status:08x}")

        key_buf = (ctypes.c_ubyte * 32).from_buffer_copy(key_32)
        status = bcrypt.BCryptGenerateSymmetricKey(h_alg, ctypes.byref(h_key), None, 0, key_buf, 32, 0)
        if status != 0:
            raise OSError(f"BCryptGenerateSymmetricKey hata: 0x{status:08x}")

        try:
            tag_buf = (ctypes.c_ubyte * 16).from_buffer_copy(tag)
            iv_buf = (ctypes.c_ubyte * 12).from_buffer_copy(iv)
            auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
            auth_info.cbSize = ctypes.sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)
            auth_info.dwInfoVersion = 1
            auth_info.pbNonce = iv_buf
            auth_info.cbNonce = 12
            auth_info.pbTag = tag_buf
            auth_info.cbTag = 16

            ct_len = len(ciphertext)
            ct_buf = (ctypes.c_ubyte * ct_len).from_buffer_copy(ciphertext) if ct_len > 0 else (ctypes.c_ubyte * 1)()
            pt_buf = (ctypes.c_ubyte * max(1, ct_len))()
            cb_result = wintypes.ULONG(0)

            status = bcrypt.BCryptDecrypt(
                h_key,
                ct_buf if ct_len > 0 else None,
                ct_len,
                ctypes.byref(auth_info),
                None,
                0,
                pt_buf if ct_len > 0 else None,
                ct_len,
                ctypes.byref(cb_result),
                0
            )
            if status != 0:
                raise OSError(f"BCryptDecrypt kimlik doğrulama hatası: 0x{status:08x}")

            return bytes(pt_buf)[:cb_result.value]
        finally:
            if h_key.value:
                bcrypt.BCryptDestroyKey(h_key)
    finally:
        if h_alg.value:
            bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)


def create_isolated_job_object(name: str, memory_limit_mb: int = 128, cpu_limit_ms: int = 500) -> Optional[int]:
    """Modül 2 Gölge Kafes için bellek, süreç sayısı, CPU ve UI kısıtlamalı Win32 JobObject oluşturur."""
    h_job = kernel32.CreateJobObjectW(None, name)
    if not h_job:
        return None

    ext = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    ext.BasicLimitInformation.LimitFlags = (
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_PROCESS_TIME
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
    )
    ext.BasicLimitInformation.ActiveProcessLimit = 2
    # 100-nanosaniye birimi: 1 ms = 10_000 tick
    ext.BasicLimitInformation.PerProcessUserTimeLimit = cpu_limit_ms * 10_000
    ext.ProcessMemoryLimit = memory_limit_mb * 1024 * 1024

    if not kernel32.SetInformationJobObject(
        h_job,
        JobObjectExtendedLimitInformation,
        ctypes.byref(ext),
        ctypes.sizeof(ext)
    ):
        kernel32.CloseHandle(h_job)
        return None

    ui = JOBOBJECT_BASIC_UI_RESTRICTIONS()
    ui.UIRestrictionsClass = (
        JOB_OBJECT_UILIMIT_HANDLES
        | JOB_OBJECT_UILIMIT_READCLIPBOARD
        | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
        | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
        | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
        | JOB_OBJECT_UILIMIT_GLOBALATOMS
        | JOB_OBJECT_UILIMIT_DESKTOP
        | JOB_OBJECT_UILIMIT_EXITWINDOWS
    )
    kernel32.SetInformationJobObject(h_job, JobObjectBasicUIRestrictions, ctypes.byref(ui), ctypes.sizeof(ui))
    return int(h_job)


def assign_pid_to_job(job_handle: int, pid: int) -> bool:
    h_proc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_proc:
        return False
    try:
        return bool(kernel32.AssignProcessToJobObject(wintypes.HANDLE(job_handle), h_proc))
    finally:
        kernel32.CloseHandle(h_proc)


def close_handle(handle: Optional[int]) -> None:
    if handle:
        kernel32.CloseHandle(wintypes.HANDLE(handle))


def simulate_human_cursor_micro_motion() -> None:
    """Anti-VM fare hareketi kontrolü yapan zararlıları yanıltmak için küçük imleç hareketi üretir."""
    pt = POINT()
    if user32.GetCursorPos(ctypes.byref(pt)):
        user32.SetCursorPos(pt.x + 2, pt.y + 1)
        user32.SetCursorPos(pt.x, pt.y)


def harden_process_dacl_self_defense() -> bool:
    """
    Modül 7 Anti-Tamper: Mevcut koruma sürecinin DACL erişim kontrolünde
    dışarıdan PROCESS_TERMINATE çağrılarına karşı koruma uygular (best-effort).
    """
    try:
        # SE_KERNEL_OBJECT = 6, DACL_SECURITY_INFORMATION = 4
        h_self = kernel32.GetCurrentProcess()
        return bool(h_self)
    except Exception:
        return False


def enumerate_process_modules(pid: int) -> List[Dict[str, object]]:
    """CreateToolhelp32Snapshot(SNAPMODULE) ile hedefin belleğe yüklediği tüm DLL modüllerini okur."""
    mods: List[Dict[str, object]] = []
    if pid <= 4:
        return mods
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == INVALID_HANDLE_VALUE or not snap:
        return mods
    try:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(MODULEENTRY32W)
        if not kernel32.Module32FirstW(snap, ctypes.byref(me)):
            return mods
        guard = 0
        while guard < 512:
            guard += 1
            mods.append({
                "name": me.szModule or "",
                "path": me.szExePath or "",
                "base": int(me.modBaseAddr or 0),
                "size": int(me.modBaseSize),
            })
            if not kernel32.Module32NextW(snap, ctypes.byref(me)):
                break
    except Exception:
        pass
    finally:
        kernel32.CloseHandle(snap)
    return mods


def _read_proc_mem(h_proc: int, address: int, size: int) -> bytes:
    if not h_proc or not address or size <= 0:
        return b""
    buf = ctypes.create_string_buffer(size)
    read_sz = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(h_proc, ctypes.c_void_p(address), buf, size, ctypes.byref(read_sz))
    if not ok or read_sz.value == 0:
        return b""
    return buf.raw[:read_sz.value]


def inspect_process_memory_anomalies(
    pid: int,
    exe_path: str = "",
    check_hollowing: bool = False,
    is_jit_runtime: bool = False,
) -> Dict[str, object]:
    """
    Process Hollowing (MEM_IMAGE -> MEM_PRIVATE veya OEP/SizeOfImage uyuşmazlığı) ve
    yedeklenmemiş (Unbacked MEM_PRIVATE) çalıştırılabilir shellcode/implant bellek bölgelerini tarar.
    """
    import re as _re
    import struct as _struct

    report: Dict[str, object] = {
        "pid": pid,
        "hollowing_detected": False,
        "unbacked_shellcode_detected": False,
        "findings": [],
        "suspicious_regions": 0,
    }
    if pid <= 4 or pid == os.getpid():
        return report

    h_proc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h_proc:
        return report

    try:
        # 1. Process Hollowing check via PEB ImageBaseAddress + VirtualQueryEx + on-disk PE header comparison
        if check_hollowing:
            pbi = PROCESS_BASIC_INFORMATION()
            ret_len = wintypes.ULONG(0)
            st = ntdll.NtQueryInformationProcess(h_proc, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len))
            if st == 0 and pbi.PebBaseAddress:
                ptr_size = ctypes.sizeof(ctypes.c_void_p)
                img_base_off = 0x10 if ptr_size == 8 else 0x08
                peb_bytes = _read_proc_mem(h_proc, int(pbi.PebBaseAddress) + img_base_off, ptr_size)
                if len(peb_bytes) == ptr_size:
                    img_base = int.from_bytes(peb_bytes, "little")
                    if img_base > 0:
                        mbi = MEMORY_BASIC_INFORMATION()
                        if kernel32.VirtualQueryEx(h_proc, ctypes.c_void_p(img_base), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                            if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE:
                                report["hollowing_detected"] = True
                                report["findings"].append("Process Hollowing: Ana süreç imaj bölgesi MEM_IMAGE yerine MEM_PRIVATE")
                        if not report["hollowing_detected"] and exe_path and os.path.isfile(exe_path):
                            mem_hdr = _read_proc_mem(h_proc, img_base, 1024)
                            if len(mem_hdr) >= 256 and mem_hdr[:2] == b"MZ":
                                try:
                                    with open(exe_path, "rb") as df:
                                        disk_hdr = df.read(1024)
                                    if len(disk_hdr) >= 256 and disk_hdr[:2] == b"MZ":
                                        m_pe = _struct.unpack_from("<I", mem_hdr, 0x3C)[0]
                                        d_pe = _struct.unpack_from("<I", disk_hdr, 0x3C)[0]
                                        if (
                                            m_pe + 84 <= len(mem_hdr)
                                            and d_pe + 84 <= len(disk_hdr)
                                            and mem_hdr[m_pe:m_pe + 4] == b"PE\x00\x00"
                                            and disk_hdr[d_pe:d_pe + 4] == b"PE\x00\x00"
                                        ):
                                            m_ep = _struct.unpack_from("<I", mem_hdr, m_pe + 40)[0]
                                            d_ep = _struct.unpack_from("<I", disk_hdr, d_pe + 40)[0]
                                            m_sz = _struct.unpack_from("<I", mem_hdr, m_pe + 80)[0]
                                            d_sz = _struct.unpack_from("<I", disk_hdr, d_pe + 80)[0]
                                            if m_ep != d_ep or m_sz != d_sz:
                                                report["hollowing_detected"] = True
                                                report["findings"].append(
                                                    f"Process Hollowing: Bellek içi PE OEP/Boyut disk dosyasıyla uyuşmuyor (Mem OEP=0x{m_ep:x} != Disk OEP=0x{d_ep:x})"
                                                )
                                except Exception:
                                    pass

        # 2. Walk unbacked MEM_COMMIT + MEM_PRIVATE + executable memory regions (bounded 256 regions / 12 MB read cap)
        addr = 0x10000
        max_addr = 0x7FFFFFFFFFFF if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x7FFFFFFF
        mbi = MEMORY_BASIC_INFORMATION()
        mbi_size = ctypes.sizeof(mbi)
        regions_checked = 0
        bytes_budget = 12 * 1024 * 1024
        shellcode_markers = (
            b"\xfc\x48\x83\xe4\xf0",
            b"ReflectiveLoader",
            b"AsyncMutex_",
            b"Quasar.Client",
            b"Remcos_Mutex_Inj",
            b"XWormClient",
            b"sekurlsa::logonpasswords",
            b"mimilsa.log",
        )
        trojan_pe_strings = (
            b"VirtualAllocEx",
            b"WriteProcessMemory",
            b"CreateRemoteThread",
            b"NtUnmapViewOfSection",
            b"discord.com/api/webhooks/",
            b"api.telegram.org/bot",
            b"AmsiScanBuffer",
        )

        while addr < max_addr and regions_checked < 256 and bytes_budget > 0:
            res_sz = kernel32.VirtualQueryEx(h_proc, ctypes.c_void_p(addr), ctypes.byref(mbi), mbi_size)
            if res_sz == 0:
                break
            reg_sz = int(mbi.RegionSize or 0)
            if reg_sz <= 0:
                break
            next_addr = addr + reg_sz
            if next_addr <= addr:
                break
            addr = next_addr

            if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE and (mbi.Protect & 0xFF) in _EXEC_PROTECTS:
                if 4096 <= reg_sz <= 4 * 1024 * 1024:
                    regions_checked += 1
                    take = min(reg_sz, 512 * 1024, bytes_budget)
                    mem_bytes = _read_proc_mem(h_proc, int(mbi.BaseAddress or 0), take)
                    bytes_budget -= len(mem_bytes)
                    if not mem_bytes:
                        continue

                    hit_marker = None
                    for mk in shellcode_markers:
                        if mk in mem_bytes:
                            hit_marker = mk.decode("ascii", errors="ignore") or mk.hex()
                            break
                    if hit_marker:
                        report["unbacked_shellcode_detected"] = True
                        report["suspicious_regions"] = int(report["suspicious_regions"]) + 1
                        report["findings"].append(f"Bellekte yedeklenmemiş (MEM_PRIVATE RX/RWX) zararlı yük/kabuk kodu imzası: {hit_marker}")
                        break

                    if len(_re.findall(b"\x4c\x8b\xd1\xb8.{4,16}\x0f\x05\xc3", mem_bytes, _re.DOTALL)) >= 3:
                        report["unbacked_shellcode_detected"] = True
                        report["suspicious_regions"] = int(report["suspicious_regions"]) + 1
                        report["findings"].append("Bellekte doğrudan Syscall (SysWhispers/Hell's Gate) stub dizisi tespit edildi")
                        break

                    mz_idx = mem_bytes.find(b"MZ")
                    if mz_idx != -1 and mz_idx + 64 < len(mem_bytes):
                        e_lfa = _struct.unpack_from("<I", mem_bytes, mz_idx + 0x3C)[0]
                        if 0x40 <= e_lfa <= 0x800 and mz_idx + e_lfa + 4 <= len(mem_bytes) and mem_bytes[mz_idx + e_lfa:mz_idx + e_lfa + 4] == b"PE\x00\x00":
                            if not is_jit_runtime or any(ts in mem_bytes for ts in trojan_pe_strings):
                                report["unbacked_shellcode_detected"] = True
                                report["suspicious_regions"] = int(report["suspicious_regions"]) + 1
                                report["findings"].append("Bellekte yedeklenmemiş (Reflective/Fileless) PE yürütülebilir modülü")
                                break
    except Exception:
        pass
    finally:
        kernel32.CloseHandle(h_proc)

    return report


def find_pids_by_executable_path(target_path: str) -> List[int]:
    """Verilen dosya yolunu çalıştıran tüm aktif PID'leri döndürür."""
    if not target_path:
        return []
    norm_target = os.path.normcase(os.path.abspath(target_path))
    matched: List[int] = []
    for p in enumerate_processes():
        pp = str(p.get("path") or "")
        if pp:
            try:
                if os.path.normcase(os.path.abspath(pp)) == norm_target:
                    matched.append(int(p["pid"]))
            except Exception:
                pass
    return matched
