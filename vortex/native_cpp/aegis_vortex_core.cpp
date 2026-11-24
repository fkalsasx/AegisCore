/**
 * AEGIS-VORTEX :: C++20 Win32 Çekirdek Müdahale & İzolasyon Motoru
 * - Modül 2: Win32 JobObject + UI Restrictions + 500ms Gölge Kafes Yürütücüsü
 * - Modül 4: ReadDirectoryChangesW Sıfır-Tolerans Canary İzleyici + NtSuspendProcess Dondurucu
 * - Modül 7: Anti-Tamper DACL Süreç Sertleştirme
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>

typedef LONG(NTAPI* pfnNtSuspendProcess)(HANDLE ProcessHandle);
typedef LONG(NTAPI* pfnNtResumeProcess)(HANDLE ProcessHandle);

namespace aegis {

struct TelemetryEvent {
    std::string source;
    std::string event_type;
    DWORD pid;
    std::string detail;

    void emit_json() const {
        std::cout << "{\"source_module\":\"" << source
                  << "\",\"event_type\":\"" << event_type
                  << "\",\"pid\":" << pid
                  << ",\"detail\":\"" << detail << "\"}\n" << std::flush;
    }
};

class ProcessController {
public:
    static bool freeze_process(DWORD pid) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;
        auto NtSuspendProcess = reinterpret_cast<pfnNtSuspendProcess>(GetProcAddress(hNtdll, "NtSuspendProcess"));
        if (!NtSuspendProcess) return false;

        HANDLE hProc = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
        if (!hProc) return false;

        LONG status = NtSuspendProcess(hProc);
        CloseHandle(hProc);
        return status == 0;
    }

    static bool terminate_pid(DWORD pid) {
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!hProc) return false;
        BOOL ok = TerminateProcess(hProc, 1);
        CloseHandle(hProc);
        return ok != FALSE;
    }

    static bool harden_self_dacl() {
        HANDLE hSelf = GetCurrentProcess();
        // Dış süreçlerin PROCESS_TERMINATE / WRITE_DAC erişimini kısıtlamak için boş DACL yerine güvenli kontrol
        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = PROCESS_TERMINATE | PROCESS_VM_WRITE | WRITE_DAC;
        ea.grfAccessMode = DENY_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
        ea.Trustee.ptstrName = const_cast<LPWSTR>(L"EVERYONE");

        PACL pNewDacl = nullptr;
        if (SetEntriesInAclW(1, &ea, nullptr, &pNewDacl) == ERROR_SUCCESS) {
            DWORD res = SetSecurityInfo(hSelf, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewDacl, nullptr);
            LocalFree(pNewDacl);
            return res == ERROR_SUCCESS;
        }
        return false;
    }
};

class ShadowCageRunner {
public:
    static int detonate_500ms(const std::wstring& exePath, DWORD memoryMb = 128) {
        HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
        if (!hJob) return -1;

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION ext{};
        ext.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
            JOB_OBJECT_LIMIT_PROCESS_MEMORY |
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        ext.BasicLimitInformation.ActiveProcessLimit = 2;
        ext.ProcessMemoryLimit = static_cast<SIZE_T>(memoryMb) * 1024ULL * 1024ULL;
        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &ext, sizeof(ext));

        JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
        ui.UIRestrictionsClass =
            JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_READCLIPBOARD |
            JOB_OBJECT_UILIMIT_WRITECLIPBOARD | JOB_OBJECT_UILIMIT_DESKTOP |
            JOB_OBJECT_UILIMIT_EXITWINDOWS;
        SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &ui, sizeof(ui));

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        std::wstring cmd = exePath;

        if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            CloseHandle(hJob);
            return -2;
        }

        AssignProcessToJobObject(hJob, pi.hProcess);
        ResumeThread(pi.hThread);

        TelemetryEvent{"MOD2_CPP_SHADOW_CAGE", "SANDBOX_DETONATED", pi.dwProcessId, "500ms isolated observation started"}.emit_json();

        WaitForSingleObject(pi.hProcess, 500);
        TerminateJobObject(hJob, 0);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(hJob);
        return 0;
    }
};

class CanaryDirectoryWatcher {
public:
    static void watch_blocking(const std::wstring& directory, std::atomic<bool>& running) {
        HANDLE hDir = CreateFileW(
            directory.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr
        );
        if (hDir == INVALID_HANDLE_VALUE) return;

        std::vector<BYTE> buffer(32768);
        DWORD bytesReturned = 0;

        while (running.load()) {
            if (!ReadDirectoryChangesW(
                    hDir, buffer.data(), static_cast<DWORD>(buffer.size()), FALSE,
                    FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
                    &bytesReturned, nullptr, nullptr)) {
                break;
            }

            BYTE* ptr = buffer.data();
            while (true) {
                auto* fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(ptr);
                std::wstring wname(fni->FileName, fni->FileNameLength / sizeof(WCHAR));
                if (wname.find(L"!_00_aegis_") != std::wstring::npos || wname.find(L"~_zz_aegis_") != std::wstring::npos) {
                    TelemetryEvent{"MOD4_CPP_CANARY", "CANARY_TOUCHED", 0, "Zero-tolerance canary integrity breach"}.emit_json();
                }
                if (fni->NextEntryOffset == 0) break;
                ptr += fni->NextEntryOffset;
            }
        }
        CloseHandle(hDir);
    }
};

} // namespace aegis

int wmain(int argc, wchar_t* argv[]) {
    aegis::ProcessController::harden_self_dacl();
    if (argc < 2) {
        aegis::TelemetryEvent{"AEGIS_CPP_CORE", "READY", GetCurrentProcessId(), "Usage: aegis_vortex_core <freeze pid | detonate path | watch dir>"}.emit_json();
        return 0;
    }

    std::wstring cmd = argv[1];
    if (cmd == L"freeze" && argc >= 3) {
        DWORD pid = static_cast<DWORD>(_wtoi(argv[2]));
        bool ok = aegis::ProcessController::freeze_process(pid);
        aegis::TelemetryEvent{"MOD4_CPP_FREEZER", ok ? "PROCESS_FROZEN" : "FREEZE_FAILED", pid, "NtSuspendProcess invoked"}.emit_json();
    } else if (cmd == L"detonate" && argc >= 3) {
        return aegis::ShadowCageRunner::detonate_500ms(argv[2]);
    } else if (cmd == L"watch" && argc >= 3) {
        std::atomic<bool> running{true};
        aegis::CanaryDirectoryWatcher::watch_blocking(argv[2], running);
    }
    return 0;
}
