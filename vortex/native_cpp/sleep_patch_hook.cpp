/**
 * AEGIS-VORTEX :: Modül 2 Gölge Kafes Uyku Atlatma (Sleep-Patching / Time-Acceleration)
 * PE Import Address Table (IAT) üzerinde Sleep, SleepEx ve NtDelayExecution çağrılarını
 * sıfır milisaniyeye yönlendiren yerel C++ DLL kanca motoru.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstring>

typedef VOID(WINAPI* pfnSleep)(DWORD dwMilliseconds);
typedef DWORD(WINAPI* pfnSleepEx)(DWORD dwMilliseconds, BOOL bAlertable);
typedef NTSTATUS(NTAPI* pfnNtDelayExecution)(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

static pfnSleep g_origSleep = nullptr;
static pfnSleepEx g_origSleepEx = nullptr;
static pfnNtDelayExecution g_origNtDelay = nullptr;

VOID WINAPI HookedSleep(DWORD dwMilliseconds) {
    // Uzun uyku atlatma (Sleep(600000) -> anında 1 ms)
    if (dwMilliseconds > 50) {
        dwMilliseconds = 1;
    }
    if (g_origSleep) g_origSleep(dwMilliseconds);
}

DWORD WINAPI HookedSleepEx(DWORD dwMilliseconds, BOOL bAlertable) {
    if (dwMilliseconds > 50) {
        dwMilliseconds = 1;
    }
    return g_origSleepEx ? g_origSleepEx(dwMilliseconds, bAlertable) : 0;
}

NTSTATUS NTAPI HookedNtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval) {
    LARGE_INTEGER accelerated{};
    if (DelayInterval && DelayInterval->QuadPart < -500000LL) {
        accelerated.QuadPart = -10000LL; // 1 ms negatif göreli süre
        DelayInterval = &accelerated;
    }
    return g_origNtDelay ? g_origNtDelay(Alertable, DelayInterval) : 0;
}

static void PatchIATEntry(const char* targetDll, const char* funcName, void* hookFn, void** origFnOut) {
    HMODULE hMain = GetModuleHandleW(nullptr);
    if (!hMain) return;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hMain);
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hMain) + dos->e_lfanew);
    auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress == 0) return;

    auto* impDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<BYTE*>(hMain) + impDir.VirtualAddress);
    for (; impDesc->Name != 0; ++impDesc) {
        const char* dllName = reinterpret_cast<const char*>(reinterpret_cast<BYTE*>(hMain) + impDesc->Name);
        if (_stricmp(dllName, targetDll) != 0) continue;

        auto* origThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<BYTE*>(hMain) + impDesc->OriginalFirstThunk);
        auto* iatThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<BYTE*>(hMain) + impDesc->FirstThunk);

        for (; origThunk->u1.AddressOfData != 0; ++origThunk, ++iatThunk) {
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) continue;
            auto* importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<BYTE*>(hMain) + origThunk->u1.AddressOfData);
            if (strcmp(importByName->Name, funcName) == 0) {
                DWORD oldProt = 0;
                if (VirtualProtect(&iatThunk->u1.Function, sizeof(ULONG_PTR), PAGE_READWRITE, &oldProt)) {
                    *origFnOut = reinterpret_cast<void*>(iatThunk->u1.Function);
                    iatThunk->u1.Function = reinterpret_cast<ULONG_PTR>(hookFn);
                    VirtualProtect(&iatThunk->u1.Function, sizeof(ULONG_PTR), oldProt, &oldProt);
                }
                break;
            }
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        PatchIATEntry("kernel32.dll", "Sleep", reinterpret_cast<void*>(HookedSleep), reinterpret_cast<void**>(&g_origSleep));
        PatchIATEntry("kernel32.dll", "SleepEx", reinterpret_cast<void*>(HookedSleepEx), reinterpret_cast<void**>(&g_origSleepEx));
        PatchIATEntry("ntdll.dll", "NtDelayExecution", reinterpret_cast<void*>(HookedNtDelayExecution), reinterpret_cast<void**>(&g_origNtDelay));
    }
    return TRUE;
}
