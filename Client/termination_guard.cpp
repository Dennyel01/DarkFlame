#include "termination_guard.h"

#include "logger.h"

#include <MinHook.h>

#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <cwctype>
#include <intrin.h>
#include <string>
#include <vector>

namespace
{
using ExitProcessFn = void(WINAPI*)(UINT);
using RtlExitUserProcessFn = void(NTAPI*)(ULONG);
using TerminateProcessFn = BOOL(WINAPI*)(HANDLE, UINT);
using NtTerminateProcessFn = LONG(NTAPI*)(HANDLE, LONG);
using MessageBoxWFn = int(WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT);
using MessageBoxAFn = int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);

std::atomic_bool g_started{};
std::atomic<void*> g_netcBase{};

ExitProcessFn g_exitProcess{};
RtlExitUserProcessFn g_rtlExitUserProcess{};
TerminateProcessFn g_terminateProcess{};
NtTerminateProcessFn g_ntTerminateProcess{};
MessageBoxWFn g_messageBoxW{};
MessageBoxAFn g_messageBoxA{};

void* AllocationBase(void* address)
{
    if(!address)
        return nullptr;
    MEMORY_BASIC_INFORMATION memory{};
    if(!VirtualQuery(address, &memory, sizeof(memory)))
        return nullptr;
    return memory.AllocationBase;
}

bool FromNetc(void* caller)
{
    void* expected = g_netcBase.load(std::memory_order_acquire);
    return expected && AllocationBase(caller) == expected;
}

bool IsCurrentProcess(HANDLE process)
{
    if(!process || process == GetCurrentProcess())
        return true;
    return GetProcessId(process) == GetCurrentProcessId();
}

void LogBlocked(const wchar_t* action, void* caller)
{
    static std::atomic_uint32_t count{};
    if(count.fetch_add(1, std::memory_order_relaxed) >= 8)
        return;
    wchar_t buffer[192]{};
    swprintf_s(buffer, L"[guard] blocked %ls from netc (caller %p)",
        action, caller);
    Log::Write(buffer);
}

bool ContainsNoCase(const std::wstring& text, const wchar_t* needle)
{
    if(text.empty() || !needle || !*needle)
        return false;
    std::wstring haystack = text;
    std::wstring target = needle;
    for(wchar_t& ch : haystack)
        ch = static_cast<wchar_t>(towlower(ch));
    for(wchar_t& ch : target)
        ch = static_cast<wchar_t>(towlower(ch));
    return haystack.find(target) != std::wstring::npos;
}

std::string Lower(std::string value)
{
    for(char& ch : value)
        ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
    return value;
}

bool LooksLikeIntegrityDialog(const std::wstring& text)
{
    return ContainsNoCase(text, L"integrity")
        || ContainsNoCase(text, L"violation")
        || ContainsNoCase(text, L"terminated");
}

bool LooksLikeIntegrityDialog(const std::string& text)
{
    const std::string lowered = Lower(text);
    return lowered.find("integrity") != std::string::npos
        || lowered.find("violation") != std::string::npos
        || lowered.find("terminated") != std::string::npos;
}

std::wstring Widen(const char* value)
{
    if(!value || !*value)
        return {};
    const int size = MultiByteToWideChar(CP_ACP, 0, value, -1, nullptr, 0);
    if(size <= 1)
        return {};
    std::wstring output(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_ACP, 0, value, -1, output.data(), size);
    output.resize(static_cast<std::size_t>(size - 1));
    return output;
}

__declspec(noinline) void WINAPI HookExitProcess(UINT code)
{
    void* caller = _ReturnAddress();
    if(FromNetc(caller))
    {
        LogBlocked(L"ExitProcess", caller);
        // ExitProcess never returns. Killing only the calling thread keeps the
        // game alive instead of running into the dead code after the call.
        ExitThread(0);
    }
    g_exitProcess(code);
}

__declspec(noinline) void NTAPI HookRtlExitUserProcess(ULONG code)
{
    void* caller = _ReturnAddress();
    if(FromNetc(caller))
    {
        LogBlocked(L"RtlExitUserProcess", caller);
        ExitThread(0);
    }
    g_rtlExitUserProcess(code);
}

__declspec(noinline) BOOL WINAPI HookTerminateProcess(HANDLE process, UINT code)
{
    void* caller = _ReturnAddress();
    if(IsCurrentProcess(process) && FromNetc(caller))
    {
        LogBlocked(L"TerminateProcess", caller);
        return TRUE;
    }
    return g_terminateProcess(process, code);
}

__declspec(noinline) LONG NTAPI HookNtTerminateProcess(HANDLE process,
    LONG status)
{
    void* caller = _ReturnAddress();
    if(IsCurrentProcess(process) && FromNetc(caller))
    {
        LogBlocked(L"NtTerminateProcess", caller);
        return 0;
    }
    return g_ntTerminateProcess(process, status);
}

__declspec(noinline) int WINAPI HookMessageBoxW(HWND window, LPCWSTR text,
    LPCWSTR caption, UINT type)
{
    void* caller = _ReturnAddress();
    if(FromNetc(caller))
    {
        std::wstring all = caption ? caption : L"";
        all += L" ";
        if(text)
            all += text;
        if(LooksLikeIntegrityDialog(all))
        {
            static std::atomic_bool logged{};
            if(!logged.exchange(true, std::memory_order_acq_rel))
                Log::Write(L"[guard] suppressed netc integrity dialog");
            return IDOK;
        }
    }
    return g_messageBoxW(window, text, caption, type);
}

__declspec(noinline) int WINAPI HookMessageBoxA(HWND window, LPCSTR text,
    LPCSTR caption, UINT type)
{
    void* caller = _ReturnAddress();
    if(FromNetc(caller))
    {
        std::string all = caption ? caption : "";
        all += " ";
        if(text)
            all += text;
        if(LooksLikeIntegrityDialog(all))
        {
            static std::atomic_bool logged{};
            if(!logged.exchange(true, std::memory_order_acq_rel))
            {
                const std::wstring wide = Widen(all.c_str());
                Log::Write(L"[guard] suppressed netc integrity dialog: "
                    + wide);
            }
            return IDOK;
        }
    }
    return g_messageBoxA(window, text, caption, type);
}

struct HookEntry
{
    const wchar_t* module{};
    const char* name{};
    void* detour{};
    void** original{};
};

bool Install()
{
    std::vector<HookEntry> entries{
        {L"kernel32.dll", "ExitProcess", reinterpret_cast<void*>(&HookExitProcess),
            reinterpret_cast<void**>(&g_exitProcess)},
        {L"ntdll.dll", "RtlExitUserProcess",
            reinterpret_cast<void*>(&HookRtlExitUserProcess),
            reinterpret_cast<void**>(&g_rtlExitUserProcess)},
        {L"kernel32.dll", "TerminateProcess",
            reinterpret_cast<void*>(&HookTerminateProcess),
            reinterpret_cast<void**>(&g_terminateProcess)},
        {L"ntdll.dll", "NtTerminateProcess",
            reinterpret_cast<void*>(&HookNtTerminateProcess),
            reinterpret_cast<void**>(&g_ntTerminateProcess)},
        {L"user32.dll", "MessageBoxW", reinterpret_cast<void*>(&HookMessageBoxW),
            reinterpret_cast<void**>(&g_messageBoxW)},
        {L"user32.dll", "MessageBoxA", reinterpret_cast<void*>(&HookMessageBoxA),
            reinterpret_cast<void**>(&g_messageBoxA)}
    };

    std::size_t enabled{};
    for(HookEntry& entry : entries)
    {
        HMODULE module = GetModuleHandleW(entry.module);
        if(!module)
            module = LoadLibraryW(entry.module);
        void* target = module
            ? reinterpret_cast<void*>(GetProcAddress(module, entry.name)) : nullptr;
        if(!target)
            continue;
        if(MH_CreateHook(target, entry.detour, entry.original) != MH_OK)
            continue;
        if(MH_EnableHook(target) != MH_OK)
        {
            MH_RemoveHook(target);
            continue;
        }
        ++enabled;
    }

    wchar_t message[96]{};
    swprintf_s(message, L"[guard] termination guard installed: %zu hooks",
        enabled);
    Log::Write(message);
    return enabled != 0;
}
}

bool TerminationGuard::Start()
{
    if(g_started.exchange(true))
        return false;
    return Install();
}

void TerminationGuard::SetNetcModule(HMODULE module)
{
    g_netcBase.store(module, std::memory_order_release);
}
