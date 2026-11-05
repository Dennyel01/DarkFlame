#pragma once

#include <Windows.h>

#include <string_view>

namespace MemoryModuleDumper
{
bool Schedule(HMODULE module, std::wstring_view path, DWORD delayMs = 5'000);

// Synchronous snapshot. Used when the image must be captured before any hook
// patches the module's code (otherwise the dumped bytes no longer match the
// file and signature scanning becomes unreliable).
bool CaptureNow(HMODULE module, std::wstring_view path);
}
