#pragma once

#include <string_view>

namespace LuaBridgeSignatures
{
// IsNameAllowed is a separate callee of OnPreFunction, not resolved via the access pattern.
inline constexpr std::string_view CallHookPattern =
    "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? "
    "33 C5 89 45 ? 53 56 57 50 8D 45 ? 64 A3 ? ? ? ? 80 3D";
inline constexpr std::string_view LuaNewThreadPattern =
    "55 8B EC 56 8B 75 ? 8B 4E ? 8B 41 ? 3B 41 ? 72 ? 56 E8 ? ? ? ? "
    "83 C4 ? 56";
inline constexpr std::string_view LuaFunctionRegistryPattern =
    "55 8B EC 83 EC ? 56 8B 75 ? 3B 35";
// GetVirtualMachine: new client builds carry the real (hardened) body, older
// builds expose a 5-byte jmp thunk (ILT) instead. Try the body first.
inline constexpr std::string_view GetVirtualMachinePatterns[] = {
    "55 8B EC 83 EC 20 53 56 57 8B 7D 08 8B D9 89 5D FC 85 FF 0F 84 ? ? ? ? 57 E8",
    "E9 20 E8 55 00",
};
// The hardened GetVirtualMachine body calls its state-key helper directly at
// this offset (relative call). Its presence is used to detect the hardened
// CLuaManager layout (encoded virtual-machine vector at +0x48). The helper is
// never invoked by the bridge because it depends on the client module's TLS.
inline constexpr std::size_t GetVirtualMachineKeyCallOffset = 0x2A;
inline constexpr std::string_view LuaManagerLoadPattern =
    "8B 0D ? ? ? ? 57 C7 45 ? ? ? ? ? E8 ? ? ? ? 85 C0 0F 84 ? ? ? ? "
    "83 78 ? ?";
// AddDebugHook/RemoveDebugHook entry points (ABI unchanged). New builds use
// plain direct calls, older builds used virtualized stubs.
inline constexpr std::string_view AddDebugHookPatterns[] = {
    "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC 98 00 00 00 A1 ? ? ? ? "
    "33 C5 89 45 F0 53 56 57 50 8D 45 F4 64 A3 ? ? ? ? 8B 45 08 8B 55 10 8B 5D 0C",
    "9C E8 ? ? ? ? B8 AC B4 15 68",
};
inline constexpr std::string_view RemoveDebugHookPatterns[] = {
    "55 8B EC A1 ? ? ? ? 53 56 57 8B B0 50 01 00 00 8B F9 8B 4D 0C "
    "E8 ? ? ? ? 50 8B CE E8",
    "E8 ? ? ? ? 01 94 14 42 55 52 9F",
};
inline constexpr std::string_view LuaMToRefPattern =
    "55 8B EC 83 EC ? A1 ? ? ? ? 56 8B 75";
inline constexpr std::string_view LuaFunctionRefDtorPattern =
    "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 56 A1 ? ? ? ? 33 C5 50 "
    "8D 45 ? 64 A3 ? ? ? ? 8B F1 FF 76 ? FF 76";
// +1 g_pClientGame, +11 manager offset, +16 rel32 OnPreFunction;
// esi=fn, edi=lua_State*; false=skip native. The manager offset moved between
// builds (0xD8 -> 0xE4), so it is wildcarded here and decoded at runtime.
inline constexpr std::string_view ClientGameDebugHookAccessPatterns[] = {
    "A1 ? ? ? ? 6A 01 57 56 8B 88 ? ? ? ? E8",
    "A1 ? ? ? ? 6A 01 57 56 8B 88 D8 00 00 00 E8 ? ? ? ?",
};
inline constexpr std::size_t ClientGameSlotOffset = 1;
inline constexpr std::size_t DebugHookManagerFieldOffset = 11;
inline constexpr std::size_t OnPreFunctionCallOffset = 16;
}
