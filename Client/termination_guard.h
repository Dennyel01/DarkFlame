#pragma once

#include <Windows.h>

namespace TerminationGuard
{
// Installs detours around the process termination entry points. Calls that come
// from netc.dll (the anti-cheat module) are swallowed so a false positive cannot
// kill the game process. Termination initiated by the game itself is untouched.
bool Start();

// Netc is loaded after the client, so the guard needs its base address to tell
// anti-cheat code apart from the game. Safe to call with nullptr.
void SetNetcModule(HMODULE module);
}
