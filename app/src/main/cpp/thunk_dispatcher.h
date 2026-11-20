#ifndef SH3_THUNK_DISPATCHER_H
#define SH3_THUNK_DISPATCHER_H

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <unordered_map>
#include "i_x86_cpu.h"

class ThunkDispatcher {
public:
    void buildReverseMap(const std::unordered_map<std::string, uint32_t>& forwardThunkTable);
    void registerModule(const std::string& name, uint32_t baseAddr) {
        std::string low;
        low.reserve(name.size());
        for (char c : name) low.push_back((c >= 65 && c <= 90) ? static_cast<char>(c + 32) : c);
        size_t cut = 0;
        for (size_t i = 0; i < low.size(); ++i) if (low[i] == 47 || low[i] == 92) cut = i + 1;
        if (cut > 0) low = low.substr(cut);
        m_loadedModules[low] = baseAddr;
        std::string orig = (cut > 0) ? name.substr(cut) : name;
        m_moduleNamesByBase[baseAddr] = orig;
    }
    uint32_t findLoadedModule(const std::string& rawPath) const {
        std::string low;
        low.reserve(rawPath.size());
        for (char c : rawPath) low.push_back((c >= 65 && c <= 90) ? static_cast<char>(c + 32) : c);
        size_t cut = 0;
        for (size_t i = 0; i < low.size(); ++i) if (low[i] == 47 || low[i] == 92) cut = i + 1;
        if (cut > 0) low = low.substr(cut);
        auto it = m_loadedModules.find(low);
        if (it != m_loadedModules.end()) return it->second;
        if (low.find(46) == std::string::npos) {
            it = m_loadedModules.find(low + ".dll");
            if (it != m_loadedModules.end()) return it->second;
        }
        return 0u;
    }
    std::string findModuleNameByBase(uint32_t base) const {
        if (base == 0u) return "Stronghold3.exe";
        auto it = m_moduleNamesByBase.find(base);
        if (it != m_moduleNamesByBase.end()) return it->second;
        return "Stronghold3.exe";
    }
    uint32_t getOrCreateVirtualModule(const std::string& rawPath) {
        std::string low;
        low.reserve(rawPath.size());
        for (char c : rawPath) low.push_back((c >= 65 && c <= 90) ? static_cast<char>(c + 32) : c);
        size_t cut = 0;
        for (size_t i = 0; i < low.size(); ++i) if (low[i] == 47 || low[i] == 92) cut = i + 1;
        if (cut > 0) low = low.substr(cut);
        if (low.empty()) return 0x61000000u;
        if (low.find(46) == std::string::npos) low += ".dll";
        auto it = m_virtualModsByName.find(low);
        if (it != m_virtualModsByName.end()) return it->second;
        uint32_t handle = 0x61000000u + static_cast<uint32_t>(m_virtualModsByName.size()) * 0x10000u;
        m_virtualModsByName[low] = handle;
        m_virtualModNamesByBase[handle] = low;
        return handle;
    }
    std::string findVirtualModuleName(uint32_t base) const {
        auto it = m_virtualModNamesByBase.find(base);
        if (it != m_virtualModNamesByBase.end()) return it->second;
        return "";
    }
    std::string resolveVirtualDllPrefix(uint32_t hMod, const std::string& fn) const {
        std::string vm = findVirtualModuleName(hMod);
        if (!vm.empty()) return vm;
        if (fn == "Direct3DCreate9" || fn == "Direct3DCreate9Ex") return "d3d9.dll";
        if (fn == "DirectInput8Create") return "dinput8.dll";
        if (fn == "GetStockObject" || fn == "GetDeviceCaps" || fn == "DeleteObject" ||
            fn == "DeleteDC" || fn == "SelectObject" || fn == "CreateCompatibleDC" ||
            fn == "SetDeviceGammaRamp" || fn == "GetDeviceGammaRamp") return "gdi32.dll";
        if (fn == "LoadIconA" || fn == "LoadIconW" || fn == "LoadCursorA" || fn == "LoadCursorW" ||
            fn == "LoadImageA" || fn == "LoadImageW" || fn == "SetCursor" || fn == "ShowCursor" ||
            fn == "GetCursorPos" || fn == "SetCursorPos" || fn == "ClipCursor" ||
            fn == "RegisterClassA" || fn == "RegisterClassW" || fn == "RegisterClassExA" || fn == "RegisterClassExW" ||
            fn == "UnregisterClassA" || fn == "UnregisterClassW" || fn == "GetClassInfoA" || fn == "GetClassInfoW" ||
            fn == "GetClassInfoExA" || fn == "GetClassInfoExW" || fn == "CreateWindowExA" || fn == "CreateWindowExW" ||
            fn == "DestroyWindow" || fn == "ShowWindow" || fn == "UpdateWindow" || fn == "SetForegroundWindow" ||
            fn == "BringWindowToTop" || fn == "IsWindow" || fn == "IsWindowVisible" || fn == "IsWindowEnabled" ||
            fn == "IsIconic" || fn == "IsZoomed" || fn == "SetFocus" || fn == "SetActiveWindow" ||
            fn == "GetForegroundWindow" || fn == "GetActiveWindow" || fn == "GetFocus" || fn == "GetDesktopWindow" ||
            fn == "SetCapture" || fn == "GetCapture" || fn == "ReleaseCapture" ||
            fn == "SetWindowTextA" || fn == "SetWindowTextW" || fn == "GetWindowTextA" || fn == "GetWindowTextW" ||
            fn == "AdjustWindowRect" || fn == "AdjustWindowRectEx" || fn == "InvalidateRect" || fn == "ValidateRect" ||
            fn == "GetClientRect" || fn == "GetWindowRect" || fn == "SetWindowPos" || fn == "MoveWindow" ||
            fn == "ClientToScreen" || fn == "ScreenToClient" || fn == "GetSystemMetrics" ||
            fn == "SystemParametersInfoA" || fn == "SystemParametersInfoW" ||
            fn == "MonitorFromWindow" || fn == "MonitorFromRect" || fn == "MonitorFromPoint" ||
            fn == "GetMonitorInfoA" || fn == "GetMonitorInfoW" ||
            fn == "ChangeDisplaySettingsA" || fn == "ChangeDisplaySettingsW" ||
            fn == "ChangeDisplaySettingsExA" || fn == "ChangeDisplaySettingsExW" ||
            fn == "EnumDisplayDevicesA" || fn == "EnumDisplayDevicesW" || fn == "EnumDisplayMonitors" ||
            fn == "EnumDisplaySettingsA" || fn == "EnumDisplaySettingsW" ||
            fn == "GetWindowLongA" || fn == "GetWindowLongW" || fn == "SetWindowLongA" || fn == "SetWindowLongW" ||
            fn == "PeekMessageA" || fn == "PeekMessageW" || fn == "TranslateMessage" ||
            fn == "DispatchMessageA" || fn == "DispatchMessageW" || fn == "PostQuitMessage" ||
            fn == "DefWindowProcA" || fn == "DefWindowProcW" || fn == "SendMessageA" || fn == "SendMessageW" ||
            fn == "PostMessageA" || fn == "PostMessageW" || fn == "SetTimer" || fn == "KillTimer" ||
            fn == "EnableWindow" || fn == "GetWindowThreadProcessId" || fn == "GetDC" || fn == "ReleaseDC" ||
            fn == "MessageBoxA" || fn == "MessageBoxW" || fn == "FindWindowA" || fn == "FindWindowW") return "user32.dll";
        return "dynamic";
    }
    bool isLoadedModuleBase(uint32_t base) const {
        if (base == 0u) return false;
        for (const auto& kv : m_loadedModules) if (kv.second == base) return true;
        return false;
    }
    std::string resolveAddress(uint32_t thunkAddr) const;
    size_t count() const { return m_reverseMap.size(); }

    bool onThunkTrap(uint32_t thunkAddr, uint32_t returnAddr);
    bool handleThunkCall(IX86CPU* cpu, uint32_t thunkAddr, uint32_t returnAddr, uint32_t& outNextEip);

    uint32_t lastTrappedAddress() const { return m_lastTrappedAddr; }
    uint32_t lastReturnAddress() const { return m_lastReturnAddr; }
    const std::string& lastMsgBox() const { return m_lastMsgBox; }
    const std::string& d3dTrace() const { return m_d3dTrace; }
    const std::string& lastTrappedSymbol() const { return m_lastTrappedSym; }
    const std::vector<std::string>& handledLog() const { return m_handledLog; }

private:
    std::unordered_map<uint32_t, std::string> m_reverseMap;
    std::unordered_map<std::string, uint32_t> m_loadedModules;
    std::unordered_map<uint32_t, std::string> m_moduleNamesByBase;
    std::unordered_map<int32_t, uint32_t> m_winLongs;
    std::unordered_map<std::string, uint32_t> m_virtualModsByName;
    std::unordered_map<uint32_t, std::string> m_virtualModNamesByBase;
    std::vector<std::string> m_handledLog;
    uint32_t    m_lastTrappedAddr = 0;
    uint32_t    m_lastReturnAddr  = 0;
    std::string m_lastTrappedSym;
    uint32_t    m_lastError      = 0u;
    uint32_t    m_dynThunkCursor = 0x70008000u;
    uint32_t    m_nextTlsIndex   = 1u;
    std::unordered_map<uint32_t, uint32_t> m_tlsSlots;
    uint32_t    m_heapCursor = 0x20000000u;
    uint32_t    m_heapEnd    = 0x30000000u;
    std::unordered_map<uint32_t, uint32_t> m_allocSizes;
    std::unordered_map<uint32_t, std::vector<uint32_t>> m_freeBins;
    uint32_t    m_oomCount   = 0;

    std::string m_lastMsgBox;
    std::string m_d3dTrace;
    bool m_postD3dActive = false;
    std::string m_lastCmp;

    void logSym(const std::string& s) {
        if (m_postD3dActive && m_d3dTrace.size() < 512u) {
            if (s.find("!malloc") == std::string::npos && s.find("!free") == std::string::npos &&
                s.find("!realloc") == std::string::npos && s.find("!calloc") == std::string::npos &&
                s.find("!??") == std::string::npos && s.find("CriticalSection") == std::string::npos &&
                s.find("Interlocked") == std::string::npos && s.find("TlsGetValue") == std::string::npos &&
                s.find("TlsSetValue") == std::string::npos && s.find("LastError") == std::string::npos &&
                s.find("CurrentThreadId") == std::string::npos && s.find("!mem") == std::string::npos &&
                s.find("!str") == std::string::npos && s.find("!wcs") == std::string::npos &&
                s.find("!_lock") == std::string::npos && s.find("!_unlock") == std::string::npos &&
                s.find("Pointer") == std::string::npos && s.find("Heap") == std::string::npos &&
                s.find("QueryPerformance") == std::string::npos && s.find("GetTickCount") == std::string::npos &&
                s.find("!fread") == std::string::npos && s.find("!fseek") == std::string::npos &&
                s.find("!ftell") == std::string::npos && s.find("!feof") == std::string::npos &&
                s.find("!ferror") == std::string::npos && s.find("printf") == std::string::npos &&
                s.find("!qsort") == std::string::npos && s.find("!bsearch") == std::string::npos &&
                s.find("!rand") == std::string::npos && s.find("!_CI") == std::string::npos && s.find("!_ftol") == std::string::npos && s.find("IDirect3D9::") == std::string::npos) {
                size_t bang = s.find(33);
                std::string sh = (bang != std::string::npos) ? s.substr(bang + 1) : s;
                m_d3dTrace += sh + " ";
            }
        }
        if (m_handledLog.size() >= 4096) return;
        if (s.find("!malloc") != std::string::npos || s.find("!calloc") != std::string::npos ||
            s.find("!realloc") != std::string::npos || s.find("!free") != std::string::npos ||
            s.find("!??") != std::string::npos || s.find("!str") != std::string::npos ||
            s.find("!_str") != std::string::npos || s.find("!mem") != std::string::npos ||
            s.find("!is") != std::string::npos || s.find("!to") != std::string::npos ||
            s.find("!Interlocked") != std::string::npos || s.find("CriticalSection") != std::string::npos ||
            s.find("WideChar") != std::string::npos || s.find("!GetLastError") != std::string::npos ||
            s.find("!sprintf") != std::string::npos || s.find("!_snprintf") != std::string::npos ||
            s.find("!_vsnprintf") != std::string::npos || s.find("!fread") != std::string::npos ||
            s.find("!ferror") != std::string::npos || s.find("!fseek") != std::string::npos ||
            s.find("!ftell") != std::string::npos || s.find("!feof") != std::string::npos || s.find("!DecodePointer") != std::string::npos || s.find("!EncodePointer") != std::string::npos || s.find("!_lock") != std::string::npos || s.find("!_unlock") != std::string::npos || s.find("!__dllonexit") != std::string::npos || s == "msvcr100.dll!rand" || s == "msvcr100.dll!bsearch") return;
        if (m_handledLog.size() < 4096) m_handledLog.push_back(s);
    }

    uint32_t allocGuest(uint32_t size) {
        if (size == 0) size = 16;
        uint32_t aligned = (size + 15u) & ~15u;
        auto bit = m_freeBins.find(aligned);
        if (bit != m_freeBins.end() && !bit->second.empty()) {
            uint32_t ptr = bit->second.back();
            bit->second.pop_back();
            m_allocSizes[ptr] = size;
            return ptr;
        }
        if (m_heapCursor + aligned > m_heapEnd) {
            if (++m_oomCount <= 5) {
                char oom[96];
                snprintf(oom, sizeof(oom), "HEAP_OOM(req=%u, used=%uMB)", size, (m_heapCursor - 0x20000000u) >> 20);
                m_handledLog.push_back(oom);
            }
            return 0u;
        }
        uint32_t ptr = m_heapCursor;
        m_heapCursor += aligned;
        m_allocSizes[ptr] = size;
        return ptr;
    }

    void freeGuest(uint32_t ptr) {
        if (ptr < 0x20000000u || ptr >= m_heapEnd) return;
        auto it = m_allocSizes.find(ptr);
        if (it == m_allocSizes.end()) return;
        uint32_t aligned = (it->second + 15u) & ~15u;
        m_allocSizes.erase(it);
        m_freeBins[aligned].push_back(ptr);
    }
};

#endif // SH3_THUNK_DISPATCHER_H
