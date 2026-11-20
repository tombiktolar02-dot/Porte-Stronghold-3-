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
    std::string m_lastCmp;

    void logSym(const std::string& s) {
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
