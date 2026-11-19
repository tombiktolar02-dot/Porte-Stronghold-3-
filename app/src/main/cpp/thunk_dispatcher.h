#ifndef SH3_THUNK_DISPATCHER_H
#define SH3_THUNK_DISPATCHER_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include "i_x86_cpu.h"

class ThunkDispatcher {
public:
    void buildReverseMap(const std::unordered_map<std::string, uint32_t>& forwardThunkTable);
    std::string resolveAddress(uint32_t thunkAddr) const;
    size_t count() const { return m_reverseMap.size(); }

    bool onThunkTrap(uint32_t thunkAddr, uint32_t returnAddr);
    bool handleThunkCall(IX86CPU* cpu, uint32_t thunkAddr, uint32_t returnAddr, uint32_t& outNextEip);

    uint32_t lastTrappedAddress() const { return m_lastTrappedAddr; }
    uint32_t lastReturnAddress() const { return m_lastReturnAddr; }
    const std::string& lastTrappedSymbol() const { return m_lastTrappedSym; }
    const std::vector<std::string>& handledLog() const { return m_handledLog; }

private:
    std::unordered_map<uint32_t, std::string> m_reverseMap;
    std::vector<std::string> m_handledLog;
    uint32_t    m_lastTrappedAddr = 0;
    uint32_t    m_lastReturnAddr  = 0;
    std::string m_lastTrappedSym;
    uint32_t    m_lastError      = 0u;
    uint32_t    m_dynThunkCursor = 0x70008000u;
    uint32_t    m_heapCursor = 0x20000000u;
    uint32_t    m_heapEnd    = 0x22000000u;
    std::unordered_map<uint32_t, uint32_t> m_allocSizes;

    uint32_t allocGuest(uint32_t size) {
        if (size == 0) size = 16;
        uint32_t aligned = (size + 15u) & ~15u;
        if (m_heapCursor + aligned > m_heapEnd) return 0u;
        uint32_t ptr = m_heapCursor;
        m_heapCursor += aligned;
        m_allocSizes[ptr] = size;
        return ptr;
    }
};

#endif // SH3_THUNK_DISPATCHER_H
