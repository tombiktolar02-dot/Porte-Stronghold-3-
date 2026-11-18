#ifndef SH3_THUNK_DISPATCHER_H
#define SH3_THUNK_DISPATCHER_H

#include <cstdint>
#include <string>
#include <unordered_map>

class ThunkDispatcher {
public:
    void buildReverseMap(const std::unordered_map<std::string, uint32_t>& forwardThunkTable);
    std::string resolveAddress(uint32_t thunkAddr) const;
    size_t count() const { return m_reverseMap.size(); }

    bool onThunkTrap(uint32_t thunkAddr, uint32_t returnAddr);
    uint32_t lastTrappedAddress() const { return m_lastTrappedAddr; }
    const std::string& lastTrappedSymbol() const { return m_lastTrappedSym; }

private:
    std::unordered_map<uint32_t, std::string> m_reverseMap;
    uint32_t    m_lastTrappedAddr = 0;
    uint32_t    m_lastReturnAddr  = 0;
    std::string m_lastTrappedSym;
};

#endif // SH3_THUNK_DISPATCHER_H
