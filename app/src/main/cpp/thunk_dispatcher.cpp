#include "thunk_dispatcher.h"
#include <android/log.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "SH3_DISPATCH", __VA_ARGS__)

void ThunkDispatcher::buildReverseMap(const std::unordered_map<std::string, uint32_t>& forwardThunkTable) {
    m_reverseMap.clear();
    m_reverseMap.reserve(forwardThunkTable.size());
    for (const auto& kv : forwardThunkTable) {
        m_reverseMap[kv.second] = kv.first;
    }
}

std::string ThunkDispatcher::resolveAddress(uint32_t thunkAddr) const {
    auto it = m_reverseMap.find(thunkAddr);
    if (it != m_reverseMap.end()) return it->second;
    return "UNKNOWN_THUNK";
}

bool ThunkDispatcher::onThunkTrap(uint32_t thunkAddr, uint32_t returnAddr) {
    m_lastTrappedAddr = thunkAddr;
    m_lastReturnAddr  = returnAddr;
    m_lastTrappedSym  = resolveAddress(thunkAddr);
    LOGI("Caught Thunk Trap at 0x%08X -> %s ( caller ret: 0x%08X )",
         thunkAddr, m_lastTrappedSym.c_str(), returnAddr);
    return true; // Stop execution cleanly on first external call in Stage 5
}
