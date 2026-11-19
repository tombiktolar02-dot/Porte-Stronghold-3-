#include "thunk_dispatcher.h"
#include <android/log.h>
#include <time.h>

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
    LOGI("Caught Thunk Trap at 0x%08X -> %s (caller ret: 0x%08X)",
         thunkAddr, m_lastTrappedSym.c_str(), returnAddr);
    return true;
}

bool ThunkDispatcher::handleThunkCall(IX86CPU* cpu, uint32_t thunkAddr, uint32_t returnAddr, uint32_t& outNextEip) {
    if (!cpu) return false;
    std::string sym = resolveAddress(thunkAddr);
    uint32_t esp = cpu->readRegister(X86Reg::ESP);

    if (sym == "kernel32.dll!GetSystemTimeAsFileTime") {
        uint32_t lpFileTime = 0;
        cpu->readGuestMemory(esp + 4, &lpFileTime, 4);
        struct timespec ts{};
        clock_gettime(CLOCK_REALTIME, &ts);
        uint64_t ft = (static_cast<uint64_t>(ts.tv_sec) + 11644473600ULL) * 10000000ULL
                    + static_cast<uint64_t>(ts.tv_nsec / 100);
        if (lpFileTime != 0) {
            cpu->writeGuestMemory(lpFileTime, &ft, 8);
        }
        cpu->writeRegister(X86Reg::ESP, esp + 8); // retAddr + 1 stdcall arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCurrentProcessId") {
        cpu->writeRegister(X86Reg::EAX, 0x00000543u);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCurrentThreadId") {
        cpu->writeRegister(X86Reg::EAX, 0x00000001u);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetTickCount") {
        struct timespec ts{};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint32_t ms = static_cast<uint32_t>(ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL);
        cpu->writeRegister(X86Reg::EAX, ms);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!QueryPerformanceCounter") {
        uint32_t lpPerfCount = 0;
        cpu->readGuestMemory(esp + 4, &lpPerfCount, 4);
        struct timespec ts{};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t qpc = static_cast<uint64_t>(ts.tv_sec) * 10000000ULL
                     + static_cast<uint64_t>(ts.tv_nsec / 100);
        if (lpPerfCount != 0) {
            cpu->writeGuestMemory(lpPerfCount, &qpc, 8);
        }
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // retAddr + 1 stdcall arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    return false; // Unimplemented Win32 API -> stop cleanly
}
