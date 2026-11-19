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

    if (sym == "kernel32.dll!GetStartupInfoW") {
        uint32_t lpStartupInfo = 0;
        cpu->readGuestMemory(esp + 4, &lpStartupInfo, 4);
        if (lpStartupInfo != 0) {
            uint8_t si[68] = {};
            uint32_t cb = 68u;
            si[0] = static_cast<uint8_t>(cb & 0xFFu);
            si[1] = static_cast<uint8_t>((cb >> 8) & 0xFFu);
            cpu->writeGuestMemory(lpStartupInfo, si, sizeof(si));
        }
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetModuleHandleW" || sym == "kernel32.dll!GetModuleHandleA") {
        uint32_t lpModuleName = 0;
        cpu->readGuestMemory(esp + 4, &lpModuleName, 4);
        uint32_t hMod = (lpModuleName == 0) ? 0x00400000u : 0u;
        cpu->writeRegister(X86Reg::EAX, hMod);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!HeapSetInformation") {
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 20); // stdcall: retAddr + 4 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__set_app_type" ||
        sym == "msvcr100.dll!__setusermatherr" ||
        sym == "msvcr100.dll!_configthreadlocale") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl: caller cleans args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!InterlockedCompareExchange") {
        uint32_t destPtr = 0, exchange = 0, comperand = 0;
        cpu->readGuestMemory(esp + 4,  &destPtr,   4);
        cpu->readGuestMemory(esp + 8,  &exchange,  4);
        cpu->readGuestMemory(esp + 12, &comperand, 4);
        uint32_t oldVal = 0;
        if (destPtr != 0) {
            cpu->readGuestMemory(destPtr, &oldVal, 4);
            if (oldVal == comperand) {
                cpu->writeGuestMemory(destPtr, &exchange, 4);
            }
        }
        cpu->writeRegister(X86Reg::EAX, oldVal);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: retAddr + 3 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!InterlockedExchange") {
        uint32_t targetPtr = 0, newVal = 0;
        cpu->readGuestMemory(esp + 4, &targetPtr, 4);
        cpu->readGuestMemory(esp + 8, &newVal,    4);
        uint32_t oldVal = 0;
        if (targetPtr != 0) {
            cpu->readGuestMemory(targetPtr, &oldVal, 4);
            cpu->writeGuestMemory(targetPtr, &newVal, 4);
        }
        cpu->writeRegister(X86Reg::EAX, oldVal);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: retAddr + 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!Sleep") {
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_initterm_e") {
        cpu->writeRegister(X86Reg::EAX, 0u); // 0 = success
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl: caller cleans args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_initterm") {
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl: caller cleans args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_ismbblead") {
        cpu->writeRegister(X86Reg::EAX, 0u); // ASCII char is not a multibyte lead byte
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl: caller cleans args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!LoadLibraryA") {
        uint32_t namePtr = 0;
        cpu->readGuestMemory(esp + 4, &namePtr, 4);
        char nameBuf[128] = {};
        if (namePtr != 0) {
            cpu->readGuestMemory(namePtr, nameBuf, sizeof(nameBuf) - 1);
            nameBuf[sizeof(nameBuf) - 1] = '\0';
        }
        cpu->writeRegister(X86Reg::EAX, 0x61000000u);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym + "(\"" + std::string(nameBuf) + "\")");
        return true;
    }

    if (sym == "kernel32.dll!LoadLibraryW") {
        cpu->writeRegister(X86Reg::EAX, 0x61000000u);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!FreeLibrary") {
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_controlfp" || sym == "msvcr100.dll!_control87") {
        cpu->writeRegister(X86Reg::EAX, 0x0008001Fu); // Default x87 FPU control word
        cpu->writeRegister(X86Reg::ESP, esp + 4);     // cdecl: caller cleans args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    return false; // Unimplemented Win32 API -> stop cleanly
}
