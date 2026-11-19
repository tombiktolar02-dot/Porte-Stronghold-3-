#include <sys/stat.h>
#include <cstdio>
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

    if (sym == "kernel32.dll!DecodePointer" || sym == "kernel32.dll!EncodePointer") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_lock" || sym == "msvcr100.dll!_unlock") {
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl: caller cleans args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__dllonexit" || sym == "msvcr100.dll!_onexit") {
        uint32_t funcPtr = 0;
        cpu->readGuestMemory(esp + 4, &funcPtr, 4);
        cpu->writeRegister(X86Reg::EAX, funcPtr); // return registered func pointer
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl: caller cleans args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!malloc" ||
        sym == "msvcr100.dll!??2@YAPAXI@Z" ||
        sym == "msvcr100.dll!??_U@YAPAXI@Z") {
        uint32_t sz = 0;
        cpu->readGuestMemory(esp + 4, &sz, 4);
        uint32_t ptr = allocGuest(sz);
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!calloc" || sym == "msvcr100.dll!_calloc_crt") {
        uint32_t num = 0, sz = 0;
        cpu->readGuestMemory(esp + 4, &num, 4);
        cpu->readGuestMemory(esp + 8, &sz,  4);
        uint32_t total = num * sz;
        uint32_t ptr = allocGuest(total);
        if (ptr != 0 && total > 0) {
            std::vector<uint8_t> zeros(total, 0);
            cpu->writeGuestMemory(ptr, zeros.data(), total);
        }
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!realloc") {
        uint32_t oldPtr = 0, newSz = 0;
        cpu->readGuestMemory(esp + 4, &oldPtr, 4);
        cpu->readGuestMemory(esp + 8, &newSz,  4);
        uint32_t newPtr = allocGuest(newSz);
        if (oldPtr != 0 && newPtr != 0) {
            auto it = m_allocSizes.find(oldPtr);
            uint32_t copySz = (it != m_allocSizes.end()) ? it->second : 0u;
            if (copySz > newSz) copySz = newSz;
            if (copySz > 0) {
                std::vector<uint8_t> tmp(copySz);
                cpu->readGuestMemory(oldPtr, tmp.data(), copySz);
                cpu->writeGuestMemory(newPtr, tmp.data(), copySz);
            }
        }
        cpu->writeRegister(X86Reg::EAX, newPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!free" ||
        sym == "msvcr100.dll!??3@YAXPAX@Z" ||
        sym == "msvcr100.dll!??_V@YAXPAX@Z") {
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_msize" || sym == "msvcr100.dll!_aligned_msize") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        uint32_t sz = 0;
        auto it = m_allocSizes.find(ptr);
        if (it != m_allocSizes.end()) sz = it->second;
        cpu->writeRegister(X86Reg::EAX, sz);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_aligned_malloc") {
        uint32_t sz = 0;
        cpu->readGuestMemory(esp + 4, &sz, 4);
        uint32_t ptr = allocGuest(sz);
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_aligned_free") {
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetProcAddress") {
        uint32_t hMod = 0, namePtr = 0;
        cpu->readGuestMemory(esp + 4, &hMod,    4);
        cpu->readGuestMemory(esp + 8, &namePtr, 4);
        std::string procStr;
        if (namePtr > 0xFFFFu) {
            char nameBuf[128] = {};
            cpu->readGuestMemory(namePtr, nameBuf, sizeof(nameBuf) - 1);
            nameBuf[sizeof(nameBuf) - 1] = '\0';
            procStr = std::string("\"") + nameBuf + "\"";
        } else {
            procStr = "#" + std::to_string(namePtr);
        }
        uint32_t resolvedAddr = 0u;
        if (namePtr > 0xFFFFu) {
            std::string rawName = procStr.substr(1, procStr.size() - 2);
            std::string suffix = "!" + rawName;
            for (const auto& kv : m_reverseMap) {
                if (kv.second.size() >= suffix.size() &&
                    kv.second.compare(kv.second.size() - suffix.size(), suffix.size(), suffix) == 0) {
                    resolvedAddr = kv.first;
                    break;
                }
            }
            if (resolvedAddr == 0u && m_dynThunkCursor < 0x7000E000u) {
                resolvedAddr = m_dynThunkCursor;
                m_dynThunkCursor += 0x10u;
                m_reverseMap[resolvedAddr] = "dynamic!" + rawName;
            }
        }
        cpu->writeRegister(X86Reg::EAX, resolvedAddr);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: retAddr + 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym + "(" + procStr + ")");
        return true;
    }

    if (sym == "kernel32.dll!GetLastError") {
        cpu->writeRegister(X86Reg::EAX, m_lastError);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: retAddr only
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!SetLastError") {
        uint32_t errCode = 0;
        cpu->readGuestMemory(esp + 4, &errCode, 4);
        m_lastError = errCode;
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "user32.dll!EnumDisplayDevicesA" || sym == "dynamic!EnumDisplayDevicesA") {
        cpu->writeRegister(X86Reg::EAX, 0u);       // FALSE: no more display devices
        cpu->writeRegister(X86Reg::ESP, esp + 20); // stdcall: retAddr + 4 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "user32.dll!EnumDisplayMonitors" || sym == "dynamic!EnumDisplayMonitors") {
        cpu->writeRegister(X86Reg::EAX, 1u);       // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 20); // stdcall: retAddr + 4 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "user32.dll!EnumDisplaySettingsA" || sym == "dynamic!EnumDisplaySettingsA") {
        uint32_t iModeNum = 0, lpDevMode = 0;
        cpu->readGuestMemory(esp + 8,  &iModeNum,  4);
        cpu->readGuestMemory(esp + 12, &lpDevMode, 4);
        uint32_t retVal = 0u;
        if (iModeNum == 0u || iModeNum == 0xFFFFFFFFu || iModeNum == 0xFFFFFFFEu) {
            if (lpDevMode != 0) {
                uint32_t dmFields = 0x005C0000u; // BITSPERPEL | PELSWIDTH | PELSHEIGHT | DISPLAYFREQUENCY
                uint32_t bpp = 32u, w = 1280u, h = 720u, flags = 0u, freq = 60u;
                cpu->writeGuestMemory(lpDevMode + 40,  &dmFields, 4);
                cpu->writeGuestMemory(lpDevMode + 104, &bpp,      4);
                cpu->writeGuestMemory(lpDevMode + 108, &w,        4);
                cpu->writeGuestMemory(lpDevMode + 112, &h,        4);
                cpu->writeGuestMemory(lpDevMode + 116, &flags,    4);
                cpu->writeGuestMemory(lpDevMode + 120, &freq,     4);
            }
            retVal = 1u; // TRUE
        }
        cpu->writeRegister(X86Reg::EAX, retVal);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: retAddr + 3 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!InterlockedIncrement") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        uint32_t val = 0;
        if (ptr != 0) {
            cpu->readGuestMemory(ptr, &val, 4);
            val += 1u;
            cpu->writeGuestMemory(ptr, &val, 4);
        }
        cpu->writeRegister(X86Reg::EAX, val);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!InterlockedDecrement") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        uint32_t val = 0;
        if (ptr != 0) {
            cpu->readGuestMemory(ptr, &val, 4);
            val -= 1u;
            cpu->writeGuestMemory(ptr, &val, 4);
        }
        cpu->writeRegister(X86Reg::EAX, val);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!InterlockedExchangeAdd") {
        uint32_t ptr = 0, addVal = 0;
        cpu->readGuestMemory(esp + 4, &ptr,    4);
        cpu->readGuestMemory(esp + 8, &addVal, 4);
        uint32_t oldVal = 0;
        if (ptr != 0) {
            cpu->readGuestMemory(ptr, &oldVal, 4);
            uint32_t newVal = oldVal + addVal;
            cpu->writeGuestMemory(ptr, &newVal, 4);
        }
        cpu->writeRegister(X86Reg::EAX, oldVal);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: retAddr + 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!InitializeCriticalSection") {
        uint32_t csPtr = 0;
        cpu->readGuestMemory(esp + 4, &csPtr, 4);
        if (csPtr != 0) {
            uint8_t zeros[24] = {};
            cpu->writeGuestMemory(csPtr, zeros, sizeof(zeros));
        }
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!InitializeCriticalSectionAndSpinCount") {
        uint32_t csPtr = 0;
        cpu->readGuestMemory(esp + 4, &csPtr, 4);
        if (csPtr != 0) {
            uint8_t zeros[24] = {};
            cpu->writeGuestMemory(csPtr, zeros, sizeof(zeros));
        }
        cpu->writeRegister(X86Reg::EAX, 1u);       // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: retAddr + 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!EnterCriticalSection" ||
        sym == "kernel32.dll!LeaveCriticalSection" ||
        sym == "kernel32.dll!DeleteCriticalSection") {
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!TryEnterCriticalSection") {
        cpu->writeRegister(X86Reg::EAX, 1u);      // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!memcpy" || sym == "msvcr100.dll!memmove") {
        uint32_t dst = 0, src = 0, cnt = 0;
        cpu->readGuestMemory(esp + 4,  &dst, 4);
        cpu->readGuestMemory(esp + 8,  &src, 4);
        cpu->readGuestMemory(esp + 12, &cnt, 4);
        if (dst != 0 && src != 0 && cnt > 0) {
            std::vector<uint8_t> buf(cnt);
            cpu->readGuestMemory(src, buf.data(), cnt);
            cpu->writeGuestMemory(dst, buf.data(), cnt);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!memcpy_s" || sym == "msvcr100.dll!memmove_s") {
        uint32_t dst = 0, dstSz = 0, src = 0, cnt = 0;
        cpu->readGuestMemory(esp + 4,  &dst,   4);
        cpu->readGuestMemory(esp + 8,  &dstSz, 4);
        cpu->readGuestMemory(esp + 12, &src,   4);
        cpu->readGuestMemory(esp + 16, &cnt,   4);
        uint32_t copyLen = (cnt <= dstSz) ? cnt : dstSz;
        if (dst != 0 && src != 0 && copyLen > 0) {
            std::vector<uint8_t> buf(copyLen);
            cpu->readGuestMemory(src, buf.data(), copyLen);
            cpu->writeGuestMemory(dst, buf.data(), copyLen);
        }
        cpu->writeRegister(X86Reg::EAX, 0u); // errno_t = 0 (success)
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!memset") {
        uint32_t dst = 0, val = 0, cnt = 0;
        cpu->readGuestMemory(esp + 4,  &dst, 4);
        cpu->readGuestMemory(esp + 8,  &val, 4);
        cpu->readGuestMemory(esp + 12, &cnt, 4);
        if (dst != 0 && cnt > 0) {
            std::vector<uint8_t> buf(cnt, static_cast<uint8_t>(val & 0xFFu));
            cpu->writeGuestMemory(dst, buf.data(), cnt);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!memcmp") {
        uint32_t a = 0, b = 0, cnt = 0;
        cpu->readGuestMemory(esp + 4,  &a,   4);
        cpu->readGuestMemory(esp + 8,  &b,   4);
        cpu->readGuestMemory(esp + 12, &cnt, 4);
        int32_t res = 0;
        if (a != 0 && b != 0 && cnt > 0) {
            std::vector<uint8_t> ba(cnt), bb(cnt);
            cpu->readGuestMemory(a, ba.data(), cnt);
            cpu->readGuestMemory(b, bb.data(), cnt);
            for (uint32_t i = 0; i < cnt; ++i) {
                if (ba[i] != bb[i]) {
                    res = (ba[i] < bb[i]) ? -1 : 1;
                    break;
                }
            }
        }
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res));
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    auto readCStr = [&](uint32_t addr, size_t maxLen = 4096) -> std::string {
        std::string res;
        if (addr == 0) return res;
        for (size_t i = 0; i < maxLen; ++i) {
            uint8_t c = 0;
            if (!cpu->readGuestMemory(addr + static_cast<uint32_t>(i), &c, 1) || c == 0) break;
            res.push_back(static_cast<char>(c));
        }
        return res;
    };

    if (sym == "msvcr100.dll!tolower" || sym == "msvcr100.dll!towlower") {
        uint32_t ch = 0;
        cpu->readGuestMemory(esp + 4, &ch, 4);
        if (ch >= 0x41u && ch <= 0x5Au) ch += 32u;
        cpu->writeRegister(X86Reg::EAX, ch);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!toupper" || sym == "msvcr100.dll!towupper") {
        uint32_t ch = 0;
        cpu->readGuestMemory(esp + 4, &ch, 4);
        if (ch >= 0x61u && ch <= 0x7Au) ch -= 32u;
        cpu->writeRegister(X86Reg::EAX, ch);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strlen") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        std::string str = readCStr(ptr, 65536);
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(str.size()));
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strcmp" || sym == "msvcr100.dll!strncmp" ||
        sym == "msvcr100.dll!_stricmp" || sym == "msvcr100.dll!_strcmpi" ||
        sym == "msvcr100.dll!_strnicmp") {
        uint32_t pA = 0, pB = 0, maxN = 0xFFFFFFFFu;
        cpu->readGuestMemory(esp + 4, &pA, 4);
        cpu->readGuestMemory(esp + 8, &pB, 4);
        bool hasN = (sym == "msvcr100.dll!strncmp" || sym == "msvcr100.dll!_strnicmp");
        bool nocase = (sym == "msvcr100.dll!_stricmp" || sym == "msvcr100.dll!_strcmpi" || sym == "msvcr100.dll!_strnicmp");
        if (hasN) cpu->readGuestMemory(esp + 12, &maxN, 4);
        std::string a = readCStr(pA, hasN ? maxN : 4096);
        std::string b = readCStr(pB, hasN ? maxN : 4096);
        int32_t res = 0;
        size_t len = (a.size() < b.size()) ? a.size() : b.size();
        if (hasN && len > maxN) len = maxN;
        for (size_t i = 0; i < len; ++i) {
            uint8_t ca = static_cast<uint8_t>(a[i]);
            uint8_t cb = static_cast<uint8_t>(b[i]);
            if (nocase) {
                if (ca >= 0x41u && ca <= 0x5Au) ca += 32u;
                if (cb >= 0x41u && cb <= 0x5Au) cb += 32u;
            }
            if (ca != cb) { res = (ca < cb) ? -1 : 1; break; }
        }
        if (res == 0 && (!hasN || len < maxN)) {
            if (a.size() != b.size()) res = (a.size() < b.size()) ? -1 : 1;
        }
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res));
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strcpy") {
        uint32_t dst = 0, src = 0;
        cpu->readGuestMemory(esp + 4, &dst, 4);
        cpu->readGuestMemory(esp + 8, &src, 4);
        std::string sSrc = readCStr(src, 65536);
        if (dst != 0) {
            cpu->writeGuestMemory(dst, sSrc.c_str(), sSrc.size() + 1);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strncpy") {
        uint32_t dst = 0, src = 0, n = 0;
        cpu->readGuestMemory(esp + 4,  &dst, 4);
        cpu->readGuestMemory(esp + 8,  &src, 4);
        cpu->readGuestMemory(esp + 12, &n,   4);
        if (dst != 0 && n > 0) {
            std::string sSrc = readCStr(src, n);
            std::vector<uint8_t> outBuf(n, 0);
            size_t copyLen = (sSrc.size() < n) ? sSrc.size() : n;
            for (size_t i = 0; i < copyLen; ++i) outBuf[i] = static_cast<uint8_t>(sSrc[i]);
            cpu->writeGuestMemory(dst, outBuf.data(), n);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strchr" || sym == "msvcr100.dll!strrchr") {
        uint32_t ptr = 0, chVal = 0;
        cpu->readGuestMemory(esp + 4, &ptr,   4);
        cpu->readGuestMemory(esp + 8, &chVal, 4);
        char target = static_cast<char>(chVal & 0xFFu);
        std::string str = readCStr(ptr, 65536);
        uint32_t found = 0u;
        if (target == 0) {
            found = ptr + static_cast<uint32_t>(str.size());
        } else {
            size_t pos = (sym == "msvcr100.dll!strchr") ? str.find(target) : str.rfind(target);
            if (pos != std::string::npos) found = ptr + static_cast<uint32_t>(pos);
        }
        cpu->writeRegister(X86Reg::EAX, found);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strstr") {
        uint32_t pHay = 0, pNeedle = 0;
        cpu->readGuestMemory(esp + 4, &pHay,    4);
        cpu->readGuestMemory(esp + 8, &pNeedle, 4);
        std::string hay = readCStr(pHay, 65536);
        std::string needle = readCStr(pNeedle, 4096);
        uint32_t found = 0u;
        size_t pos = hay.find(needle);
        if (pos != std::string::npos) found = pHay + static_cast<uint32_t>(pos);
        cpu->writeRegister(X86Reg::EAX, found);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!TlsAlloc") {
        uint32_t idx = m_nextTlsIndex++;
        m_tlsSlots[idx] = 0u;
        cpu->writeRegister(X86Reg::EAX, idx);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!TlsFree") {
        uint32_t idx = 0;
        cpu->readGuestMemory(esp + 4, &idx, 4);
        m_tlsSlots.erase(idx);
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!TlsGetValue") {
        uint32_t idx = 0;
        cpu->readGuestMemory(esp + 4, &idx, 4);
        uint32_t val = 0u;
        auto it = m_tlsSlots.find(idx);
        if (it != m_tlsSlots.end()) val = it->second;
        m_lastError = 0u;
        cpu->writeRegister(X86Reg::EAX, val);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!TlsSetValue") {
        uint32_t idx = 0, val = 0;
        cpu->readGuestMemory(esp + 4, &idx, 4);
        cpu->readGuestMemory(esp + 8, &val, 4);
        m_tlsSlots[idx] = val;
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!VirtualAlloc") {
        uint32_t dwSize = 0;
        cpu->readGuestMemory(esp + 8, &dwSize, 4);
        if (dwSize == 0) dwSize = 4096u;
        uint32_t ptr = allocGuest(dwSize);
        if (ptr != 0) {
            std::vector<uint8_t> zeros(dwSize, 0);
            cpu->writeGuestMemory(ptr, zeros.data(), dwSize);
        }
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 20); // stdcall: 4 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!VirtualFree") {
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!memchr") {
        uint32_t ptr = 0, val = 0, num = 0;
        cpu->readGuestMemory(esp + 4,  &ptr, 4);
        cpu->readGuestMemory(esp + 8,  &val, 4);
        cpu->readGuestMemory(esp + 12, &num, 4);
        uint32_t found = 0u;
        if (ptr != 0 && num > 0) {
            std::vector<uint8_t> buf(num);
            cpu->readGuestMemory(ptr, buf.data(), num);
            uint8_t target = static_cast<uint8_t>(val & 0xFFu);
            for (uint32_t i = 0; i < num; ++i) {
                if (buf[i] == target) {
                    found = ptr + i;
                    break;
                }
            }
        }
        cpu->writeRegister(X86Reg::EAX, found);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strcat" || sym == "msvcr100.dll!strncat") {
        uint32_t dst = 0, src = 0, maxN = 0xFFFFFFFFu;
        cpu->readGuestMemory(esp + 4, &dst, 4);
        cpu->readGuestMemory(esp + 8, &src, 4);
        bool hasN = (sym == "msvcr100.dll!strncat");
        if (hasN) cpu->readGuestMemory(esp + 12, &maxN, 4);
        if (dst != 0 && src != 0) {
            std::string sDst = readCStr(dst, 65536);
            std::string sSrc = readCStr(src, hasN ? maxN : 65536);
            if (hasN && sSrc.size() > maxN) sSrc.resize(maxN);
            std::string combined = sDst + sSrc;
            cpu->writeGuestMemory(dst, combined.c_str(), combined.size() + 1);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!wcslen") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        uint32_t len = 0;
        if (ptr != 0) {
            for (uint32_t i = 0; i < 65536; ++i) {
                uint16_t wc = 0;
                if (!cpu->readGuestMemory(ptr + i * 2, &wc, 2) || wc == 0) break;
                ++len;
            }
        }
        cpu->writeRegister(X86Reg::EAX, len);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!wcscmp") {
        uint32_t pA = 0, pB = 0;
        cpu->readGuestMemory(esp + 4, &pA, 4);
        cpu->readGuestMemory(esp + 8, &pB, 4);
        int32_t res = 0;
        if (pA != 0 && pB != 0) {
            for (uint32_t i = 0; i < 65536; ++i) {
                uint16_t ca = 0, cb = 0;
                cpu->readGuestMemory(pA + i * 2, &ca, 2);
                cpu->readGuestMemory(pB + i * 2, &cb, 2);
                if (ca != cb) { res = (ca < cb) ? -1 : 1; break; }
                if (ca == 0) break;
            }
        }
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res));
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!wcscpy") {
        uint32_t dst = 0, src = 0;
        cpu->readGuestMemory(esp + 4, &dst, 4);
        cpu->readGuestMemory(esp + 8, &src, 4);
        if (dst != 0 && src != 0) {
            for (uint32_t i = 0; i < 65536; ++i) {
                uint16_t wc = 0;
                cpu->readGuestMemory(src + i * 2, &wc, 2);
                cpu->writeGuestMemory(dst + i * 2, &wc, 2);
                if (wc == 0) break;
            }
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!isalpha" || sym == "msvcr100.dll!isdigit" ||
        sym == "msvcr100.dll!isalnum" || sym == "msvcr100.dll!isspace" ||
        sym == "msvcr100.dll!isupper" || sym == "msvcr100.dll!islower" ||
        sym == "msvcr100.dll!isxdigit") {
        uint32_t ch = 0;
        cpu->readGuestMemory(esp + 4, &ch, 4);
        uint8_t c = static_cast<uint8_t>(ch & 0xFFu);
        uint32_t ok = 0u;
        if (sym == "msvcr100.dll!isalpha")  ok = ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) ? 1u : 0u;
        if (sym == "msvcr100.dll!isdigit")  ok = (c >= '0' && c <= '9') ? 1u : 0u;
        if (sym == "msvcr100.dll!isalnum")  ok = ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) ? 1u : 0u;
        if (sym == "msvcr100.dll!isspace")  ok = (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f') ? 1u : 0u;
        if (sym == "msvcr100.dll!isupper")  ok = (c >= 'A' && c <= 'Z') ? 1u : 0u;
        if (sym == "msvcr100.dll!islower")  ok = (c >= 'a' && c <= 'z') ? 1u : 0u;
        if (sym == "msvcr100.dll!isxdigit") ok = ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) ? 1u : 0u;
        cpu->writeRegister(X86Reg::EAX, ok);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCommandLineA") {
        const char* cmd = "Stronghold3.exe";
        uint32_t ptr = allocGuest(32);
        if (ptr != 0) cpu->writeGuestMemory(ptr, cmd, 16);
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCommandLineW") {
        const char* cmd = "Stronghold3.exe";
        uint16_t wcmd[16] = {};
        for (int i = 0; i < 16; ++i) wcmd[i] = static_cast<uint16_t>(cmd[i]);
        uint32_t ptr = allocGuest(64);
        if (ptr != 0) cpu->writeGuestMemory(ptr, wcmd, sizeof(wcmd));
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "shell32.dll!CommandLineToArgvW") {
        uint32_t pNumArgs = 0;
        cpu->readGuestMemory(esp + 8, &pNumArgs, 4);
        const char* cmd = "Stronghold3.exe";
        uint16_t wcmd[16] = {};
        for (int i = 0; i < 16; ++i) wcmd[i] = static_cast<uint16_t>(cmd[i]);
        uint32_t strPtr = allocGuest(64);
        uint32_t arrPtr = allocGuest(16);
        if (strPtr != 0 && arrPtr != 0) {
            cpu->writeGuestMemory(strPtr, wcmd, sizeof(wcmd));
            uint32_t argv[2] = { strPtr, 0u };
            cpu->writeGuestMemory(arrPtr, argv, sizeof(argv));
        }
        if (pNumArgs != 0) {
            uint32_t argc = 1u;
            cpu->writeGuestMemory(pNumArgs, &argc, 4);
        }
        cpu->writeRegister(X86Reg::EAX, arrPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!LocalFree") {
        cpu->writeRegister(X86Reg::EAX, 0u);      // NULL = success
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetModuleHandleA" || sym == "kernel32.dll!GetModuleHandleW") {
        uint32_t namePtr = 0;
        cpu->readGuestMemory(esp + 4, &namePtr, 4);
        uint32_t hMod = (namePtr == 0u) ? 0x00400000u : 0x60000000u;
        cpu->writeRegister(X86Reg::EAX, hMod);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetModuleFileNameA") {
        uint32_t bufPtr = 0, nSize = 0;
        cpu->readGuestMemory(esp + 8,  &bufPtr, 4);
        cpu->readGuestMemory(esp + 12, &nSize,  4);
        std::string path = "C:\\Stronghold3\\Stronghold3.exe";
        uint32_t written = 0;
        if (bufPtr != 0 && nSize > 1) {
            written = (path.size() < nSize - 1) ? static_cast<uint32_t>(path.size()) : (nSize - 1);
            cpu->writeGuestMemory(bufPtr, path.c_str(), written);
            uint8_t nul = 0;
            cpu->writeGuestMemory(bufPtr + written, &nul, 1);
        }
        cpu->writeRegister(X86Reg::EAX, written);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetModuleFileNameW") {
        uint32_t bufPtr = 0, nSize = 0;
        cpu->readGuestMemory(esp + 8,  &bufPtr, 4);
        cpu->readGuestMemory(esp + 12, &nSize,  4);
        std::string path = "C:\\Stronghold3\\Stronghold3.exe";
        uint32_t written = 0;
        if (bufPtr != 0 && nSize > 1) {
            written = (path.size() < nSize - 1) ? static_cast<uint32_t>(path.size()) : (nSize - 1);
            std::vector<uint16_t> wbuf(written + 1, 0);
            for (uint32_t i = 0; i < written; ++i) wbuf[i] = static_cast<uint16_t>(path[i]);
            cpu->writeGuestMemory(bufPtr, wbuf.data(), (written + 1) * 2);
        }
        cpu->writeRegister(X86Reg::EAX, written);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_chdir" || sym == "msvcr100.dll!_wchdir") {
        cpu->writeRegister(X86Reg::EAX, 0u); // 0 = success
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_getcwd") {
        uint32_t bufPtr = 0, maxLen = 0;
        cpu->readGuestMemory(esp + 4, &bufPtr, 4);
        cpu->readGuestMemory(esp + 8, &maxLen, 4);
        std::string dir = "C:\\Stronghold3";
        if (bufPtr == 0) bufPtr = allocGuest(maxLen > 0 ? maxLen : 260u);
        if (bufPtr != 0) {
            uint32_t limit = (maxLen > 1) ? (maxLen - 1) : static_cast<uint32_t>(dir.size());
            uint32_t written = (dir.size() < limit) ? static_cast<uint32_t>(dir.size()) : limit;
            cpu->writeGuestMemory(bufPtr, dir.c_str(), written);
            uint8_t nul = 0;
            cpu->writeGuestMemory(bufPtr + written, &nul, 1);
        }
        cpu->writeRegister(X86Reg::EAX, bufPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!SetCurrentDirectoryA" || sym == "kernel32.dll!SetCurrentDirectoryW") {
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCurrentDirectoryA") {
        uint32_t nBufLen = 0, lpBuf = 0;
        cpu->readGuestMemory(esp + 4, &nBufLen, 4);
        cpu->readGuestMemory(esp + 8, &lpBuf,   4);
        std::string dir = "C:\\Stronghold3";
        uint32_t written = 0;
        if (lpBuf != 0 && nBufLen > 1) {
            written = (dir.size() < nBufLen - 1) ? static_cast<uint32_t>(dir.size()) : (nBufLen - 1);
            cpu->writeGuestMemory(lpBuf, dir.c_str(), written);
            uint8_t nul = 0;
            cpu->writeGuestMemory(lpBuf + written, &nul, 1);
        }
        cpu->writeRegister(X86Reg::EAX, written);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCurrentDirectoryW") {
        uint32_t nBufLen = 0, lpBuf = 0;
        cpu->readGuestMemory(esp + 4, &nBufLen, 4);
        cpu->readGuestMemory(esp + 8, &lpBuf,   4);
        std::string dir = "C:\\Stronghold3";
        uint32_t written = 0;
        if (lpBuf != 0 && nBufLen > 1) {
            written = (dir.size() < nBufLen - 1) ? static_cast<uint32_t>(dir.size()) : (nBufLen - 1);
            std::vector<uint16_t> wbuf(written + 1, 0);
            for (uint32_t i = 0; i < written; ++i) wbuf[i] = static_cast<uint16_t>(dir[i]);
            cpu->writeGuestMemory(lpBuf, wbuf.data(), (written + 1) * 2);
        }
        cpu->writeRegister(X86Reg::EAX, written);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    auto formatGuestPrintf = [&](uint32_t fmtAddr, uint32_t vaAddr) -> std::string {
        std::string fmt = readCStr(fmtAddr, 4096);
        std::string out;
        uint32_t curVa = vaAddr;
        for (size_t i = 0; i < fmt.size(); ++i) {
            if (fmt[i] != '%') {
                out.push_back(fmt[i]);
                continue;
            }
            if (i + 1 < fmt.size() && fmt[i + 1] == '%') {
                out.push_back('%');
                ++i;
                continue;
            }
            std::string spec = "%";
            ++i;
            while (i < fmt.size() && (fmt[i] == '-' || fmt[i] == '+' || fmt[i] == ' ' || fmt[i] == '#' || fmt[i] == '0')) {
                spec.push_back(fmt[i++]);
            }
            if (i < fmt.size() && fmt[i] == '*') {
                int32_t w = 0;
                cpu->readGuestMemory(curVa, &w, 4); curVa += 4;
                spec += std::to_string(w);
                ++i;
            } else {
                while (i < fmt.size() && fmt[i] >= '0' && fmt[i] <= '9') spec.push_back(fmt[i++]);
            }
            if (i < fmt.size() && fmt[i] == '.') {
                spec.push_back(fmt[i++]);
                if (i < fmt.size() && fmt[i] == '*') {
                    int32_t pr = 0;
                    cpu->readGuestMemory(curVa, &pr, 4); curVa += 4;
                    spec += std::to_string(pr);
                    ++i;
                } else {
                    while (i < fmt.size() && fmt[i] >= '0' && fmt[i] <= '9') spec.push_back(fmt[i++]);
                }
            }
            bool is64 = false;
            if (i + 2 < fmt.size() && fmt[i] == 'I' && fmt[i+1] == '6' && fmt[i+2] == '4') {
                is64 = true; i += 3;
            } else if (i + 1 < fmt.size() && fmt[i] == 'l' && fmt[i+1] == 'l') {
                is64 = true; i += 2;
            } else if (i < fmt.size() && (fmt[i] == 'l' || fmt[i] == 'h' || fmt[i] == 'z')) {
                ++i;
            }
            if (i >= fmt.size()) break;
            char t = fmt[i];
            char tmp[128] = {};
            if (t == 's') {
                uint32_t strPtr = 0;
                cpu->readGuestMemory(curVa, &strPtr, 4); curVa += 4;
                out += (strPtr != 0) ? readCStr(strPtr, 4096) : "(null)";
            } else if (t == 'c') {
                uint32_t ch = 0;
                cpu->readGuestMemory(curVa, &ch, 4); curVa += 4;
                out.push_back(static_cast<char>(ch & 0xFFu));
            } else if (t == 'd' || t == 'i') {
                if (is64) {
                    int64_t v = 0;
                    cpu->readGuestMemory(curVa, &v, 8); curVa += 8;
                    spec += "lld";
                    std::snprintf(tmp, sizeof(tmp), spec.c_str(), (long long)v);
                } else {
                    int32_t v = 0;
                    cpu->readGuestMemory(curVa, &v, 4); curVa += 4;
                    spec.push_back(t);
                    std::snprintf(tmp, sizeof(tmp), spec.c_str(), v);
                }
                out += tmp;
            } else if (t == 'u' || t == 'x' || t == 'X' || t == 'o' || t == 'p') {
                if (is64 && t != 'p') {
                    uint64_t v = 0;
                    cpu->readGuestMemory(curVa, &v, 8); curVa += 8;
                    spec += "ll"; spec.push_back(t);
                    std::snprintf(tmp, sizeof(tmp), spec.c_str(), (unsigned long long)v);
                } else {
                    uint32_t v = 0;
                    cpu->readGuestMemory(curVa, &v, 4); curVa += 4;
                    if (t == 'p') {
                        std::snprintf(tmp, sizeof(tmp), "%08X", v);
                    } else {
                        spec.push_back(t);
                        std::snprintf(tmp, sizeof(tmp), spec.c_str(), v);
                    }
                }
                out += tmp;
            } else if (t == 'f' || t == 'F' || t == 'g' || t == 'G' || t == 'e' || t == 'E') {
                double v = 0.0;
                cpu->readGuestMemory(curVa, &v, 8); curVa += 8;
                spec.push_back(t);
                std::snprintf(tmp, sizeof(tmp), spec.c_str(), v);
                out += tmp;
            } else {
                out.push_back(t);
            }
        }
        return out;
    };

    if (sym == "msvcr100.dll!_vsnprintf" || sym == "msvcr100.dll!vsnprintf" ||
        sym == "msvcr100.dll!vsprintf"   || sym == "msvcr100.dll!_vsnprintf_s" ||
        sym == "msvcr100.dll!_snprintf"  || sym == "msvcr100.dll!snprintf" ||
        sym == "msvcr100.dll!sprintf"    || sym == "msvcr100.dll!sprintf_s" ||
        sym == "msvcr100.dll!_vscprintf") {
        uint32_t bufPtr = 0, maxCount = 0xFFFFFFFFu, fmtAddr = 0, vaAddr = 0;
        if (sym == "msvcr100.dll!_vscprintf") {
            cpu->readGuestMemory(esp + 4, &fmtAddr, 4);
            cpu->readGuestMemory(esp + 8, &vaAddr,  4);
        } else if (sym == "msvcr100.dll!_vsnprintf" || sym == "msvcr100.dll!vsnprintf") {
            cpu->readGuestMemory(esp + 4,  &bufPtr,   4);
            cpu->readGuestMemory(esp + 8,  &maxCount, 4);
            cpu->readGuestMemory(esp + 12, &fmtAddr,  4);
            cpu->readGuestMemory(esp + 16, &vaAddr,   4);
        } else if (sym == "msvcr100.dll!_vsnprintf_s") {
            uint32_t bufSz = 0, cnt = 0;
            cpu->readGuestMemory(esp + 4,  &bufPtr,  4);
            cpu->readGuestMemory(esp + 8,  &bufSz,   4);
            cpu->readGuestMemory(esp + 12, &cnt,     4);
            cpu->readGuestMemory(esp + 16, &fmtAddr, 4);
            cpu->readGuestMemory(esp + 20, &vaAddr,  4);
            maxCount = (cnt != 0xFFFFFFFFu && cnt < bufSz) ? cnt : bufSz;
        } else if (sym == "msvcr100.dll!vsprintf") {
            cpu->readGuestMemory(esp + 4,  &bufPtr,  4);
            cpu->readGuestMemory(esp + 8,  &fmtAddr, 4);
            cpu->readGuestMemory(esp + 12, &vaAddr,  4);
        } else if (sym == "msvcr100.dll!_snprintf" || sym == "msvcr100.dll!snprintf" || sym == "msvcr100.dll!sprintf_s") {
            cpu->readGuestMemory(esp + 4,  &bufPtr,   4);
            cpu->readGuestMemory(esp + 8,  &maxCount, 4);
            cpu->readGuestMemory(esp + 12, &fmtAddr,  4);
            vaAddr = esp + 16;
        } else { // sprintf
            cpu->readGuestMemory(esp + 4, &bufPtr,  4);
            cpu->readGuestMemory(esp + 8, &fmtAddr, 4);
            vaAddr = esp + 12;
        }

        std::string formatted = formatGuestPrintf(fmtAddr, vaAddr);
        uint32_t written = static_cast<uint32_t>(formatted.size());
        if (bufPtr != 0 && maxCount > 0) {
            uint32_t limit = (maxCount == 0xFFFFFFFFu) ? written : ((written < maxCount - 1) ? written : (maxCount - 1));
            if (limit > 0) cpu->writeGuestMemory(bufPtr, formatted.c_str(), limit);
            uint8_t nul = 0;
            cpu->writeGuestMemory(bufPtr + limit, &nul, 1);
            written = limit;
        }
        cpu->writeRegister(X86Reg::EAX, written);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!IsDebuggerPresent") {
        cpu->writeRegister(X86Reg::EAX, 0u);      // FALSE
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!OutputDebugStringA") {
        uint32_t strPtr = 0;
        cpu->readGuestMemory(esp + 4, &strPtr, 4);
        std::string msg = readCStr(strPtr, 256);
        while (!msg.empty() && (msg.back() == 10 || msg.back() == 13)) msg.pop_back();
        if (msg.size() > 64) msg.resize(64);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym + "(\"" + msg + "\")");
        return true;
    }

    if (sym == "kernel32.dll!OutputDebugStringW" || sym == "kernel32.dll!Sleep") {
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!SetUnhandledExceptionFilter") {
        cpu->writeRegister(X86Reg::EAX, 0u);      // previous filter = NULL
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!UnhandledExceptionFilter") {
        cpu->writeRegister(X86Reg::EAX, 1u);      // EXCEPTION_EXECUTE_HANDLER
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!QueryPerformanceFrequency") {
        uint32_t lpFreq = 0;
        cpu->readGuestMemory(esp + 4, &lpFreq, 4);
        if (lpFreq != 0) {
            uint64_t freq = 10000000ULL;
            cpu->writeGuestMemory(lpFreq, &freq, 8);
        }
        cpu->writeRegister(X86Reg::EAX, 1u);      // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetSystemInfo" || sym == "kernel32.dll!GetNativeSystemInfo") {
        uint32_t lpInfo = 0;
        cpu->readGuestMemory(esp + 4, &lpInfo, 4);
        if (lpInfo != 0) {
            uint32_t info[9] = {
                0u,          // wProcessorArchitecture = INTEL, wReserved = 0
                4096u,       // dwPageSize
                0x00010000u, // lpMinimumApplicationAddress
                0x7FFEFFFFu, // lpMaximumApplicationAddress
                0x0000000Fu, // dwActiveProcessorMask (4 cores)
                4u,          // dwNumberOfProcessors
                586u,        // dwProcessorType
                65536u,      // dwAllocationGranularity
                6u           // wProcessorLevel = 6, wProcessorRevision = 0
            };
            cpu->writeGuestMemory(lpInfo, info, sizeof(info));
        }
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GlobalMemoryStatusEx") {
        uint32_t lpBuf = 0;
        cpu->readGuestMemory(esp + 4, &lpBuf, 4);
        if (lpBuf != 0) {
            uint32_t memLoad = 30u;
            uint64_t totalPhys = 4ULL * 1024 * 1024 * 1024;
            uint64_t availPhys = 2ULL * 1024 * 1024 * 1024;
            uint64_t totalVirt = 2ULL * 1024 * 1024 * 1024;
            uint64_t availVirt = 1536ULL * 1024 * 1024;
            uint64_t zero64 = 0ULL;
            cpu->writeGuestMemory(lpBuf + 4,  &memLoad,   4);
            cpu->writeGuestMemory(lpBuf + 8,  &totalPhys, 8);
            cpu->writeGuestMemory(lpBuf + 16, &availPhys, 8);
            cpu->writeGuestMemory(lpBuf + 24, &totalPhys, 8);
            cpu->writeGuestMemory(lpBuf + 32, &availPhys, 8);
            cpu->writeGuestMemory(lpBuf + 40, &totalVirt, 8);
            cpu->writeGuestMemory(lpBuf + 48, &availVirt, 8);
            cpu->writeGuestMemory(lpBuf + 56, &zero64,    8);
        }
        cpu->writeRegister(X86Reg::EAX, 1u);      // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetVersionExA" || sym == "kernel32.dll!GetVersionExW") {
        uint32_t lpVer = 0;
        cpu->readGuestMemory(esp + 4, &lpVer, 4);
        if (lpVer != 0) {
            uint32_t ver[4] = { 6u, 1u, 7601u, 2u }; // Windows 7 SP1 NT
            uint16_t emptyCsd = 0;
            cpu->writeGuestMemory(lpVer + 4,  ver,       sizeof(ver));
            cpu->writeGuestMemory(lpVer + 20, &emptyCsd, 2);
        }
        cpu->writeRegister(X86Reg::EAX, 1u);      // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetVersion") {
        cpu->writeRegister(X86Reg::EAX, 0x1DB10106u); // Win 6.1 build 7601
        cpu->writeRegister(X86Reg::ESP, esp + 4);     // stdcall: 0 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCurrentProcess") {
        cpu->writeRegister(X86Reg::EAX, 0xFFFFFFFFu);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCurrentThread") {
        cpu->writeRegister(X86Reg::EAX, 0xFFFFFFFEu);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetProcessHeap") {
        cpu->writeRegister(X86Reg::EAX, 0x20000000u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!HeapAlloc") {
        uint32_t dwFlags = 0, dwBytes = 0;
        cpu->readGuestMemory(esp + 8,  &dwFlags, 4);
        cpu->readGuestMemory(esp + 12, &dwBytes, 4);
        uint32_t ptr = allocGuest(dwBytes);
        if (ptr != 0 && (dwFlags & 0x8u) && dwBytes > 0) {
            std::vector<uint8_t> zeros(dwBytes, 0);
            cpu->writeGuestMemory(ptr, zeros.data(), dwBytes);
        }
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!HeapReAlloc") {
        uint32_t dwFlags = 0, oldPtr = 0, newSz = 0;
        cpu->readGuestMemory(esp + 8,  &dwFlags, 4);
        cpu->readGuestMemory(esp + 12, &oldPtr,  4);
        cpu->readGuestMemory(esp + 16, &newSz,   4);
        uint32_t newPtr = allocGuest(newSz);
        if (newPtr != 0) {
            if ((dwFlags & 0x8u) && newSz > 0) {
                std::vector<uint8_t> zeros(newSz, 0);
                cpu->writeGuestMemory(newPtr, zeros.data(), newSz);
            }
            if (oldPtr != 0) {
                auto it = m_allocSizes.find(oldPtr);
                uint32_t copySz = (it != m_allocSizes.end()) ? it->second : 0u;
                if (copySz > newSz) copySz = newSz;
                if (copySz > 0) {
                    std::vector<uint8_t> tmp(copySz);
                    cpu->readGuestMemory(oldPtr, tmp.data(), copySz);
                    cpu->writeGuestMemory(newPtr, tmp.data(), copySz);
                }
            }
        }
        cpu->writeRegister(X86Reg::EAX, newPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 20); // stdcall: 4 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!HeapFree") {
        cpu->writeRegister(X86Reg::EAX, 1u);       // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!HeapSize") {
        uint32_t lpMem = 0;
        cpu->readGuestMemory(esp + 12, &lpMem, 4);
        uint32_t sz = 0;
        auto it = m_allocSizes.find(lpMem);
        if (it != m_allocSizes.end()) sz = it->second;
        cpu->writeRegister(X86Reg::EAX, sz);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "advapi32.dll!RegOpenKeyExA" || sym == "advapi32.dll!RegOpenKeyExW") {
        uint32_t subKeyPtr = 0, phkResult = 0;
        cpu->readGuestMemory(esp + 8,  &subKeyPtr, 4);
        cpu->readGuestMemory(esp + 20, &phkResult, 4);
        if (phkResult != 0) {
            uint32_t zero = 0u;
            cpu->writeGuestMemory(phkResult, &zero, 4);
        }
        std::string keyLog;
        if (sym == "advapi32.dll!RegOpenKeyExA" && subKeyPtr != 0) {
            keyLog = readCStr(subKeyPtr, 128);
            if (keyLog.size() > 48) keyLog.resize(48);
        }
        cpu->writeRegister(X86Reg::EAX, 2u);       // ERROR_FILE_NOT_FOUND
        cpu->writeRegister(X86Reg::ESP, esp + 24); // stdcall: retAddr + 5 args
        outNextEip = returnAddr;
        m_handledLog.push_back(keyLog.empty() ? sym : (sym + "(\"" + keyLog + "\")"));
        return true;
    }

    if (sym == "advapi32.dll!RegOpenKeyA" || sym == "advapi32.dll!RegOpenKeyW") {
        uint32_t phkResult = 0;
        cpu->readGuestMemory(esp + 12, &phkResult, 4);
        if (phkResult != 0) {
            uint32_t zero = 0u;
            cpu->writeGuestMemory(phkResult, &zero, 4);
        }
        cpu->writeRegister(X86Reg::EAX, 2u);       // ERROR_FILE_NOT_FOUND
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: retAddr + 3 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "advapi32.dll!RegQueryValueExA" || sym == "advapi32.dll!RegQueryValueExW") {
        cpu->writeRegister(X86Reg::EAX, 2u);       // ERROR_FILE_NOT_FOUND
        cpu->writeRegister(X86Reg::ESP, esp + 28); // stdcall: retAddr + 6 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "advapi32.dll!RegSetValueExA" || sym == "advapi32.dll!RegSetValueExW") {
        cpu->writeRegister(X86Reg::EAX, 0u);       // ERROR_SUCCESS
        cpu->writeRegister(X86Reg::ESP, esp + 28); // stdcall: retAddr + 6 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "advapi32.dll!RegCreateKeyExA" || sym == "advapi32.dll!RegCreateKeyExW") {
        uint32_t phkResult = 0;
        cpu->readGuestMemory(esp + 32, &phkResult, 4);
        if (phkResult != 0) {
            uint32_t dummyKey = 0x50000001u;
            cpu->writeGuestMemory(phkResult, &dummyKey, 4);
        }
        cpu->writeRegister(X86Reg::EAX, 0u);       // ERROR_SUCCESS
        cpu->writeRegister(X86Reg::ESP, esp + 40); // stdcall: retAddr + 9 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "advapi32.dll!RegCloseKey") {
        cpu->writeRegister(X86Reg::EAX, 0u);      // ERROR_SUCCESS
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "advapi32.dll!GetUserNameA") {
        uint32_t lpBuf = 0, pcbBuf = 0;
        cpu->readGuestMemory(esp + 4, &lpBuf,  4);
        cpu->readGuestMemory(esp + 8, &pcbBuf, 4);
        const char* user = "Player";
        if (lpBuf != 0) cpu->writeGuestMemory(lpBuf, user, 7);
        if (pcbBuf != 0) {
            uint32_t len = 7u;
            cpu->writeGuestMemory(pcbBuf, &len, 4);
        }
        cpu->writeRegister(X86Reg::EAX, 1u);       // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: retAddr + 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "advapi32.dll!GetUserNameW") {
        uint32_t lpBuf = 0, pcbBuf = 0;
        cpu->readGuestMemory(esp + 4, &lpBuf,  4);
        cpu->readGuestMemory(esp + 8, &pcbBuf, 4);
        const char* user = "Player";
        uint16_t wuser[7] = {};
        for (int i = 0; i < 7; ++i) wuser[i] = static_cast<uint16_t>(user[i]);
        if (lpBuf != 0) cpu->writeGuestMemory(lpBuf, wuser, sizeof(wuser));
        if (pcbBuf != 0) {
            uint32_t len = 7u;
            cpu->writeGuestMemory(pcbBuf, &len, 4);
        }
        cpu->writeRegister(X86Reg::EAX, 1u);       // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: retAddr + 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "shell32.dll!SHGetFolderPathA" || sym == "shell32.dll!SHGetSpecialFolderPathA") {
        uint32_t pathPtr = 0;
        bool isSpecial = (sym == "shell32.dll!SHGetSpecialFolderPathA");
        cpu->readGuestMemory(isSpecial ? (esp + 8) : (esp + 20), &pathPtr, 4);
        std::string docs = "C:\\Stronghold3\\Documents";
        if (pathPtr != 0) cpu->writeGuestMemory(pathPtr, docs.c_str(), docs.size() + 1);
        cpu->writeRegister(X86Reg::EAX, isSpecial ? 1u : 0u); // TRUE / S_OK
        cpu->writeRegister(X86Reg::ESP, isSpecial ? (esp + 20) : (esp + 24));
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "shell32.dll!SHGetFolderPathW" || sym == "shell32.dll!SHGetSpecialFolderPathW") {
        uint32_t pathPtr = 0;
        bool isSpecial = (sym == "shell32.dll!SHGetSpecialFolderPathW");
        cpu->readGuestMemory(isSpecial ? (esp + 8) : (esp + 20), &pathPtr, 4);
        std::string docs = "C:\\Stronghold3\\Documents";
        if (pathPtr != 0) {
            std::vector<uint16_t> wdocs(docs.size() + 1, 0);
            for (size_t i = 0; i < docs.size(); ++i) wdocs[i] = static_cast<uint16_t>(docs[i]);
            cpu->writeGuestMemory(pathPtr, wdocs.data(), wdocs.size() * 2);
        }
        cpu->writeRegister(X86Reg::EAX, isSpecial ? 1u : 0u); // TRUE / S_OK
        cpu->writeRegister(X86Reg::ESP, isSpecial ? (esp + 20) : (esp + 24));
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    auto readWStr = [&](uint32_t addr, size_t maxChars = 65536) -> std::vector<uint16_t> {
        std::vector<uint16_t> res;
        if (addr == 0) return res;
        for (size_t i = 0; i < maxChars; ++i) {
            uint16_t wc = 0;
            if (!cpu->readGuestMemory(addr + static_cast<uint32_t>(i * 2), &wc, 2) || wc == 0) break;
            res.push_back(wc);
        }
        return res;
    };

    if (sym == "kernel32.dll!lstrlenA") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        uint32_t len = (ptr != 0) ? static_cast<uint32_t>(readCStr(ptr, 65536).size()) : 0u;
        cpu->writeRegister(X86Reg::EAX, len);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrlenW") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        uint32_t len = (ptr != 0) ? static_cast<uint32_t>(readWStr(ptr, 65536).size()) : 0u;
        cpu->writeRegister(X86Reg::EAX, len);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcpyA") {
        uint32_t dst = 0, src = 0;
        cpu->readGuestMemory(esp + 4, &dst, 4);
        cpu->readGuestMemory(esp + 8, &src, 4);
        if (dst != 0 && src != 0) {
            std::string str = readCStr(src, 65536);
            cpu->writeGuestMemory(dst, str.c_str(), str.size() + 1);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcpyW") {
        uint32_t dst = 0, src = 0;
        cpu->readGuestMemory(esp + 4, &dst, 4);
        cpu->readGuestMemory(esp + 8, &src, 4);
        if (dst != 0 && src != 0) {
            auto wstr = readWStr(src, 65536);
            wstr.push_back(0);
            cpu->writeGuestMemory(dst, wstr.data(), wstr.size() * 2);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcpynA") {
        uint32_t dst = 0, src = 0;
        int32_t maxLen = 0;
        cpu->readGuestMemory(esp + 4,  &dst,    4);
        cpu->readGuestMemory(esp + 8,  &src,    4);
        cpu->readGuestMemory(esp + 12, &maxLen, 4);
        if (dst != 0 && maxLen > 0) {
            std::string str = (src != 0) ? readCStr(src, static_cast<size_t>(maxLen)) : "";
            size_t copyLen = (str.size() < static_cast<size_t>(maxLen - 1)) ? str.size() : static_cast<size_t>(maxLen - 1);
            if (copyLen > 0) cpu->writeGuestMemory(dst, str.c_str(), copyLen);
            uint8_t nul = 0;
            cpu->writeGuestMemory(dst + static_cast<uint32_t>(copyLen), &nul, 1);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcpynW") {
        uint32_t dst = 0, src = 0;
        int32_t maxLen = 0;
        cpu->readGuestMemory(esp + 4,  &dst,    4);
        cpu->readGuestMemory(esp + 8,  &src,    4);
        cpu->readGuestMemory(esp + 12, &maxLen, 4);
        if (dst != 0 && maxLen > 0) {
            auto wstr = (src != 0) ? readWStr(src, static_cast<size_t>(maxLen)) : std::vector<uint16_t>{};
            size_t copyLen = (wstr.size() < static_cast<size_t>(maxLen - 1)) ? wstr.size() : static_cast<size_t>(maxLen - 1);
            if (copyLen > 0) cpu->writeGuestMemory(dst, wstr.data(), copyLen * 2);
            uint16_t nul = 0;
            cpu->writeGuestMemory(dst + static_cast<uint32_t>(copyLen * 2), &nul, 2);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcatA") {
        uint32_t dst = 0, src = 0;
        cpu->readGuestMemory(esp + 4, &dst, 4);
        cpu->readGuestMemory(esp + 8, &src, 4);
        if (dst != 0 && src != 0) {
            std::string combined = readCStr(dst, 65536) + readCStr(src, 65536);
            cpu->writeGuestMemory(dst, combined.c_str(), combined.size() + 1);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcatW") {
        uint32_t dst = 0, src = 0;
        cpu->readGuestMemory(esp + 4, &dst, 4);
        cpu->readGuestMemory(esp + 8, &src, 4);
        if (dst != 0 && src != 0) {
            auto wdst = readWStr(dst, 65536);
            auto wsrc = readWStr(src, 65536);
            wdst.insert(wdst.end(), wsrc.begin(), wsrc.end());
            wdst.push_back(0);
            cpu->writeGuestMemory(dst, wdst.data(), wdst.size() * 2);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcmpA" || sym == "kernel32.dll!lstrcmpiA") {
        uint32_t pA = 0, pB = 0;
        cpu->readGuestMemory(esp + 4, &pA, 4);
        cpu->readGuestMemory(esp + 8, &pB, 4);
        bool nocase = (sym == "kernel32.dll!lstrcmpiA");
        std::string a = readCStr(pA, 65536);
        std::string b = readCStr(pB, 65536);
        int32_t res = 0;
        size_t len = (a.size() < b.size()) ? a.size() : b.size();
        for (size_t i = 0; i < len; ++i) {
            uint8_t ca = static_cast<uint8_t>(a[i]);
            uint8_t cb = static_cast<uint8_t>(b[i]);
            if (nocase) {
                if (ca >= 0x41u && ca <= 0x5Au) ca += 32u;
                if (cb >= 0x41u && cb <= 0x5Au) cb += 32u;
            }
            if (ca != cb) { res = (ca < cb) ? -1 : 1; break; }
        }
        if (res == 0 && a.size() != b.size()) res = (a.size() < b.size()) ? -1 : 1;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res));
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcmpW" || sym == "kernel32.dll!lstrcmpiW") {
        uint32_t pA = 0, pB = 0;
        cpu->readGuestMemory(esp + 4, &pA, 4);
        cpu->readGuestMemory(esp + 8, &pB, 4);
        bool nocase = (sym == "kernel32.dll!lstrcmpiW");
        auto a = readWStr(pA, 65536);
        auto b = readWStr(pB, 65536);
        int32_t res = 0;
        size_t len = (a.size() < b.size()) ? a.size() : b.size();
        for (size_t i = 0; i < len; ++i) {
            uint16_t ca = a[i], cb = b[i];
            if (nocase) {
                if (ca >= 0x41u && ca <= 0x5Au) ca += 32u;
                if (cb >= 0x41u && cb <= 0x5Au) cb += 32u;
            }
            if (ca != cb) { res = (ca < cb) ? -1 : 1; break; }
        }
        if (res == 0 && a.size() != b.size()) res = (a.size() < b.size()) ? -1 : 1;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res));
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!MultiByteToWideChar") {
        uint32_t mbPtr = 0, wcPtr = 0;
        int32_t cbMultiByte = 0, cchWideChar = 0;
        cpu->readGuestMemory(esp + 12, &mbPtr,       4);
        cpu->readGuestMemory(esp + 16, &cbMultiByte, 4);
        cpu->readGuestMemory(esp + 20, &wcPtr,       4);
        cpu->readGuestMemory(esp + 24, &cchWideChar, 4);
        std::vector<uint16_t> outW;
        if (mbPtr != 0) {
            if (cbMultiByte < 0) {
                std::string str = readCStr(mbPtr, 65536);
                outW.reserve(str.size() + 1);
                for (char ch : str) outW.push_back(static_cast<uint8_t>(ch));
                outW.push_back(0);
            } else if (cbMultiByte > 0) {
                std::vector<uint8_t> raw(static_cast<size_t>(cbMultiByte));
                cpu->readGuestMemory(mbPtr, raw.data(), raw.size());
                outW.reserve(raw.size());
                for (uint8_t b : raw) outW.push_back(b);
            }
        }
        uint32_t needed = static_cast<uint32_t>(outW.size());
        uint32_t ret = needed;
        if (cchWideChar > 0) {
            if (static_cast<uint32_t>(cchWideChar) < needed) {
                if (wcPtr != 0) cpu->writeGuestMemory(wcPtr, outW.data(), static_cast<size_t>(cchWideChar) * 2);
                m_lastError = 122u; // ERROR_INSUFFICIENT_BUFFER
                ret = 0u;
            } else if (wcPtr != 0 && needed > 0) {
                cpu->writeGuestMemory(wcPtr, outW.data(), outW.size() * 2);
            }
        }
        cpu->writeRegister(X86Reg::EAX, ret);
        cpu->writeRegister(X86Reg::ESP, esp + 28); // stdcall: 6 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!WideCharToMultiByte") {
        uint32_t wcPtr = 0, mbPtr = 0, usedDefPtr = 0;
        int32_t cchWideChar = 0, cbMultiByte = 0;
        cpu->readGuestMemory(esp + 12, &wcPtr,       4);
        cpu->readGuestMemory(esp + 16, &cchWideChar, 4);
        cpu->readGuestMemory(esp + 20, &mbPtr,       4);
        cpu->readGuestMemory(esp + 24, &cbMultiByte, 4);
        cpu->readGuestMemory(esp + 32, &usedDefPtr,  4);
        if (usedDefPtr != 0) {
            uint32_t zero = 0u;
            cpu->writeGuestMemory(usedDefPtr, &zero, 4);
        }
        std::vector<uint8_t> outB;
        if (wcPtr != 0) {
            if (cchWideChar < 0) {
                auto wstr = readWStr(wcPtr, 65536);
                outB.reserve(wstr.size() + 1);
                for (uint16_t wc : wstr) outB.push_back(wc <= 0xFFu ? static_cast<uint8_t>(wc) : 0x3Fu);
                outB.push_back(0);
            } else if (cchWideChar > 0) {
                std::vector<uint16_t> raw(static_cast<size_t>(cchWideChar));
                cpu->readGuestMemory(wcPtr, raw.data(), raw.size() * 2);
                outB.reserve(raw.size());
                for (uint16_t wc : raw) outB.push_back(wc <= 0xFFu ? static_cast<uint8_t>(wc) : 0x3Fu);
            }
        }
        uint32_t needed = static_cast<uint32_t>(outB.size());
        uint32_t ret = needed;
        if (cbMultiByte > 0) {
            if (static_cast<uint32_t>(cbMultiByte) < needed) {
                if (mbPtr != 0) cpu->writeGuestMemory(mbPtr, outB.data(), static_cast<size_t>(cbMultiByte));
                m_lastError = 122u; // ERROR_INSUFFICIENT_BUFFER
                ret = 0u;
            } else if (mbPtr != 0 && needed > 0) {
                cpu->writeGuestMemory(mbPtr, outB.data(), outB.size());
            }
        }
        cpu->writeRegister(X86Reg::EAX, ret);
        cpu->writeRegister(X86Reg::ESP, esp + 36); // stdcall: 8 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetACP" || sym == "kernel32.dll!GetOEMCP") {
        cpu->writeRegister(X86Reg::EAX, 1252u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!setlocale") {
        uint32_t cStrPtr = allocGuest(4);
        if (cStrPtr != 0) {
            const char cLoc[2] = { 0x43, 0x00 }; // "C"
            cpu->writeGuestMemory(cStrPtr, cLoc, 2);
        }
        cpu->writeRegister(X86Reg::EAX, cStrPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!localeconv") {
        uint32_t lcPtr = allocGuest(80);
        uint32_t dotPtr = allocGuest(4);
        uint32_t empPtr = allocGuest(4);
        uint32_t negPtr = allocGuest(4);
        if (lcPtr != 0 && dotPtr != 0 && empPtr != 0 && negPtr != 0) {
            const char dotS[2] = { 0x2E, 0x00 }; // "."
            const char empS[1] = { 0x00 };
            const char negS[2] = { 0x2D, 0x00 }; // "-"
            cpu->writeGuestMemory(dotPtr, dotS, 2);
            cpu->writeGuestMemory(empPtr, empS, 1);
            cpu->writeGuestMemory(negPtr, negS, 2);
            uint32_t ptrs[10] = {
                dotPtr, empPtr, empPtr, empPtr, empPtr,
                empPtr, empPtr, empPtr, empPtr, negPtr
            };
            cpu->writeGuestMemory(lcPtr, ptrs, sizeof(ptrs));
            uint8_t chars[8] = { 127, 127, 127, 127, 127, 127, 127, 127 };
            cpu->writeGuestMemory(lcPtr + 40, chars, sizeof(chars));
        }
        cpu->writeRegister(X86Reg::EAX, lcPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__pctype_func") {
        uint32_t tblPtr = allocGuest(512);
        if (tblPtr != 0) {
            uint16_t tbl[256] = { 0 };
            for (int c = 0; c < 128; ++c) {
                uint16_t f = 0;
                if (c >= 'A' && c <= 'Z') f |= 0x01;
                if (c >= 'a' && c <= 'z') f |= 0x02;
                if (c >= '0' && c <= '9') f |= 0x04;
                if (c == ' ' || (c >= 0x09 && c <= 0x0D)) f |= 0x08;
                if ((c >= 0x21 && c <= 0x2F) || (c >= 0x3A && c <= 0x40) ||
                    (c >= 0x5B && c <= 0x60) || (c >= 0x7B && c <= 0x7E)) f |= 0x10;
                if (c < 0x20 || c == 0x7F) f |= 0x20;
                if (c == ' ' || c == 0x09) f |= 0x40;
                if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) f |= 0x80;
                tbl[c] = f;
            }
            cpu->writeGuestMemory(tblPtr, tbl, sizeof(tbl));
        }
        cpu->writeRegister(X86Reg::EAX, tblPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__uncaught_exception") {
        cpu->writeRegister(X86Reg::EAX, 0u); // false: no active exception
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_errno") {
        static uint32_t s_errnoPtr = 0;
        if (s_errnoPtr == 0) {
            s_errnoPtr = allocGuest(4);
            uint32_t zero = 0;
            if (s_errnoPtr != 0) cpu->writeGuestMemory(s_errnoPtr, &zero, 4);
        }
        cpu->writeRegister(X86Reg::EAX, s_errnoPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__iob_func") {
        static uint32_t s_iobPtr = 0;
        if (s_iobPtr == 0) {
            s_iobPtr = allocGuest(96); // 3 x 32-byte FILE structs
            uint8_t zeros[96] = { 0 };
            if (s_iobPtr != 0) cpu->writeGuestMemory(s_iobPtr, zeros, sizeof(zeros));
        }
        cpu->writeRegister(X86Reg::EAX, s_iobPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_encode_pointer" || sym == "msvcr100.dll!_decode_pointer") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!___lc_collate_cp_func" ||
        sym == "msvcr100.dll!_encoded_null" ||
        sym == "msvcr100.dll!atexit" ||
        sym == "msvcr100.dll!_invalid_parameter_noinfo" ||
        sym == "msvcr100.dll!_invalid_parameter_noinfo_noreturn" ||
        sym == "msvcr100.dll!_set_invalid_parameter_handler" ||
        sym == "msvcr100.dll!_set_purecall_handler" ||
        sym == "msvcr100.dll!__CppXcptFilter" ||
        sym == "msvcr100.dll!_XcptFilter") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    static FILE* s_cFiles[64] = { nullptr };
    auto readGuestCStrLocal = [&](uint32_t addr) -> std::string {
        std::string out;
        if (addr == 0) return out;
        for (int i = 0; i < 512; ++i) {
            char ch = 0;
            cpu->readGuestMemory(addr + i, &ch, 1);
            if (ch == 0) break;
            out.push_back(ch);
        }
        return out;
    };
    auto getHostFile = [&](uint32_t handle) -> FILE* {
        if (handle < 0x6F000000u) return nullptr;
        uint32_t idx = (handle - 0x6F000000u) >> 5;
        if (idx >= 64) return nullptr;
        return s_cFiles[idx];
    };

    if (sym == "msvcr100.dll!fopen") {
        uint32_t pathPtr = 0, modePtr = 0;
        cpu->readGuestMemory(esp + 4, &pathPtr, 4);
        cpu->readGuestMemory(esp + 8, &modePtr, 4);
        std::string path = readGuestCStrLocal(pathPtr);
        std::string mode = readGuestCStrLocal(modePtr);
        for (char& c : path) { if (c == 0x5C) c = 0x2F; }
        uint32_t guestHandle = 0;
        FILE* f = nullptr;
        if (!path.empty() && !mode.empty()) {
            f = fopen(path.c_str(), mode.c_str());
            if (!f && path[0] != 0x2F) f = fopen(("../" + path).c_str(), mode.c_str());
            if (!f && path[0] != 0x2F) f = fopen(("../../" + path).c_str(), mode.c_str());
        }
        if (f != nullptr) {
            for (uint32_t i = 1; i < 64; ++i) {
                if (s_cFiles[i] == nullptr) {
                    s_cFiles[i] = f;
                    guestHandle = 0x6F000000u + (i << 5);
                    break;
                }
            }
            if (guestHandle == 0) fclose(f);
        }
        cpu->writeRegister(X86Reg::EAX, guestHandle);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        char fmlog[256]; snprintf(fmlog, sizeof(fmlog), "%s('%s','%s')->0x%X", sym.c_str(), path.c_str(), mode.c_str(), guestHandle);
        m_handledLog.push_back(fmlog);
        return true;
    }

    if (sym == "msvcr100.dll!fclose") {
        uint32_t handle = 0;
        cpu->readGuestMemory(esp + 4, &handle, 4);
        uint32_t res = 0xFFFFFFFFu;
        if (handle >= 0x6F000000u) {
            uint32_t idx = (handle - 0x6F000000u) >> 5;
            if (idx < 64 && s_cFiles[idx] != nullptr) {
                res = static_cast<uint32_t>(fclose(s_cFiles[idx]));
                s_cFiles[idx] = nullptr;
            }
        }
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!fread") {
        uint32_t bufPtr = 0, sz = 0, cnt = 0, handle = 0;
        cpu->readGuestMemory(esp + 4, &bufPtr, 4);
        cpu->readGuestMemory(esp + 8, &sz, 4);
        cpu->readGuestMemory(esp + 12, &cnt, 4);
        cpu->readGuestMemory(esp + 16, &handle, 4);
        FILE* f = getHostFile(handle);
        uint32_t readCnt = 0;
        if (f != nullptr && bufPtr != 0 && sz > 0 && cnt > 0) {
            uint32_t total = sz * cnt;
            if (total <= 4096) {
                uint8_t sbuf[4096];
                readCnt = static_cast<uint32_t>(fread(sbuf, sz, cnt, f));
                if (readCnt > 0) cpu->writeGuestMemory(bufPtr, sbuf, readCnt * sz);
            } else {
                std::vector<uint8_t> tmp(total);
                readCnt = static_cast<uint32_t>(fread(tmp.data(), sz, cnt, f));
                if (readCnt > 0) cpu->writeGuestMemory(bufPtr, tmp.data(), readCnt * sz);
            }
        }
        cpu->writeRegister(X86Reg::EAX, readCnt);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        static uint32_t s_freadCount = 0;
        if ((++s_freadCount % 50000) == 0 && f != nullptr) {
            struct stat fst;
            long fsz = (fstat(fileno(f), &fst) == 0) ? static_cast<long>(fst.st_size) : -1L;
            char pbuf[160];
            snprintf(pbuf, sizeof(pbuf), "VFS_PROGRESS(reads=%u, pos=%ld/%ld)", s_freadCount, ftell(f), fsz);
            m_handledLog.push_back(pbuf);
        }
        return true;
    }

    if (sym == "msvcr100.dll!fwrite") {
        uint32_t bufPtr = 0, sz = 0, cnt = 0, handle = 0;
        cpu->readGuestMemory(esp + 4, &bufPtr, 4);
        cpu->readGuestMemory(esp + 8, &sz, 4);
        cpu->readGuestMemory(esp + 12, &cnt, 4);
        cpu->readGuestMemory(esp + 16, &handle, 4);
        FILE* f = getHostFile(handle);
        uint32_t writtenCnt = 0;
        if (f != nullptr && bufPtr != 0 && sz > 0 && cnt > 0) {
            uint32_t total = sz * cnt;
            if (total <= 4096) {
                uint8_t sbuf[4096];
                readCnt = static_cast<uint32_t>(fread(sbuf, sz, cnt, f));
                if (readCnt > 0) cpu->writeGuestMemory(bufPtr, sbuf, readCnt * sz);
            } else {
                std::vector<uint8_t> tmp(total);
                readCnt = static_cast<uint32_t>(fread(tmp.data(), sz, cnt, f));
                if (readCnt > 0) cpu->writeGuestMemory(bufPtr, tmp.data(), readCnt * sz);
            }
        }
        cpu->writeRegister(X86Reg::EAX, writtenCnt);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!fseek") {
        uint32_t handle = 0, origin = 0;
        int32_t offset = 0;
        cpu->readGuestMemory(esp + 4, &handle, 4);
        cpu->readGuestMemory(esp + 8, &offset, 4);
        cpu->readGuestMemory(esp + 12, &origin, 4);
        FILE* f = getHostFile(handle);
        uint32_t res = (f != nullptr) ? static_cast<uint32_t>(fseek(f, offset, static_cast<int>(origin))) : 0xFFFFFFFFu;
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "msvcr100.dll!ftell") {
        uint32_t handle = 0;
        cpu->readGuestMemory(esp + 4, &handle, 4);
        FILE* f = getHostFile(handle);
        uint32_t res = (f != nullptr) ? static_cast<uint32_t>(ftell(f)) : 0xFFFFFFFFu;
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "msvcr100.dll!fflush") {
        uint32_t handle = 0;
        cpu->readGuestMemory(esp + 4, &handle, 4);
        FILE* f = getHostFile(handle);
        if (f != nullptr) fflush(f);
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!feof" || sym == "msvcr100.dll!ferror") {
        uint32_t handle = 0;
        cpu->readGuestMemory(esp + 4, &handle, 4);
        FILE* f = getHostFile(handle);
        uint32_t res = 0;
        if (f != nullptr) res = (sym == "msvcr100.dll!feof") ? static_cast<uint32_t>(feof(f)) : static_cast<uint32_t>(ferror(f));
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "kernel32.dll!GetFileAttributesA") {
        uint32_t pathPtr = 0;
        cpu->readGuestMemory(esp + 4, &pathPtr, 4);
        std::string path = readGuestCStrLocal(pathPtr);
        for (char& c : path) { if (c == 0x5C) c = 0x2F; }
        struct stat st;
        uint32_t attrs = 0xFFFFFFFFu; // INVALID_FILE_ATTRIBUTES
        if (!path.empty() && stat(path.c_str(), &st) == 0) {
            attrs = S_ISDIR(st.st_mode) ? 0x10u : 0x80u; // DIR or NORMAL
        }
        cpu->writeRegister(X86Reg::EAX, attrs);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall (1 arg)
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "kernel32.dll!CreateDirectoryA") {
        uint32_t pathPtr = 0;
        cpu->readGuestMemory(esp + 4, &pathPtr, 4);
        std::string path = readGuestCStrLocal(pathPtr);
        for (char& c : path) { if (c == 0x5C) c = 0x2F; }
        uint32_t ok = 0u;
        if (!path.empty()) {
            struct stat st;
            if (mkdir(path.c_str(), 0777) == 0 || stat(path.c_str(), &st) == 0) {
                ok = 1u;
            }
        }
        cpu->writeRegister(X86Reg::EAX, ok);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall (2 args)
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strtok") {
        static uint32_t s_strtokNext = 0;
        uint32_t strPtr = 0, delimPtr = 0;
        cpu->readGuestMemory(esp + 4, &strPtr, 4);
        cpu->readGuestMemory(esp + 8, &delimPtr, 4);
        if (strPtr != 0) s_strtokNext = strPtr;
        std::string delims = readGuestCStrLocal(delimPtr);
        uint32_t tokenStart = 0;
        if (s_strtokNext != 0) {
            uint32_t cur = s_strtokNext;
            char ch = 0;
            while (true) {
                cpu->readGuestMemory(cur, &ch, 1);
                if (ch == 0) { s_strtokNext = 0; break; }
                if (delims.find(ch) == std::string::npos) { tokenStart = cur; break; }
                cur++;
            }
            if (tokenStart != 0) {
                while (true) {
                    cpu->readGuestMemory(cur, &ch, 1);
                    if (ch == 0) { s_strtokNext = 0; break; }
                    if (delims.find(ch) != std::string::npos) {
                        char zero = 0;
                        cpu->writeGuestMemory(cur, &zero, 1);
                        s_strtokNext = cur + 1;
                        break;
                    }
                    cur++;
                }
            }
        }
        cpu->writeRegister(X86Reg::EAX, tokenStart);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!atoi" || sym == "msvcr100.dll!atol") {
        uint32_t strPtr = 0;
        cpu->readGuestMemory(esp + 4, &strPtr, 4);
        std::string s = readGuestCStrLocal(strPtr);
        uint32_t val = static_cast<uint32_t>(std::atoi(s.c_str()));
        cpu->writeRegister(X86Reg::EAX, val);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strtol" || sym == "msvcr100.dll!strtoul") {
        uint32_t strPtr = 0, endPtrAddr = 0, base = 10;
        cpu->readGuestMemory(esp + 4, &strPtr, 4);
        cpu->readGuestMemory(esp + 8, &endPtrAddr, 4);
        cpu->readGuestMemory(esp + 12, &base, 4);
        std::string s = readGuestCStrLocal(strPtr);
        char* endHost = nullptr;
        uint32_t val = (sym == "msvcr100.dll!strtol")
            ? static_cast<uint32_t>(std::strtol(s.c_str(), &endHost, static_cast<int>(base)))
            : static_cast<uint32_t>(std::strtoul(s.c_str(), &endHost, static_cast<int>(base)));
        if (endPtrAddr != 0) {
            uint32_t endGuest = strPtr + static_cast<uint32_t>(endHost - s.c_str());
            cpu->writeGuestMemory(endPtrAddr, &endGuest, 4);
        }
        cpu->writeRegister(X86Reg::EAX, val);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strpbrk") {
        uint32_t s1Ptr = 0, s2Ptr = 0;
        cpu->readGuestMemory(esp + 4, &s1Ptr, 4);
        cpu->readGuestMemory(esp + 8, &s2Ptr, 4);
        std::string s1 = readGuestCStrLocal(s1Ptr);
        std::string s2 = readGuestCStrLocal(s2Ptr);
        size_t pos = s1.find_first_of(s2);
        uint32_t res = (pos == std::string::npos) ? 0u : (s1Ptr + static_cast<uint32_t>(pos));
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strspn" || sym == "msvcr100.dll!strcspn") {
        uint32_t s1Ptr = 0, s2Ptr = 0;
        cpu->readGuestMemory(esp + 4, &s1Ptr, 4);
        cpu->readGuestMemory(esp + 8, &s2Ptr, 4);
        std::string s1 = readGuestCStrLocal(s1Ptr);
        std::string s2 = readGuestCStrLocal(s2Ptr);
        uint32_t res = (sym == "msvcr100.dll!strspn")
            ? static_cast<uint32_t>(std::strspn(s1.c_str(), s2.c_str()))
            : static_cast<uint32_t>(std::strcspn(s1.c_str(), s2.c_str()));
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_strdup") {
        uint32_t strPtr = 0;
        cpu->readGuestMemory(esp + 4, &strPtr, 4);
        std::string s = readGuestCStrLocal(strPtr);
        uint32_t dst = allocGuest(static_cast<uint32_t>(s.size() + 1));
        if (dst != 0) cpu->writeGuestMemory(dst, s.c_str(), s.size() + 1);
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strcpy_s" || sym == "msvcr100.dll!strcat_s") {
        uint32_t dstPtr = 0, dstSz = 0, srcPtr = 0;
        cpu->readGuestMemory(esp + 4, &dstPtr, 4);
        cpu->readGuestMemory(esp + 8, &dstSz, 4);
        cpu->readGuestMemory(esp + 12, &srcPtr, 4);
        std::string src = readGuestCStrLocal(srcPtr);
        if (dstPtr != 0 && dstSz > 0) {
            if (sym == "msvcr100.dll!strcpy_s") {
                size_t n = std::min<size_t>(src.size(), dstSz - 1);
                if (n > 0) cpu->writeGuestMemory(dstPtr, src.c_str(), n);
                char z = 0; cpu->writeGuestMemory(dstPtr + static_cast<uint32_t>(n), &z, 1);
            } else {
                std::string cur = readGuestCStrLocal(dstPtr);
                std::string combined = cur + src;
                size_t n = std::min<size_t>(combined.size(), dstSz - 1);
                if (n > 0) cpu->writeGuestMemory(dstPtr, combined.c_str(), n);
                char z = 0; cpu->writeGuestMemory(dstPtr + static_cast<uint32_t>(n), &z, 1);
            }
        }
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "steam_api.dll!SteamAPI_RestartAppIfNecessary") {
        cpu->writeRegister(X86Reg::EAX, 0u); // false: do not restart via Steam
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "steam_api.dll!SteamAPI_Init" ||
        sym == "steam_api.dll!SteamAPI_InitSafe" ||
        sym == "steam_api.dll!SteamAPI_IsSteamRunning") {
        cpu->writeRegister(X86Reg::EAX, 0u); // false: skip Steam interfaces
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "steam_api.dll!SteamAPI_Shutdown" ||
        sym == "steam_api.dll!SteamAPI_RunCallbacks" ||
        sym == "steam_api.dll!SteamAPI_RegisterCallback" ||
        sym == "steam_api.dll!SteamAPI_UnregisterCallback" ||
        sym == "steam_api.dll!SteamAPI_RegisterCallResult" ||
        sym == "steam_api.dll!SteamAPI_UnregisterCallResult" ||
        sym == "steam_api.dll!SteamUser" ||
        sym == "steam_api.dll!SteamFriends" ||
        sym == "steam_api.dll!SteamUtils" ||
        sym == "steam_api.dll!SteamUserStats" ||
        sym == "steam_api.dll!SteamApps" ||
        sym == "steam_api.dll!SteamRemoteStorage" ||
        sym == "steam_api.dll!SteamNetworking" ||
        sym == "steam_api.dll!SteamMatchmaking") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!ldiv" || sym == "msvcr100.dll!div") {
        int32_t numer = 0, denom = 1;
        cpu->readGuestMemory(esp + 4, &numer, 4);
        cpu->readGuestMemory(esp + 8, &denom, 4);
        int32_t quot = (denom != 0) ? (numer / denom) : 0;
        int32_t rem  = (denom != 0) ? (numer % denom) : 0;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(quot));
        cpu->writeRegister(X86Reg::EDX, static_cast<uint32_t>(rem));
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        char lbuf[96]; snprintf(lbuf, sizeof(lbuf), "%s(n=%d,d=%d)", sym.c_str(), numer, denom);
        m_handledLog.push_back(lbuf);
        return true;
    }

    if (sym == "msvcr100.dll!abs" || sym == "msvcr100.dll!labs") {
        int32_t v = 0;
        cpu->readGuestMemory(esp + 4, &v, 4);
        uint32_t res = static_cast<uint32_t>(v < 0 ? -v : v);
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!srand") {
        uint32_t seed = 1;
        cpu->readGuestMemory(esp + 4, &seed, 4);
        std::srand(seed);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!rand") {
        uint32_t r = static_cast<uint32_t>(std::rand() & 0x7FFF);
        cpu->writeRegister(X86Reg::EAX, r);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!sscanf" || sym == "msvcr100.dll!sscanf_s") {
        bool isSecure = (sym == "msvcr100.dll!sscanf_s");
        uint32_t bufPtr = 0, fmtPtr = 0;
        cpu->readGuestMemory(esp + 4, &bufPtr, 4);
        cpu->readGuestMemory(esp + 8, &fmtPtr, 4);
        std::string buf = readGuestCStrLocal(bufPtr);
        std::string fmt = readGuestCStrLocal(fmtPtr);
        const char* p = buf.c_str();
        const char* f = fmt.c_str();
        uint32_t argOff = 12;
        int matched = 0;
        while (*f) {
            if (std::isspace(static_cast<unsigned char>(*f))) {
                while (std::isspace(static_cast<unsigned char>(*p))) p++;
                f++;
                continue;
            }
            if (*f != 0x25) {
                if (*p != *f) break;
                p++; f++;
                continue;
            }
            f++;
            if (*f == 0x25) { if (*p != 0x25) break; p++; f++; continue; }
            bool suppress = false;
            if (*f == 0x2A) { suppress = true; f++; }
            int width = 0;
            while (*f >= 0x30 && *f <= 0x39) { width = width * 10 + (*f - 0x30); f++; }
            bool isLong = false, isShort = false;
            if (*f == 0x6C) { isLong = true; f++; if (*f == 0x6C) f++; }
            else if (*f == 0x68) { isShort = true; f++; if (*f == 0x68) f++; }
            char spec = *f++;
            if (spec == 0) break;
            if (spec != 0x63) { while (std::isspace(static_cast<unsigned char>(*p))) p++; }
            if (*p == 0) break;
            if (spec == 0x64 || spec == 0x69 || spec == 0x75 || spec == 0x78 || spec == 0x58 || spec == 0x6F) {
                int base = (spec == 0x78 || spec == 0x58) ? 16 : (spec == 0x6F ? 8 : (spec == 0x69 ? 0 : 10));
                char* endp = nullptr;
                uint32_t val = (spec == 0x75 || spec == 0x78 || spec == 0x58 || spec == 0x6F)
                    ? static_cast<uint32_t>(std::strtoul(p, &endp, base))
                    : static_cast<uint32_t>(std::strtol(p, &endp, base));
                if (endp == p) break;
                p = endp;
                if (!suppress) {
                    uint32_t dst = 0; cpu->readGuestMemory(esp + argOff, &dst, 4); argOff += 4;
                    if (dst != 0) {
                        if (isShort) { uint16_t v16 = static_cast<uint16_t>(val); cpu->writeGuestMemory(dst, &v16, 2); }
                        else { cpu->writeGuestMemory(dst, &val, 4); }
                    }
                    matched++;
                }
            } else if (spec == 0x66 || spec == 0x67 || spec == 0x65 || spec == 0x47 || spec == 0x45) {
                char* endp = nullptr;
                double dval = std::strtod(p, &endp);
                if (endp == p) break;
                p = endp;
                if (!suppress) {
                    uint32_t dst = 0; cpu->readGuestMemory(esp + argOff, &dst, 4); argOff += 4;
                    if (dst != 0) {
                        if (isLong) { cpu->writeGuestMemory(dst, &dval, 8); }
                        else { float fval = static_cast<float>(dval); cpu->writeGuestMemory(dst, &fval, 4); }
                    }
                    matched++;
                }
            } else if (spec == 0x73) {
                std::string tok;
                while (*p && !std::isspace(static_cast<unsigned char>(*p)) && (width == 0 || static_cast<int>(tok.size()) < width)) {
                    tok.push_back(*p++);
                }
                if (tok.empty()) break;
                if (!suppress) {
                    uint32_t dst = 0; cpu->readGuestMemory(esp + argOff, &dst, 4); argOff += 4;
                    uint32_t maxSz = 0xFFFFFFFFu;
                    if (isSecure) { cpu->readGuestMemory(esp + argOff, &maxSz, 4); argOff += 4; }
                    if (dst != 0 && maxSz > 0) {
                        size_t n = std::min<size_t>(tok.size(), maxSz - 1);
                        if (n > 0) cpu->writeGuestMemory(dst, tok.c_str(), n);
                        char z = 0; cpu->writeGuestMemory(dst + static_cast<uint32_t>(n), &z, 1);
                    }
                    matched++;
                }
            } else if (spec == 0x63) {
                char ch = *p++;
                if (!suppress) {
                    uint32_t dst = 0; cpu->readGuestMemory(esp + argOff, &dst, 4); argOff += 4;
                    if (isSecure) argOff += 4;
                    if (dst != 0) cpu->writeGuestMemory(dst, &ch, 1);
                    matched++;
                }
            } else { break; }
        }
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(matched));
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!atof" || sym == "msvcr100.dll!strtod") {
        uint32_t strPtr = 0, endPtrAddr = 0;
        cpu->readGuestMemory(esp + 4, &strPtr, 4);
        if (sym == "msvcr100.dll!strtod") cpu->readGuestMemory(esp + 8, &endPtrAddr, 4);
        std::string s = readGuestCStrLocal(strPtr);
        char* endHost = nullptr;
        double val = std::strtod(s.c_str(), &endHost);
        if (endPtrAddr != 0) {
            uint32_t endGuest = strPtr + static_cast<uint32_t>(endHost - s.c_str());
            cpu->writeGuestMemory(endPtrAddr, &endGuest, 4);
        }
        (void)val;
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!___lc_codepage_func") {
        cpu->writeRegister(X86Reg::EAX, 0u); // C locale
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!___lc_handle_func") {
        uint32_t hPtr = allocGuest(24);
        if (hPtr != 0) {
            uint32_t zeros[6] = { 0, 0, 0, 0, 0, 0 };
            cpu->writeGuestMemory(hPtr, zeros, sizeof(zeros));
        }
        cpu->writeRegister(X86Reg::EAX, hPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!___mb_cur_max_func") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_lock" || sym == "msvcr100.dll!_unlock") {
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        m_handledLog.push_back(sym);
        return true;
    }

    return false; // Unimplemented Win32 API -> stop cleanly
}
