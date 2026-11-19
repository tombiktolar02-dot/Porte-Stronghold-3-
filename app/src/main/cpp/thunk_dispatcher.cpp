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

    if (sym == "msvcr100.dll!calloc") {
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

    return false; // Unimplemented Win32 API -> stop cleanly
}
