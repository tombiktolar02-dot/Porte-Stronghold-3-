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

    return false; // Unimplemented Win32 API -> stop cleanly
}
