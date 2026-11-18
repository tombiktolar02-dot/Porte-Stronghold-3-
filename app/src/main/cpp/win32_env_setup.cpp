#include "win32_env_setup.h"
#include <sys/mman.h>
#include <cstring>
#include <sstream>

bool setupWin32GuestEnvironment(IX86CPU* cpu, uint32_t exeImageBase, Win32EnvState& outState, std::string& outReport) {
    if (!cpu) return false;

    const size_t envBlockSize = 3 * 4096; // 0x7FFDD000 (TLS), 0x7FFDE000 (PEB), 0x7FFDF000 (TEB)
    uint8_t* envMem = (uint8_t*)mmap(nullptr, envBlockSize, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (envMem == MAP_FAILED) return false;

    uint8_t* stackMem = (uint8_t*)mmap(nullptr, outState.stackSize, PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stackMem == MAP_FAILED) {
        munmap(envMem, envBlockSize);
        return false;
    }

    memset(envMem, 0, envBlockSize);
    memset(stackMem, 0, outState.stackSize);

    auto* peb = reinterpret_cast<Win32PEB32*>(envMem + 4096);
    peb->BeingDebugged    = 0;
    peb->ImageBaseAddress = exeImageBase;
    peb->ProcessHeap      = 0x00300000u;

    auto* teb = reinterpret_cast<Win32TEB32*>(envMem + 8192);
    teb->ExceptionList         = 0xFFFFFFFFu;
    teb->StackBase             = outState.stackBase;
    teb->StackLimit            = outState.stackBase - outState.stackSize;
    teb->Self                  = outState.tebGuestAddr;
    teb->ClientIdUniqueProcess = 0x00000543u & 0xFFFFu;
    teb->ClientIdUniqueThread  = 0x00000001u;
    teb->ThreadLocalStoragePtr = outState.tlsGuestAddr;
    teb->ProcessEnvironmentBlk = outState.pebGuestAddr;
    teb->LastErrorValue        = 0;

    outState.envHostPage  = envMem;
    outState.stackHostMem = stackMem;

    uint32_t stackBottom = outState.stackBase - outState.stackSize;
    cpu->mapGuestMemory(outState.tlsGuestAddr, envBlockSize, envMem);
    cpu->mapGuestMemory(stackBottom, outState.stackSize, stackMem);

    // Push fake return address (sentinel thunk 0x70FFFFF0) at initialESP
    uint32_t sentinelRet = 0x70FFFFF0u;
    uint32_t espOffset = outState.initialESP - stackBottom;
    if (espOffset + 4 <= outState.stackSize) {
        memcpy(stackMem + espOffset, &sentinelRet, sizeof(uint32_t));
    }

    cpu->writeRegister(X86Reg::ESP, outState.initialESP);
    cpu->writeRegister(X86Reg::EBP, outState.initialESP);
    cpu->writeRegister(X86Reg::FS_BASE, outState.tebGuestAddr);

    std::ostringstream ss;
    ss << "[ENV OK] TEB=0x" << std::hex << outState.tebGuestAddr
       << " (FS:[18]=0x" << teb->Self << ", SEH=0x" << teb->ExceptionList << ")"
       << " | PEB=0x" << outState.pebGuestAddr
       << " | ESP=0x" << outState.initialESP << std::dec;
    outReport = ss.str();
    return true;
}

void destroyWin32GuestEnvironment(Win32EnvState& state) {
    if (state.envHostPage) {
        munmap(state.envHostPage, 3 * 4096);
        state.envHostPage = nullptr;
    }
    if (state.stackHostMem) {
        munmap(state.stackHostMem, state.stackSize);
        state.stackHostMem = nullptr;
    }
}
