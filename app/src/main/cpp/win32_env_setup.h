#ifndef SH3_WIN32_ENV_SETUP_H
#define SH3_WIN32_ENV_SETUP_H

#include <cstdint>
#include <string>
#include "i_x86_cpu.h"

#pragma pack(push, 1)
struct Win32PEB32 {
    uint8_t  InheritedAddressSpace;
    uint8_t  ReadImageFileExecOptions;
    uint8_t  BeingDebugged;
    uint8_t  BitField;
    uint32_t Mutant;
    uint32_t ImageBaseAddress;
    uint32_t Ldr;
    uint32_t ProcessParameters;
    uint32_t SubSystemData;
    uint32_t ProcessHeap;
    uint8_t  ReservedPad[224];
};

struct Win32TEB32 {
    uint32_t ExceptionList;        // FS:[0x00] -> SEH Chain Head (0xFFFFFFFF)
    uint32_t StackBase;            // FS:[0x04] -> Top of stack
    uint32_t StackLimit;           // FS:[0x08] -> Bottom of stack
    uint32_t SubSystemTib;         // FS:[0x0C]
    uint32_t FiberData;            // FS:[0x10]
    uint32_t ArbitraryUserPointer; // FS:[0x14]
    uint32_t Self;                 // FS:[0x18] -> Linear address of TEB
    uint32_t EnvironmentPointer;   // FS:[0x1C]
    uint32_t ClientIdUniqueProcess;// FS:[0x20] -> PID
    uint32_t ClientIdUniqueThread; // FS:[0x24] -> TID
    uint32_t ActiveRpcHandle;      // FS:[0x28]
    uint32_t ThreadLocalStoragePtr;// FS:[0x2C] -> TLS Array pointer
    uint32_t ProcessEnvironmentBlk;// FS:[0x30] -> Pointer to PEB
    uint32_t LastErrorValue;       // FS:[0x34] -> GetLastError() storage
    uint8_t  ReservedPad[196];
};
#pragma pack(pop)

struct Win32EnvState {
    uint8_t* envHostPage  = nullptr;
    uint8_t* stackHostMem = nullptr;
    uint32_t tebGuestAddr = 0x7FFDF000u;
    uint32_t pebGuestAddr = 0x7FFDE000u;
    uint32_t tlsGuestAddr = 0x7FFDD000u;
    uint32_t stackBase    = 0x00200000u;
    uint32_t stackSize    = 0x00040000u; // 256 KB aligned stack
    uint32_t initialESP   = 0x001FFF00u;
};

bool setupWin32GuestEnvironment(IX86CPU* cpu, uint32_t exeImageBase, Win32EnvState& outState, std::string& outReport);
void destroyWin32GuestEnvironment(Win32EnvState& state);

#endif // SH3_WIN32_ENV_SETUP_H
