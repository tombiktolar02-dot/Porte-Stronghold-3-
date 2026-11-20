#ifndef SH3_I_X86_CPU_H
#define SH3_I_X86_CPU_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <functional>

enum class X86Reg : int {
    EAX = 0, ECX, EDX, EBX,
    ESP, EBP, ESI, EDI,
    EIP, EFLAGS,
    FS_BASE
};

struct X86StepResult {
    bool        haltedOnThunk = false;
    bool        faulted       = false;
    uint32_t    stopAddress   = 0;
    uint32_t    stepsExecuted = 0;
    std::string reason;
};

using ThunkTrapCallback = std::function<bool(uint32_t thunkAddr, uint32_t returnAddr)>;

class IX86CPU {
public:
    virtual ~IX86CPU() = default;
    virtual const char* backendName() const = 0;
    virtual bool initialize() = 0;
    virtual bool mapGuestMemory(uint32_t guestAddr, size_t size, void* hostPtr) = 0;
    virtual bool readGuestMemory(uint32_t guestAddr, void* dst, size_t size) = 0;
    virtual bool writeGuestMemory(uint32_t guestAddr, const void* src, size_t size) = 0;
    virtual void writeRegister(X86Reg reg, uint32_t value) = 0;
    virtual uint32_t readRegister(X86Reg reg) const = 0;
    virtual void setThunkRange(uint32_t startAddr, uint32_t endAddr, ThunkTrapCallback cb) = 0;
    virtual X86StepResult stepInstructions(uint32_t entryPoint, uint32_t maxInstructions) = 0;
    virtual double popFpuDouble() { return 0.0; }
    virtual void pushFpuDouble(double /*val*/) {}
};

IX86CPU* createActiveX86CPU();

#endif // SH3_I_X86_CPU_H
