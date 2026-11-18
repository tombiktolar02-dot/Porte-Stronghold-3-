#include "i_x86_cpu.h"
#include <vector>
#include <cstring>
#include <sstream>

struct GuestRegion {
    uint32_t guestStart;
    size_t   size;
    uint8_t* hostPtr;
};

class StubBranchProbeCPU : public IX86CPU {
public:
    const char* backendName() const override {
        return "SH3-x86-BranchProbe-v1.1 (Zero-Dep Pre-Unicorn Validator)";
    }

    bool initialize() override {
        memset(m_regs, 0, sizeof(m_regs));
        m_regions.clear();
        return true;
    }

    bool mapGuestMemory(uint32_t guestAddr, size_t size, void* hostPtr) override {
        if (!hostPtr || size == 0) return false;
        m_regions.push_back({guestAddr, size, reinterpret_cast<uint8_t*>(hostPtr)});
        return true;
    }

    bool readGuestMemory(uint32_t guestAddr, void* dst, size_t size) override {
        for (const auto& r : m_regions) {
            if (guestAddr >= r.guestStart && (guestAddr + size) <= (r.guestStart + r.size)) {
                memcpy(dst, r.hostPtr + (guestAddr - r.guestStart), size);
                return true;
            }
        }
        return false;
    }

    bool writeGuestMemory(uint32_t guestAddr, const void* src, size_t size) override {
        for (const auto& r : m_regions) {
            if (guestAddr >= r.guestStart && (guestAddr + size) <= (r.guestStart + r.size)) {
                memcpy(r.hostPtr + (guestAddr - r.guestStart), src, size);
                return true;
            }
        }
        return false;
    }

    void writeRegister(X86Reg reg, uint32_t value) override {
        m_regs[static_cast<int>(reg)] = value;
    }

    uint32_t readRegister(X86Reg reg) const override {
        return m_regs[static_cast<int>(reg)];
    }

    void setThunkRange(uint32_t startAddr, uint32_t endAddr, ThunkTrapCallback cb) override {
        m_thunkStart = startAddr;
        m_thunkEnd   = endAddr;
        m_trapCb     = std::move(cb);
    }

    X86StepResult stepInstructions(uint32_t entryPoint, uint32_t maxInstructions) override {
        X86StepResult res{};
        uint32_t eip = entryPoint;
        uint32_t esp = m_regs[static_cast<int>(X86Reg::ESP)];

        for (uint32_t step = 0; step < maxInstructions; ++step) {
            m_regs[static_cast<int>(X86Reg::EIP)] = eip;
            if (eip >= m_thunkStart && eip < m_thunkEnd) {
                uint32_t retAddr = 0;
                readGuestMemory(esp, &retAddr, 4);
                if (m_trapCb) m_trapCb(eip, retAddr);
                res.haltedOnThunk = true;
                res.stopAddress   = eip;
                res.stepsExecuted = step;
                res.reason        = "THUNK_TRAP_REACHED";
                return res;
            }

            uint8_t op[8]{};
            if (!readGuestMemory(eip, op, 6)) {
                res.faulted       = true;
                res.stopAddress   = eip;
                res.stepsExecuted = step;
                res.reason        = "UNMAPPED_FETCH";
                return res;
            }

            res.stepsExecuted = step + 1;

            // Relative CALL (E8 rel32)
            if (op[0] == 0xE8) {
                int32_t rel = 0;
                memcpy(&rel, &op[1], 4);
                uint32_t nextEip = eip + 5;
                esp -= 4;
                writeGuestMemory(esp, &nextEip, 4);
                m_regs[static_cast<int>(X86Reg::ESP)] = esp;
                eip = static_cast<uint32_t>(static_cast<int64_t>(nextEip) + rel);
                continue;
            }
            // Relative JMP (E9 rel32) or short JMP (EB rel8)
            if (op[0] == 0xE9) {
                int32_t rel = 0;
                memcpy(&rel, &op[1], 4);
                eip = static_cast<uint32_t>(static_cast<int64_t>(eip + 5) + rel);
                continue;
            }
            if (op[0] == 0xEB) {
                int8_t rel8 = static_cast<int8_t>(op[1]);
                eip = static_cast<uint32_t>(static_cast<int64_t>(eip + 2) + rel8);
                continue;
            }
            // Indirect CALL/JMP via IAT: FF 15 [disp32] or FF 25 [disp32]
            if (op[0] == 0xFF && (op[1] == 0x15 || op[1] == 0x25)) {
                uint32_t iatPtr = 0;
                memcpy(&iatPtr, &op[2], 4);
                uint32_t targetAddr = 0;
                if (readGuestMemory(iatPtr, &targetAddr, 4)) {
                    if (op[1] == 0x15) {
                        uint32_t nextEip = eip + 6;
                        esp -= 4;
                        writeGuestMemory(esp, &nextEip, 4);
                        m_regs[static_cast<int>(X86Reg::ESP)] = esp;
                    }
                    eip = targetAddr;
                    continue;
                }
            }
            // Common MSVC __security_init_cookie & CRT prologue instructions
            if (op[0] == 0x8B && op[1] == 0xFF) { eip += 2; continue; } // mov edi, edi
            if (op[0] >= 0x50 && op[0] <= 0x57) { esp -= 4; eip += 1; continue; } // push reg
            if (op[0] >= 0x58 && op[0] <= 0x5F) { esp += 4; eip += 1; continue; } // pop reg
            if (op[0] == 0x8B && op[1] == 0xEC) { eip += 2; continue; } // mov ebp, esp
            if (op[0] == 0x83 && op[1] == 0xEC) { esp -= op[2]; eip += 3; continue; } // sub esp, imm8
            if (op[0] == 0xA1)                  { eip += 5; continue; } // mov eax, [moffs32]
            if (op[0] == 0x33 && op[1] == 0xC5) { eip += 2; continue; } // xor eax, ebp
            if (op[0] == 0x89 && op[1] == 0x45) { eip += 3; continue; } // mov [ebp+disp8], eax
            if (op[0] == 0x3B || op[0] == 0x3D) { eip += (op[0] == 0x3D ? 5 : 2); continue; } // cmp
            if (op[0] == 0x74 || op[0] == 0x75) { eip += 2; continue; } // je / jne fallthrough to init path
            if (op[0] == 0x8D && op[1] == 0x45) { eip += 3; continue; } // lea eax, [ebp+disp8]

            res.stopAddress = eip;
            res.reason      = "PROLOGUE_BRANCH_TRACE_COMPLETE";
            return res;
        }
        res.stopAddress = eip;
        res.reason      = "MAX_STEPS_REACHED";
        return res;
    }

private:
    uint32_t m_regs[16]{};
    std::vector<GuestRegion> m_regions;
    uint32_t m_thunkStart = 0x70000000u;
    uint32_t m_thunkEnd   = 0x7FFFFFFFu;
    ThunkTrapCallback m_trapCb;
};

IX86CPU* createActiveX86CPU() {
    return new StubBranchProbeCPU();
}
