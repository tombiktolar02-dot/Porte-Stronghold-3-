#include "i_x86_cpu.h"
#include <unicorn/unicorn.h>
#include <android/log.h>
#include <sys/mman.h>
#include <cstring>
#include <sstream>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "SH3_UNICORN", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "SH3_UNICORN", __VA_ARGS__)

static uint64_t makeGdtDescriptor(uint32_t base, uint32_t limit, uint8_t access, uint8_t flags) {
    uint64_t desc = 0;
    desc |= (uint64_t)(limit & 0xFFFFu);
    desc |= (uint64_t)(base & 0xFFFFFFu) << 16;
    desc |= (uint64_t)(access) << 40;
    desc |= (uint64_t)((limit >> 16) & 0x0Fu) << 48;
    desc |= (uint64_t)(flags & 0x0Fu) << 52;
    desc |= (uint64_t)((base >> 24) & 0xFFu) << 56;
    return desc;
}

class UnicornX86CPU : public IX86CPU {
public:
    ~UnicornX86CPU() override {
        if (m_uc) {
            uc_close(m_uc);
            m_uc = nullptr;
        }
        if (m_gdtHostPage) {
            munmap(m_gdtHostPage, 4096);
            m_gdtHostPage = nullptr;
        }
        if (m_thunkDataPage) {
            munmap(m_thunkDataPage, 65536);
            m_thunkDataPage = nullptr;
        }
        if (m_guestHeapPage) {
            munmap(m_guestHeapPage, 32 * 1024 * 1024);
            m_guestHeapPage = nullptr;
        }
    }

    const char* backendName() const override {
        return "Unicorn-x86-32 (ARM64 Native Backend + GDT/FS)";
    }

    bool initialize() override {
        if (m_uc) {
            uc_close(m_uc);
            m_uc = nullptr;
        }
        uc_err err = uc_open(UC_ARCH_X86, UC_MODE_32, &m_uc);
        if (err != UC_ERR_OK) {
            LOGE("uc_open failed: %s", uc_strerror(err));
            return false;
        }

        if (!m_gdtHostPage) {
            m_gdtHostPage = (uint8_t*)mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (m_gdtHostPage == MAP_FAILED) {
                m_gdtHostPage = nullptr;
                return false;
            }
        }
        memset(m_gdtHostPage, 0, 4096);

        // Map GDT page at 0x7FFDC000
        err = uc_mem_map_ptr(m_uc, m_gdtGuestAddr, 4096, UC_PROT_READ | UC_PROT_WRITE, m_gdtHostPage);
        if (err != UC_ERR_OK) {
            LOGE("GDT map failed: %s", uc_strerror(err));
            return false;
        }

        setupGdtAndSegments(0x7FFDF000u);

        if (!m_thunkDataPage) {
            m_thunkDataPage = (uint8_t*)mmap(nullptr, 65536, PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (m_thunkDataPage == MAP_FAILED) {
                m_thunkDataPage = nullptr;
                return false;
            }
        }
        memset(m_thunkDataPage, 0, 65536);
        err = uc_mem_map_ptr(m_uc, 0x70000000u, 65536, UC_PROT_READ | UC_PROT_WRITE, m_thunkDataPage);
        if (err != UC_ERR_OK) {
            LOGE("Thunk RW data map failed: %s", uc_strerror(err));
            return false;
        }
        if (!m_guestHeapPage) {
            m_guestHeapPage = (uint8_t*)mmap(nullptr, 32 * 1024 * 1024, PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (m_guestHeapPage == MAP_FAILED) {
                m_guestHeapPage = nullptr;
                return false;
            }
        }
        err = uc_mem_map_ptr(m_uc, 0x20000000u, 32 * 1024 * 1024, UC_PROT_READ | UC_PROT_WRITE, m_guestHeapPage);
        if (err != UC_ERR_OK) {
            LOGE("Guest Heap map failed: %s", uc_strerror(err));
            return false;
        }

        uc_hook_add(m_uc, &m_codeHook, UC_HOOK_CODE, (void*)onCodeStep, this, 1, 0);
        uc_hook_add(m_uc, &m_unmappedHook, UC_HOOK_MEM_UNMAPPED, (void*)onMemUnmapped, this, 1, 0);
        uc_hook_add(m_uc, &m_fetchProtHook, UC_HOOK_MEM_FETCH_PROT, (void*)onMemUnmapped, this, 1, 0);
        return true;
    }

    bool mapGuestMemory(uint32_t guestAddr, size_t size, void* hostPtr) override {
        if (!m_uc || !hostPtr || size == 0) return false;
        size_t alignedSize = (size + 4095u) & ~4095u;
        uc_err err = uc_mem_map_ptr(m_uc, guestAddr, alignedSize, UC_PROT_ALL, hostPtr);
        if (err != UC_ERR_OK) {
            LOGE("mapGuestMemory(0x%08X, %zu) failed: %s", guestAddr, alignedSize, uc_strerror(err));
            return false;
        }
        return true;
    }

    bool readGuestMemory(uint32_t guestAddr, void* dst, size_t size) override {
        if (!m_uc) return false;
        return uc_mem_read(m_uc, guestAddr, dst, size) == UC_ERR_OK;
    }

    bool writeGuestMemory(uint32_t guestAddr, const void* src, size_t size) override {
        if (!m_uc) return false;
        return uc_mem_write(m_uc, guestAddr, src, size) == UC_ERR_OK;
    }

    void writeRegister(X86Reg reg, uint32_t value) override {
        if (!m_uc) return;
        if (reg == X86Reg::FS_BASE) {
            setupGdtAndSegments(value);
            return;
        }
        int ucReg = toUcReg(reg);
        if (ucReg >= 0) uc_reg_write(m_uc, ucReg, &value);
    }

    uint32_t readRegister(X86Reg reg) const override {
        if (!m_uc) return 0;
        if (reg == X86Reg::FS_BASE) return m_fsBase;
        uint32_t val = 0;
        int ucReg = toUcReg(reg);
        if (ucReg >= 0) uc_reg_read(m_uc, ucReg, &val);
        return val;
    }

    void setThunkRange(uint32_t startAddr, uint32_t endAddr, ThunkTrapCallback cb) override {
        m_thunkStart = startAddr;
        m_thunkEnd   = endAddr;
        m_trapCb     = std::move(cb);
    }

    X86StepResult stepInstructions(uint32_t entryPoint, uint32_t maxInstructions) override {
        X86StepResult res{};
        if (!m_uc) {
            res.faulted = true;
            res.reason  = "UC_NOT_INITIALIZED";
            return res;
        }

        m_steps       = 0;
        m_trapped     = false;
        m_faulted     = false;
        m_trapAddr    = 0;
        m_faultAddr   = 0;
        m_faultReason.clear();

        uc_err err = uc_emu_start(m_uc, entryPoint, 0, 0, maxInstructions);

        uint32_t stopEip = readRegister(X86Reg::EIP);
        res.stepsExecuted = m_steps;
        res.stopAddress   = m_trapped ? m_trapAddr : stopEip;

        if (m_trapped) {
            res.haltedOnThunk = true;
            res.reason        = "THUNK_TRAP_REACHED";
        } else if (m_faulted) {
            res.faulted = true;
            res.reason  = m_faultReason;
        } else if (err != UC_ERR_OK) {
            res.faulted = true;
            res.reason  = std::string("UC_ERR: ") + uc_strerror(err);
        } else {
            res.reason = "MAX_STEPS_REACHED";
        }
        return res;
    }

private:
    void setupGdtAndSegments(uint32_t fsBase) {
        m_fsBase = fsBase;
        auto* gdt = reinterpret_cast<uint64_t*>(m_gdtHostPage);
        gdt[0] = 0;                                                  // Null
        gdt[1] = makeGdtDescriptor(0, 0xFFFFFu, 0x9Au, 0x0Cu);       // CS (0x08): Flat 32-bit Code
        gdt[2] = makeGdtDescriptor(0, 0xFFFFFu, 0x92u, 0x0Cu);       // DS/ES/SS (0x10): Flat 32-bit Data
        gdt[3] = makeGdtDescriptor(fsBase, 0x0FFFu, 0x92u, 0x04u);   // FS (0x18): TEB 32-bit Data

        uc_x86_mmr gdtr{};
        gdtr.base  = m_gdtGuestAddr;
        gdtr.limit = 4095;
        uc_reg_write(m_uc, UC_X86_REG_GDTR, &gdtr);

        uint32_t cs = 0x08, ds = 0x10, fs = 0x18;
        uc_reg_write(m_uc, UC_X86_REG_CS, &cs);
        uc_reg_write(m_uc, UC_X86_REG_DS, &ds);
        uc_reg_write(m_uc, UC_X86_REG_ES, &ds);
        uc_reg_write(m_uc, UC_X86_REG_SS, &ds);
        uc_reg_write(m_uc, UC_X86_REG_FS, &fs);
    }

    static int toUcReg(X86Reg reg) {
        switch (reg) {
            case X86Reg::EAX:    return UC_X86_REG_EAX;
            case X86Reg::ECX:    return UC_X86_REG_ECX;
            case X86Reg::EDX:    return UC_X86_REG_EDX;
            case X86Reg::EBX:    return UC_X86_REG_EBX;
            case X86Reg::ESP:    return UC_X86_REG_ESP;
            case X86Reg::EBP:    return UC_X86_REG_EBP;
            case X86Reg::ESI:    return UC_X86_REG_ESI;
            case X86Reg::EDI:    return UC_X86_REG_EDI;
            case X86Reg::EIP:    return UC_X86_REG_EIP;
            case X86Reg::EFLAGS: return UC_X86_REG_EFLAGS;
            default:             return -1;
        }
    }

    static void onCodeStep(uc_engine* /*uc*/, uint64_t /*address*/, uint32_t /*size*/, void* user_data) {
        auto* self = reinterpret_cast<UnicornX86CPU*>(user_data);
        self->m_steps++;
    }

    static bool onMemUnmapped(uc_engine* uc, uc_mem_type type, uint64_t address,
                              int size, int64_t /*value*/, void* user_data) {
        auto* self = reinterpret_cast<UnicornX86CPU*>(user_data);
        uint32_t addr32 = static_cast<uint32_t>(address);

        if ((type == UC_MEM_FETCH_UNMAPPED || type == UC_MEM_FETCH_PROT) && addr32 >= self->m_thunkStart && addr32 < self->m_thunkEnd) {
            uint32_t esp = 0, retAddr = 0;
            uc_reg_read(uc, UC_X86_REG_ESP, &esp);
            uc_mem_read(uc, esp, &retAddr, 4);
            self->m_trapped  = true;
            self->m_trapAddr = addr32;
            if (self->m_trapCb) {
                self->m_trapCb(addr32, retAddr);
            }
            uc_emu_stop(uc);
            return false;
        }

        self->m_faulted   = true;
        self->m_faultAddr = addr32;
        char fbuf[96];
        snprintf(fbuf, sizeof(fbuf), "UNMAPPED_MEM(type=%d, addr=0x%08X, sz=%d)", (int)type, addr32, size);
        self->m_faultReason = fbuf;
        LOGE("%s", fbuf);
        uc_emu_stop(uc);
        return false;
    }

    uc_engine*  m_uc = nullptr;
    uc_hook     m_codeHook = 0;
    uc_hook     m_unmappedHook = 0;
    uc_hook     m_fetchProtHook = 0;
    uint8_t*    m_thunkDataPage = nullptr;
    uint8_t*    m_guestHeapPage = nullptr;
    uint8_t*    m_gdtHostPage = nullptr;
    uint32_t    m_gdtGuestAddr = 0x7FFDC000u;
    uint32_t    m_fsBase = 0x7FFDF000u;
    uint32_t    m_thunkStart = 0x70000000u;
    uint32_t    m_thunkEnd   = 0x7FFFFFFFu;
    ThunkTrapCallback m_trapCb;

    uint32_t    m_steps = 0;
    bool        m_trapped = false;
    bool        m_faulted = false;
    uint32_t    m_trapAddr = 0;
    uint32_t    m_faultAddr = 0;
    std::string m_faultReason;
};

IX86CPU* createActiveX86CPU() {
    return new UnicornX86CPU();
}
