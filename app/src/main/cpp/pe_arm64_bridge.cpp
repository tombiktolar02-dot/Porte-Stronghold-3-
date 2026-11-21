#include <chrono>
#include <unistd.h>
#include <mutex>
#include <jni.h>
#include <android/log.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <string>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <map>
#include <memory>

#include "i_x86_cpu.h"
#include "win32_env_setup.h"
#include "thunk_dispatcher.h"
#include <android/native_window_jni.h>
#include "dxvk_backend_probe.h"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "SH3_BRIDGE", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "SH3_BRIDGE", __VA_ARGS__)

#pragma pack(push, 1)
struct DOSHeader {
    uint16_t e_magic;
    uint8_t  pad[58];
    uint32_t e_lfanew;
};
struct DataDir {
    uint32_t VirtualAddress;
    uint32_t Size;
};
struct NTHeader32 {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PtrToSym;
    uint32_t NumSyms;
    uint16_t SizeOfOptHdr;
    uint16_t Characteristics;
    uint16_t Magic;
    uint8_t  LinkerVer[2];
    uint32_t SizeOfCode;
    uint32_t SizeOfInitData;
    uint32_t SizeOfUninitData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint8_t  OSVer[16];
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t StacksAndHeaps[4];
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DataDir  DataDirectory[16];
};
struct SectionHeader {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint8_t  pad[12];
    uint32_t Characteristics;
};
struct ExportDir {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
};
struct ImportDesc {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};
struct BaseRelocBlock {
    uint32_t PageRVA;
    uint32_t BlockSize;
};
#pragma pack(pop)

static std::string toLowerStr(const char* s) {
    std::string out;
    while (s && *s) {
        out.push_back((char)std::tolower((unsigned char)*s++));
    }
    return out;
}

struct LoadedModule {
    std::string name;
    std::string lowerName;
    uint8_t*    mappedBase = nullptr;
    uint32_t    sizeOfImage = 0;
    uint32_t    simBase = 0;
    uint32_t    entryPointRVA = 0;
    uint32_t    engineSymsLinked = 0;
    uint32_t    nativeThunksLinked = 0;
    NTHeader32  nt{};
    std::unordered_map<std::string, uint32_t> nameExports;
    std::unordered_map<uint32_t, uint32_t>    ordExports;
};

static std::vector<LoadedModule> g_modules;
static std::unordered_map<std::string, size_t> g_modIndex;
static uint32_t g_nextThunkAddr = 0x70000000;
static std::unordered_map<std::string, uint32_t> g_thunkTable;
static std::map<std::string, uint32_t> g_dllThunkCounts;

static std::string redirectWinPath(const std::string& binDir, const char* winPath) {
    std::string rel(winPath ? winPath : "");
    for (char& c : rel) {
        if (c == '\\') c = '/';
    }
    std::string full = binDir + "/" + rel;
    std::vector<std::string> parts;
    std::stringstream ss(full);
    std::string item;
    while (std::getline(ss, item, '/')) {
        if (item.empty() || item == ".") continue;
        if (item == "..") {
            if (!parts.empty()) parts.pop_back();
        } else {
            parts.push_back(item);
        }
    }
    std::string resolved = "/";
    for (size_t i = 0; i < parts.size(); ++i) {
        resolved += parts[i];
        if (i + 1 < parts.size()) resolved += "/";
    }
    return resolved;
}

static bool mapAndIndexPE(const std::string& baseDir, const char* name, uint32_t targetSimBase) {
    std::string path = baseDir + "/" + name;
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) return false;

    DOSHeader dos{};
    fread(&dos, sizeof(dos), 1, fp);
    fseek(fp, dos.e_lfanew, SEEK_SET);
    NTHeader32 nt{};
    fread(&nt, sizeof(nt), 1, fp);

    std::vector<SectionHeader> secs(nt.NumberOfSections);
    fread(secs.data(), sizeof(SectionHeader), nt.NumberOfSections, fp);

    size_t allocSize = (nt.SizeOfImage + 4095) & ~4095u;
    uint8_t* base = (uint8_t*)mmap(nullptr, allocSize, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        fclose(fp);
        return false;
    }

    fseek(fp, 0, SEEK_SET);
    fread(base, 1, nt.SizeOfHeaders, fp);
    for (const auto& s : secs) {
        if (s.SizeOfRawData > 0 && s.VirtualAddress + s.SizeOfRawData <= allocSize) {
            fseek(fp, s.PointerToRawData, SEEK_SET);
            fread(base + s.VirtualAddress, 1, s.SizeOfRawData, fp);
        }
    }
    fclose(fp);

    int32_t delta = (int32_t)(targetSimBase - nt.ImageBase);
    DataDir relocDir = nt.DataDirectory[5];
    if (delta != 0 && relocDir.VirtualAddress > 0 && relocDir.Size > 0) {
        uint32_t offset = 0;
        while (offset + sizeof(BaseRelocBlock) <= relocDir.Size) {
            auto* blk = (BaseRelocBlock*)(base + relocDir.VirtualAddress + offset);
            if (blk->BlockSize == 0) break;
            uint32_t count = (blk->BlockSize - sizeof(BaseRelocBlock)) / sizeof(uint16_t);
            auto* entries = (uint16_t*)((uint8_t*)blk + sizeof(BaseRelocBlock));
            for (uint32_t i = 0; i < count; ++i) {
                if ((entries[i] >> 12) == 3) {
                    uint32_t patchRVA = blk->PageRVA + (entries[i] & 0x0FFF);
                    if (patchRVA + 4 <= allocSize) {
                        *(uint32_t*)(base + patchRVA) += (uint32_t)delta;
                    }
                }
            }
            offset += blk->BlockSize;
        }
    }

    LoadedModule mod;
    mod.name = name;
    mod.lowerName = toLowerStr(name);
    mod.mappedBase = base;
    mod.sizeOfImage = (uint32_t)allocSize;
    mod.simBase = targetSimBase;
    mod.entryPointRVA = nt.AddressOfEntryPoint;
    mod.nt = nt;

    DataDir expDir = nt.DataDirectory[0];
    if (expDir.VirtualAddress > 0 && expDir.VirtualAddress + sizeof(ExportDir) <= allocSize) {
        auto* ed = (ExportDir*)(base + expDir.VirtualAddress);
        auto* funcs = (uint32_t*)(base + ed->AddressOfFunctions);
        auto* names = (uint32_t*)(base + ed->AddressOfNames);
        auto* ords  = (uint16_t*)(base + ed->AddressOfNameOrdinals);

        for (uint32_t i = 0; i < ed->NumberOfFunctions; ++i) {
            if (funcs[i] != 0) {
                mod.ordExports[ed->Base + i] = targetSimBase + funcs[i];
            }
        }
        for (uint32_t i = 0; i < ed->NumberOfNames; ++i) {
            if (names[i] < allocSize && ords[i] < ed->NumberOfFunctions) {
                const char* fnName = (const char*)(base + names[i]);
                uint32_t fnAddr = targetSimBase + funcs[ords[i]];
                mod.nameExports[fnName] = fnAddr;
            }
        }
    }

    g_modIndex[mod.lowerName] = g_modules.size();
    g_modules.push_back(std::move(mod));
    return true;
}

alignas(4096) static uint8_t g_fastStubPage[4096] = {};
static bool g_fastStubInit = false;

static void initFastStubPage() {
    if (g_fastStubInit) return;
    memset(g_fastStubPage, 0xCC, sizeof(g_fastStubPage));
    // 256-byte ASCII ctype lookup table at 0x6D000E00
    uint8_t* tbl = g_fastStubPage + 0xE00u;
    memset(tbl, 0, 256);
    for (int c = 0; c < 128; ++c) {
        uint8_t m = 0;
        if (c >= 'A' && c <= 'Z') m |= 0x01u;
        if (c >= 'a' && c <= 'z') m |= 0x02u;
        if (c >= '0' && c <= '9') m |= 0x04u;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f') m |= 0x08u;
        if (c < 0x20 || c == 0x7F) m |= 0x20u;
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) m |= 0x80u;
        if (c >= 0x21 && c <= 0x7E && !(m & 0x07u)) m |= 0x10u;
        tbl[c] = m;
    }
    auto emitCtype = [&](uint32_t off, uint8_t mask) {
        const uint8_t code[27] = {
            0x8B,0x44,0x24,0x04,                   // mov eax, [esp+4]
            0x3D,0xFF,0x00,0x00,0x00,              // cmp eax, 0xFF
            0x77,0x0D,                             // ja +13 (.zero)
            0x0F,0xB6,0x80,0x00,0x0E,0x00,0x6D,    // movzx eax, byte [eax+0x6D000E00]
            0x25,mask,0x00,0x00,0x00,              // and eax, mask
            0xC3,                                  // ret
            0x31,0xC0,                             // xor eax, eax
            0xC3                                   // ret
        };
        memcpy(g_fastStubPage + off, code, sizeof(code));
    };
    emitCtype(0x000u, 0x07u); // isalnum
    emitCtype(0x020u, 0x03u); // isalpha
    emitCtype(0x040u, 0x04u); // isdigit
    emitCtype(0x060u, 0x08u); // isspace
    emitCtype(0x080u, 0x01u); // isupper
    emitCtype(0x0A0u, 0x02u); // islower
    emitCtype(0x0C0u, 0x80u); // isxdigit
    emitCtype(0x0E0u, 0x10u); // ispunct
    emitCtype(0x100u, 0x20u); // iscntrl

    // tolower @ 0x120
    const uint8_t s_tolower[] = {0x8B,0x44,0x24,0x04,0x8D,0x48,0xBF,0x83,0xF9,0x19,0x77,0x03,0x83,0xC0,0x20,0xC3};
    memcpy(g_fastStubPage + 0x120u, s_tolower, sizeof(s_tolower));
    // toupper @ 0x140
    const uint8_t s_toupper[] = {0x8B,0x44,0x24,0x04,0x8D,0x48,0x9F,0x83,0xF9,0x19,0x77,0x03,0x83,0xE8,0x20,0xC3};
    memcpy(g_fastStubPage + 0x140u, s_toupper, sizeof(s_toupper));
    // memcpy / memmove @ 0x160 (overlap-safe, dword-accelerated)
    const uint8_t s_memmove[] = {
        0x57,0x56,0x8B,0x7C,0x24,0x0C,0x8B,0x74,0x24,0x10,0x8B,0x4C,0x24,0x14,0x8B,0xC7,
        0x85,0xC9,0x74,0x26,0x3B,0xFE,0x76,0x13,0x8D,0x14,0x0E,0x3B,0xFA,0x73,0x0C,
        0x01,0xCF,0x4F,0x01,0xCE,0x4E,0xFD,0xF3,0xA4,0xFC,0xEB,0x0F,
        0xFC,0x8B,0xD1,0xC1,0xE9,0x02,0xF3,0xA5,0x8B,0xCA,0x83,0xE1,0x03,0xF3,0xA4,
        0x5E,0x5F,0xC3
    };
    memcpy(g_fastStubPage + 0x160u, s_memmove, sizeof(s_memmove));
    // memset @ 0x1A0 (dword-accelerated)
    const uint8_t s_memset[] = {
        0x57,0x8B,0x7C,0x24,0x08,0x0F,0xB6,0x44,0x24,0x0C,0x8B,0x4C,0x24,0x10,0x8B,0xD7,
        0x69,0xC0,0x01,0x01,0x01,0x01,0xFC,0x51,0xC1,0xE9,0x02,0xF3,0xAB,0x59,0x83,0xE1,0x03,0xF3,0xAA,
        0x8B,0xC2,0x5F,0xC3
    };
    memcpy(g_fastStubPage + 0x1A0u, s_memset, sizeof(s_memset));
    // strlen @ 0x1E0
    const uint8_t s_strlen[] = {
        0x8B,0x54,0x24,0x04,0x31,0xC0,0x85,0xD2,0x74,0x0E,0x8B,0xCA,
        0x80,0x39,0x00,0x74,0x03,0x41,0xEB,0xF8,0x8B,0xC1,0x2B,0xC2,0xC3
    };
    memcpy(g_fastStubPage + 0x1E0u, s_strlen, sizeof(s_strlen));
    // strcmp @ 0x220 (null-guarded)
    const uint8_t s_strcmp[] = {
        0x8B,0x4C,0x24,0x04,0x8B,0x54,0x24,0x08,0x31,0xC0,0x85,0xC9,0x74,0x18,0x85,0xD2,0x74,0x14,
        0x0F,0xB6,0x01,0x3A,0x02,0x75,0x08,0x84,0xC0,0x74,0x09,0x41,0x42,0xEB,0xF1,
        0x0F,0xB6,0x12,0x2B,0xC2,0xC3
    };
    memcpy(g_fastStubPage + 0x220u, s_strcmp, sizeof(s_strcmp));
    // strncmp @ 0x260
    const uint8_t s_strncmp[] = {
        0x56,0x8B,0x74,0x24,0x08,0x8B,0x54,0x24,0x0C,0x8B,0x4C,0x24,0x10,0x31,0xC0,0x85,0xC9,0x74,0x19,
        0x0F,0xB6,0x06,0x3A,0x02,0x75,0x0D,0x84,0xC0,0x74,0x0E,0x46,0x42,0x49,0x75,0xF0,
        0x31,0xC0,0xEB,0x05,0x0F,0xB6,0x12,0x2B,0xC2,0x5E,0xC3
    };
    memcpy(g_fastStubPage + 0x260u, s_strncmp, sizeof(s_strncmp));
    // memcmp @ 0x2A0
    const uint8_t s_memcmp[] = {
        0x56,0x8B,0x74,0x24,0x08,0x8B,0x54,0x24,0x0C,0x8B,0x4C,0x24,0x10,0x31,0xC0,0x85,0xC9,0x74,0x15,
        0x0F,0xB6,0x06,0x3A,0x02,0x75,0x09,0x46,0x42,0x49,0x75,0xF4,
        0x31,0xC0,0xEB,0x05,0x0F,0xB6,0x12,0x2B,0xC2,0x5E,0xC3
    };
    memcpy(g_fastStubPage + 0x2A0u, s_memcmp, sizeof(s_memcmp));
    // strchr @ 0x2E0
    const uint8_t s_strchr[] = {
        0x8B,0x44,0x24,0x04,0x8A,0x54,0x24,0x08,0x85,0xC0,0x74,0x0F,
        0x8A,0x08,0x3A,0xCA,0x74,0x09,0x84,0xC9,0x74,0x03,0x40,0xEB,0xF3,0x31,0xC0,0xC3
    };
    memcpy(g_fastStubPage + 0x2E0u, s_strchr, sizeof(s_strchr));
    // Win32/CRT no-ops & Interlocked atomics @ 0x320..0x3A0
    const uint8_t s_ret4[]  = {0xC2,0x04,0x00};
    const uint8_t s_ret0[]  = {0xC3};
    const uint8_t s_echo1[] = {0x8B,0x44,0x24,0x04,0xC2,0x04,0x00};
    const uint8_t s_iinc[]  = {0x8B,0x4C,0x24,0x04,0xFF,0x01,0x8B,0x01,0xC2,0x04,0x00};
    const uint8_t s_idec[]  = {0x8B,0x4C,0x24,0x04,0xFF,0x09,0x8B,0x01,0xC2,0x04,0x00};
    const uint8_t s_ixchg[] = {0x8B,0x4C,0x24,0x04,0x8B,0x54,0x24,0x08,0x8B,0x01,0x89,0x11,0xC2,0x08,0x00};
    const uint8_t s_ixadd[] = {0x8B,0x4C,0x24,0x04,0x8B,0x54,0x24,0x08,0x8B,0x01,0x01,0x11,0xC2,0x08,0x00};
    const uint8_t s_icxch[] = {0x8B,0x4C,0x24,0x04,0x8B,0x54,0x24,0x08,0x8B,0x44,0x24,0x0C,0x0F,0xB1,0x11,0xC2,0x0C,0x00};
    memcpy(g_fastStubPage + 0x320u, s_ret4,  sizeof(s_ret4));
    memcpy(g_fastStubPage + 0x330u, s_ret0,  sizeof(s_ret0));
    memcpy(g_fastStubPage + 0x340u, s_echo1, sizeof(s_echo1));
    memcpy(g_fastStubPage + 0x350u, s_iinc,  sizeof(s_iinc));
    memcpy(g_fastStubPage + 0x360u, s_idec,  sizeof(s_idec));
    memcpy(g_fastStubPage + 0x370u, s_ixchg, sizeof(s_ixchg));
    memcpy(g_fastStubPage + 0x380u, s_ixadd, sizeof(s_ixadd));
    memcpy(g_fastStubPage + 0x390u, s_icxch, sizeof(s_icxch));
    g_fastStubInit = true;
}

static uint32_t getFastStubAddr(const std::string& fullKey) {
    static const std::unordered_map<std::string, uint32_t> kFast = {
        {"msvcr100.dll!isalnum",  0x6D000000u}, {"msvcr100.dll!isalpha",  0x6D000020u},
        {"msvcr100.dll!isdigit",  0x6D000040u}, {"msvcr100.dll!isspace",  0x6D000060u},
        {"msvcr100.dll!isupper",  0x6D000080u}, {"msvcr100.dll!islower",  0x6D0000A0u},
        {"msvcr100.dll!isxdigit", 0x6D0000C0u}, {"msvcr100.dll!ispunct",  0x6D0000E0u},
        {"msvcr100.dll!iscntrl",  0x6D000100u}, {"msvcr100.dll!tolower",  0x6D000120u},
        {"msvcr100.dll!toupper",  0x6D000140u}, {"msvcr100.dll!memcpy",   0x6D000160u},
        {"msvcr100.dll!memmove",  0x6D000160u}, {"msvcr100.dll!memset",   0x6D0001A0u},
        {"msvcr100.dll!strlen",   0x6D0001E0u}, {"msvcr100.dll!strcmp",   0x6D000220u},
        {"msvcr100.dll!strncmp",  0x6D000260u}, {"msvcr100.dll!memcmp",   0x6D0002A0u},
        {"msvcr100.dll!strchr",   0x6D0002E0u}, {"msvcr100.dll!_lock",    0x6D000330u},
        {"msvcr100.dll!_unlock",  0x6D000330u},
        {"kernel32.dll!EnterCriticalSection",       0x6D000320u},
        {"kernel32.dll!LeaveCriticalSection",       0x6D000320u},
        {"kernel32.dll!DeleteCriticalSection",      0x6D000320u},
        {"kernel32.dll!EncodePointer",              0x6D000340u},
        {"kernel32.dll!DecodePointer",              0x6D000340u},
        {"kernel32.dll!InterlockedIncrement",       0x6D000350u},
        {"kernel32.dll!InterlockedDecrement",       0x6D000360u},
        {"kernel32.dll!InterlockedExchange",        0x6D000370u},
        {"kernel32.dll!InterlockedExchangeAdd",     0x6D000380u},
        {"kernel32.dll!InterlockedCompareExchange", 0x6D000390u},
    };
    auto it = kFast.find(fullKey);
    return (it != kFast.end()) ? it->second : 0u;
}

static uint32_t getOrAllocNativeThunk(const std::string& dllLower, const std::string& symKey) {
    std::string fullKey = dllLower + "!" + symKey;
    if (uint32_t fa = getFastStubAddr(fullKey)) return fa;
    auto it = g_thunkTable.find(fullKey);
    if (it != g_thunkTable.end()) return it->second;
    uint32_t addr = g_nextThunkAddr;
    g_nextThunkAddr += 16;
    g_thunkTable[fullKey] = addr;
    g_dllThunkCounts[dllLower]++;
    return addr;
}

static void linkModuleIAT(LoadedModule& mod) {
    DataDir impDir = mod.nt.DataDirectory[1];
    if (impDir.VirtualAddress > 0 && impDir.VirtualAddress + sizeof(ImportDesc) <= mod.sizeOfImage) {
        auto* id = (ImportDesc*)(mod.mappedBase + impDir.VirtualAddress);
        while (id->Name != 0 && id->Name < mod.sizeOfImage) {
            const char* dllName = (const char*)(mod.mappedBase + id->Name);
            std::string dllLower = toLowerStr(dllName);
            auto modIt = g_modIndex.find(dllLower);

            uint32_t iltRVA = id->OriginalFirstThunk ? id->OriginalFirstThunk : id->FirstThunk;
            uint32_t iatRVA = id->FirstThunk;

            if (iltRVA > 0 && iatRVA > 0 && iltRVA + 4 <= mod.sizeOfImage && iatRVA + 4 <= mod.sizeOfImage) {
                uint32_t* ilt = (uint32_t*)(mod.mappedBase + iltRVA);
                uint32_t* iat = (uint32_t*)(mod.mappedBase + iatRVA);

                while (*ilt != 0) {
                    uint32_t val = *ilt;
                    uint32_t resolvedAddr = 0;

                    if (modIt != g_modIndex.end()) {
                        const LoadedModule& targetMod = g_modules[modIt->second];
                        if (val & 0x80000000u) {
                            uint32_t ord = val & 0xFFFFu;
                            auto oIt = targetMod.ordExports.find(ord);
                            if (oIt != targetMod.ordExports.end()) resolvedAddr = oIt->second;
                        } else if (val + 2 < mod.sizeOfImage) {
                            const char* fnName = (const char*)(mod.mappedBase + val + 2);
                            auto nIt = targetMod.nameExports.find(fnName);
                            if (nIt != targetMod.nameExports.end()) resolvedAddr = nIt->second;
                        }
                    }

                    if (resolvedAddr != 0) {
                        mod.engineSymsLinked++;
                    } else {
                        std::string symName;
                        if (val & 0x80000000u) {
                            symName = "#" + std::to_string(val & 0xFFFFu);
                        } else if (val + 2 < mod.sizeOfImage) {
                            symName = (const char*)(mod.mappedBase + val + 2);
                        }
                        resolvedAddr = getOrAllocNativeThunk(dllLower, symName);
                        mod.nativeThunksLinked++;
                    }

                    *iat = resolvedAddr;
                    ilt++;
                    iat++;
                }
            }
            id++;
        }
    }
}

static std::string dumpEntryBytes(const LoadedModule& mod, size_t nBytes) {
    if (mod.entryPointRVA + nBytes > mod.sizeOfImage) return "OUT_OF_RANGE";
    const uint8_t* p = mod.mappedBase + mod.entryPointRVA;
    char buf[128];
    size_t pos = 0;
    for (size_t i = 0; i < nBytes && pos + 4 < sizeof(buf); ++i) {
        pos += snprintf(buf + pos, sizeof(buf) - pos, "%02X ", p[i]);
    }
    if (pos > 0 && buf[pos - 1] == ' ') buf[pos - 1] = '\0';
    return std::string(buf);
}

static std::string runStage5BootstrapProbe() {
    std::ostringstream out;
    out << sh3DxvkRunLiveProbe() << "\n";
    out << "\n=== Stage 5: x86 CPU Interface + TEB/PEB + Thunk Trap ===\n";
    if (g_modules.empty()) {
        out << "[STAGE5 ERR] No modules mapped in memory.\n";
        return out.str();
    }

    std::unique_ptr<IX86CPU> cpu(createActiveX86CPU());
    if (!cpu || !cpu->initialize()) {
        out << "[STAGE5 ERR] Failed to initialize x86 CPU backend.\n";
        return out.str();
    }
    out << "CPU Backend : " << cpu->backendName() << "\n";

    for (const auto& m : g_modules) {
        cpu->mapGuestMemory(m.simBase, m.sizeOfImage, m.mappedBase);
    }

    Win32EnvState envState{};
    std::string envReport;
    if (!setupWin32GuestEnvironment(cpu.get(), g_modules[0].simBase, envState, envReport)) {
        out << "[STAGE5 ERR] Failed to setup TEB/PEB environment.\n";
        return out.str();
    }
    out << envReport << "\n";

    ThunkDispatcher dispatcher;
    initFastStubPage();
    cpu->mapGuestMemory(0x6D000000u, 4096u, g_fastStubPage);
    dispatcher.buildReverseMap(g_thunkTable);
    for (const auto& m : g_modules) {
        if (m.simBase != 0u) dispatcher.registerModule(m.name, m.simBase);
    }
    {
        const char cmdA[] = "Stronghold3.exe";
        const char16_t cmdW[] = u"Stronghold3.exe";
        uint32_t ptrA = 0x7000F000u;
        uint32_t ptrW = 0x7000F100u;
        cpu->writeGuestMemory(ptrA, cmdA, sizeof(cmdA));
        cpu->writeGuestMemory(ptrW, cmdW, sizeof(cmdW));
        auto itA = g_thunkTable.find("msvcr100.dll!_acmdln");
        if (itA != g_thunkTable.end()) cpu->writeGuestMemory(itA->second, &ptrA, 4);
        auto itW = g_thunkTable.find("msvcr100.dll!_wcmdln");
        if (itW != g_thunkTable.end()) cpu->writeGuestMemory(itW->second, &ptrW, 4);
    }
    out << "Reverse Thunk Map Indexed: " << dispatcher.count() << " entries\n";

    cpu->setThunkRange(0x70000000u, 0x7000FFF0u,
        [&dispatcher](uint32_t thunkAddr, uint32_t retAddr) {
            return dispatcher.onThunkTrap(thunkAddr, retAddr);
        });

    uint32_t totalSteps = 0;
    const uint32_t maxTotalSteps = 2000000000u;
    X86StepResult stepRes{};
    bool dllAbort = false;
    {
        const char* initOrder[] = {
            "msvcp100.dll", "lua100.dll", "vbase100.dll", "vision100.dll", "pathengine.dll",
            "havok.vplugin", "visionengineplugin.vplugin", "strongholdbase.dll", "supahfly.dll"
        };
        std::vector<size_t> order;
        std::vector<bool> queued(g_modules.size(), false);
        for (const char* n : initOrder) {
            auto it = g_modIndex.find(n);
            if (it != g_modIndex.end() && it->second > 0 && !queued[it->second]) {
                order.push_back(it->second); queued[it->second] = true;
            }
        }
        for (size_t i = 1; i < g_modules.size(); ++i) {
            if (!queued[i]) order.push_back(i);
        }
        const uint32_t baseEsp = cpu->readRegister(X86Reg::ESP);
        const uint32_t dllSentinel = 0x7000FFE0u;
        for (size_t idx : order) {
            const LoadedModule& mod = g_modules[idx];
            if (mod.entryPointRVA == 0) continue;
            uint32_t callEsp = baseEsp - 32u;
            uint32_t args[4] = { dllSentinel, mod.simBase, 1u, 0u };
            cpu->writeGuestMemory(callEsp, args, sizeof(args));
            cpu->writeRegister(X86Reg::ESP, callEsp);
            uint32_t dEip = mod.simBase + mod.entryPointRVA;
            uint32_t dSteps = 0;
            X86StepResult dRes{};
            bool dDone = false;
            for (int di = 0; di < 100000 && dSteps < 5000000; ++di) {
                dRes = cpu->stepInstructions(dEip, 5000000 - dSteps);
                dSteps += dRes.stepsExecuted;
                if (dRes.haltedOnThunk) {
                    if (dRes.stopAddress == dllSentinel) { dDone = true; break; }
                    uint32_t nxt = 0;
                    if (dispatcher.handleThunkCall(cpu.get(), dispatcher.lastTrappedAddress(), dispatcher.lastReturnAddress(), nxt)) {
                        dEip = nxt; continue;
                    }
                    break;
                }
                break;
            }
            totalSteps += dSteps;
            char dbuf[224];
            if (dDone) {
                snprintf(dbuf, sizeof(dbuf), "[DLLMAIN] %-26s -> OK (ret=%u, steps=%u)\n", mod.name.c_str(), cpu->readRegister(X86Reg::EAX), dSteps);
                out << dbuf;
            } else {
                snprintf(dbuf, sizeof(dbuf), "[DLLMAIN] %-26s -> FAIL (%s, EIP=0x%08X)\n", mod.name.c_str(), dRes.reason.c_str(), dRes.stopAddress);
                out << dbuf;
                stepRes = dRes; dllAbort = true; break;
            }
        }
        cpu->writeRegister(X86Reg::ESP, baseEsp);
    }
    uint32_t currentEip = g_modules[0].simBase + g_modules[0].entryPointRVA;

    auto loopStart = std::chrono::steady_clock::now();
    uint32_t hleExecCount = 0;
    uint32_t lastHleAddr = 0, lastHleRet = 0;
    if (!dllAbort)
    for (int iter = 0; iter < 20000000 && totalSteps < maxTotalSteps; ++iter) {
        if ((iter & 4095) == 4095) {
            auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - loopStart).count();
            if (elapsedMs >= 180000) {
                stepRes.reason = "WATCHDOG_TIMEOUT_180S";
                stepRes.haltedOnThunk = false;
                stepRes.stopAddress = currentEip;
                break;
            }
        }
        uint32_t rem = maxTotalSteps - totalSteps;
        uint32_t slice = (rem > 500000u) ? 500000u : rem;
        stepRes = cpu->stepInstructions(currentEip, slice);
        totalSteps += stepRes.stepsExecuted;
        if (stepRes.haltedOnThunk) {
            lastHleAddr = dispatcher.lastTrappedAddress();
            lastHleRet = dispatcher.lastReturnAddress();
            uint32_t nextEip = 0;
            if (dispatcher.handleThunkCall(cpu.get(), lastHleAddr, lastHleRet, nextEip)) {
                ++hleExecCount;
                currentEip = nextEip;
                continue;
            }
            break; // Unimplemented API reached
        }
        if (!stepRes.faulted && stepRes.stepsExecuted > 0) {
            currentEip = cpu->readRegister(X86Reg::EIP);
            auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - loopStart).count();
            if (elapsedMs >= 180000) {
                stepRes.reason = "WATCHDOG_TIMEOUT_180S";
                stepRes.stopAddress = currentEip;
                break;
            }
            continue;
        }
        break; // Faulted or max steps reached
    }

    char sbuf[256];
    snprintf(sbuf, sizeof(sbuf),
             "Stage 6-A Loop: %s | TotalSteps: %u | HLE Calls: %zu | StopEIP: 0x%08X\n",
             stepRes.reason.c_str(), totalSteps, dispatcher.handledLog().size(), stepRes.stopAddress);
    out << sbuf;

    if (!dispatcher.d3dTrace().empty()) {
        out << "[D3D9 TRACE] " << dispatcher.d3dTrace() << "\n";
    }
    if (!dispatcher.d3d9BridgeStatus().empty()) { out << "[DXVK BRIDGE] " << dispatcher.d3d9BridgeStatus() << "\n"; }
    if (!dispatcher.lastMsgBox().empty()) {
        out << "[LAST MSGBOX] " << dispatcher.lastMsgBox() << "\n";
    }
    if (stepRes.reason == "WATCHDOG_TIMEOUT_180S") {
        snprintf(sbuf, sizeof(sbuf),
                 "[WATCHDOG] RealHLE=%u | LastHLE=0x%08X (%s) | LastRet=0x%08X | EAX=0x%08X ESP=0x%08X\n",
                 hleExecCount, lastHleAddr, dispatcher.lastTrappedSymbol().c_str(), lastHleRet,
                 cpu->readRegister(X86Reg::EAX), cpu->readRegister(X86Reg::ESP));
        out << sbuf;
    }
    if (stepRes.haltedOnThunk) {
        snprintf(sbuf, sizeof(sbuf),
                 "[NEXT TRAP] 0x%08X (%s) | Ret: 0x%08X\n",
                 dispatcher.lastTrappedAddress(),
                 dispatcher.lastTrappedSymbol().c_str(),
                 dispatcher.lastReturnAddress());
        out << sbuf;
    }

    const auto& hlog = dispatcher.handledLog();
    std::vector<std::string> lines;
    for (size_t i = 0; i < hlog.size(); ) {
        size_t j = i + 1;
        while (j < hlog.size() && hlog[j] == hlog[i]) ++j;
        size_t cnt = j - i;
        std::string line = "  [HLE OK #" + std::to_string(i + 1) + "] " + hlog[i];
        if (cnt > 1) line += " (x" + std::to_string(cnt) + ")";
        if (line.find("!malloc") == std::string::npos &&
            line.find("!_msize") == std::string::npos &&
            line.find("!free") == std::string::npos &&
            line.find("!memcpy") == std::string::npos &&
            line.find("!memmove") == std::string::npos &&
            line.find("CriticalSection") == std::string::npos &&
            line.find("!isspace") == std::string::npos &&
            line.find("!tolower") == std::string::npos &&
            line.find("!isalnum") == std::string::npos &&
            line.find("!isalpha") == std::string::npos &&
            line.find("!fread") == std::string::npos &&
            line.find("!ferror") == std::string::npos &&
            line.find("!fseek") == std::string::npos &&
            line.find("!ftell") == std::string::npos) {
            lines.push_back(line);
        }
        i = j;
    }
    size_t startIdx = (lines.size() > 14) ? (lines.size() - 14) : 0;
    if (startIdx > 0) {
        out << "  ... (" << startIdx << " earlier HLE groups hidden) ...\n";
    }
    for (size_t k = startIdx; k < lines.size(); ++k) {
        out << lines[k] << "\n";
    }

    destroyWin32GuestEnvironment(envState);
    return out.str();
}

extern "C" JNIEXPORT void JNICALL
Java_com_bolt_stronghold3wrapper_MainActivity_setNativeSurface(
        JNIEnv* env, jobject /*thiz*/, jobject jSurface) {
    ANativeWindow* win = jSurface ? ANativeWindow_fromSurface(env, jSurface) : nullptr;
    sh3DxvkSetNativeWindow(win);
    if (win) ANativeWindow_release(win);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_bolt_stronghold3wrapper_MainActivity_inspectEngineBinaries(
        JNIEnv* env, jobject /*thiz*/, jstring jBinDir) {
    for (auto& m : g_modules) {
        if (m.mappedBase) munmap(m.mappedBase, m.sizeOfImage);
    }
    static std::mutex g_bridgeMutex;
    std::lock_guard<std::mutex> bridgeLock(g_bridgeMutex);

    g_modules.clear();
    g_modIndex.clear();
    g_thunkTable.clear();
    g_dllThunkCounts.clear();
    g_nextThunkAddr = 0x70000000;

    const char* cDir = env->GetStringUTFChars(jBinDir, nullptr);
    std::string baseDir(cDir ? cDir : "");
    if (!baseDir.empty()) chdir(baseDir.c_str());
    env->ReleaseStringUTFChars(jBinDir, cDir);

    struct ModSpec { const char* name; uint32_t simBase; };
    const ModSpec specs[] = {
        {"Stronghold3.exe",            0x00400000},
        {"vBase100.dll",               0x10000000},
        {"Vision100.dll",              0x11000000},
        {"StrongholdBase.dll",         0x12000000},
        {"SupahFly.dll",               0x13000000},
        {"VisionEnginePlugin.vPlugin", 0x14000000},
        {"Havok.vPlugin",              0x15000000},
        {"PathEngine.dll",             0x16000000},
        {"msvcp100.dll",               0x17000000},
        {"lua100.dll",                 0x18000000},
        {"FMod.vPlugin",               0x19000000}
    };

    for (const auto& s : specs) {
        mapAndIndexPE(baseDir, s.name, s.simBase);
    }

    for (size_t i = 0; i < g_modules.size(); ++i) {
        linkModuleIAT(g_modules[i]);
    }

    std::ostringstream report;
    report << runStage5BootstrapProbe() << "\n";
    report << "=== SH3 ARM64 Bridge (Stage 4 + Stage 5 Bootstrap) ===\n";
    for (const auto& m : g_modules) {
        char mbuf[160];
        snprintf(mbuf, sizeof(mbuf),
                 "[LINKED] %-26s | EngineSyms:%4u | NativeThunks:%3u | EP:0x%08X\n",
                 m.name.c_str(), m.engineSymsLinked, m.nativeThunksLinked,
                 m.simBase + m.entryPointRVA);
        report << mbuf;
    }

    if (!g_modules.empty()) {
        char epbuf[64];
        snprintf(epbuf, sizeof(epbuf), "\nEXE EP (0x%08X): ",
                 g_modules[0].simBase + g_modules[0].entryPointRVA);
        report << epbuf << dumpEntryBytes(g_modules[0], 12) << "\n";
    }

    report << "\n--- External DLL Thunk Breakdown (Total: " << g_thunkTable.size() << " unique fn) ---\n";
    int col = 0;
    for (const auto& kv : g_dllThunkCounts) {
        char tbuf[96];
        snprintf(tbuf, sizeof(tbuf), "%-14s : %3u fn", kv.first.c_str(), kv.second);
        report << tbuf;
        col++;
        if (col % 2 == 0) report << "\n";
        else report << " | ";
    }
    if (col % 2 != 0) report << "\n";

    std::string cfgPath = redirectWinPath(baseDir, "config.xml");
    struct stat st{};
    if (stat(cfgPath.c_str(), &st) == 0) {
        report << "\n[CFG OK] config.xml Exact: " << st.st_size << " Bytes\n";
    }
    std::string corePath = redirectWinPath(baseDir, "../assets_archive/core.v");
    FILE* cfp = fopen(corePath.c_str(), "rb");
    if (!cfp) {
        corePath = redirectWinPath(baseDir, "assets_archive/core.v");
        cfp = fopen(corePath.c_str(), "rb");
    }
    if (cfp) {
        uint8_t magic[8]{};
        size_t r = fread(magic, 1, 8, cfp);
        fclose(cfp);
        if (r == 8) {
            char hbuf[96];
            snprintf(hbuf, sizeof(hbuf),
                     "[VFS OK] core.v Magic (8B): %02X %02X %02X %02X %02X %02X %02X %02X\n",
                     magic[0], magic[1], magic[2], magic[3],
                     magic[4], magic[5], magic[6], magic[7]);
            report << hbuf;
        }
    }

    return env->NewStringUTF(report.str().c_str());
}
