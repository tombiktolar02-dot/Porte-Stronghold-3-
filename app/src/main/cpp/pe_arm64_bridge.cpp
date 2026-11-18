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
    NTHeader32  nt{};
    std::unordered_map<std::string, uint32_t> nameExports;
    std::unordered_map<uint32_t, uint32_t>    ordExports;
};

static std::vector<LoadedModule> g_modules;
static std::unordered_map<std::string, size_t> g_modIndex;
static uint32_t g_nextThunkAddr = 0x70000000;
static std::unordered_map<std::string, uint32_t> g_thunkTable;

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

static uint32_t getOrAllocNativeThunk(const std::string& dllLower, const std::string& symKey) {
    std::string fullKey = dllLower + "!" + symKey;
    auto it = g_thunkTable.find(fullKey);
    if (it != g_thunkTable.end()) return it->second;
    uint32_t addr = g_nextThunkAddr;
    g_nextThunkAddr += 16;
    g_thunkTable[fullKey] = addr;
    return addr;
}

static std::string linkModuleIAT(LoadedModule& mod) {
    DataDir impDir = mod.nt.DataDirectory[1];
    uint32_t linkedEngine = 0;
    uint32_t linkedThunks = 0;

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
                        if (resolvedAddr != 0) linkedEngine++;
                    }

                    if (resolvedAddr == 0) {
                        std::string symName;
                        if (val & 0x80000000u) {
                            symName = "#" + std::to_string(val & 0xFFFFu);
                        } else if (val + 2 < mod.sizeOfImage) {
                            symName = (const char*)(mod.mappedBase + val + 2);
                        }
                        resolvedAddr = getOrAllocNativeThunk(dllLower, symName);
                        linkedThunks++;
                    }

                    *iat = resolvedAddr;
                    ilt++;
                    iat++;
                }
            }
            id++;
        }
    }

    char buf[256];
    snprintf(buf, sizeof(buf),
             "[LINKED] %-24s | EngineSyms:%4u | NativeThunks:%4u | EP:0x%08X\n",
             mod.name.c_str(), linkedEngine, linkedThunks, mod.simBase + mod.entryPointRVA);
    LOGI("%s", buf);
    return std::string(buf);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_bolt_stronghold3wrapper_MainActivity_inspectEngineBinaries(
        JNIEnv* env, jobject /*thiz*/, jstring jBinDir) {
    for (auto& m : g_modules) {
        if (m.mappedBase) munmap(m.mappedBase, m.sizeOfImage);
    }
    g_modules.clear();
    g_modIndex.clear();
    g_thunkTable.clear();
    g_nextThunkAddr = 0x70000000;

    const char* cDir = env->GetStringUTFChars(jBinDir, nullptr);
    std::string baseDir(cDir ? cDir : "");
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
        {"PathEngine.dll",             0x16000000}
    };

    for (const auto& s : specs) {
        mapAndIndexPE(baseDir, s.name, s.simBase);
    }

    std::ostringstream report;
    report << "=== SH3 ARM64 Bridge (Stage 3: IAT Linker + Thunks + File I/O) ===\n";
    for (auto& m : g_modules) {
        report << linkModuleIAT(m);
    }

    report << "\n--- Win32 Path Redirector & Asset Archive Verification ---\n";
    const char* winPaths[] = {
        "..\\..\\assets\\core.v",
        "..\\..\\assets\\loc.v",
        "config.xml"
    };
    for (const char* wp : winPaths) {
        std::string androidPath = redirectWinPath(baseDir, wp);
        struct stat st{};
        if (stat(androidPath.c_str(), &st) == 0) {
            char abuf[256];
            snprintf(abuf, sizeof(abuf), "[ASSET OK] %-22s -> %lld KB\n",
                     wp, (long long)(st.st_size / 1024));
            report << abuf;
        } else {
            report << "[ASSET ERR] " << wp << " -> " << androidPath << "\n";
        }
    }

    report << "Unique ARM64 Native System Thunks Bound: " << g_thunkTable.size() << "\n";
    return env->NewStringUTF(report.str().c_str());
}
