#include <jni.h>
#include <android/log.h>
#include <sys/mman.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <sstream>
#include <vector>

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

struct LoadedModule {
    std::string name;
    uint8_t*    mappedBase = nullptr;
    uint32_t    sizeOfImage = 0;
    uint32_t    simBase = 0;
};

static std::vector<LoadedModule> g_modules;

static std::string mapAndRelocatePE(const std::string& baseDir, const char* name, uint32_t targetSimBase) {
    std::string path = baseDir + "/" + name;
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) return std::string("[ERR] Open failed: ") + name + "\n";

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
        return std::string("[ERR] mmap failed: ") + name + "\n";
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
    uint32_t relocCount = 0;
    DataDir relocDir = nt.DataDirectory[5];
    if (delta != 0 && relocDir.VirtualAddress > 0 && relocDir.Size > 0) {
        uint32_t offset = 0;
        while (offset + sizeof(BaseRelocBlock) <= relocDir.Size) {
            auto* blk = (BaseRelocBlock*)(base + relocDir.VirtualAddress + offset);
            if (blk->BlockSize == 0) break;
            uint32_t count = (blk->BlockSize - sizeof(BaseRelocBlock)) / sizeof(uint16_t);
            auto* entries = (uint16_t*)((uint8_t*)blk + sizeof(BaseRelocBlock));
            for (uint32_t i = 0; i < count; ++i) {
                uint16_t type = entries[i] >> 12;
                uint16_t rvaOff = entries[i] & 0x0FFF;
                if (type == 3) { // IMAGE_REL_BASED_HIGHLOW
                    uint32_t patchRVA = blk->PageRVA + rvaOff;
                    if (patchRVA + 4 <= allocSize) {
                        uint32_t* ptr = (uint32_t*)(base + patchRVA);
                        *ptr += (uint32_t)delta;
                        relocCount++;
                    }
                }
            }
            offset += blk->BlockSize;
        }
    }

    uint32_t numExports = 0;
    DataDir expDir = nt.DataDirectory[0];
    if (expDir.VirtualAddress > 0 && expDir.VirtualAddress + sizeof(ExportDir) <= allocSize) {
        auto* ed = (ExportDir*)(base + expDir.VirtualAddress);
        numExports = ed->NumberOfFunctions;
    }

    uint32_t numImportDLLs = 0;
    uint32_t numImportFuncs = 0;
    DataDir impDir = nt.DataDirectory[1];
    if (impDir.VirtualAddress > 0 && impDir.VirtualAddress + sizeof(ImportDesc) <= allocSize) {
        auto* id = (ImportDesc*)(base + impDir.VirtualAddress);
        while (id->Name != 0) {
            numImportDLLs++;
            uint32_t thunkRVA = id->OriginalFirstThunk ? id->OriginalFirstThunk : id->FirstThunk;
            if (thunkRVA > 0 && thunkRVA + 4 <= allocSize) {
                uint32_t* thunk = (uint32_t*)(base + thunkRVA);
                while (*thunk != 0) {
                    numImportFuncs++;
                    thunk++;
                }
            }
            id++;
        }
    }

    g_modules.push_back({name, base, (uint32_t)allocSize, targetSimBase});

    char buf[256];
    snprintf(buf, sizeof(buf),
             "[MAPPED] %-24s | VBase:0x%08X | Relocs:%6u | Exp:%4u | Imp:%2u DLLs (%4u fn)\n",
             name, targetSimBase, relocCount, numExports, numImportDLLs, numImportFuncs);
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

    std::ostringstream report;
    report << "=== SH3 ARM64 Native PE Loader (Stage 2: mmap + Reloc + IAT/EAT) ===\n";
    report << "Mapped into Galaxy S22 RAM | Base Relocation & Symbol Scan:\n\n";
    for (const auto& s : specs) {
        report << mapAndRelocatePE(baseDir, s.name, s.simBase);
    }
    return env->NewStringUTF(report.str().c_str());
}
