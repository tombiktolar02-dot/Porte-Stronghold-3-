#include <jni.h>
#include <android/log.h>
#include <cstdio>
#include <cstdint>
#include <string>
#include <sstream>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "SH3_BRIDGE", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "SH3_BRIDGE", __VA_ARGS__)

#pragma pack(push, 1)
struct DOSHeader {
    uint16_t e_magic;
    uint8_t  pad[58];
    uint32_t e_lfanew;
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
};
#pragma pack(pop)

static std::string inspectPE(const std::string& baseDir, const char* name) {
    std::string path = baseDir + "/" + name;
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) return std::string("[ERR] Cannot open: ") + name + "\n";

    DOSHeader dos{};
    if (fread(&dos, sizeof(dos), 1, fp) != 1 || dos.e_magic != 0x5A4D) {
        fclose(fp);
        return std::string("[ERR] Bad MZ: ") + name + "\n";
    }
    fseek(fp, dos.e_lfanew, SEEK_SET);
    NTHeader32 nt{};
    if (fread(&nt, sizeof(nt), 1, fp) != 1 || nt.Signature != 0x00004550) {
        fclose(fp);
        return std::string("[ERR] Bad PE: ") + name + "\n";
    }
    fclose(fp);

    char buf[256];
    snprintf(buf, sizeof(buf),
             "[OK] %-26s | Sec:%2u | Base:0x%08X | EP:0x%08X | ImgSz:%u KB\n",
             name, nt.NumberOfSections, nt.ImageBase,
             nt.AddressOfEntryPoint, nt.SizeOfImage / 1024);
    LOGI("%s", buf);
    return std::string(buf);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_bolt_stronghold3wrapper_MainActivity_inspectEngineBinaries(
        JNIEnv* env, jobject /*thiz*/, jstring jBinDir) {
    const char* cDir = env->GetStringUTFChars(jBinDir, nullptr);
    std::string baseDir(cDir ? cDir : "");
    env->ReleaseStringUTFChars(jBinDir, cDir);

    const char* bins[] = {
        "Stronghold3.exe",
        "vBase100.dll",
        "Vision100.dll",
        "StrongholdBase.dll",
        "SupahFly.dll",
        "VisionEnginePlugin.vPlugin",
        "Havok.vPlugin",
        "PathEngine.dll"
    };

    std::ostringstream report;
    report << "=== SH3 ARM64 Native PE Bridge (Stage 1) ===\n";
    report << "Target Dir: " << baseDir << "\n\n";
    for (const char* b : bins) {
        report << inspectPE(baseDir, b);
    }
    return env->NewStringUTF(report.str().c_str());
}
