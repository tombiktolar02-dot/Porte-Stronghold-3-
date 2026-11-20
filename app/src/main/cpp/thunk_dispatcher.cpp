#include <sys/stat.h>
#include <cstdio>
#include "thunk_dispatcher.h"
#include <cmath>
#include <chrono>
#include <ctime>
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

    if (thunkAddr >= 0x7000C000u && thunkAddr < 0x7000CE00u) {
        if (thunkAddr == 0x7000C040u) m_d3dTrace = "DEV: ";
        if (m_d3dTrace.size() < 512u) { if (thunkAddr < 0x7000C100u) m_d3dTrace += "S" + std::to_string((thunkAddr-0x7000C000u)>>2) + " "; else if (thunkAddr < 0x7000C300u) m_d3dTrace += "D" + std::to_string((thunkAddr-0x7000C100u)>>2) + " "; }
        if (m_d3d9Bridge.handleVtableThunk(thunkAddr,cpu,esp,returnAddr,outNextEip,[this](uint32_t s){return allocGuest(s);},[this](uint32_t a,const std::string& n){m_reverseMap[a]=n;})) { logSym(sym); return true; }
        return false; }
    if (thunkAddr >= 0x7000C000u && thunkAddr < 0x7000C100u) {
        uint32_t slot = (thunkAddr - 0x7000C000u) >> 2;
        if (m_d3dTrace.size() < 512u) m_d3dTrace += "S" + std::to_string(slot) + " ";
        if (slot == 0) { // IDirect3D9::QueryInterface
            uint32_t thisPtr = 0u, ppv = 0u;
            cpu->readGuestMemory(esp + 4,  &thisPtr, 4);
            cpu->readGuestMemory(esp + 12, &ppv,     4);
            if (ppv >= 0x10000u) cpu->writeGuestMemory(ppv, &thisPtr, 4);
            cpu->writeRegister(X86Reg::EAX, 0u);
            cpu->writeRegister(X86Reg::ESP, esp + 16u);
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
        if (slot == 1 || slot == 2) { // AddRef / Release
            cpu->writeRegister(X86Reg::EAX, (slot == 1) ? 2u : 1u);
            cpu->writeRegister(X86Reg::ESP, esp + 8u);
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
        if (slot == 3) { // RegisterSoftwareDevice
            cpu->writeRegister(X86Reg::EAX, 0u);
            cpu->writeRegister(X86Reg::ESP, esp + 12u);
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
        if (slot == 4) { // GetAdapterCount
            cpu->writeRegister(X86Reg::EAX, 1u);
            cpu->writeRegister(X86Reg::ESP, esp + 8u);
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
        if (slot == 5) { // GetAdapterIdentifier(this, Adapter, Flags, pIdentifier)
            uint32_t pId = 0u;
            cpu->readGuestMemory(esp + 16, &pId, 4);
            if (pId >= 0x10000u) {
                std::vector<uint8_t> idBuf(1100, 0u);
                const char drv[] = "d3d9.dll";
                const char desc[] = "Stronghold3 ARM64 Virtual GPU";
                const char dev[] = "\\\\.\\DISPLAY1";
                memcpy(idBuf.data(),        drv,  sizeof(drv));
                memcpy(idBuf.data() + 512,  desc, sizeof(desc));
                memcpy(idBuf.data() + 1024, dev,  sizeof(dev));
                uint32_t vendorId = 0x10DEu, deviceId = 0x1180u;
                memcpy(idBuf.data() + 1064, &vendorId, 4);
                memcpy(idBuf.data() + 1068, &deviceId, 4);
                cpu->writeGuestMemory(pId, idBuf.data(), idBuf.size());
            }
            cpu->writeRegister(X86Reg::EAX, 0u);
            cpu->writeRegister(X86Reg::ESP, esp + 20u);
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
        if (slot == 6) { // GetAdapterModeCount
            cpu->writeRegister(X86Reg::EAX, 1u);
            cpu->writeRegister(X86Reg::ESP, esp + 16u);
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
        if (slot == 7) { // EnumAdapterModes(this, Adapter, Format, Mode, pMode)
            uint32_t reqFmt = 22u, modeIdx = 0u, pMode = 0u;
            cpu->readGuestMemory(esp + 12, &reqFmt,  4);
            cpu->readGuestMemory(esp + 16, &modeIdx, 4);
            cpu->readGuestMemory(esp + 20, &pMode,   4);
            uint32_t hr = (modeIdx == 0u) ? 0u : 0x8876086Cu;
            if (modeIdx == 0u && pMode >= 0x10000u) {
                uint32_t dm[4] = { 1280u, 720u, 60u, (reqFmt != 0u) ? reqFmt : 22u };
                cpu->writeGuestMemory(pMode, dm, sizeof(dm));
            }
            cpu->writeRegister(X86Reg::EAX, hr);
            cpu->writeRegister(X86Reg::ESP, esp + 24u);
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
        if (slot == 8) { // GetAdapterDisplayMode(this, Adapter, pMode)
            uint32_t pMode = 0u;
            cpu->readGuestMemory(esp + 12, &pMode, 4);
            if (pMode >= 0x10000u) {
                uint32_t dm[4] = { 1280u, 720u, 60u, 22u };
                cpu->writeGuestMemory(pMode, dm, sizeof(dm));
            }
            cpu->writeRegister(X86Reg::EAX, 0u);
            cpu->writeRegister(X86Reg::ESP, esp + 16u);
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
        if (slot == 9 || slot == 12) { // CheckDeviceType / CheckDepthStencilMatch
            cpu->writeRegister(X86Reg::EAX, 0u);
            cpu->writeRegister(X86Reg::ESP, esp + 28u);
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
        if (slot == 10 || slot == 11) { // CheckDeviceFormat / CheckDeviceMultiSampleType
            if (slot == 11) {
                uint32_t pQual = 0u;
                cpu->readGuestMemory(esp + 28, &pQual, 4);
                if (pQual >= 0x10000u) { uint32_t q = 1u; cpu->writeGuestMemory(pQual, &q, 4); }
            }
            cpu->writeRegister(X86Reg::EAX, 0u);
            cpu->writeRegister(X86Reg::ESP, esp + 32u);
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
        if (slot == 13) { // CheckDeviceFormatConversion
            cpu->writeRegister(X86Reg::EAX, 0u);
            cpu->writeRegister(X86Reg::ESP, esp + 24u);
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
        if (slot == 14) { // GetDeviceCaps(this, Adapter, DevType, pCaps) - exact d3d9caps.h layout
            uint32_t pCaps = 0u;
            cpu->readGuestMemory(esp + 16, &pCaps, 4);
            if (pCaps >= 0x10000u) {
                uint32_t caps[76] = {};
                caps[0]  = 1u;          // DeviceType = D3DDEVTYPE_HAL
                caps[1]  = 0u;          // AdapterOrdinal
                caps[2]  = 0x00020000u; // Caps
                caps[3]  = 0x60020000u; // Caps2
                caps[4]  = 0x000003A0u; // Caps3
                caps[5]  = 0x80000001u; // PresentationIntervals
                caps[6]  = 0x00000001u; // CursorCaps
                caps[7]  = 0x001BBEF0u; // DevCaps (HW T&L, PureDevice, HW Raster)
                caps[8]  = 0x002FCCF2u; // PrimitiveMiscCaps
                caps[9]  = 0x07732191u; // RasterCaps
                caps[10] = 0x000000FFu; // ZCmpCaps
                caps[11] = 0x00003FFFu; // SrcBlendCaps
                caps[12] = 0x00003FFFu; // DestBlendCaps
                caps[13] = 0x000000FFu; // AlphaCmpCaps
                caps[14] = 0x00084208u; // ShadeCaps
                caps[15] = 0x0001EC45u; // TextureCaps
                caps[16] = 0x03030700u; // TextureFilterCaps
                caps[17] = 0x03030700u; // CubeTextureFilterCaps
                caps[18] = 0x03030700u; // VolumeTextureFilterCaps
                caps[19] = 0x0000003Fu; // TextureAddressCaps
                caps[20] = 0x0000003Fu; // VolumeTextureAddressCaps
                caps[21] = 0x0000001Fu; // LineCaps
                caps[22] = 4096u;       // MaxTextureWidth
                caps[23] = 4096u;       // MaxTextureHeight
                caps[24] = 2048u;       // MaxVolumeExtent
                caps[25] = 8192u;       // MaxTextureRepeat
                caps[26] = 4096u;       // MaxTextureAspectRatio
                caps[27] = 16u;         // MaxAnisotropy
                caps[28] = 0x4E6E6B28u; // MaxVertexW (1e9f)
                caps[34] = 0x000001FFu; // StencilCaps
                caps[35] = 0x00180008u; // FVFCaps
                caps[36] = 0x03FFFFFFu; // TextureOpCaps
                caps[37] = 8u;          // MaxTextureBlendStages
                caps[38] = 8u;          // MaxSimultaneousTextures
                caps[39] = 0x0000013Bu; // VertexProcessingCaps
                caps[40] = 8u;          // MaxActiveLights
                caps[41] = 6u;          // MaxUserClipPlanes
                caps[42] = 4u;          // MaxVertexBlendMatrices
                caps[43] = 255u;        // MaxVertexBlendMatrixIndex
                caps[44] = 0x42800000u; // MaxPointSize (64.0f)
                caps[45] = 1048575u;    // MaxPrimitiveCount
                caps[46] = 1048575u;    // MaxVertexIndex
                caps[47] = 16u;         // MaxStreams
                caps[48] = 255u;        // MaxStreamStride
                caps[49] = 0xFFFE0300u; // VertexShaderVersion 3.0
                caps[50] = 256u;        // MaxVertexShaderConst
                caps[51] = 0xFFFF0300u; // PixelShaderVersion 3.0
                caps[52] = 0x477FFF00u; // PixelShader1xMaxValue (65504.0f)
                caps[53] = 0x00000051u; // DevCaps2
                caps[58] = 1u;          // NumberOfAdaptersInGroup
                caps[59] = 0x000003FFu; // DeclTypes
                caps[60] = 4u;          // NumSimultaneousRTs
                caps[61] = 0x03000300u; // StretchRectFilterCaps
                caps[62] = 1u; caps[63] = 24u; caps[64] = 32u; caps[65] = 4u; // VS20Caps
                caps[66] = 31u; caps[67] = 24u; caps[68] = 32u; caps[69] = 4u; caps[70] = 512u; // PS20Caps
                caps[71] = 0x03000300u; // VertexTextureFilterCaps
                caps[72] = 65535u;      // MaxVShaderInstructionsExecuted
                caps[73] = 65535u;      // MaxPShaderInstructionsExecuted
                caps[74] = 512u;        // MaxVertexShader30InstructionSlots
                caps[75] = 512u;        // MaxPixelShader30InstructionSlots
                cpu->writeGuestMemory(pCaps, caps, sizeof(caps));
            }
            cpu->writeRegister(X86Reg::EAX, 0u);
            cpu->writeRegister(X86Reg::ESP, esp + 20u);
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
        if (slot == 15) { // GetAdapterMonitor
            cpu->writeRegister(X86Reg::EAX, 0x00010001u);
            cpu->writeRegister(X86Reg::ESP, esp + 12u);
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
        if (slot == 16) { // CreateDevice(this, Adapter, DevType, hWnd, Flags, pPP, ppDev)
            uint32_t ppDev = 0u;
            cpu->readGuestMemory(esp + 28, &ppDev, 4);
            uint32_t vtAddr = allocGuest(119 * 4);
            uint32_t devObj = allocGuest(16);
            if (vtAddr != 0u && devObj != 0u) {
                uint32_t vt[119];
                for (uint32_t si = 0; si < 119; ++si) {
                    vt[si] = 0x7000C100u + si * 4u;
                    char vname[64];
                    snprintf(vname, sizeof(vname), "IDirect3DDevice9::vslot[%u]", si);
                    m_reverseMap[vt[si]] = vname;
                }
                cpu->writeGuestMemory(vtAddr, vt, sizeof(vt));
                cpu->writeGuestMemory(devObj, &vtAddr, 4);
                if (ppDev >= 0x10000u) cpu->writeGuestMemory(ppDev, &devObj, 4);
            }
            cpu->writeRegister(X86Reg::EAX, 0u); // D3D_OK
            cpu->writeRegister(X86Reg::ESP, esp + 32u);
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
        return false;
    }

    static bool s_di8IsWide = false;
    if (thunkAddr >= 0x7000B000u && thunkAddr < 0x7000B200u) {
        uint32_t iface = (thunkAddr - 0x7000B000u) >> 8;
        uint32_t slot  = ((thunkAddr - 0x7000B000u) & 0xFFu) >> 2;
        if (iface == 0) { // IDirectInput8 (COM stdcall)
            if (slot == 1 || slot == 2) { // AddRef / Release
                cpu->writeRegister(X86Reg::EAX, (slot == 1) ? 2u : 1u);
                cpu->writeRegister(X86Reg::ESP, esp + 8u);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 0) { // QueryInterface
                uint32_t thisPtr = 0u, pRiid = 0u, ppv = 0u, d1 = 0xFFFFFFFFu;
                cpu->readGuestMemory(esp + 4,  &thisPtr, 4);
                cpu->readGuestMemory(esp + 8,  &pRiid,   4);
                cpu->readGuestMemory(esp + 12, &ppv,     4);
                if (pRiid >= 0x10000u) cpu->readGuestMemory(pRiid, &d1, 4);
                bool ok = (iface == 0) ? (d1 == 0u || d1 == 0xBF798030u || d1 == 0xBF798031u)
                                       : (d1 == 0u || d1 == 0x54D41080u || d1 == 0x54D41081u);
                uint32_t out = ok ? thisPtr : 0u;
                if (ppv >= 0x10000u) cpu->writeGuestMemory(ppv, &out, 4);
                cpu->writeRegister(X86Reg::EAX, ok ? 0u : 0x80004002u);
                cpu->writeRegister(X86Reg::ESP, esp + 16u);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 3) { // CreateDevice(this, rguid, lplpDev, pUnkOuter)
                uint32_t lplpDev = 0u;
                cpu->readGuestMemory(esp + 12, &lplpDev, 4);
                uint32_t vtAddr = allocGuest(32 * 4);
                uint32_t devObj = allocGuest(16);
                if (vtAddr != 0u && devObj != 0u) {
                    uint32_t vt[32];
                    for (uint32_t si = 0; si < 32; ++si) {
                        vt[si] = 0x7000B100u + si * 4u;
                        char vname[64];
                        snprintf(vname, sizeof(vname), "IDirectInputDevice8::vslot[%u]", si);
                        m_reverseMap[vt[si]] = vname;
                    }
                    cpu->writeGuestMemory(vtAddr, vt, sizeof(vt));
                    cpu->writeGuestMemory(devObj, &vtAddr, 4);
                    if (lplpDev >= 0x10000u) cpu->writeGuestMemory(lplpDev, &devObj, 4);
                }
                cpu->writeRegister(X86Reg::EAX, 0u); // DI_OK
                cpu->writeRegister(X86Reg::ESP, esp + 20u);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 63) { // EnumDevices_Finish
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 4u);
                outNextEip = returnAddr;
                return true;
            }
            if (slot == 4) { // EnumDevices(this, dwDevType, lpCallback, pvRef, dwFlags)
                uint32_t devType = 0u, lpCb = 0u, pvRef = 0u;
                cpu->readGuestMemory(esp + 8,  &devType, 4);
                cpu->readGuestMemory(esp + 12, &lpCb,    4);
                cpu->readGuestMemory(esp + 16, &pvRef,   4);
                bool isMouse = (devType == 0x12u || devType == 2u);
                bool isKbd   = (devType == 0x13u || devType == 3u);
                if (lpCb >= 0x10000u && (isMouse || isKbd)) {
                    uint32_t pDdi = allocGuest(1152u);
                    if (pDdi != 0u) {
                        std::vector<uint8_t> ddi(1152u, 0u);
                        uint32_t sz = s_di8IsWide ? 1100u : 580u;
                        memcpy(&ddi[0], &sz, 4);
                        const uint8_t guid[16] = { isMouse ? (uint8_t)0x60 : (uint8_t)0x61, 0x2B, 0x1D, 0x6F, 0xA0, 0xD5, 0xCF, 0x11, 0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 };
                        memcpy(&ddi[4], guid, 16); memcpy(&ddi[20], guid, 16);
                        uint32_t dt = isMouse ? 0x00000212u : 0x00000413u;
                        memcpy(&ddi[36], &dt, 4);
                        const char* nm = isMouse ? "Mouse" : "Keyboard";
                        if (s_di8IsWide) {
                            for (size_t i = 0; nm[i]; ++i) { ddi[40 + i*2] = (uint8_t)nm[i]; ddi[560 + i*2] = (uint8_t)nm[i]; }
                        } else {
                            memcpy(&ddi[40], nm, strlen(nm)); memcpy(&ddi[300], nm, strlen(nm));
                        }
                        uint16_t up = 1u, us = isMouse ? 2u : 6u;
                        size_t uo = s_di8IsWide ? 1096u : 576u;
                        memcpy(&ddi[uo], &up, 2); memcpy(&ddi[uo + 2u], &us, 2);
                        cpu->writeGuestMemory(pDdi, ddi.data(), ddi.size());
                        uint32_t fin = 0x7000B0FCu;
                        m_reverseMap[fin] = "IDirectInput8::EnumDevices_Finish";
                        cpu->writeGuestMemory(esp + 20u, &returnAddr, 4);
                        cpu->writeGuestMemory(esp + 16u, &pvRef,      4);
                        cpu->writeGuestMemory(esp + 12u, &pDdi,       4);
                        cpu->writeGuestMemory(esp + 8u,  &fin,        4);
                        cpu->writeRegister(X86Reg::ESP, esp + 8u);
                        outNextEip = lpCb;
                        logSym(sym);
                        return true;
                    }
                }
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 24u);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 5) { // GetDeviceStatus
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 12u);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 6 || slot == 7) { // RunControlPanel / Initialize
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 16u);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 8) { // FindDevice
                cpu->writeRegister(X86Reg::EAX, 0x80070002u);
                cpu->writeRegister(X86Reg::ESP, esp + 20u);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 9 || slot == 10) { // EnumDevicesBySemantics / ConfigureDevices
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + (slot == 9 ? 28u : 24u));
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
        }
        if (iface == 1) { // IDirectInputDevice8 (COM stdcall)
            if (slot == 1 || slot == 2) { // AddRef / Release
                cpu->writeRegister(X86Reg::EAX, (slot == 1) ? 2u : 1u);
                cpu->writeRegister(X86Reg::ESP, esp + 8u);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 0) { // QueryInterface
                uint32_t thisPtr = 0u, pRiid = 0u, ppv = 0u, d1 = 0xFFFFFFFFu;
                cpu->readGuestMemory(esp + 4,  &thisPtr, 4);
                cpu->readGuestMemory(esp + 8,  &pRiid,   4);
                cpu->readGuestMemory(esp + 12, &ppv,     4);
                if (pRiid >= 0x10000u) cpu->readGuestMemory(pRiid, &d1, 4);
                bool ok = (iface == 0) ? (d1 == 0u || d1 == 0xBF798030u || d1 == 0xBF798031u)
                                       : (d1 == 0u || d1 == 0x54D41080u || d1 == 0x54D41081u);
                uint32_t out = ok ? thisPtr : 0u;
                if (ppv >= 0x10000u) cpu->writeGuestMemory(ppv, &out, 4);
                cpu->writeRegister(X86Reg::EAX, ok ? 0u : 0x80004002u);
                cpu->writeRegister(X86Reg::ESP, esp + 16u);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 3 || slot == 11 || slot == 12 || slot == 15) { // GetCapabilities/SetDataFormat/SetEventNotification/GetDeviceInfo
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 12u);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 4 || slot == 14 || slot == 17) { // EnumObjects/GetObjectInfo/Initialize
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 20u);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 5 || slot == 6 || slot == 13 || slot == 16) { // GetProperty/SetProperty/SetCooperativeLevel/RunControlPanel
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 16u);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 7 || slot == 8 || slot == 25) { // Acquire / Unacquire / Poll
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 8u);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 9) { // GetDeviceState(this, cbData, lpvData)
                uint32_t cbData = 0u, lpvData = 0u;
                cpu->readGuestMemory(esp + 8,  &cbData,  4);
                cpu->readGuestMemory(esp + 12, &lpvData, 4);
                if (lpvData >= 0x10000u && cbData > 0u) {
                    uint32_t n = (cbData > 4096u) ? 4096u : cbData;
                    std::vector<uint8_t> z(n, 0u);
                    cpu->writeGuestMemory(lpvData, z.data(), n);
                }
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 16u);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 10) { // GetDeviceData(this, cbObj, rgdod, pdwInOut, dwFlags)
                uint32_t pdwInOut = 0u;
                cpu->readGuestMemory(esp + 16, &pdwInOut, 4);
                if (pdwInOut >= 0x10000u) { uint32_t z = 0u; cpu->writeGuestMemory(pdwInOut, &z, 4); }
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 24u);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
        }
        return false;
    }

    if (thunkAddr >= 0x7000A000u && thunkAddr < 0x7000A800u) {
        uint32_t iface = (thunkAddr - 0x7000A000u) >> 8;
        uint32_t slot  = ((thunkAddr - 0x7000A000u) & 0xFFu) >> 2;
        if (iface == 0) { // ISteamUser
            if (slot == 0 || slot == 1) { // GetHSteamUser / BLoggedOn
                cpu->writeRegister(X86Reg::EAX, 1u);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 2) { // GetSteamID(CSteamID* sret)
                uint32_t sretPtr = 0;
                cpu->readGuestMemory(esp + 4, &sretPtr, 4);
                uint64_t fakeId = 0x0110000100000001ULL;
                if (sretPtr >= 0x10000u) cpu->writeGuestMemory(sretPtr, &fakeId, 8);
                cpu->writeRegister(X86Reg::EAX, sretPtr);
                cpu->writeRegister(X86Reg::ESP, esp + 8);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
        }
        if (iface == 1) { // ISteamFriends
            if (slot == 1) { // SetPersonaName
                cpu->writeRegister(X86Reg::EAX, 1u);
                cpu->writeRegister(X86Reg::EDX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 8);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 2) { // GetPersonaState (Online)
                cpu->writeRegister(X86Reg::EAX, 1u);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 3) { // GetFriendCount
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 8);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 0) { // GetPersonaName
                static uint32_t s_pName = 0;
                uint8_t chk = 0;
                if (s_pName != 0) cpu->readGuestMemory(s_pName, &chk, 1);
                if (s_pName == 0 || chk != 0x50u) {
                    const char nm[] = "Player";
                    s_pName = allocGuest(sizeof(nm));
                    if (s_pName != 0) cpu->writeGuestMemory(s_pName, nm, sizeof(nm));
                }
                cpu->writeRegister(X86Reg::EAX, s_pName);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
        }
        if (iface == 2) { // ISteamUtils
            if (slot == 0 || slot == 1 || slot == 2) {
                cpu->writeRegister(X86Reg::EAX, 1u);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 3) { // GetServerRealTime
                cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(time(nullptr)));
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 4) { // GetIPCountry
                const char cc[] = "US";
                uint32_t p = allocGuest(sizeof(cc));
                if (p != 0) cpu->writeGuestMemory(p, cc, sizeof(cc));
                cpu->writeRegister(X86Reg::EAX, p);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 8) { // GetCurrentBatteryPower
                cpu->writeRegister(X86Reg::EAX, 255u);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 9) { // GetAppID (Stronghold 3 = 47400)
                cpu->writeRegister(X86Reg::EAX, 47400u);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 5 || slot == 6) { // GetImageSize / GetImageRGBA
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 16);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 7) { // GetCSERIPPort
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 12);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 10 || slot == 16) { // SetOverlayNotificationPosition / SetWarningMessageHook
                cpu->writeRegister(X86Reg::ESP, esp + 8);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 11) { // IsAPICallCompleted(uint64, bool*)
                uint32_t pFailed = 0;
                cpu->readGuestMemory(esp + 12, &pFailed, 4);
                if (pFailed >= 0x10000u) { uint8_t z = 0; cpu->writeGuestMemory(pFailed, &z, 1); }
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 16);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 12) { // GetAPICallFailureReason(uint64)
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 12);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 13) { // GetAPICallResult(uint64, void*, int, int, bool*)
                uint32_t pFailed = 0;
                cpu->readGuestMemory(esp + 24, &pFailed, 4);
                if (pFailed >= 0x10000u) { uint8_t z = 0; cpu->writeGuestMemory(pFailed, &z, 1); }
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 28);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 14 || slot == 15 || slot == 18) { // RunFrame / GetIPCCallCount / BOverlayNeedsPresent
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 17) { // IsOverlayEnabled
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
        }
        if (iface == 3) { // ISteamUserStats
            if (slot == 1 || slot == 2) { // GetStat(const char*, int32*/float*)
                uint32_t pVal = 0;
                cpu->readGuestMemory(esp + 8, &pVal, 4);
                if (pVal >= 0x10000u) { uint32_t z = 0; cpu->writeGuestMemory(pVal, &z, 4); }
                cpu->writeRegister(X86Reg::EAX, 1u);
                cpu->writeRegister(X86Reg::ESP, esp + 12);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 3 || slot == 4) { // SetStat(const char*, int32/float)
                cpu->writeRegister(X86Reg::EAX, 1u);
                cpu->writeRegister(X86Reg::ESP, esp + 12);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 5) { // UpdateAvgRateStat(const char*, float, double)
                cpu->writeRegister(X86Reg::EAX, 1u);
                cpu->writeRegister(X86Reg::ESP, esp + 20);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 6) { // GetAchievement(const char*, bool*)
                uint32_t pAch = 0;
                cpu->readGuestMemory(esp + 8, &pAch, 4);
                if (pAch >= 0x10000u) { uint8_t z = 0; cpu->writeGuestMemory(pAch, &z, 1); }
                cpu->writeRegister(X86Reg::EAX, 1u);
                cpu->writeRegister(X86Reg::ESP, esp + 12);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 7 || slot == 8) { // SetAchievement / ClearAchievement
                cpu->writeRegister(X86Reg::EAX, 1u);
                cpu->writeRegister(X86Reg::ESP, esp + 8);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 9) { // GetAchievementAndUnlockTime
                uint32_t pAch = 0, pTime = 0;
                cpu->readGuestMemory(esp + 8, &pAch, 4);
                cpu->readGuestMemory(esp + 12, &pTime, 4);
                if (pAch >= 0x10000u) { uint8_t z = 0; cpu->writeGuestMemory(pAch, &z, 1); }
                if (pTime >= 0x10000u) { uint32_t z = 0; cpu->writeGuestMemory(pTime, &z, 4); }
                cpu->writeRegister(X86Reg::EAX, 1u);
                cpu->writeRegister(X86Reg::ESP, esp + 16);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 10) { // StoreStats
                cpu->writeRegister(X86Reg::EAX, 1u);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 0) { // RequestCurrentStats
                cpu->writeRegister(X86Reg::EAX, 1u);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
        }
        if (iface == 4) { // ISteamApps
            if (slot == 0) { // BIsSubscribed
                cpu->writeRegister(X86Reg::EAX, 1u);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 1 || slot == 2 || slot == 3) {
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 4 || slot == 5) { // GetCurrentGameLanguage / Available
                const char lang[] = "english";
                uint32_t p = allocGuest(sizeof(lang));
                if (p != 0) cpu->writeGuestMemory(p, lang, sizeof(lang));
                cpu->writeRegister(X86Reg::EAX, p);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 6 || slot == 7) { // BIsSubscribedApp / BIsDlcInstalled
                cpu->writeRegister(X86Reg::EAX, 1u);
                cpu->writeRegister(X86Reg::ESP, esp + 8);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
        }
        if (iface == 7) { // ISteamMatchmaking
            if (slot == 0) { // GetFavoriteGameCount
                cpu->writeRegister(X86Reg::EAX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 4) { // RequestLobbyList
                cpu->writeRegister(X86Reg::EAX, 1u);
                cpu->writeRegister(X86Reg::EDX, 0u);
                cpu->writeRegister(X86Reg::ESP, esp + 4);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 5 || slot == 6) { // AddRequestLobbyListString/NumericalFilter
                cpu->writeRegister(X86Reg::ESP, esp + 16);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 7) { // AddRequestLobbyListNearValueFilter
                cpu->writeRegister(X86Reg::ESP, esp + 12);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
            if (slot == 8 || slot == 9 || slot == 10) {
                cpu->writeRegister(X86Reg::ESP, esp + 8);
                outNextEip = returnAddr;
                logSym(sym);
                return true;
            }
        }
        return false;
    }

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
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCurrentProcessId") {
        cpu->writeRegister(X86Reg::EAX, 0x00000543u);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCurrentThreadId") {
        cpu->writeRegister(X86Reg::EAX, 0x00000001u);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetTickCount") {
        struct timespec ts{};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint32_t ms = static_cast<uint32_t>(ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL);
        cpu->writeRegister(X86Reg::EAX, ms);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        logSym(sym);
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
        logSym(sym);
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
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetModuleHandleW" || sym == "kernel32.dll!GetModuleHandleA") {
        uint32_t lpModuleName = 0;
        cpu->readGuestMemory(esp + 4, &lpModuleName, 4);
        uint32_t hMod = 0u;
        if (lpModuleName == 0u) {
            hMod = 0x00400000u;
        } else {
            std::string modName;
            if (sym == "kernel32.dll!GetModuleHandleW") {
                for (int i = 0; i < 127; ++i) {
                    uint16_t wc = 0;
                    cpu->readGuestMemory(lpModuleName + i * 2, &wc, 2);
                    if (wc == 0) break;
                    modName.push_back(static_cast<char>(wc & 0xFFu));
                }
            } else {
                for (int i = 0; i < 127; ++i) {
                    char c = 0;
                    cpu->readGuestMemory(lpModuleName + i, &c, 1);
                    if (c == 0) break;
                    modName.push_back(c);
                }
            }
            hMod = findLoadedModule(modName);
            if (hMod == 0u) {
                std::string lowM;
                for (char c : modName) lowM.push_back((c >= 65 && c <= 90) ? static_cast<char>(c + 32) : c);
                if (lowM == "user32" || lowM == "user32.dll" || lowM == "gdi32" || lowM == "gdi32.dll" ||
                    lowM == "d3d9" || lowM == "d3d9.dll" || lowM == "dinput8" || lowM == "dinput8.dll") {
                    hMod = getOrCreateVirtualModule(lowM);
                } else {
                    auto vit = m_virtualModsByName.find(lowM);
                    if (vit != m_virtualModsByName.end()) hMod = vit->second;
                }
            }
        }
        cpu->writeRegister(X86Reg::EAX, hMod);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!HeapSetInformation") {
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 20); // stdcall: retAddr + 4 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__set_app_type" ||
        sym == "msvcr100.dll!__setusermatherr" ||
        sym == "msvcr100.dll!_configthreadlocale") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl: caller cleans args
        outNextEip = returnAddr;
        logSym(sym);
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
        logSym(sym);
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
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!Sleep") {
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_initterm_e" || sym == "msvcr100.dll!_initterm") {
        const bool isE = (sym == "msvcr100.dll!_initterm_e");
        uint32_t pfbegin = 0, pfend = 0;
        cpu->readGuestMemory(esp + 4, &pfbegin, 4);
        cpu->readGuestMemory(esp + 8, &pfend, 4);
        uint32_t retCode = 0;
        uint32_t ranCount = 0;
        bool cbAbort = false;
        if (pfbegin != 0 && pfend > pfbegin && (pfend - pfbegin) <= 0x100000u) {
            const uint32_t sentinelRet = 0x7000FFD0u;
            for (uint32_t p = pfbegin; p + 4 <= pfend; p += 4) {
                uint32_t fn = 0;
                cpu->readGuestMemory(p, &fn, 4);
                if (fn == 0) continue;
                uint32_t savedEsp = cpu->readRegister(X86Reg::ESP);
                uint32_t savedEbp = cpu->readRegister(X86Reg::EBP);
                uint32_t savedEbx = cpu->readRegister(X86Reg::EBX);
                uint32_t savedEsi = cpu->readRegister(X86Reg::ESI);
                uint32_t savedEdi = cpu->readRegister(X86Reg::EDI);
                uint32_t savedEfl = cpu->readRegister(X86Reg::EFLAGS);
                uint32_t cbEsp = savedEsp - 64u;
                cpu->writeGuestMemory(cbEsp, &sentinelRet, 4);
                cpu->writeRegister(X86Reg::ESP, cbEsp);
                uint32_t curEip = fn;
                for (int guard = 0; guard < 10000; ++guard) {
                    X86StepResult st = cpu->stepInstructions(curEip, 200000);
                    if (st.faulted) {
                        if (m_handledLog.size() < 4096) m_handledLog.push_back("INITTERM_FAULT: " + st.reason);
                        cbAbort = true;
                        break;
                    }
                    if (st.haltedOnThunk) {
                        if (st.stopAddress == sentinelRet) break;
                        uint32_t curEsp = cpu->readRegister(X86Reg::ESP);
                        uint32_t innerRet = 0;
                        cpu->readGuestMemory(curEsp, &innerRet, 4);
                        uint32_t nextAfterThunk = innerRet;
                        if (!handleThunkCall(cpu, st.stopAddress, innerRet, nextAfterThunk)) {
                            cbAbort = true;
                            break;
                        }
                        curEip = nextAfterThunk;
                        continue;
                    }
                    uint32_t nextIp = cpu->readRegister(X86Reg::EIP);
                    if (nextIp == sentinelRet || nextIp == curEip) break;
                    curEip = nextIp;
                }
                uint32_t fnRet = cpu->readRegister(X86Reg::EAX);
                cpu->writeRegister(X86Reg::ESP, savedEsp);
                cpu->writeRegister(X86Reg::EBP, savedEbp);
                cpu->writeRegister(X86Reg::EBX, savedEbx);
                cpu->writeRegister(X86Reg::ESI, savedEsi);
                cpu->writeRegister(X86Reg::EDI, savedEdi);
                cpu->writeRegister(X86Reg::EFLAGS, savedEfl);
                if (cbAbort) break;
                ++ranCount;
                if (isE && fnRet != 0) { retCode = fnRet; break; }
            }
        }
        if (cbAbort) return false;
        if (isE) cpu->writeRegister(X86Reg::EAX, retCode);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        char ibuf[96];
        snprintf(ibuf, sizeof(ibuf), "%s(ran=%u,ret=%u)", sym.c_str(), ranCount, retCode);
        if (m_handledLog.size() < 4096) m_handledLog.push_back(ibuf);
        return true;
    }

    if (sym == "msvcr100.dll!_ismbblead") {
        cpu->writeRegister(X86Reg::EAX, 0u); // ASCII char is not a multibyte lead byte
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl: caller cleans args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!LoadLibraryA" || sym == "kernel32.dll!LoadLibraryExA") {
        bool isEx = (sym == "kernel32.dll!LoadLibraryExA");
        uint32_t namePtr = 0;
        cpu->readGuestMemory(esp + 4, &namePtr, 4);
        std::string modName;
        if (namePtr >= 0x10000u) {
            for (int i = 0; i < 127; ++i) {
                char c = 0;
                cpu->readGuestMemory(namePtr + i, &c, 1);
                if (c == 0) break;
                modName.push_back(c);
            }
        }
        uint32_t realBase = findLoadedModule(modName);
        std::string lowMod;
        lowMod.reserve(modName.size());
        for (char c : modName) lowMod.push_back((c >= 65 && c <= 90) ? static_cast<char>(c + 32) : c);
        bool isVPlugin = (lowMod.size() >= 8 && lowMod.compare(lowMod.size() - 8, 8, ".vplugin") == 0);
        uint32_t hMod = (realBase != 0u) ? realBase : (isVPlugin ? 0u : getOrCreateVirtualModule(modName));
        cpu->writeRegister(X86Reg::EAX, hMod);
        cpu->writeRegister(X86Reg::ESP, esp + (isEx ? 16u : 8u)); // stdcall
        outNextEip = returnAddr;
        char lbuf[224];
        snprintf(lbuf, sizeof(lbuf), "%s(\"%s\")->0x%08X", sym.c_str(), modName.c_str(), hMod);
        m_handledLog.push_back(lbuf);
        if (m_postD3dActive && m_d3dTrace.size() < 320u) m_d3dTrace += "LL(" + modName + ") ";
        return true;
    }

    if (sym == "kernel32.dll!LoadLibraryW" || sym == "kernel32.dll!LoadLibraryExW") {
        bool isEx = (sym == "kernel32.dll!LoadLibraryExW");
        uint32_t namePtr = 0;
        cpu->readGuestMemory(esp + 4, &namePtr, 4);
        std::string modName;
        if (namePtr >= 0x10000u) {
            for (int i = 0; i < 127; ++i) {
                uint16_t wc = 0;
                cpu->readGuestMemory(namePtr + i * 2, &wc, 2);
                if (wc == 0) break;
                modName.push_back(static_cast<char>(wc & 0xFFu));
            }
        }
        uint32_t realBase = findLoadedModule(modName);
        std::string lowMod;
        lowMod.reserve(modName.size());
        for (char c : modName) lowMod.push_back((c >= 65 && c <= 90) ? static_cast<char>(c + 32) : c);
        bool isVPlugin = (lowMod.size() >= 8 && lowMod.compare(lowMod.size() - 8, 8, ".vplugin") == 0);
        uint32_t hMod = (realBase != 0u) ? realBase : (isVPlugin ? 0u : getOrCreateVirtualModule(modName));
        cpu->writeRegister(X86Reg::EAX, hMod);
        cpu->writeRegister(X86Reg::ESP, esp + (isEx ? 16u : 8u)); // stdcall
        outNextEip = returnAddr;
        char lbuf[224];
        snprintf(lbuf, sizeof(lbuf), "%s(\"%s\")->0x%08X", sym.c_str(), modName.c_str(), hMod);
        m_handledLog.push_back(lbuf);
        if (m_postD3dActive && m_d3dTrace.size() < 320u) m_d3dTrace += "LL(" + modName + ") ";
        return true;
    }

    if (sym == "kernel32.dll!FreeLibrary") {
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_controlfp" || sym == "msvcr100.dll!_control87") {
        cpu->writeRegister(X86Reg::EAX, 0x0008001Fu); // Default x87 FPU control word
        cpu->writeRegister(X86Reg::ESP, esp + 4);     // cdecl: caller cleans args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!DecodePointer" || sym == "kernel32.dll!EncodePointer") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_lock" || sym == "msvcr100.dll!_unlock") {
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl: caller cleans args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__dllonexit" || sym == "msvcr100.dll!_onexit") {
        uint32_t funcPtr = 0;
        cpu->readGuestMemory(esp + 4, &funcPtr, 4);
        cpu->writeRegister(X86Reg::EAX, funcPtr); // return registered func pointer
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl: caller cleans args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!malloc" || sym == "msvcr100.dll!_malloc_crt" ||
        sym == "msvcr100.dll!??2@YAPAXI@Z" ||
        sym == "msvcr100.dll!??_U@YAPAXI@Z") {
        uint32_t sz = 0;
        cpu->readGuestMemory(esp + 4, &sz, 4);
        uint32_t ptr = allocGuest(sz);
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!calloc" || sym == "msvcr100.dll!_calloc_crt") {
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
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!realloc" || sym == "msvcr100.dll!_realloc_crt") {
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
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!free" ||
        sym == "msvcr100.dll!??3@YAXPAX@Z" ||
        sym == "msvcr100.dll!??_V@YAXPAX@Z") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        freeGuest(ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
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
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_aligned_malloc") {
        uint32_t sz = 0;
        cpu->readGuestMemory(esp + 4, &sz, 4);
        uint32_t ptr = allocGuest(sz);
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_aligned_free") {
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
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
        bool resolvedFromRealPe = false;
        if (isLoadedModuleBase(hMod)) {
            resolvedFromRealPe = true;
            uint16_t mz = 0;
            cpu->readGuestMemory(hMod, &mz, 2);
            if (mz == 0x5A4Du) {
                uint32_t lfanew = 0;
                cpu->readGuestMemory(hMod + 0x3Cu, &lfanew, 4);
                if (lfanew > 0u && lfanew < 0x4000u) {
                    uint32_t peSig = 0;
                    uint16_t optMagic = 0;
                    cpu->readGuestMemory(hMod + lfanew, &peSig, 4);
                    cpu->readGuestMemory(hMod + lfanew + 24u, &optMagic, 2);
                    if (peSig == 0x00004550u && optMagic == 0x010Bu) {
                        uint32_t expRva = 0, expSize = 0;
                        cpu->readGuestMemory(hMod + lfanew + 0x78u, &expRva, 4);
                        cpu->readGuestMemory(hMod + lfanew + 0x7Cu, &expSize, 4);
                        if (expRva != 0u) {
                            uint32_t expDir[10] = {};
                            cpu->readGuestMemory(hMod + expRva, expDir, sizeof(expDir));
                            uint32_t ordBase      = expDir[4];
                            uint32_t numFuncs     = expDir[5];
                            uint32_t numNames     = expDir[6];
                            uint32_t addrFuncsRva = expDir[7];
                            uint32_t addrNamesRva = expDir[8];
                            uint32_t addrOrdsRva  = expDir[9];
                            if (numFuncs > 65536u) numFuncs = 65536u;
                            if (numNames > 65536u) numNames = 65536u;
                            if (namePtr > 0xFFFFu) {
                                std::string rawName = procStr.substr(1, procStr.size() - 2);
                                if (!rawName.empty() && numNames > 0u && addrNamesRva != 0u && addrOrdsRva != 0u && addrFuncsRva != 0u) {
                                    std::vector<uint32_t> nameRvas(numNames);
                                    cpu->readGuestMemory(hMod + addrNamesRva, nameRvas.data(), numNames * 4u);
                                    for (uint32_t ni = 0; ni < numNames; ++ni) {
                                        if (nameRvas[ni] == 0u) continue;
                                        bool match = true;
                                        for (size_t ci = 0; ci <= rawName.size(); ++ci) {
                                            char ch = 0;
                                            cpu->readGuestMemory(hMod + nameRvas[ni] + static_cast<uint32_t>(ci), &ch, 1);
                                            char expected = (ci < rawName.size()) ? rawName[ci] : 0;
                                            if (ch != expected) { match = false; break; }
                                        }
                                        if (match) {
                                            uint16_t ordIdx = 0;
                                            cpu->readGuestMemory(hMod + addrOrdsRva + ni * 2u, &ordIdx, 2);
                                            if (ordIdx < numFuncs) {
                                                uint32_t funcRva = 0;
                                                cpu->readGuestMemory(hMod + addrFuncsRva + static_cast<uint32_t>(ordIdx) * 4u, &funcRva, 4);
                                                if (funcRva != 0u && !(funcRva >= expRva && funcRva < expRva + expSize)) {
                                                    resolvedAddr = hMod + funcRva;
                                                }
                                            }
                                            break;
                                        }
                                    }
                                }
                            } else if (namePtr >= ordBase && (namePtr - ordBase) < numFuncs && addrFuncsRva != 0u) {
                                uint32_t funcRva = 0;
                                cpu->readGuestMemory(hMod + addrFuncsRva + (namePtr - ordBase) * 4u, &funcRva, 4);
                                if (funcRva != 0u && !(funcRva >= expRva && funcRva < expRva + expSize)) {
                                    resolvedAddr = hMod + funcRva;
                                }
                            }
                        }
                    }
                }
            }
        }
        if (!resolvedFromRealPe && namePtr > 0xFFFFu) {
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
                m_reverseMap[resolvedAddr] = resolveVirtualDllPrefix(hMod, rawName) + "!" + rawName;
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
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!SetLastError") {
        uint32_t errCode = 0;
        cpu->readGuestMemory(esp + 4, &errCode, 4);
        m_lastError = errCode;
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!EnumDisplayDevicesA" || sym == "dynamic!EnumDisplayDevicesA") {
        uint32_t lpDev = 0u, iDevNum = 0u, lpDD = 0u;
        cpu->readGuestMemory(esp + 4,  &lpDev,   4);
        cpu->readGuestMemory(esp + 8,  &iDevNum, 4);
        cpu->readGuestMemory(esp + 12, &lpDD,    4);
        uint32_t retVal = 0u;
        if (iDevNum == 0u && lpDD >= 0x10000u) {
            uint32_t cb = 0u;
            cpu->readGuestMemory(lpDD, &cb, 4);
            if (cb < 168u || cb > 424u) cb = 424u;
            std::vector<uint8_t> dd(424, 0u);
            memcpy(dd.data(), &cb, 4);
            bool isMon = (lpDev >= 0x10000u);
            const char* devName = isMon ? "\\\\.\\DISPLAY1\\Monitor0" : "\\\\.\\DISPLAY1";
            const char* devStr  = isMon ? "Generic PnP Monitor" : "Stronghold3 ARM64 Virtual GPU";
            uint32_t flags      = isMon ? 0x00000003u : 0x00000005u;
            const char* devId   = isMon ? "MONITOR\\DEFAULT" : "PCI\\VEN_10DE&DEV_1180";
            strncpy(reinterpret_cast<char*>(dd.data() + 4),   devName, 31);
            strncpy(reinterpret_cast<char*>(dd.data() + 36),  devStr,  127);
            memcpy(dd.data() + 164, &flags, 4);
            strncpy(reinterpret_cast<char*>(dd.data() + 168), devId,   127);
            cpu->writeGuestMemory(lpDD, dd.data(), cb);
            retVal = 1u;
        }
        cpu->writeRegister(X86Reg::EAX, retVal);
        cpu->writeRegister(X86Reg::ESP, esp + 20u); // stdcall: retAddr + 4 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!EnumDisplayDevicesW" || sym == "dynamic!EnumDisplayDevicesW") {
        uint32_t lpDev = 0u, iDevNum = 0u, lpDD = 0u;
        cpu->readGuestMemory(esp + 4,  &lpDev,   4);
        cpu->readGuestMemory(esp + 8,  &iDevNum, 4);
        cpu->readGuestMemory(esp + 12, &lpDD,    4);
        uint32_t retVal = 0u;
        if (iDevNum == 0u && lpDD >= 0x10000u) {
            uint32_t cb = 0u;
            cpu->readGuestMemory(lpDD, &cb, 4);
            if (cb < 328u || cb > 840u) cb = 840u;
            std::vector<uint8_t> dd(840, 0u);
            memcpy(dd.data(), &cb, 4);
            bool isMon = (lpDev >= 0x10000u);
            const char16_t* devName = isMon ? u"\\\\.\\DISPLAY1\\Monitor0" : u"\\\\.\\DISPLAY1";
            const char16_t* devStr  = isMon ? u"Generic PnP Monitor" : u"Stronghold3 ARM64 Virtual GPU";
            uint32_t flags          = isMon ? 0x00000003u : 0x00000005u;
            for (size_t i = 0; devName[i] && i < 31; ++i) memcpy(dd.data() + 4 + i * 2, &devName[i], 2);
            for (size_t i = 0; devStr[i] && i < 127; ++i) memcpy(dd.data() + 68 + i * 2, &devStr[i], 2);
            memcpy(dd.data() + 324, &flags, 4);
            cpu->writeGuestMemory(lpDD, dd.data(), cb);
            retVal = 1u;
        }
        cpu->writeRegister(X86Reg::EAX, retVal);
        cpu->writeRegister(X86Reg::ESP, esp + 20u); // stdcall: retAddr + 4 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!EnumDisplayMonitors" || sym == "dynamic!EnumDisplayMonitors") {
        cpu->writeRegister(X86Reg::EAX, 1u);       // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 20); // stdcall: retAddr + 4 args
        outNextEip = returnAddr;
        logSym(sym);
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
        logSym(sym);
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
        logSym(sym);
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
        logSym(sym);
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
        logSym(sym);
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
        logSym(sym);
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
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!EnterCriticalSection" ||
        sym == "kernel32.dll!LeaveCriticalSection" ||
        sym == "kernel32.dll!DeleteCriticalSection") {
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!TryEnterCriticalSection") {
        cpu->writeRegister(X86Reg::EAX, 1u);      // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        logSym(sym);
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
        logSym(sym);
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
        logSym(sym);
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
        logSym(sym);
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
        logSym(sym);
        return true;
    }

    auto readCStr = [&](uint32_t addr, size_t maxLen = 4096) -> std::string {
        std::string res;
        if (addr == 0) return res;
        for (size_t i = 0; i < maxLen; ++i) {
            uint8_t c = 0;
            if (!cpu->readGuestMemory(addr + static_cast<uint32_t>(i), &c, 1) || c == 0) break;
            res.push_back(static_cast<char>(c));
        }
        return res;
    };

    if (sym == "msvcr100.dll!tolower" || sym == "msvcr100.dll!towlower") {
        uint32_t ch = 0;
        cpu->readGuestMemory(esp + 4, &ch, 4);
        if (ch >= 0x41u && ch <= 0x5Au) ch += 32u;
        cpu->writeRegister(X86Reg::EAX, ch);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!toupper" || sym == "msvcr100.dll!towupper") {
        uint32_t ch = 0;
        cpu->readGuestMemory(esp + 4, &ch, 4);
        if (ch >= 0x61u && ch <= 0x7Au) ch -= 32u;
        cpu->writeRegister(X86Reg::EAX, ch);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strlen") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        std::string str = readCStr(ptr, 65536);
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(str.size()));
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strcmp" || sym == "msvcr100.dll!strncmp" ||
        sym == "msvcr100.dll!_stricmp" || sym == "msvcr100.dll!_strcmpi" ||
        sym == "msvcr100.dll!_strnicmp") {
        uint32_t pA = 0, pB = 0, maxN = 0xFFFFFFFFu;
        cpu->readGuestMemory(esp + 4, &pA, 4);
        cpu->readGuestMemory(esp + 8, &pB, 4);
        bool hasN = (sym == "msvcr100.dll!strncmp" || sym == "msvcr100.dll!_strnicmp");
        bool nocase = (sym == "msvcr100.dll!_stricmp" || sym == "msvcr100.dll!_strcmpi" || sym == "msvcr100.dll!_strnicmp");
        if (hasN) cpu->readGuestMemory(esp + 12, &maxN, 4);
        std::string a = readCStr(pA, hasN ? maxN : 4096);
        std::string b = readCStr(pB, hasN ? maxN : 4096);
        int32_t res = 0;
        size_t len = (a.size() < b.size()) ? a.size() : b.size();
        if (hasN && len > maxN) len = maxN;
        for (size_t i = 0; i < len; ++i) {
            uint8_t ca = static_cast<uint8_t>(a[i]);
            uint8_t cb = static_cast<uint8_t>(b[i]);
            if (nocase) {
                if (ca >= 0x41u && ca <= 0x5Au) ca += 32u;
                if (cb >= 0x41u && cb <= 0x5Au) cb += 32u;
            }
            if (ca != cb) { res = (ca < cb) ? -1 : 1; break; }
        }
        if (nocase) m_lastCmp = a.substr(0, 32) + "|" + b.substr(0, 32);
        if (res == 0 && (!hasN || len < maxN)) {
            if (a.size() != b.size()) res = (a.size() < b.size()) ? -1 : 1;
        }
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res));
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strcpy") {
        uint32_t dst = 0, src = 0;
        cpu->readGuestMemory(esp + 4, &dst, 4);
        cpu->readGuestMemory(esp + 8, &src, 4);
        std::string sSrc = readCStr(src, 65536);
        if (dst != 0) {
            cpu->writeGuestMemory(dst, sSrc.c_str(), sSrc.size() + 1);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strncpy") {
        uint32_t dst = 0, src = 0, n = 0;
        cpu->readGuestMemory(esp + 4,  &dst, 4);
        cpu->readGuestMemory(esp + 8,  &src, 4);
        cpu->readGuestMemory(esp + 12, &n,   4);
        if (dst != 0 && n > 0) {
            std::string sSrc = readCStr(src, n);
            std::vector<uint8_t> outBuf(n, 0);
            size_t copyLen = (sSrc.size() < n) ? sSrc.size() : n;
            for (size_t i = 0; i < copyLen; ++i) outBuf[i] = static_cast<uint8_t>(sSrc[i]);
            cpu->writeGuestMemory(dst, outBuf.data(), n);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strchr" || sym == "msvcr100.dll!strrchr") {
        uint32_t ptr = 0, chVal = 0;
        cpu->readGuestMemory(esp + 4, &ptr,   4);
        cpu->readGuestMemory(esp + 8, &chVal, 4);
        char target = static_cast<char>(chVal & 0xFFu);
        std::string str = readCStr(ptr, 65536);
        uint32_t found = 0u;
        if (target == 0) {
            found = ptr + static_cast<uint32_t>(str.size());
        } else {
            size_t pos = (sym == "msvcr100.dll!strchr") ? str.find(target) : str.rfind(target);
            if (pos != std::string::npos) found = ptr + static_cast<uint32_t>(pos);
        }
        cpu->writeRegister(X86Reg::EAX, found);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strstr") {
        uint32_t pHay = 0, pNeedle = 0;
        cpu->readGuestMemory(esp + 4, &pHay,    4);
        cpu->readGuestMemory(esp + 8, &pNeedle, 4);
        std::string hay = readCStr(pHay, 65536);
        std::string needle = readCStr(pNeedle, 4096);
        uint32_t found = 0u;
        size_t pos = hay.find(needle);
        if (pos != std::string::npos) found = pHay + static_cast<uint32_t>(pos);
        cpu->writeRegister(X86Reg::EAX, found);
        cpu->writeRegister(X86Reg::ESP, esp + 4);
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!TlsAlloc") {
        uint32_t idx = m_nextTlsIndex++;
        m_tlsSlots[idx] = 0u;
        cpu->writeRegister(X86Reg::EAX, idx);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!TlsFree") {
        uint32_t idx = 0;
        cpu->readGuestMemory(esp + 4, &idx, 4);
        m_tlsSlots.erase(idx);
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!TlsGetValue") {
        uint32_t idx = 0;
        cpu->readGuestMemory(esp + 4, &idx, 4);
        uint32_t val = 0u;
        auto it = m_tlsSlots.find(idx);
        if (it != m_tlsSlots.end()) val = it->second;
        m_lastError = 0u;
        cpu->writeRegister(X86Reg::EAX, val);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!TlsSetValue") {
        uint32_t idx = 0, val = 0;
        cpu->readGuestMemory(esp + 4, &idx, 4);
        cpu->readGuestMemory(esp + 8, &val, 4);
        m_tlsSlots[idx] = val;
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!VirtualAlloc") {
        uint32_t dwSize = 0;
        cpu->readGuestMemory(esp + 8, &dwSize, 4);
        if (dwSize == 0) dwSize = 4096u;
        uint32_t ptr = allocGuest(dwSize);
        if (ptr != 0) {
            std::vector<uint8_t> zeros(dwSize, 0);
            cpu->writeGuestMemory(ptr, zeros.data(), dwSize);
        }
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 20); // stdcall: 4 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!VirtualFree") {
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!memchr") {
        uint32_t ptr = 0, val = 0, num = 0;
        cpu->readGuestMemory(esp + 4,  &ptr, 4);
        cpu->readGuestMemory(esp + 8,  &val, 4);
        cpu->readGuestMemory(esp + 12, &num, 4);
        uint32_t found = 0u;
        if (ptr != 0 && num > 0) {
            std::vector<uint8_t> buf(num);
            cpu->readGuestMemory(ptr, buf.data(), num);
            uint8_t target = static_cast<uint8_t>(val & 0xFFu);
            for (uint32_t i = 0; i < num; ++i) {
                if (buf[i] == target) {
                    found = ptr + i;
                    break;
                }
            }
        }
        cpu->writeRegister(X86Reg::EAX, found);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strcat" || sym == "msvcr100.dll!strncat") {
        uint32_t dst = 0, src = 0, maxN = 0xFFFFFFFFu;
        cpu->readGuestMemory(esp + 4, &dst, 4);
        cpu->readGuestMemory(esp + 8, &src, 4);
        bool hasN = (sym == "msvcr100.dll!strncat");
        if (hasN) cpu->readGuestMemory(esp + 12, &maxN, 4);
        if (dst != 0 && src != 0) {
            std::string sDst = readCStr(dst, 65536);
            std::string sSrc = readCStr(src, hasN ? maxN : 65536);
            if (hasN && sSrc.size() > maxN) sSrc.resize(maxN);
            std::string combined = sDst + sSrc;
            cpu->writeGuestMemory(dst, combined.c_str(), combined.size() + 1);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!wcslen") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        uint32_t len = 0;
        if (ptr != 0) {
            for (uint32_t i = 0; i < 65536; ++i) {
                uint16_t wc = 0;
                if (!cpu->readGuestMemory(ptr + i * 2, &wc, 2) || wc == 0) break;
                ++len;
            }
        }
        cpu->writeRegister(X86Reg::EAX, len);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!wcscmp") {
        uint32_t pA = 0, pB = 0;
        cpu->readGuestMemory(esp + 4, &pA, 4);
        cpu->readGuestMemory(esp + 8, &pB, 4);
        int32_t res = 0;
        if (pA != 0 && pB != 0) {
            for (uint32_t i = 0; i < 65536; ++i) {
                uint16_t ca = 0, cb = 0;
                cpu->readGuestMemory(pA + i * 2, &ca, 2);
                cpu->readGuestMemory(pB + i * 2, &cb, 2);
                if (ca != cb) { res = (ca < cb) ? -1 : 1; break; }
                if (ca == 0) break;
            }
        }
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res));
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!wcscpy") {
        uint32_t dst = 0, src = 0;
        cpu->readGuestMemory(esp + 4, &dst, 4);
        cpu->readGuestMemory(esp + 8, &src, 4);
        if (dst != 0 && src != 0) {
            for (uint32_t i = 0; i < 65536; ++i) {
                uint16_t wc = 0;
                cpu->readGuestMemory(src + i * 2, &wc, 2);
                cpu->writeGuestMemory(dst + i * 2, &wc, 2);
                if (wc == 0) break;
            }
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!isalpha" || sym == "msvcr100.dll!isdigit" ||
        sym == "msvcr100.dll!isalnum" || sym == "msvcr100.dll!isspace" ||
        sym == "msvcr100.dll!isupper" || sym == "msvcr100.dll!islower" ||
        sym == "msvcr100.dll!isxdigit") {
        uint32_t ch = 0;
        cpu->readGuestMemory(esp + 4, &ch, 4);
        uint8_t c = static_cast<uint8_t>(ch & 0xFFu);
        uint32_t ok = 0u;
        if (sym == "msvcr100.dll!isalpha")  ok = ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) ? 1u : 0u;
        if (sym == "msvcr100.dll!isdigit")  ok = (c >= '0' && c <= '9') ? 1u : 0u;
        if (sym == "msvcr100.dll!isalnum")  ok = ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) ? 1u : 0u;
        if (sym == "msvcr100.dll!isspace")  ok = (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f') ? 1u : 0u;
        if (sym == "msvcr100.dll!isupper")  ok = (c >= 'A' && c <= 'Z') ? 1u : 0u;
        if (sym == "msvcr100.dll!islower")  ok = (c >= 'a' && c <= 'z') ? 1u : 0u;
        if (sym == "msvcr100.dll!isxdigit") ok = ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) ? 1u : 0u;
        cpu->writeRegister(X86Reg::EAX, ok);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCommandLineA") {
        const char* cmd = "Stronghold3.exe";
        uint32_t ptr = allocGuest(32);
        if (ptr != 0) cpu->writeGuestMemory(ptr, cmd, 16);
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCommandLineW") {
        const char* cmd = "Stronghold3.exe";
        uint16_t wcmd[16] = {};
        for (int i = 0; i < 16; ++i) wcmd[i] = static_cast<uint16_t>(cmd[i]);
        uint32_t ptr = allocGuest(64);
        if (ptr != 0) cpu->writeGuestMemory(ptr, wcmd, sizeof(wcmd));
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "shell32.dll!CommandLineToArgvW") {
        uint32_t pNumArgs = 0;
        cpu->readGuestMemory(esp + 8, &pNumArgs, 4);
        const char* cmd = "Stronghold3.exe";
        uint16_t wcmd[16] = {};
        for (int i = 0; i < 16; ++i) wcmd[i] = static_cast<uint16_t>(cmd[i]);
        uint32_t strPtr = allocGuest(64);
        uint32_t arrPtr = allocGuest(16);
        if (strPtr != 0 && arrPtr != 0) {
            cpu->writeGuestMemory(strPtr, wcmd, sizeof(wcmd));
            uint32_t argv[2] = { strPtr, 0u };
            cpu->writeGuestMemory(arrPtr, argv, sizeof(argv));
        }
        if (pNumArgs != 0) {
            uint32_t argc = 1u;
            cpu->writeGuestMemory(pNumArgs, &argc, 4);
        }
        cpu->writeRegister(X86Reg::EAX, arrPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!LocalFree") {
        cpu->writeRegister(X86Reg::EAX, 0u);      // NULL = success
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetModuleHandleA" || sym == "kernel32.dll!GetModuleHandleW") {
        uint32_t namePtr = 0;
        cpu->readGuestMemory(esp + 4, &namePtr, 4);
        uint32_t hMod = (namePtr == 0u) ? 0x00400000u : 0x60000000u;
        cpu->writeRegister(X86Reg::EAX, hMod);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetModuleFileNameA") {
        uint32_t hMod = 0, bufPtr = 0, nSize = 0;
        cpu->readGuestMemory(esp + 4,  &hMod,   4);
        cpu->readGuestMemory(esp + 8,  &bufPtr, 4);
        cpu->readGuestMemory(esp + 12, &nSize,  4);
        std::string path = "C:\\Stronghold3\\" + findModuleNameByBase(hMod);
        uint32_t written = 0;
        if (bufPtr != 0 && nSize > 1) {
            written = (path.size() < nSize - 1) ? static_cast<uint32_t>(path.size()) : (nSize - 1);
            cpu->writeGuestMemory(bufPtr, path.c_str(), written);
            uint8_t nul = 0;
            cpu->writeGuestMemory(bufPtr + written, &nul, 1);
        }
        cpu->writeRegister(X86Reg::EAX, written);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetModuleFileNameW") {
        uint32_t hMod = 0, bufPtr = 0, nSize = 0;
        cpu->readGuestMemory(esp + 4,  &hMod,   4);
        cpu->readGuestMemory(esp + 8,  &bufPtr, 4);
        cpu->readGuestMemory(esp + 12, &nSize,  4);
        std::string path = "C:\\Stronghold3\\" + findModuleNameByBase(hMod);
        uint32_t written = 0;
        if (bufPtr != 0 && nSize > 1) {
            written = (path.size() < nSize - 1) ? static_cast<uint32_t>(path.size()) : (nSize - 1);
            std::vector<uint16_t> wbuf(written + 1, 0);
            for (uint32_t i = 0; i < written; ++i) wbuf[i] = static_cast<uint16_t>(path[i]);
            cpu->writeGuestMemory(bufPtr, wbuf.data(), (written + 1) * 2);
        }
        cpu->writeRegister(X86Reg::EAX, written);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_chdir" || sym == "msvcr100.dll!_wchdir") {
        cpu->writeRegister(X86Reg::EAX, 0u); // 0 = success
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_getcwd") {
        uint32_t bufPtr = 0, maxLen = 0;
        cpu->readGuestMemory(esp + 4, &bufPtr, 4);
        cpu->readGuestMemory(esp + 8, &maxLen, 4);
        std::string dir = "C:\\Stronghold3";
        if (bufPtr == 0) bufPtr = allocGuest(maxLen > 0 ? maxLen : 260u);
        if (bufPtr != 0) {
            uint32_t limit = (maxLen > 1) ? (maxLen - 1) : static_cast<uint32_t>(dir.size());
            uint32_t written = (dir.size() < limit) ? static_cast<uint32_t>(dir.size()) : limit;
            cpu->writeGuestMemory(bufPtr, dir.c_str(), written);
            uint8_t nul = 0;
            cpu->writeGuestMemory(bufPtr + written, &nul, 1);
        }
        cpu->writeRegister(X86Reg::EAX, bufPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!SetCurrentDirectoryA" || sym == "kernel32.dll!SetCurrentDirectoryW") {
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCurrentDirectoryA") {
        uint32_t nBufLen = 0, lpBuf = 0;
        cpu->readGuestMemory(esp + 4, &nBufLen, 4);
        cpu->readGuestMemory(esp + 8, &lpBuf,   4);
        std::string dir = "C:\\Stronghold3";
        uint32_t written = 0;
        if (lpBuf != 0 && nBufLen > 1) {
            written = (dir.size() < nBufLen - 1) ? static_cast<uint32_t>(dir.size()) : (nBufLen - 1);
            cpu->writeGuestMemory(lpBuf, dir.c_str(), written);
            uint8_t nul = 0;
            cpu->writeGuestMemory(lpBuf + written, &nul, 1);
        }
        cpu->writeRegister(X86Reg::EAX, written);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCurrentDirectoryW") {
        uint32_t nBufLen = 0, lpBuf = 0;
        cpu->readGuestMemory(esp + 4, &nBufLen, 4);
        cpu->readGuestMemory(esp + 8, &lpBuf,   4);
        std::string dir = "C:\\Stronghold3";
        uint32_t written = 0;
        if (lpBuf != 0 && nBufLen > 1) {
            written = (dir.size() < nBufLen - 1) ? static_cast<uint32_t>(dir.size()) : (nBufLen - 1);
            std::vector<uint16_t> wbuf(written + 1, 0);
            for (uint32_t i = 0; i < written; ++i) wbuf[i] = static_cast<uint16_t>(dir[i]);
            cpu->writeGuestMemory(lpBuf, wbuf.data(), (written + 1) * 2);
        }
        cpu->writeRegister(X86Reg::EAX, written);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    auto formatGuestPrintf = [&](uint32_t fmtAddr, uint32_t vaAddr) -> std::string {
        std::string fmt = readCStr(fmtAddr, 4096);
        std::string out;
        uint32_t curVa = vaAddr;
        for (size_t i = 0; i < fmt.size(); ++i) {
            if (fmt[i] != '%') {
                out.push_back(fmt[i]);
                continue;
            }
            if (i + 1 < fmt.size() && fmt[i + 1] == '%') {
                out.push_back('%');
                ++i;
                continue;
            }
            std::string spec = "%";
            ++i;
            while (i < fmt.size() && (fmt[i] == '-' || fmt[i] == '+' || fmt[i] == ' ' || fmt[i] == '#' || fmt[i] == '0')) {
                spec.push_back(fmt[i++]);
            }
            if (i < fmt.size() && fmt[i] == '*') {
                int32_t w = 0;
                cpu->readGuestMemory(curVa, &w, 4); curVa += 4;
                spec += std::to_string(w);
                ++i;
            } else {
                while (i < fmt.size() && fmt[i] >= '0' && fmt[i] <= '9') spec.push_back(fmt[i++]);
            }
            if (i < fmt.size() && fmt[i] == '.') {
                spec.push_back(fmt[i++]);
                if (i < fmt.size() && fmt[i] == '*') {
                    int32_t pr = 0;
                    cpu->readGuestMemory(curVa, &pr, 4); curVa += 4;
                    spec += std::to_string(pr);
                    ++i;
                } else {
                    while (i < fmt.size() && fmt[i] >= '0' && fmt[i] <= '9') spec.push_back(fmt[i++]);
                }
            }
            bool is64 = false;
            if (i + 2 < fmt.size() && fmt[i] == 'I' && fmt[i+1] == '6' && fmt[i+2] == '4') {
                is64 = true; i += 3;
            } else if (i + 1 < fmt.size() && fmt[i] == 'l' && fmt[i+1] == 'l') {
                is64 = true; i += 2;
            } else if (i < fmt.size() && (fmt[i] == 'l' || fmt[i] == 'h' || fmt[i] == 'z')) {
                ++i;
            }
            if (i >= fmt.size()) break;
            char t = fmt[i];
            char tmp[128] = {};
            if (t == 's') {
                uint32_t strPtr = 0;
                cpu->readGuestMemory(curVa, &strPtr, 4); curVa += 4;
                out += (strPtr != 0) ? readCStr(strPtr, 4096) : "(null)";
            } else if (t == 'c') {
                uint32_t ch = 0;
                cpu->readGuestMemory(curVa, &ch, 4); curVa += 4;
                out.push_back(static_cast<char>(ch & 0xFFu));
            } else if (t == 'd' || t == 'i') {
                if (is64) {
                    int64_t v = 0;
                    cpu->readGuestMemory(curVa, &v, 8); curVa += 8;
                    spec += "lld";
                    std::snprintf(tmp, sizeof(tmp), spec.c_str(), (long long)v);
                } else {
                    int32_t v = 0;
                    cpu->readGuestMemory(curVa, &v, 4); curVa += 4;
                    spec.push_back(t);
                    std::snprintf(tmp, sizeof(tmp), spec.c_str(), v);
                }
                out += tmp;
            } else if (t == 'u' || t == 'x' || t == 'X' || t == 'o' || t == 'p') {
                if (is64 && t != 'p') {
                    uint64_t v = 0;
                    cpu->readGuestMemory(curVa, &v, 8); curVa += 8;
                    spec += "ll"; spec.push_back(t);
                    std::snprintf(tmp, sizeof(tmp), spec.c_str(), (unsigned long long)v);
                } else {
                    uint32_t v = 0;
                    cpu->readGuestMemory(curVa, &v, 4); curVa += 4;
                    if (t == 'p') {
                        std::snprintf(tmp, sizeof(tmp), "%08X", v);
                    } else {
                        spec.push_back(t);
                        std::snprintf(tmp, sizeof(tmp), spec.c_str(), v);
                    }
                }
                out += tmp;
            } else if (t == 'f' || t == 'F' || t == 'g' || t == 'G' || t == 'e' || t == 'E') {
                double v = 0.0;
                cpu->readGuestMemory(curVa, &v, 8); curVa += 8;
                spec.push_back(t);
                std::snprintf(tmp, sizeof(tmp), spec.c_str(), v);
                out += tmp;
            } else {
                out.push_back(t);
            }
        }
        return out;
    };

    if (sym == "msvcr100.dll!_vsnprintf" || sym == "msvcr100.dll!vsnprintf" ||
        sym == "msvcr100.dll!vsprintf"   || sym == "msvcr100.dll!_vsnprintf_s" ||
        sym == "msvcr100.dll!_snprintf"  || sym == "msvcr100.dll!snprintf" ||
        sym == "msvcr100.dll!sprintf"    || sym == "msvcr100.dll!sprintf_s" ||
        sym == "msvcr100.dll!_vscprintf") {
        uint32_t bufPtr = 0, maxCount = 0xFFFFFFFFu, fmtAddr = 0, vaAddr = 0;
        if (sym == "msvcr100.dll!_vscprintf") {
            cpu->readGuestMemory(esp + 4, &fmtAddr, 4);
            cpu->readGuestMemory(esp + 8, &vaAddr,  4);
        } else if (sym == "msvcr100.dll!_vsnprintf" || sym == "msvcr100.dll!vsnprintf") {
            cpu->readGuestMemory(esp + 4,  &bufPtr,   4);
            cpu->readGuestMemory(esp + 8,  &maxCount, 4);
            cpu->readGuestMemory(esp + 12, &fmtAddr,  4);
            cpu->readGuestMemory(esp + 16, &vaAddr,   4);
        } else if (sym == "msvcr100.dll!_vsnprintf_s") {
            uint32_t bufSz = 0, cnt = 0;
            cpu->readGuestMemory(esp + 4,  &bufPtr,  4);
            cpu->readGuestMemory(esp + 8,  &bufSz,   4);
            cpu->readGuestMemory(esp + 12, &cnt,     4);
            cpu->readGuestMemory(esp + 16, &fmtAddr, 4);
            cpu->readGuestMemory(esp + 20, &vaAddr,  4);
            maxCount = (cnt != 0xFFFFFFFFu && cnt < bufSz) ? cnt : bufSz;
        } else if (sym == "msvcr100.dll!vsprintf") {
            cpu->readGuestMemory(esp + 4,  &bufPtr,  4);
            cpu->readGuestMemory(esp + 8,  &fmtAddr, 4);
            cpu->readGuestMemory(esp + 12, &vaAddr,  4);
        } else if (sym == "msvcr100.dll!_snprintf" || sym == "msvcr100.dll!snprintf" || sym == "msvcr100.dll!sprintf_s") {
            cpu->readGuestMemory(esp + 4,  &bufPtr,   4);
            cpu->readGuestMemory(esp + 8,  &maxCount, 4);
            cpu->readGuestMemory(esp + 12, &fmtAddr,  4);
            vaAddr = esp + 16;
        } else { // sprintf
            cpu->readGuestMemory(esp + 4, &bufPtr,  4);
            cpu->readGuestMemory(esp + 8, &fmtAddr, 4);
            vaAddr = esp + 12;
        }

        std::string formatted = formatGuestPrintf(fmtAddr, vaAddr);
        uint32_t written = static_cast<uint32_t>(formatted.size());
        if (bufPtr != 0 && maxCount > 0) {
            uint32_t limit = (maxCount == 0xFFFFFFFFu) ? written : ((written < maxCount - 1) ? written : (maxCount - 1));
            if (limit > 0) cpu->writeGuestMemory(bufPtr, formatted.c_str(), limit);
            uint8_t nul = 0;
            cpu->writeGuestMemory(bufPtr + limit, &nul, 1);
            written = limit;
        }
        cpu->writeRegister(X86Reg::EAX, written);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!IsDebuggerPresent") {
        cpu->writeRegister(X86Reg::EAX, 0u);      // FALSE
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!OutputDebugStringA") {
        uint32_t strPtr = 0;
        cpu->readGuestMemory(esp + 4, &strPtr, 4);
        std::string msg = readCStr(strPtr, 256);
        while (!msg.empty() && (msg.back() == 10 || msg.back() == 13)) msg.pop_back();
        if (msg.size() > 64) msg.resize(64);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        m_handledLog.push_back(sym + "(\"" + msg + "\")");
        return true;
    }

    if (sym == "kernel32.dll!OutputDebugStringW" || sym == "kernel32.dll!Sleep") {
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!SetUnhandledExceptionFilter") {
        cpu->writeRegister(X86Reg::EAX, 0u);      // previous filter = NULL
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!UnhandledExceptionFilter") {
        cpu->writeRegister(X86Reg::EAX, 1u);      // EXCEPTION_EXECUTE_HANDLER
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!QueryPerformanceFrequency") {
        uint32_t lpFreq = 0;
        cpu->readGuestMemory(esp + 4, &lpFreq, 4);
        if (lpFreq != 0) {
            uint64_t freq = 10000000ULL;
            cpu->writeGuestMemory(lpFreq, &freq, 8);
        }
        cpu->writeRegister(X86Reg::EAX, 1u);      // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetSystemInfo" || sym == "kernel32.dll!GetNativeSystemInfo") {
        uint32_t lpInfo = 0;
        cpu->readGuestMemory(esp + 4, &lpInfo, 4);
        if (lpInfo != 0) {
            uint32_t info[9] = {
                0u,          // wProcessorArchitecture = INTEL, wReserved = 0
                4096u,       // dwPageSize
                0x00010000u, // lpMinimumApplicationAddress
                0x7FFEFFFFu, // lpMaximumApplicationAddress
                0x0000000Fu, // dwActiveProcessorMask (4 cores)
                4u,          // dwNumberOfProcessors
                586u,        // dwProcessorType
                65536u,      // dwAllocationGranularity
                6u           // wProcessorLevel = 6, wProcessorRevision = 0
            };
            cpu->writeGuestMemory(lpInfo, info, sizeof(info));
        }
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GlobalMemoryStatusEx") {
        uint32_t lpBuf = 0;
        cpu->readGuestMemory(esp + 4, &lpBuf, 4);
        if (lpBuf != 0) {
            uint32_t memLoad = 30u;
            uint64_t totalPhys = 4ULL * 1024 * 1024 * 1024;
            uint64_t availPhys = 2ULL * 1024 * 1024 * 1024;
            uint64_t totalVirt = 2ULL * 1024 * 1024 * 1024;
            uint64_t availVirt = 1536ULL * 1024 * 1024;
            uint64_t zero64 = 0ULL;
            cpu->writeGuestMemory(lpBuf + 4,  &memLoad,   4);
            cpu->writeGuestMemory(lpBuf + 8,  &totalPhys, 8);
            cpu->writeGuestMemory(lpBuf + 16, &availPhys, 8);
            cpu->writeGuestMemory(lpBuf + 24, &totalPhys, 8);
            cpu->writeGuestMemory(lpBuf + 32, &availPhys, 8);
            cpu->writeGuestMemory(lpBuf + 40, &totalVirt, 8);
            cpu->writeGuestMemory(lpBuf + 48, &availVirt, 8);
            cpu->writeGuestMemory(lpBuf + 56, &zero64,    8);
        }
        cpu->writeRegister(X86Reg::EAX, 1u);      // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetVersionExA" || sym == "kernel32.dll!GetVersionExW") {
        uint32_t lpVer = 0;
        cpu->readGuestMemory(esp + 4, &lpVer, 4);
        if (lpVer != 0) {
            uint32_t ver[4] = { 6u, 1u, 7601u, 2u }; // Windows 7 SP1 NT
            uint16_t emptyCsd = 0;
            cpu->writeGuestMemory(lpVer + 4,  ver,       sizeof(ver));
            cpu->writeGuestMemory(lpVer + 20, &emptyCsd, 2);
        }
        cpu->writeRegister(X86Reg::EAX, 1u);      // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetVersion") {
        cpu->writeRegister(X86Reg::EAX, 0x1DB10106u); // Win 6.1 build 7601
        cpu->writeRegister(X86Reg::ESP, esp + 4);     // stdcall: 0 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCurrentProcess") {
        cpu->writeRegister(X86Reg::EAX, 0xFFFFFFFFu);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetCurrentThread") {
        cpu->writeRegister(X86Reg::EAX, 0xFFFFFFFEu);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetProcessHeap") {
        cpu->writeRegister(X86Reg::EAX, 0x20000000u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!HeapAlloc") {
        uint32_t dwFlags = 0, dwBytes = 0;
        cpu->readGuestMemory(esp + 8,  &dwFlags, 4);
        cpu->readGuestMemory(esp + 12, &dwBytes, 4);
        uint32_t ptr = allocGuest(dwBytes);
        if (ptr != 0 && (dwFlags & 0x8u) && dwBytes > 0) {
            std::vector<uint8_t> zeros(dwBytes, 0);
            cpu->writeGuestMemory(ptr, zeros.data(), dwBytes);
        }
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!HeapReAlloc") {
        uint32_t dwFlags = 0, oldPtr = 0, newSz = 0;
        cpu->readGuestMemory(esp + 8,  &dwFlags, 4);
        cpu->readGuestMemory(esp + 12, &oldPtr,  4);
        cpu->readGuestMemory(esp + 16, &newSz,   4);
        uint32_t newPtr = allocGuest(newSz);
        if (newPtr != 0) {
            if ((dwFlags & 0x8u) && newSz > 0) {
                std::vector<uint8_t> zeros(newSz, 0);
                cpu->writeGuestMemory(newPtr, zeros.data(), newSz);
            }
            if (oldPtr != 0) {
                auto it = m_allocSizes.find(oldPtr);
                uint32_t copySz = (it != m_allocSizes.end()) ? it->second : 0u;
                if (copySz > newSz) copySz = newSz;
                if (copySz > 0) {
                    std::vector<uint8_t> tmp(copySz);
                    cpu->readGuestMemory(oldPtr, tmp.data(), copySz);
                    cpu->writeGuestMemory(newPtr, tmp.data(), copySz);
                }
            }
        }
        cpu->writeRegister(X86Reg::EAX, newPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 20); // stdcall: 4 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!HeapFree") {
        cpu->writeRegister(X86Reg::EAX, 1u);       // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!HeapSize") {
        uint32_t lpMem = 0;
        cpu->readGuestMemory(esp + 12, &lpMem, 4);
        uint32_t sz = 0;
        auto it = m_allocSizes.find(lpMem);
        if (it != m_allocSizes.end()) sz = it->second;
        cpu->writeRegister(X86Reg::EAX, sz);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "advapi32.dll!RegOpenKeyExA" || sym == "advapi32.dll!RegOpenKeyExW") {
        uint32_t subKeyPtr = 0, phkResult = 0;
        cpu->readGuestMemory(esp + 8,  &subKeyPtr, 4);
        cpu->readGuestMemory(esp + 20, &phkResult, 4);
        if (phkResult != 0) {
            uint32_t zero = 0u;
            cpu->writeGuestMemory(phkResult, &zero, 4);
        }
        std::string keyLog;
        if (sym == "advapi32.dll!RegOpenKeyExA" && subKeyPtr != 0) {
            keyLog = readCStr(subKeyPtr, 128);
            if (keyLog.size() > 48) keyLog.resize(48);
        }
        cpu->writeRegister(X86Reg::EAX, 2u);       // ERROR_FILE_NOT_FOUND
        cpu->writeRegister(X86Reg::ESP, esp + 24); // stdcall: retAddr + 5 args
        outNextEip = returnAddr;
        m_handledLog.push_back(keyLog.empty() ? sym : (sym + "(\"" + keyLog + "\")"));
        return true;
    }

    if (sym == "advapi32.dll!RegOpenKeyA" || sym == "advapi32.dll!RegOpenKeyW") {
        uint32_t phkResult = 0;
        cpu->readGuestMemory(esp + 12, &phkResult, 4);
        if (phkResult != 0) {
            uint32_t zero = 0u;
            cpu->writeGuestMemory(phkResult, &zero, 4);
        }
        cpu->writeRegister(X86Reg::EAX, 2u);       // ERROR_FILE_NOT_FOUND
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: retAddr + 3 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "advapi32.dll!RegQueryValueExA" || sym == "advapi32.dll!RegQueryValueExW") {
        cpu->writeRegister(X86Reg::EAX, 2u);       // ERROR_FILE_NOT_FOUND
        cpu->writeRegister(X86Reg::ESP, esp + 28); // stdcall: retAddr + 6 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "advapi32.dll!RegSetValueExA" || sym == "advapi32.dll!RegSetValueExW") {
        cpu->writeRegister(X86Reg::EAX, 0u);       // ERROR_SUCCESS
        cpu->writeRegister(X86Reg::ESP, esp + 28); // stdcall: retAddr + 6 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "advapi32.dll!RegCreateKeyExA" || sym == "advapi32.dll!RegCreateKeyExW") {
        uint32_t phkResult = 0;
        cpu->readGuestMemory(esp + 32, &phkResult, 4);
        if (phkResult != 0) {
            uint32_t dummyKey = 0x50000001u;
            cpu->writeGuestMemory(phkResult, &dummyKey, 4);
        }
        cpu->writeRegister(X86Reg::EAX, 0u);       // ERROR_SUCCESS
        cpu->writeRegister(X86Reg::ESP, esp + 40); // stdcall: retAddr + 9 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "advapi32.dll!RegCloseKey") {
        cpu->writeRegister(X86Reg::EAX, 0u);      // ERROR_SUCCESS
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: retAddr + 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "advapi32.dll!GetUserNameA") {
        uint32_t lpBuf = 0, pcbBuf = 0;
        cpu->readGuestMemory(esp + 4, &lpBuf,  4);
        cpu->readGuestMemory(esp + 8, &pcbBuf, 4);
        const char* user = "Player";
        if (lpBuf != 0) cpu->writeGuestMemory(lpBuf, user, 7);
        if (pcbBuf != 0) {
            uint32_t len = 7u;
            cpu->writeGuestMemory(pcbBuf, &len, 4);
        }
        cpu->writeRegister(X86Reg::EAX, 1u);       // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: retAddr + 2 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "advapi32.dll!GetUserNameW") {
        uint32_t lpBuf = 0, pcbBuf = 0;
        cpu->readGuestMemory(esp + 4, &lpBuf,  4);
        cpu->readGuestMemory(esp + 8, &pcbBuf, 4);
        const char* user = "Player";
        uint16_t wuser[7] = {};
        for (int i = 0; i < 7; ++i) wuser[i] = static_cast<uint16_t>(user[i]);
        if (lpBuf != 0) cpu->writeGuestMemory(lpBuf, wuser, sizeof(wuser));
        if (pcbBuf != 0) {
            uint32_t len = 7u;
            cpu->writeGuestMemory(pcbBuf, &len, 4);
        }
        cpu->writeRegister(X86Reg::EAX, 1u);       // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: retAddr + 2 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "shell32.dll!SHGetFolderPathA" || sym == "shell32.dll!SHGetSpecialFolderPathA") {
        uint32_t pathPtr = 0;
        bool isSpecial = (sym == "shell32.dll!SHGetSpecialFolderPathA");
        cpu->readGuestMemory(isSpecial ? (esp + 8) : (esp + 20), &pathPtr, 4);
        std::string docs = "C:\\Stronghold3\\Documents";
        if (pathPtr != 0) cpu->writeGuestMemory(pathPtr, docs.c_str(), docs.size() + 1);
        cpu->writeRegister(X86Reg::EAX, isSpecial ? 1u : 0u); // TRUE / S_OK
        cpu->writeRegister(X86Reg::ESP, isSpecial ? (esp + 20) : (esp + 24));
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "shell32.dll!SHGetFolderPathW" || sym == "shell32.dll!SHGetSpecialFolderPathW") {
        uint32_t pathPtr = 0;
        bool isSpecial = (sym == "shell32.dll!SHGetSpecialFolderPathW");
        cpu->readGuestMemory(isSpecial ? (esp + 8) : (esp + 20), &pathPtr, 4);
        std::string docs = "C:\\Stronghold3\\Documents";
        if (pathPtr != 0) {
            std::vector<uint16_t> wdocs(docs.size() + 1, 0);
            for (size_t i = 0; i < docs.size(); ++i) wdocs[i] = static_cast<uint16_t>(docs[i]);
            cpu->writeGuestMemory(pathPtr, wdocs.data(), wdocs.size() * 2);
        }
        cpu->writeRegister(X86Reg::EAX, isSpecial ? 1u : 0u); // TRUE / S_OK
        cpu->writeRegister(X86Reg::ESP, isSpecial ? (esp + 20) : (esp + 24));
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    auto readWStr = [&](uint32_t addr, size_t maxChars = 65536) -> std::vector<uint16_t> {
        std::vector<uint16_t> res;
        if (addr == 0) return res;
        for (size_t i = 0; i < maxChars; ++i) {
            uint16_t wc = 0;
            if (!cpu->readGuestMemory(addr + static_cast<uint32_t>(i * 2), &wc, 2) || wc == 0) break;
            res.push_back(wc);
        }
        return res;
    };

    if (sym == "kernel32.dll!lstrlenA") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        uint32_t len = (ptr != 0) ? static_cast<uint32_t>(readCStr(ptr, 65536).size()) : 0u;
        cpu->writeRegister(X86Reg::EAX, len);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrlenW") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        uint32_t len = (ptr != 0) ? static_cast<uint32_t>(readWStr(ptr, 65536).size()) : 0u;
        cpu->writeRegister(X86Reg::EAX, len);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall: 1 arg
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcpyA") {
        uint32_t dst = 0, src = 0;
        cpu->readGuestMemory(esp + 4, &dst, 4);
        cpu->readGuestMemory(esp + 8, &src, 4);
        if (dst != 0 && src != 0) {
            std::string str = readCStr(src, 65536);
            cpu->writeGuestMemory(dst, str.c_str(), str.size() + 1);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcpyW") {
        uint32_t dst = 0, src = 0;
        cpu->readGuestMemory(esp + 4, &dst, 4);
        cpu->readGuestMemory(esp + 8, &src, 4);
        if (dst != 0 && src != 0) {
            auto wstr = readWStr(src, 65536);
            wstr.push_back(0);
            cpu->writeGuestMemory(dst, wstr.data(), wstr.size() * 2);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcpynA") {
        uint32_t dst = 0, src = 0;
        int32_t maxLen = 0;
        cpu->readGuestMemory(esp + 4,  &dst,    4);
        cpu->readGuestMemory(esp + 8,  &src,    4);
        cpu->readGuestMemory(esp + 12, &maxLen, 4);
        if (dst != 0 && maxLen > 0) {
            std::string str = (src != 0) ? readCStr(src, static_cast<size_t>(maxLen)) : "";
            size_t copyLen = (str.size() < static_cast<size_t>(maxLen - 1)) ? str.size() : static_cast<size_t>(maxLen - 1);
            if (copyLen > 0) cpu->writeGuestMemory(dst, str.c_str(), copyLen);
            uint8_t nul = 0;
            cpu->writeGuestMemory(dst + static_cast<uint32_t>(copyLen), &nul, 1);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcpynW") {
        uint32_t dst = 0, src = 0;
        int32_t maxLen = 0;
        cpu->readGuestMemory(esp + 4,  &dst,    4);
        cpu->readGuestMemory(esp + 8,  &src,    4);
        cpu->readGuestMemory(esp + 12, &maxLen, 4);
        if (dst != 0 && maxLen > 0) {
            auto wstr = (src != 0) ? readWStr(src, static_cast<size_t>(maxLen)) : std::vector<uint16_t>{};
            size_t copyLen = (wstr.size() < static_cast<size_t>(maxLen - 1)) ? wstr.size() : static_cast<size_t>(maxLen - 1);
            if (copyLen > 0) cpu->writeGuestMemory(dst, wstr.data(), copyLen * 2);
            uint16_t nul = 0;
            cpu->writeGuestMemory(dst + static_cast<uint32_t>(copyLen * 2), &nul, 2);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall: 3 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcatA") {
        uint32_t dst = 0, src = 0;
        cpu->readGuestMemory(esp + 4, &dst, 4);
        cpu->readGuestMemory(esp + 8, &src, 4);
        if (dst != 0 && src != 0) {
            std::string combined = readCStr(dst, 65536) + readCStr(src, 65536);
            cpu->writeGuestMemory(dst, combined.c_str(), combined.size() + 1);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcatW") {
        uint32_t dst = 0, src = 0;
        cpu->readGuestMemory(esp + 4, &dst, 4);
        cpu->readGuestMemory(esp + 8, &src, 4);
        if (dst != 0 && src != 0) {
            auto wdst = readWStr(dst, 65536);
            auto wsrc = readWStr(src, 65536);
            wdst.insert(wdst.end(), wsrc.begin(), wsrc.end());
            wdst.push_back(0);
            cpu->writeGuestMemory(dst, wdst.data(), wdst.size() * 2);
        }
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcmpA" || sym == "kernel32.dll!lstrcmpiA") {
        uint32_t pA = 0, pB = 0;
        cpu->readGuestMemory(esp + 4, &pA, 4);
        cpu->readGuestMemory(esp + 8, &pB, 4);
        bool nocase = (sym == "kernel32.dll!lstrcmpiA");
        std::string a = readCStr(pA, 65536);
        std::string b = readCStr(pB, 65536);
        int32_t res = 0;
        size_t len = (a.size() < b.size()) ? a.size() : b.size();
        for (size_t i = 0; i < len; ++i) {
            uint8_t ca = static_cast<uint8_t>(a[i]);
            uint8_t cb = static_cast<uint8_t>(b[i]);
            if (nocase) {
                if (ca >= 0x41u && ca <= 0x5Au) ca += 32u;
                if (cb >= 0x41u && cb <= 0x5Au) cb += 32u;
            }
            if (ca != cb) { res = (ca < cb) ? -1 : 1; break; }
        }
        if (res == 0 && a.size() != b.size()) res = (a.size() < b.size()) ? -1 : 1;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res));
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!lstrcmpW" || sym == "kernel32.dll!lstrcmpiW") {
        uint32_t pA = 0, pB = 0;
        cpu->readGuestMemory(esp + 4, &pA, 4);
        cpu->readGuestMemory(esp + 8, &pB, 4);
        bool nocase = (sym == "kernel32.dll!lstrcmpiW");
        auto a = readWStr(pA, 65536);
        auto b = readWStr(pB, 65536);
        int32_t res = 0;
        size_t len = (a.size() < b.size()) ? a.size() : b.size();
        for (size_t i = 0; i < len; ++i) {
            uint16_t ca = a[i], cb = b[i];
            if (nocase) {
                if (ca >= 0x41u && ca <= 0x5Au) ca += 32u;
                if (cb >= 0x41u && cb <= 0x5Au) cb += 32u;
            }
            if (ca != cb) { res = (ca < cb) ? -1 : 1; break; }
        }
        if (res == 0 && a.size() != b.size()) res = (a.size() < b.size()) ? -1 : 1;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res));
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall: 2 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!MultiByteToWideChar") {
        uint32_t mbPtr = 0, wcPtr = 0;
        int32_t cbMultiByte = 0, cchWideChar = 0;
        cpu->readGuestMemory(esp + 12, &mbPtr,       4);
        cpu->readGuestMemory(esp + 16, &cbMultiByte, 4);
        cpu->readGuestMemory(esp + 20, &wcPtr,       4);
        cpu->readGuestMemory(esp + 24, &cchWideChar, 4);
        std::vector<uint16_t> outW;
        if (mbPtr != 0) {
            if (cbMultiByte < 0) {
                std::string str = readCStr(mbPtr, 65536);
                outW.reserve(str.size() + 1);
                for (char ch : str) outW.push_back(static_cast<uint8_t>(ch));
                outW.push_back(0);
            } else if (cbMultiByte > 0) {
                std::vector<uint8_t> raw(static_cast<size_t>(cbMultiByte));
                cpu->readGuestMemory(mbPtr, raw.data(), raw.size());
                outW.reserve(raw.size());
                for (uint8_t b : raw) outW.push_back(b);
            }
        }
        uint32_t needed = static_cast<uint32_t>(outW.size());
        uint32_t ret = needed;
        if (cchWideChar > 0) {
            if (static_cast<uint32_t>(cchWideChar) < needed) {
                if (wcPtr != 0) cpu->writeGuestMemory(wcPtr, outW.data(), static_cast<size_t>(cchWideChar) * 2);
                m_lastError = 122u; // ERROR_INSUFFICIENT_BUFFER
                ret = 0u;
            } else if (wcPtr != 0 && needed > 0) {
                cpu->writeGuestMemory(wcPtr, outW.data(), outW.size() * 2);
            }
        }
        cpu->writeRegister(X86Reg::EAX, ret);
        cpu->writeRegister(X86Reg::ESP, esp + 28); // stdcall: 6 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!WideCharToMultiByte") {
        uint32_t wcPtr = 0, mbPtr = 0, usedDefPtr = 0;
        int32_t cchWideChar = 0, cbMultiByte = 0;
        cpu->readGuestMemory(esp + 12, &wcPtr,       4);
        cpu->readGuestMemory(esp + 16, &cchWideChar, 4);
        cpu->readGuestMemory(esp + 20, &mbPtr,       4);
        cpu->readGuestMemory(esp + 24, &cbMultiByte, 4);
        cpu->readGuestMemory(esp + 32, &usedDefPtr,  4);
        if (usedDefPtr != 0) {
            uint32_t zero = 0u;
            cpu->writeGuestMemory(usedDefPtr, &zero, 4);
        }
        std::vector<uint8_t> outB;
        if (wcPtr != 0) {
            if (cchWideChar < 0) {
                auto wstr = readWStr(wcPtr, 65536);
                outB.reserve(wstr.size() + 1);
                for (uint16_t wc : wstr) outB.push_back(wc <= 0xFFu ? static_cast<uint8_t>(wc) : 0x3Fu);
                outB.push_back(0);
            } else if (cchWideChar > 0) {
                std::vector<uint16_t> raw(static_cast<size_t>(cchWideChar));
                cpu->readGuestMemory(wcPtr, raw.data(), raw.size() * 2);
                outB.reserve(raw.size());
                for (uint16_t wc : raw) outB.push_back(wc <= 0xFFu ? static_cast<uint8_t>(wc) : 0x3Fu);
            }
        }
        uint32_t needed = static_cast<uint32_t>(outB.size());
        uint32_t ret = needed;
        if (cbMultiByte > 0) {
            if (static_cast<uint32_t>(cbMultiByte) < needed) {
                if (mbPtr != 0) cpu->writeGuestMemory(mbPtr, outB.data(), static_cast<size_t>(cbMultiByte));
                m_lastError = 122u; // ERROR_INSUFFICIENT_BUFFER
                ret = 0u;
            } else if (mbPtr != 0 && needed > 0) {
                cpu->writeGuestMemory(mbPtr, outB.data(), outB.size());
            }
        }
        cpu->writeRegister(X86Reg::EAX, ret);
        cpu->writeRegister(X86Reg::ESP, esp + 36); // stdcall: 8 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetACP" || sym == "kernel32.dll!GetOEMCP") {
        cpu->writeRegister(X86Reg::EAX, 1252u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall: 0 args
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!setlocale") {
        uint32_t cStrPtr = allocGuest(4);
        if (cStrPtr != 0) {
            const char cLoc[2] = { 0x43, 0x00 }; // "C"
            cpu->writeGuestMemory(cStrPtr, cLoc, 2);
        }
        cpu->writeRegister(X86Reg::EAX, cStrPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!localeconv") {
        uint32_t lcPtr = allocGuest(80);
        uint32_t dotPtr = allocGuest(4);
        uint32_t empPtr = allocGuest(4);
        uint32_t negPtr = allocGuest(4);
        if (lcPtr != 0 && dotPtr != 0 && empPtr != 0 && negPtr != 0) {
            const char dotS[2] = { 0x2E, 0x00 }; // "."
            const char empS[1] = { 0x00 };
            const char negS[2] = { 0x2D, 0x00 }; // "-"
            cpu->writeGuestMemory(dotPtr, dotS, 2);
            cpu->writeGuestMemory(empPtr, empS, 1);
            cpu->writeGuestMemory(negPtr, negS, 2);
            uint32_t ptrs[10] = {
                dotPtr, empPtr, empPtr, empPtr, empPtr,
                empPtr, empPtr, empPtr, empPtr, negPtr
            };
            cpu->writeGuestMemory(lcPtr, ptrs, sizeof(ptrs));
            uint8_t chars[8] = { 127, 127, 127, 127, 127, 127, 127, 127 };
            cpu->writeGuestMemory(lcPtr + 40, chars, sizeof(chars));
        }
        cpu->writeRegister(X86Reg::EAX, lcPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__pctype_func") {
        uint32_t tblPtr = allocGuest(512);
        if (tblPtr != 0) {
            uint16_t tbl[256] = { 0 };
            for (int c = 0; c < 128; ++c) {
                uint16_t f = 0;
                if (c >= 'A' && c <= 'Z') f |= 0x01;
                if (c >= 'a' && c <= 'z') f |= 0x02;
                if (c >= '0' && c <= '9') f |= 0x04;
                if (c == ' ' || (c >= 0x09 && c <= 0x0D)) f |= 0x08;
                if ((c >= 0x21 && c <= 0x2F) || (c >= 0x3A && c <= 0x40) ||
                    (c >= 0x5B && c <= 0x60) || (c >= 0x7B && c <= 0x7E)) f |= 0x10;
                if (c < 0x20 || c == 0x7F) f |= 0x20;
                if (c == ' ' || c == 0x09) f |= 0x40;
                if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) f |= 0x80;
                tbl[c] = f;
            }
            cpu->writeGuestMemory(tblPtr, tbl, sizeof(tbl));
        }
        cpu->writeRegister(X86Reg::EAX, tblPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__uncaught_exception") {
        cpu->writeRegister(X86Reg::EAX, 0u); // false: no active exception
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_errno") {
        static uint32_t s_errnoPtr = 0;
        if (s_errnoPtr == 0) {
            s_errnoPtr = allocGuest(4);
            uint32_t zero = 0;
            if (s_errnoPtr != 0) cpu->writeGuestMemory(s_errnoPtr, &zero, 4);
        }
        cpu->writeRegister(X86Reg::EAX, s_errnoPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__iob_func") {
        static uint32_t s_iobPtr = 0;
        if (s_iobPtr == 0) {
            s_iobPtr = allocGuest(96); // 3 x 32-byte FILE structs
            uint8_t zeros[96] = { 0 };
            if (s_iobPtr != 0) cpu->writeGuestMemory(s_iobPtr, zeros, sizeof(zeros));
        }
        cpu->writeRegister(X86Reg::EAX, s_iobPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_encode_pointer" || sym == "msvcr100.dll!_decode_pointer") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 4, &ptr, 4);
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!___lc_collate_cp_func" ||
        sym == "msvcr100.dll!_encoded_null" ||
        sym == "msvcr100.dll!atexit" ||
        sym == "msvcr100.dll!_invalid_parameter_noinfo" ||
        sym == "msvcr100.dll!_invalid_parameter_noinfo_noreturn" ||
        sym == "msvcr100.dll!_set_invalid_parameter_handler" ||
        sym == "msvcr100.dll!_set_purecall_handler" ||
        sym == "msvcr100.dll!__CppXcptFilter" ||
        sym == "msvcr100.dll!_XcptFilter") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    static FILE* s_cFiles[64] = { nullptr };
    auto readGuestCStrLocal = [&](uint32_t addr) -> std::string {
        std::string out;
        if (addr == 0) return out;
        for (int i = 0; i < 512; ++i) {
            char ch = 0;
            cpu->readGuestMemory(addr + i, &ch, 1);
            if (ch == 0) break;
            out.push_back(ch);
        }
        return out;
    };
    alignas(4096) static uint8_t s_cFilePage[4096] = {};
    static bool s_cFilePageMapped = false;
    if (!s_cFilePageMapped) {
        cpu->mapGuestMemory(0x6F000000u, 4096u, s_cFilePage);
        s_cFilePageMapped = true;
    }
    auto getHostFile = [&](uint32_t handle) -> FILE* {
        if (handle < 0x6F000000u) return nullptr;
        uint32_t idx = (handle - 0x6F000000u) >> 5;
        if (idx >= 64) return nullptr;
        return s_cFiles[idx];
    };

    if ((sym == "msvcr100.dll!fopen" || sym == "msvcr100.dll!_fsopen" || sym == "dynamic!_fsopen")) {
        uint32_t pathPtr = 0, modePtr = 0;
        cpu->readGuestMemory(esp + 4, &pathPtr, 4);
        cpu->readGuestMemory(esp + 8, &modePtr, 4);
        std::string path = readGuestCStrLocal(pathPtr);
        std::string mode = readGuestCStrLocal(modePtr);
        for (char& c : path) { if (c == 0x5C) c = 0x2F; }
        uint32_t guestHandle = 0;
        FILE* f = nullptr;
        if (!path.empty() && !mode.empty()) {
            f = fopen(path.c_str(), mode.c_str());
            if (!f && path[0] != 0x2F) f = fopen(("../" + path).c_str(), mode.c_str());
            if (!f && path[0] != 0x2F) f = fopen(("../../" + path).c_str(), mode.c_str());
        }
        if (f != nullptr) {
            for (uint32_t i = 1; i < 64; ++i) {
                if (s_cFiles[i] == nullptr) {
                    s_cFiles[i] = f;
                    memset(s_cFilePage + (i << 5), 0, 32);
                    guestHandle = 0x6F000000u + (i << 5);
                    break;
                }
            }
            if (guestHandle == 0) fclose(f);
        }
        cpu->writeRegister(X86Reg::EAX, guestHandle);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        char fmlog[256]; snprintf(fmlog, sizeof(fmlog), "%s('%s','%s')->0x%X", sym.c_str(), path.c_str(), mode.c_str(), guestHandle);
        m_handledLog.push_back(fmlog);
        return true;
    }

    if (sym == "msvcr100.dll!fgetc" || sym == "msvcr100.dll!getc" || sym == "dynamic!fgetc") {
        uint32_t h = 0u; cpu->readGuestMemory(esp + 4, &h, 4);
        FILE* f = getHostFile(h);
        int res = f ? fgetc(f) : -1;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res));
        cpu->writeRegister(X86Reg::ESP, esp + 4u);
        outNextEip = returnAddr; logSym(sym); return true;
    }

    if (sym == "msvcr100.dll!ungetc" || sym == "dynamic!ungetc") {
        int32_t c = 0; uint32_t h = 0u;
        cpu->readGuestMemory(esp + 4, &c, 4); cpu->readGuestMemory(esp + 8, &h, 4);
        FILE* f = getHostFile(h);
        int res = f ? ungetc(c, f) : -1;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res));
        cpu->writeRegister(X86Reg::ESP, esp + 4u);
        outNextEip = returnAddr; logSym(sym); return true;
    }

    if (sym == "msvcr100.dll!fputc" || sym == "msvcr100.dll!putc" || sym == "dynamic!fputc") {
        int32_t c = 0; uint32_t h = 0u;
        cpu->readGuestMemory(esp + 4, &c, 4); cpu->readGuestMemory(esp + 8, &h, 4);
        FILE* f = getHostFile(h);
        int res = f ? fputc(c, f) : -1;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res));
        cpu->writeRegister(X86Reg::ESP, esp + 4u);
        outNextEip = returnAddr; logSym(sym); return true;
    }

    if (sym == "msvcr100.dll!fgetpos" || sym == "dynamic!fgetpos") {
        uint32_t h = 0u, posPtr = 0u;
        cpu->readGuestMemory(esp + 4, &h, 4); cpu->readGuestMemory(esp + 8, &posPtr, 4);
        FILE* f = getHostFile(h);
        uint32_t res = 0xFFFFFFFFu;
        if (f && posPtr >= 0x10000u) {
            int64_t pos = static_cast<int64_t>(ftello(f));
            if (pos >= 0) { cpu->writeGuestMemory(posPtr, &pos, 8); res = 0u; }
        }
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4u);
        outNextEip = returnAddr; logSym(sym); return true;
    }

    if (sym == "msvcr100.dll!fsetpos" || sym == "dynamic!fsetpos") {
        uint32_t h = 0u, posPtr = 0u;
        cpu->readGuestMemory(esp + 4, &h, 4); cpu->readGuestMemory(esp + 8, &posPtr, 4);
        FILE* f = getHostFile(h);
        uint32_t res = 0xFFFFFFFFu;
        if (f && posPtr >= 0x10000u) {
            int64_t pos = 0; cpu->readGuestMemory(posPtr, &pos, 8);
            res = (fseeko(f, static_cast<off_t>(pos), SEEK_SET) == 0) ? 0u : 0xFFFFFFFFu;
        }
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4u);
        outNextEip = returnAddr; logSym(sym); return true;
    }

    if (sym == "msvcr100.dll!_fseeki64" || sym == "dynamic!_fseeki64") {
        uint32_t h = 0u; int64_t off = 0; int32_t org = 0;
        cpu->readGuestMemory(esp + 4, &h, 4); cpu->readGuestMemory(esp + 8, &off, 8); cpu->readGuestMemory(esp + 16, &org, 4);
        FILE* f = getHostFile(h);
        int res = f ? fseeko(f, static_cast<off_t>(off), org) : -1;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res));
        cpu->writeRegister(X86Reg::ESP, esp + 4u);
        outNextEip = returnAddr; logSym(sym); return true;
    }

    if (sym == "msvcr100.dll!_ftelli64" || sym == "dynamic!_ftelli64") {
        uint32_t h = 0u; cpu->readGuestMemory(esp + 4, &h, 4);
        FILE* f = getHostFile(h);
        int64_t pos = f ? static_cast<int64_t>(ftello(f)) : -1LL;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(pos & 0xFFFFFFFFULL));
        cpu->writeRegister(X86Reg::EDX, static_cast<uint32_t>((static_cast<uint64_t>(pos) >> 32) & 0xFFFFFFFFULL));
        cpu->writeRegister(X86Reg::ESP, esp + 4u);
        outNextEip = returnAddr; logSym(sym); return true;
    }

    if (sym == "msvcr100.dll!rewind" || sym == "dynamic!rewind") {
        uint32_t h = 0u; cpu->readGuestMemory(esp + 4, &h, 4);
        FILE* f = getHostFile(h);
        if (f) rewind(f);
        cpu->writeRegister(X86Reg::ESP, esp + 4u);
        outNextEip = returnAddr; logSym(sym); return true;
    }

    if (sym == "msvcr100.dll!fclose") {
        uint32_t handle = 0;
        cpu->readGuestMemory(esp + 4, &handle, 4);
        uint32_t res = 0xFFFFFFFFu;
        if (handle >= 0x6F000000u) {
            uint32_t idx = (handle - 0x6F000000u) >> 5;
            if (idx < 64 && s_cFiles[idx] != nullptr) {
                res = static_cast<uint32_t>(fclose(s_cFiles[idx]));
                s_cFiles[idx] = nullptr;
            }
        }
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!fread") {
        uint32_t bufPtr = 0, sz = 0, cnt = 0, handle = 0;
        cpu->readGuestMemory(esp + 4, &bufPtr, 4);
        cpu->readGuestMemory(esp + 8, &sz, 4);
        cpu->readGuestMemory(esp + 12, &cnt, 4);
        cpu->readGuestMemory(esp + 16, &handle, 4);
        FILE* f = getHostFile(handle);
        uint32_t readCnt = 0;
        if (f != nullptr && bufPtr != 0 && sz > 0 && cnt > 0) {
            uint32_t total = sz * cnt;
            if (total <= 4096) {
                uint8_t sbuf[4096];
                readCnt = static_cast<uint32_t>(fread(sbuf, sz, cnt, f));
                if (readCnt > 0) cpu->writeGuestMemory(bufPtr, sbuf, readCnt * sz);
            } else {
                std::vector<uint8_t> tmp(total);
                readCnt = static_cast<uint32_t>(fread(tmp.data(), sz, cnt, f));
                if (readCnt > 0) cpu->writeGuestMemory(bufPtr, tmp.data(), readCnt * sz);
            }
        }
        cpu->writeRegister(X86Reg::EAX, readCnt);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        static uint32_t s_freadCount = 0;
        if ((++s_freadCount % 50000) == 0 && f != nullptr) {
            struct stat fst;
            long fsz = (fstat(fileno(f), &fst) == 0) ? static_cast<long>(fst.st_size) : -1L;
            char pbuf[160];
            snprintf(pbuf, sizeof(pbuf), "VFS_PROGRESS(reads=%u, pos=%ld/%ld)", s_freadCount, ftell(f), fsz);
            m_handledLog.push_back(pbuf);
        }
        return true;
    }

    if (sym == "msvcr100.dll!fwrite") {
        uint32_t bufPtr = 0, sz = 0, cnt = 0, handle = 0;
        cpu->readGuestMemory(esp + 4, &bufPtr, 4);
        cpu->readGuestMemory(esp + 8, &sz, 4);
        cpu->readGuestMemory(esp + 12, &cnt, 4);
        cpu->readGuestMemory(esp + 16, &handle, 4);
        FILE* f = getHostFile(handle);
        uint32_t writtenCnt = 0;
        if (f != nullptr && bufPtr != 0 && sz > 0 && cnt > 0) {
            uint32_t total = sz * cnt;
            std::vector<uint8_t> tmp(total);
            cpu->readGuestMemory(bufPtr, tmp.data(), total);
            writtenCnt = static_cast<uint32_t>(fwrite(tmp.data(), sz, cnt, f));
        }
        cpu->writeRegister(X86Reg::EAX, writtenCnt);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!fseek") {
        uint32_t handle = 0, origin = 0;
        int32_t offset = 0;
        cpu->readGuestMemory(esp + 4, &handle, 4);
        cpu->readGuestMemory(esp + 8, &offset, 4);
        cpu->readGuestMemory(esp + 12, &origin, 4);
        FILE* f = getHostFile(handle);
        uint32_t res = (f != nullptr) ? static_cast<uint32_t>(fseek(f, offset, static_cast<int>(origin))) : 0xFFFFFFFFu;
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "msvcr100.dll!ftell") {
        uint32_t handle = 0;
        cpu->readGuestMemory(esp + 4, &handle, 4);
        FILE* f = getHostFile(handle);
        uint32_t res = (f != nullptr) ? static_cast<uint32_t>(ftell(f)) : 0xFFFFFFFFu;
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "msvcr100.dll!fflush") {
        uint32_t handle = 0;
        cpu->readGuestMemory(esp + 4, &handle, 4);
        FILE* f = getHostFile(handle);
        if (f != nullptr) fflush(f);
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!feof" || sym == "msvcr100.dll!ferror") {
        uint32_t handle = 0;
        cpu->readGuestMemory(esp + 4, &handle, 4);
        FILE* f = getHostFile(handle);
        uint32_t res = 0;
        if (f != nullptr) res = (sym == "msvcr100.dll!feof") ? static_cast<uint32_t>(feof(f)) : static_cast<uint32_t>(ferror(f));
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "kernel32.dll!GetFileAttributesA") {
        uint32_t pathPtr = 0;
        cpu->readGuestMemory(esp + 4, &pathPtr, 4);
        std::string path = readGuestCStrLocal(pathPtr);
        for (char& c : path) { if (c == 0x5C) c = 0x2F; }
        struct stat st;
        uint32_t attrs = 0xFFFFFFFFu; // INVALID_FILE_ATTRIBUTES
        if (!path.empty() && stat(path.c_str(), &st) == 0) {
            attrs = S_ISDIR(st.st_mode) ? 0x10u : 0x80u; // DIR or NORMAL
        }
        cpu->writeRegister(X86Reg::EAX, attrs);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!CreateDirectoryA") {
        uint32_t pathPtr = 0;
        cpu->readGuestMemory(esp + 4, &pathPtr, 4);
        std::string path = readGuestCStrLocal(pathPtr);
        for (char& c : path) { if (c == 0x5C) c = 0x2F; }
        uint32_t ok = 0u;
        if (!path.empty()) {
            struct stat st;
            if (mkdir(path.c_str(), 0777) == 0 || stat(path.c_str(), &st) == 0) {
                ok = 1u;
            }
        }
        cpu->writeRegister(X86Reg::EAX, ok);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strtok") {
        static uint32_t s_strtokNext = 0;
        uint32_t strPtr = 0, delimPtr = 0;
        cpu->readGuestMemory(esp + 4, &strPtr, 4);
        cpu->readGuestMemory(esp + 8, &delimPtr, 4);
        if (strPtr != 0) s_strtokNext = strPtr;
        std::string delims = readGuestCStrLocal(delimPtr);
        uint32_t tokenStart = 0;
        if (s_strtokNext != 0) {
            uint32_t cur = s_strtokNext;
            char ch = 0;
            while (true) {
                cpu->readGuestMemory(cur, &ch, 1);
                if (ch == 0) { s_strtokNext = 0; break; }
                if (delims.find(ch) == std::string::npos) { tokenStart = cur; break; }
                cur++;
            }
            if (tokenStart != 0) {
                while (true) {
                    cpu->readGuestMemory(cur, &ch, 1);
                    if (ch == 0) { s_strtokNext = 0; break; }
                    if (delims.find(ch) != std::string::npos) {
                        char zero = 0;
                        cpu->writeGuestMemory(cur, &zero, 1);
                        s_strtokNext = cur + 1;
                        break;
                    }
                    cur++;
                }
            }
        }
        cpu->writeRegister(X86Reg::EAX, tokenStart);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!atoi" || sym == "msvcr100.dll!atol") {
        uint32_t strPtr = 0;
        cpu->readGuestMemory(esp + 4, &strPtr, 4);
        std::string s = readGuestCStrLocal(strPtr);
        uint32_t val = static_cast<uint32_t>(std::atoi(s.c_str()));
        cpu->writeRegister(X86Reg::EAX, val);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strtol" || sym == "msvcr100.dll!strtoul") {
        uint32_t strPtr = 0, endPtrAddr = 0, base = 10;
        cpu->readGuestMemory(esp + 4, &strPtr, 4);
        cpu->readGuestMemory(esp + 8, &endPtrAddr, 4);
        cpu->readGuestMemory(esp + 12, &base, 4);
        std::string s = readGuestCStrLocal(strPtr);
        char* endHost = nullptr;
        uint32_t val = (sym == "msvcr100.dll!strtol")
            ? static_cast<uint32_t>(std::strtol(s.c_str(), &endHost, static_cast<int>(base)))
            : static_cast<uint32_t>(std::strtoul(s.c_str(), &endHost, static_cast<int>(base)));
        if (endPtrAddr != 0) {
            uint32_t endGuest = strPtr + static_cast<uint32_t>(endHost - s.c_str());
            cpu->writeGuestMemory(endPtrAddr, &endGuest, 4);
        }
        cpu->writeRegister(X86Reg::EAX, val);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strpbrk") {
        uint32_t s1Ptr = 0, s2Ptr = 0;
        cpu->readGuestMemory(esp + 4, &s1Ptr, 4);
        cpu->readGuestMemory(esp + 8, &s2Ptr, 4);
        std::string s1 = readGuestCStrLocal(s1Ptr);
        std::string s2 = readGuestCStrLocal(s2Ptr);
        size_t pos = s1.find_first_of(s2);
        uint32_t res = (pos == std::string::npos) ? 0u : (s1Ptr + static_cast<uint32_t>(pos));
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strspn" || sym == "msvcr100.dll!strcspn") {
        uint32_t s1Ptr = 0, s2Ptr = 0;
        cpu->readGuestMemory(esp + 4, &s1Ptr, 4);
        cpu->readGuestMemory(esp + 8, &s2Ptr, 4);
        std::string s1 = readGuestCStrLocal(s1Ptr);
        std::string s2 = readGuestCStrLocal(s2Ptr);
        uint32_t res = (sym == "msvcr100.dll!strspn")
            ? static_cast<uint32_t>(std::strspn(s1.c_str(), s2.c_str()))
            : static_cast<uint32_t>(std::strcspn(s1.c_str(), s2.c_str()));
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_strdup") {
        uint32_t strPtr = 0;
        cpu->readGuestMemory(esp + 4, &strPtr, 4);
        std::string s = readGuestCStrLocal(strPtr);
        uint32_t dst = allocGuest(static_cast<uint32_t>(s.size() + 1));
        if (dst != 0) cpu->writeGuestMemory(dst, s.c_str(), s.size() + 1);
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strcpy_s" || sym == "msvcr100.dll!strcat_s") {
        uint32_t dstPtr = 0, dstSz = 0, srcPtr = 0;
        cpu->readGuestMemory(esp + 4, &dstPtr, 4);
        cpu->readGuestMemory(esp + 8, &dstSz, 4);
        cpu->readGuestMemory(esp + 12, &srcPtr, 4);
        std::string src = readGuestCStrLocal(srcPtr);
        if (dstPtr != 0 && dstSz > 0) {
            if (sym == "msvcr100.dll!strcpy_s") {
                size_t n = std::min<size_t>(src.size(), dstSz - 1);
                if (n > 0) cpu->writeGuestMemory(dstPtr, src.c_str(), n);
                char z = 0; cpu->writeGuestMemory(dstPtr + static_cast<uint32_t>(n), &z, 1);
            } else {
                std::string cur = readGuestCStrLocal(dstPtr);
                std::string combined = cur + src;
                size_t n = std::min<size_t>(combined.size(), dstSz - 1);
                if (n > 0) cpu->writeGuestMemory(dstPtr, combined.c_str(), n);
                char z = 0; cpu->writeGuestMemory(dstPtr + static_cast<uint32_t>(n), &z, 1);
            }
        }
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "steam_api.dll!SteamAPI_RestartAppIfNecessary") {
        cpu->writeRegister(X86Reg::EAX, 0u); // false: do not restart via Steam
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "steam_api.dll!SteamAPI_Init" ||
        sym == "steam_api.dll!SteamAPI_InitSafe" ||
        sym == "steam_api.dll!SteamAPI_IsSteamRunning") {
        cpu->writeRegister(X86Reg::EAX, 1u); // true: Steam running (offline stub)
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "steam_api.dll!SteamAPI_Shutdown" ||
        sym == "steam_api.dll!SteamAPI_RunCallbacks" ||
        sym == "steam_api.dll!SteamAPI_RegisterCallback" ||
        sym == "steam_api.dll!SteamAPI_UnregisterCallback" ||
        sym == "steam_api.dll!SteamAPI_RegisterCallResult" ||
        sym == "steam_api.dll!SteamAPI_UnregisterCallResult") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    {
        int steamIdx = -1;
        if (sym == "steam_api.dll!SteamUser") steamIdx = 0;
        else if (sym == "steam_api.dll!SteamFriends") steamIdx = 1;
        else if (sym == "steam_api.dll!SteamUtils") steamIdx = 2;
        else if (sym == "steam_api.dll!SteamUserStats") steamIdx = 3;
        else if (sym == "steam_api.dll!SteamApps") steamIdx = 4;
        else if (sym == "steam_api.dll!SteamRemoteStorage") steamIdx = 5;
        else if (sym == "steam_api.dll!SteamNetworking") steamIdx = 6;
        else if (sym == "steam_api.dll!SteamMatchmaking") steamIdx = 7;
        if (steamIdx >= 0) {
            static uint32_t s_steamObjs[8] = {};
            uint32_t existingVt = 0;
            if (s_steamObjs[steamIdx] != 0) {
                cpu->readGuestMemory(s_steamObjs[steamIdx], &existingVt, 4);
            }
            if (s_steamObjs[steamIdx] == 0 || existingVt == 0) {
                uint32_t vtAddr = allocGuest(64 * 4);
                uint32_t objAddr = allocGuest(16);
                if (vtAddr != 0 && objAddr != 0) {
                    uint32_t vt[64];
                    for (uint32_t si = 0; si < 64; ++si) {
                        vt[si] = 0x7000A000u + static_cast<uint32_t>(steamIdx) * 0x100u + si * 4u;
                        static const char* kSteamNames[8] = {
                            "ISteamUser", "ISteamFriends", "ISteamUtils", "ISteamUserStats",
                            "ISteamApps", "ISteamRemoteStorage", "ISteamNetworking", "ISteamMatchmaking"
                        };
                        char vname[64];
                        snprintf(vname, sizeof(vname), "%s::vslot[%u]", kSteamNames[steamIdx], si);
                        m_reverseMap[vt[si]] = vname;
                    }
                    cpu->writeGuestMemory(vtAddr, vt, sizeof(vt));
                    cpu->writeGuestMemory(objAddr, &vtAddr, 4);
                    s_steamObjs[steamIdx] = objAddr;
                }
            }
            cpu->writeRegister(X86Reg::EAX, s_steamObjs[steamIdx]);
            cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
    }

    if (sym == "msvcr100.dll!ldiv" || sym == "msvcr100.dll!div") {
        int32_t numer = 0, denom = 1;
        cpu->readGuestMemory(esp + 4, &numer, 4);
        cpu->readGuestMemory(esp + 8, &denom, 4);
        int32_t quot = (denom != 0) ? (numer / denom) : 0;
        int32_t rem  = (denom != 0) ? (numer % denom) : 0;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(quot));
        cpu->writeRegister(X86Reg::EDX, static_cast<uint32_t>(rem));
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        char lbuf[192]; snprintf(lbuf, sizeof(lbuf), "%s(n=%d,d=%d,cmp=%s)", sym.c_str(), numer, denom, m_lastCmp.c_str());
        (void)lbuf;
        return true;
    }

    if (sym == "msvcr100.dll!abs" || sym == "msvcr100.dll!labs") {
        int32_t v = 0;
        cpu->readGuestMemory(esp + 4, &v, 4);
        uint32_t res = static_cast<uint32_t>(v < 0 ? -v : v);
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!srand") {
        uint32_t seed = 1;
        cpu->readGuestMemory(esp + 4, &seed, 4);
        std::srand(seed);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!rand") {
        uint32_t r = static_cast<uint32_t>(std::rand() & 0x7FFF);
        cpu->writeRegister(X86Reg::EAX, r);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!sscanf" || sym == "msvcr100.dll!sscanf_s") {
        bool isSecure = (sym == "msvcr100.dll!sscanf_s");
        uint32_t bufPtr = 0, fmtPtr = 0;
        cpu->readGuestMemory(esp + 4, &bufPtr, 4);
        cpu->readGuestMemory(esp + 8, &fmtPtr, 4);
        std::string buf = readGuestCStrLocal(bufPtr);
        std::string fmt = readGuestCStrLocal(fmtPtr);
        const char* p = buf.c_str();
        const char* f = fmt.c_str();
        uint32_t argOff = 12;
        int matched = 0;
        while (*f) {
            if (std::isspace(static_cast<unsigned char>(*f))) {
                while (std::isspace(static_cast<unsigned char>(*p))) p++;
                f++;
                continue;
            }
            if (*f != 0x25) {
                if (*p != *f) break;
                p++; f++;
                continue;
            }
            f++;
            if (*f == 0x25) { if (*p != 0x25) break; p++; f++; continue; }
            bool suppress = false;
            if (*f == 0x2A) { suppress = true; f++; }
            int width = 0;
            while (*f >= 0x30 && *f <= 0x39) { width = width * 10 + (*f - 0x30); f++; }
            bool isLong = false, isShort = false;
            if (*f == 0x6C) { isLong = true; f++; if (*f == 0x6C) f++; }
            else if (*f == 0x68) { isShort = true; f++; if (*f == 0x68) f++; }
            char spec = *f++;
            if (spec == 0) break;
            if (spec != 0x63) { while (std::isspace(static_cast<unsigned char>(*p))) p++; }
            if (*p == 0) break;
            if (spec == 0x64 || spec == 0x69 || spec == 0x75 || spec == 0x78 || spec == 0x58 || spec == 0x6F) {
                int base = (spec == 0x78 || spec == 0x58) ? 16 : (spec == 0x6F ? 8 : (spec == 0x69 ? 0 : 10));
                char* endp = nullptr;
                uint32_t val = (spec == 0x75 || spec == 0x78 || spec == 0x58 || spec == 0x6F)
                    ? static_cast<uint32_t>(std::strtoul(p, &endp, base))
                    : static_cast<uint32_t>(std::strtol(p, &endp, base));
                if (endp == p) break;
                p = endp;
                if (!suppress) {
                    uint32_t dst = 0; cpu->readGuestMemory(esp + argOff, &dst, 4); argOff += 4;
                    if (dst != 0) {
                        if (isShort) { uint16_t v16 = static_cast<uint16_t>(val); cpu->writeGuestMemory(dst, &v16, 2); }
                        else { cpu->writeGuestMemory(dst, &val, 4); }
                    }
                    matched++;
                }
            } else if (spec == 0x66 || spec == 0x67 || spec == 0x65 || spec == 0x47 || spec == 0x45) {
                char* endp = nullptr;
                double dval = std::strtod(p, &endp);
                if (endp == p) break;
                p = endp;
                if (!suppress) {
                    uint32_t dst = 0; cpu->readGuestMemory(esp + argOff, &dst, 4); argOff += 4;
                    if (dst != 0) {
                        if (isLong) { cpu->writeGuestMemory(dst, &dval, 8); }
                        else { float fval = static_cast<float>(dval); cpu->writeGuestMemory(dst, &fval, 4); }
                    }
                    matched++;
                }
            } else if (spec == 0x73) {
                std::string tok;
                while (*p && !std::isspace(static_cast<unsigned char>(*p)) && (width == 0 || static_cast<int>(tok.size()) < width)) {
                    tok.push_back(*p++);
                }
                if (tok.empty()) break;
                if (!suppress) {
                    uint32_t dst = 0; cpu->readGuestMemory(esp + argOff, &dst, 4); argOff += 4;
                    uint32_t maxSz = 0xFFFFFFFFu;
                    if (isSecure) { cpu->readGuestMemory(esp + argOff, &maxSz, 4); argOff += 4; }
                    if (dst != 0 && maxSz > 0) {
                        size_t n = std::min<size_t>(tok.size(), maxSz - 1);
                        if (n > 0) cpu->writeGuestMemory(dst, tok.c_str(), n);
                        char z = 0; cpu->writeGuestMemory(dst + static_cast<uint32_t>(n), &z, 1);
                    }
                    matched++;
                }
            } else if (spec == 0x63) {
                char ch = *p++;
                if (!suppress) {
                    uint32_t dst = 0; cpu->readGuestMemory(esp + argOff, &dst, 4); argOff += 4;
                    if (isSecure) argOff += 4;
                    if (dst != 0) cpu->writeGuestMemory(dst, &ch, 1);
                    matched++;
                }
            } else { break; }
        }
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(matched));
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!atof" || sym == "msvcr100.dll!strtod") {
        uint32_t strPtr = 0, endPtrAddr = 0;
        cpu->readGuestMemory(esp + 4, &strPtr, 4);
        if (sym == "msvcr100.dll!strtod") cpu->readGuestMemory(esp + 8, &endPtrAddr, 4);
        std::string s = readGuestCStrLocal(strPtr);
        char* endHost = nullptr;
        double val = std::strtod(s.c_str(), &endHost);
        if (endPtrAddr != 0) {
            uint32_t endGuest = strPtr + static_cast<uint32_t>(endHost - s.c_str());
            cpu->writeGuestMemory(endPtrAddr, &endGuest, 4);
        }
        (void)val;
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!qsort" || sym == "msvcr100.dll!bsearch") {
        bool cbUnhandled = false;
        auto invokeGuestComparator = [&](uint32_t compFn, uint32_t elemA, uint32_t elemB) -> int32_t {
            if (cbUnhandled) return 0;
            uint32_t savedEsp = cpu->readRegister(X86Reg::ESP);
            uint32_t savedEbp = cpu->readRegister(X86Reg::EBP);
            uint32_t savedEbx = cpu->readRegister(X86Reg::EBX);
            uint32_t savedEsi = cpu->readRegister(X86Reg::ESI);
            uint32_t savedEdi = cpu->readRegister(X86Reg::EDI);
            uint32_t savedEfl = cpu->readRegister(X86Reg::EFLAGS);
            uint32_t cbEsp = savedEsp - 64u;
            uint32_t sentinelRet = 0x7000FFF0u;
            cpu->writeGuestMemory(cbEsp + 0, &sentinelRet, 4);
            cpu->writeGuestMemory(cbEsp + 4, &elemA, 4);
            cpu->writeGuestMemory(cbEsp + 8, &elemB, 4);
            cpu->writeRegister(X86Reg::ESP, cbEsp);
            uint32_t curEip = compFn;
            for (int guard = 0; guard < 1024; ++guard) {
                X86StepResult st = cpu->stepInstructions(curEip, 65536);
                if (st.faulted) { m_handledLog.push_back("CB_FAULT: " + st.reason); cbUnhandled = true; break; }
                if (st.haltedOnThunk) {
                    if (st.stopAddress == sentinelRet) break;
                    uint32_t curEsp = cpu->readRegister(X86Reg::ESP);
                    uint32_t innerRet = 0;
                    cpu->readGuestMemory(curEsp, &innerRet, 4);
                    uint32_t nextAfterThunk = innerRet;
                    if (!handleThunkCall(cpu, st.stopAddress, innerRet, nextAfterThunk)) {
                        cbUnhandled = true;
                        break;
                    }
                    curEip = nextAfterThunk;
                    continue;
                }
                uint32_t nextIp = cpu->readRegister(X86Reg::EIP);
                if (nextIp == sentinelRet || nextIp == curEip) break;
                curEip = nextIp;
            }
            int32_t cmpRes = static_cast<int32_t>(cpu->readRegister(X86Reg::EAX));
            cpu->writeRegister(X86Reg::ESP, savedEsp);
            cpu->writeRegister(X86Reg::EBP, savedEbp);
            cpu->writeRegister(X86Reg::EBX, savedEbx);
            cpu->writeRegister(X86Reg::ESI, savedEsi);
            cpu->writeRegister(X86Reg::EDI, savedEdi);
            cpu->writeRegister(X86Reg::EFLAGS, savedEfl);
            return cmpRes;
        };

        if (sym == "msvcr100.dll!qsort") {
            uint32_t basePtr = 0, num = 0, elemSz = 0, compFn = 0;
            cpu->readGuestMemory(esp + 4, &basePtr, 4);
            cpu->readGuestMemory(esp + 8, &num, 4);
            cpu->readGuestMemory(esp + 12, &elemSz, 4);
            cpu->readGuestMemory(esp + 16, &compFn, 4);
            size_t logMark = m_handledLog.size();
            if (basePtr != 0 && num > 1 && elemSz > 0 && compFn != 0) {
                std::vector<uint32_t> idx(num);
                for (uint32_t i = 0; i < num; ++i) idx[i] = i;
                std::sort(idx.begin(), idx.end(), [&](uint32_t a, uint32_t b) {
                    if (cbUnhandled) return false;
                    return invokeGuestComparator(compFn, basePtr + a * elemSz, basePtr + b * elemSz) < 0;
                });
                if (!cbUnhandled) {
                    size_t totalBytes = static_cast<size_t>(num) * static_cast<size_t>(elemSz);
                    std::vector<uint8_t> orig(totalBytes), sorted(totalBytes);
                    cpu->readGuestMemory(basePtr, orig.data(), totalBytes);
                    for (uint32_t i = 0; i < num; ++i) {
                        memcpy(sorted.data() + static_cast<size_t>(i) * elemSz,
                               orig.data() + static_cast<size_t>(idx[i]) * elemSz,
                               elemSz);
                    }
                    cpu->writeGuestMemory(basePtr, sorted.data(), totalBytes);
                }
            }
            if (cbUnhandled) return false;
            if (m_handledLog.size() > logMark) m_handledLog.resize(logMark);
            char qbuf[96];
            snprintf(qbuf, sizeof(qbuf), "msvcr100.dll!qsort(n=%u,sz=%u)", num, elemSz);
            m_handledLog.push_back(qbuf);
            cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
            outNextEip = returnAddr;
            return true;
        } else {
            uint32_t keyPtr = 0, basePtr = 0, num = 0, elemSz = 0, compFn = 0;
            cpu->readGuestMemory(esp + 4, &keyPtr, 4);
            cpu->readGuestMemory(esp + 8, &basePtr, 4);
            cpu->readGuestMemory(esp + 12, &num, 4);
            cpu->readGuestMemory(esp + 16, &elemSz, 4);
            cpu->readGuestMemory(esp + 20, &compFn, 4);
            size_t logMark = m_handledLog.size();
            uint32_t foundAddr = 0;
            if (keyPtr != 0 && basePtr != 0 && num > 0 && elemSz > 0 && compFn != 0) {
                uint32_t lo = 0, hi = num;
                while (lo < hi && !cbUnhandled) {
                    uint32_t mid = lo + (hi - lo) / 2;
                    uint32_t cand = basePtr + mid * elemSz;
                    int32_t c = invokeGuestComparator(compFn, keyPtr, cand);
                    if (c == 0) { foundAddr = cand; break; }
                    else if (c < 0) { hi = mid; }
                    else { lo = mid + 1; }
                }
            }
            if (cbUnhandled) return false;
            if (m_handledLog.size() > logMark) m_handledLog.resize(logMark);
            cpu->writeRegister(X86Reg::EAX, foundAddr);
            cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
            outNextEip = returnAddr;
            logSym(sym);
            return true;
        }
    }

    if (sym == "msvcr100.dll!_stat64i32" || sym == "msvcr100.dll!_wstat64i32" ||
        sym == "msvcr100.dll!_stat32" || sym == "msvcr100.dll!_stat" ||
        sym == "msvcr100.dll!_stat64") {
        uint32_t pathPtr = 0, bufPtr = 0;
        cpu->readGuestMemory(esp + 4, &pathPtr, 4);
        cpu->readGuestMemory(esp + 8, &bufPtr, 4);
        std::string path;
        if (sym == "msvcr100.dll!_wstat64i32") {
            if (pathPtr != 0) {
                for (uint32_t k = 0; k < 512; ++k) {
                    uint16_t wc = 0;
                    cpu->readGuestMemory(pathPtr + k * 2, &wc, 2);
                    if (wc == 0) break;
                    path.push_back(static_cast<char>(wc & 0xFF));
                }
            }
        } else {
            path = readGuestCStrLocal(pathPtr);
        }
        for (char& c : path) { if (c == 0x5C) c = 0x2F; }
        while (path.size() > 1 && path.back() == 0x2F) path.pop_back();
        struct stat st;
        bool ok = false;
        if (!path.empty()) {
            if (stat(path.c_str(), &st) == 0) ok = true;
            else if (path[0] != 0x2F && stat(("../" + path).c_str(), &st) == 0) ok = true;
            else if (path[0] != 0x2F && stat(("../../" + path).c_str(), &st) == 0) ok = true;
        }
        if (ok && bufPtr != 0) {
            uint8_t sbuf[56] = {0};
            uint16_t wmode = S_ISDIR(st.st_mode) ? 0x41FFu : 0x81B6u;
            int16_t nlink = 1;
            memcpy(sbuf + 6, &wmode, 2);
            memcpy(sbuf + 8, &nlink, 2);
            if (sym == "msvcr100.dll!_stat64") {
                int64_t sz64 = static_cast<int64_t>(st.st_size);
                int64_t at64 = static_cast<int64_t>(st.st_atime);
                int64_t mt64 = static_cast<int64_t>(st.st_mtime);
                int64_t ct64 = static_cast<int64_t>(st.st_ctime);
                memcpy(sbuf + 24, &sz64, 8);
                memcpy(sbuf + 32, &at64, 8);
                memcpy(sbuf + 40, &mt64, 8);
                memcpy(sbuf + 48, &ct64, 8);
                cpu->writeGuestMemory(bufPtr, sbuf, 56);
            } else if (sym == "msvcr100.dll!_stat32" || sym == "msvcr100.dll!_stat") {
                uint32_t sz32 = static_cast<uint32_t>(st.st_size);
                int32_t at32 = static_cast<int32_t>(st.st_atime);
                int32_t mt32 = static_cast<int32_t>(st.st_mtime);
                int32_t ct32 = static_cast<int32_t>(st.st_ctime);
                memcpy(sbuf + 20, &sz32, 4);
                memcpy(sbuf + 24, &at32, 4);
                memcpy(sbuf + 28, &mt32, 4);
                memcpy(sbuf + 32, &ct32, 4);
                cpu->writeGuestMemory(bufPtr, sbuf, 36);
            } else {
                uint32_t sz32 = static_cast<uint32_t>(st.st_size);
                int64_t at64 = static_cast<int64_t>(st.st_atime);
                int64_t mt64 = static_cast<int64_t>(st.st_mtime);
                int64_t ct64 = static_cast<int64_t>(st.st_ctime);
                memcpy(sbuf + 20, &sz32, 4);
                memcpy(sbuf + 24, &at64, 8);
                memcpy(sbuf + 32, &mt64, 8);
                memcpy(sbuf + 40, &ct64, 8);
                cpu->writeGuestMemory(bufPtr, sbuf, 48);
            }
        }
        int32_t res = ok ? 0 : -1;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res));
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        char stlog[256]; snprintf(stlog, sizeof(stlog), "%s('%s')->%d", sym.c_str(), path.c_str(), res);
        m_handledLog.push_back(stlog);
        return true;
    }

    if (sym == "msvcr100.dll!_access" || sym == "msvcr100.dll!_access_s") {
        uint32_t pathPtr = 0, mode = 0;
        cpu->readGuestMemory(esp + 4, &pathPtr, 4);
        cpu->readGuestMemory(esp + 8, &mode, 4);
        std::string path = readGuestCStrLocal(pathPtr);
        for (char& c : path) { if (c == 0x5C) c = 0x2F; }
        struct stat st;
        bool ok = !path.empty() && (stat(path.c_str(), &st) == 0 || (path[0] != 0x2F && stat(("../" + path).c_str(), &st) == 0));
        uint32_t res = ok ? 0u : ((sym == "msvcr100.dll!_access_s") ? 2u : 0xFFFFFFFFu);
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_mkdir") {
        uint32_t pathPtr = 0;
        cpu->readGuestMemory(esp + 4, &pathPtr, 4);
        std::string path = readGuestCStrLocal(pathPtr);
        for (char& c : path) { if (c == 0x5C) c = 0x2F; }
        int r = (!path.empty()) ? mkdir(path.c_str(), 0755) : -1;
        if (r != 0 && errno == EEXIST) r = 0;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(r));
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_fullpath") {
        uint32_t absPtr = 0, relPtr = 0, maxLen = 0;
        cpu->readGuestMemory(esp + 4, &absPtr, 4);
        cpu->readGuestMemory(esp + 8, &relPtr, 4);
        cpu->readGuestMemory(esp + 12, &maxLen, 4);
        std::string rel = readGuestCStrLocal(relPtr);
        for (char& c : rel) { if (c == 0x2F) c = 0x5C; }
        if (absPtr == 0) {
            maxLen = static_cast<uint32_t>(rel.size() + 1);
            absPtr = allocGuest(maxLen);
        }
        if (absPtr != 0 && maxLen > 0) {
            size_t n = std::min<size_t>(rel.size(), maxLen - 1);
            if (n > 0) cpu->writeGuestMemory(absPtr, rel.c_str(), n);
            char z = 0; cpu->writeGuestMemory(absPtr + static_cast<uint32_t>(n), &z, 1);
        }
        cpu->writeRegister(X86Reg::EAX, absPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!DisableThreadLibraryCalls") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!IsProcessorFeaturePresent") {
        uint32_t feat = 0;
        cpu->readGuestMemory(esp + 4, &feat, 4);
        uint32_t supported = (feat == 2u || feat == 3u || feat == 6u || feat == 8u ||
                              feat == 10u || feat == 12u || feat == 13u) ? 1u : 0u;
        cpu->writeRegister(X86Reg::EAX, supported);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall (1 arg)
        outNextEip = returnAddr;
        char pbuf[96];
        snprintf(pbuf, sizeof(pbuf), "kernel32.dll!IsProcessorFeaturePresent(%u)->%u", feat, supported);
        if (m_handledLog.size() < 4096) m_handledLog.push_back(pbuf);
        return true;
    }

    if (sym == "comctl32.dll!#17" || sym == "comctl32.dll!InitCommonControls") {
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall (0 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "comctl32.dll!InitCommonControlsEx") {
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_time64") {
        uint32_t dstPtr = 0;
        cpu->readGuestMemory(esp + 4, &dstPtr, 4);
        int64_t now = static_cast<int64_t>(time(nullptr));
        if (dstPtr != 0) cpu->writeGuestMemory(dstPtr, &now, 8);
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(now & 0xFFFFFFFFull));
        cpu->writeRegister(X86Reg::EDX, static_cast<uint32_t>((static_cast<uint64_t>(now) >> 32) & 0xFFFFFFFFull));
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_time32" || sym == "msvcr100.dll!time") {
        uint32_t dstPtr = 0;
        cpu->readGuestMemory(esp + 4, &dstPtr, 4);
        uint32_t now = static_cast<uint32_t>(time(nullptr));
        if (dstPtr != 0) cpu->writeGuestMemory(dstPtr, &now, 4);
        cpu->writeRegister(X86Reg::EAX, now);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_localtime64" || sym == "msvcr100.dll!_localtime32" ||
        sym == "msvcr100.dll!_gmtime64" || sym == "msvcr100.dll!_gmtime32") {
        uint32_t tPtr = 0;
        cpu->readGuestMemory(esp + 4, &tPtr, 4);
        time_t tv = time(nullptr);
        if (tPtr != 0) {
            if (sym.find("64") != std::string::npos) {
                int64_t v64 = 0; cpu->readGuestMemory(tPtr, &v64, 8); tv = static_cast<time_t>(v64);
            } else {
                int32_t v32 = 0; cpu->readGuestMemory(tPtr, &v32, 4); tv = static_cast<time_t>(v32);
            }
        }
        struct tm resTm{};
        if (sym.find("gmtime") != std::string::npos) gmtime_r(&tv, &resTm);
        else localtime_r(&tv, &resTm);
        int32_t gtm[9] = { resTm.tm_sec, resTm.tm_min, resTm.tm_hour, resTm.tm_mday,
                           resTm.tm_mon, resTm.tm_year, resTm.tm_wday, resTm.tm_yday, resTm.tm_isdst };
        uint32_t outPtr = allocGuest(36);
        if (outPtr != 0) cpu->writeGuestMemory(outPtr, gtm, sizeof(gtm));
        cpu->writeRegister(X86Reg::EAX, outPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_localtime64_s" || sym == "msvcr100.dll!_localtime32_s" ||
        sym == "msvcr100.dll!_gmtime64_s" || sym == "msvcr100.dll!_gmtime32_s") {
        uint32_t outPtr = 0, tPtr = 0;
        cpu->readGuestMemory(esp + 4, &outPtr, 4);
        cpu->readGuestMemory(esp + 8, &tPtr, 4);
        time_t tv = time(nullptr);
        if (tPtr != 0) {
            if (sym.find("64") != std::string::npos) {
                int64_t v64 = 0; cpu->readGuestMemory(tPtr, &v64, 8); tv = static_cast<time_t>(v64);
            } else {
                int32_t v32 = 0; cpu->readGuestMemory(tPtr, &v32, 4); tv = static_cast<time_t>(v32);
            }
        }
        struct tm resTm{};
        if (sym.find("gmtime") != std::string::npos) gmtime_r(&tv, &resTm);
        else localtime_r(&tv, &resTm);
        int32_t gtm[9] = { resTm.tm_sec, resTm.tm_min, resTm.tm_hour, resTm.tm_mday,
                           resTm.tm_mon, resTm.tm_year, resTm.tm_wday, resTm.tm_yday, resTm.tm_isdst };
        if (outPtr != 0) cpu->writeGuestMemory(outPtr, gtm, sizeof(gtm));
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_mktime64" || sym == "msvcr100.dll!_mktime32") {
        uint32_t tmPtr = 0;
        cpu->readGuestMemory(esp + 4, &tmPtr, 4);
        int64_t res = -1;
        if (tmPtr != 0) {
            int32_t gtm[9] = {};
            cpu->readGuestMemory(tmPtr, gtm, sizeof(gtm));
            struct tm t{};
            t.tm_sec = gtm[0]; t.tm_min = gtm[1]; t.tm_hour = gtm[2];
            t.tm_mday = gtm[3]; t.tm_mon = gtm[4]; t.tm_year = gtm[5];
            t.tm_wday = gtm[6]; t.tm_yday = gtm[7]; t.tm_isdst = gtm[8];
            res = static_cast<int64_t>(mktime(&t));
        }
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res & 0xFFFFFFFFull));
        if (sym == "msvcr100.dll!_mktime64") {
            cpu->writeRegister(X86Reg::EDX, static_cast<uint32_t>((static_cast<uint64_t>(res) >> 32) & 0xFFFFFFFFull));
        }
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!HeapCreate") {
        cpu->writeRegister(X86Reg::EAX, 0x20000000u);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall (3 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!HeapDestroy") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!HeapSetInformation") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 20); // stdcall (4 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!HeapValidate") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall (3 args)
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "kernel32.dll!HeapCompact") {
        cpu->writeRegister(X86Reg::EAX, 0x100000u);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall (2 args)
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "kernel32.dll!HeapAlloc") {
        uint32_t flags = 0, bytes = 0;
        cpu->readGuestMemory(esp + 8, &flags, 4);
        cpu->readGuestMemory(esp + 12, &bytes, 4);
        uint32_t ptr = allocGuest(bytes);
        if (ptr != 0 && (flags & 0x8u) && bytes > 0) {
            std::vector<uint8_t> zeros(bytes, 0);
            cpu->writeGuestMemory(ptr, zeros.data(), bytes);
        }
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall (3 args)
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "kernel32.dll!HeapFree") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 12, &ptr, 4);
        freeGuest(ptr);
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall (3 args)
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "kernel32.dll!HeapReAlloc") {
        uint32_t flags = 0, oldPtr = 0, bytes = 0;
        cpu->readGuestMemory(esp + 8, &flags, 4);
        cpu->readGuestMemory(esp + 12, &oldPtr, 4);
        cpu->readGuestMemory(esp + 16, &bytes, 4);
        uint32_t newPtr = allocGuest(bytes);
        if (newPtr != 0) {
            if ((flags & 0x8u) && bytes > 0) {
                std::vector<uint8_t> zeros(bytes, 0);
                cpu->writeGuestMemory(newPtr, zeros.data(), bytes);
            }
            if (oldPtr != 0) {
                auto it = m_allocSizes.find(oldPtr);
                if (it != m_allocSizes.end() && it->second > 0 && bytes > 0) {
                    uint32_t copySz = std::min<uint32_t>(it->second, bytes);
                    std::vector<uint8_t> tmp(copySz);
                    cpu->readGuestMemory(oldPtr, tmp.data(), copySz);
                    cpu->writeGuestMemory(newPtr, tmp.data(), copySz);
                }
                freeGuest(oldPtr);
            }
        }
        cpu->writeRegister(X86Reg::EAX, newPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 20); // stdcall (4 args)
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "kernel32.dll!HeapSize") {
        uint32_t ptr = 0;
        cpu->readGuestMemory(esp + 12, &ptr, 4);
        uint32_t sz = 0;
        auto it = m_allocSizes.find(ptr);
        if (it != m_allocSizes.end()) sz = it->second;
        cpu->writeRegister(X86Reg::EAX, sz);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall (3 args)
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "kernel32.dll!CreateMutexA" || sym == "kernel32.dll!CreateMutexW" ||
        sym == "kernel32.dll!OpenMutexA" || sym == "kernel32.dll!OpenMutexW" ||
        sym == "kernel32.dll!OpenEventA" || sym == "kernel32.dll!OpenEventW") {
        static uint32_t s_syncHandle = 0x55000100u;
        cpu->writeRegister(X86Reg::EAX, s_syncHandle++);
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall (3 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!CreateEventA" || sym == "kernel32.dll!CreateEventW" ||
        sym == "kernel32.dll!CreateSemaphoreA" || sym == "kernel32.dll!CreateSemaphoreW") {
        static uint32_t s_syncHandle4 = 0x56000100u;
        cpu->writeRegister(X86Reg::EAX, s_syncHandle4++);
        cpu->writeRegister(X86Reg::ESP, esp + 20); // stdcall (4 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!ReleaseMutex" || sym == "kernel32.dll!SetEvent" ||
        sym == "kernel32.dll!ResetEvent" || sym == "kernel32.dll!PulseEvent") {
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!ReleaseSemaphore") {
        uint32_t prevPtr = 0;
        cpu->readGuestMemory(esp + 12, &prevPtr, 4);
        if (prevPtr != 0) { uint32_t prev = 1u; cpu->writeGuestMemory(prevPtr, &prev, 4); }
        cpu->writeRegister(X86Reg::EAX, 1u); // TRUE
        cpu->writeRegister(X86Reg::ESP, esp + 16); // stdcall (3 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!WaitForSingleObject") {
        cpu->writeRegister(X86Reg::EAX, 0u); // WAIT_OBJECT_0
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!WaitForMultipleObjects") {
        cpu->writeRegister(X86Reg::EAX, 0u); // WAIT_OBJECT_0
        cpu->writeRegister(X86Reg::ESP, esp + 20); // stdcall (4 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "winmm.dll!timeGetTime") {
        auto ms = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        cpu->writeRegister(X86Reg::EAX, ms);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall (0 args)
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "winmm.dll!timeBeginPeriod" || sym == "winmm.dll!timeEndPeriod") {
        cpu->writeRegister(X86Reg::EAX, 0u); // TIMERR_NOERROR
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "winmm.dll!timeGetDevCaps") {
        uint32_t ptc = 0, cbtc = 0;
        cpu->readGuestMemory(esp + 4, &ptc, 4);
        cpu->readGuestMemory(esp + 8, &cbtc, 4);
        if (ptc != 0 && cbtc >= 8) {
            uint32_t caps[2] = { 1u, 1000000u };
            cpu->writeGuestMemory(ptc, caps, sizeof(caps));
        }
        cpu->writeRegister(X86Reg::EAX, 0u); // TIMERR_NOERROR
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "winmm.dll!timeGetSystemTime") {
        uint32_t pmmt = 0, cbmmt = 0;
        cpu->readGuestMemory(esp + 4, &pmmt, 4);
        cpu->readGuestMemory(esp + 8, &cbmmt, 4);
        if (pmmt != 0 && cbmmt >= 8) {
            auto ms = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
            uint32_t mmtime[2] = { 1u, ms }; // TIME_MS = 1
            cpu->writeGuestMemory(pmmt, mmtime, sizeof(mmtime));
        }
        cpu->writeRegister(X86Reg::EAX, 0u); // TIMERR_NOERROR
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    static uint32_t s_fpControl = 0x0009001Fu;
    if (sym == "msvcr100.dll!_controlfp_s") {
        uint32_t curPtr = 0, newCtrl = 0, mask = 0;
        cpu->readGuestMemory(esp + 4, &curPtr, 4);
        cpu->readGuestMemory(esp + 8, &newCtrl, 4);
        cpu->readGuestMemory(esp + 12, &mask, 4);
        s_fpControl = (s_fpControl & ~mask) | (newCtrl & mask);
        if (curPtr != 0) cpu->writeGuestMemory(curPtr, &s_fpControl, 4);
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_controlfp" || sym == "msvcr100.dll!_control87") {
        uint32_t newCtrl = 0, mask = 0;
        cpu->readGuestMemory(esp + 4, &newCtrl, 4);
        cpu->readGuestMemory(esp + 8, &mask, 4);
        s_fpControl = (s_fpControl & ~mask) | (newCtrl & mask);
        cpu->writeRegister(X86Reg::EAX, s_fpControl);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__control87_2") {
        uint32_t newCtrl = 0, mask = 0, x86Ptr = 0, ssePtr = 0;
        cpu->readGuestMemory(esp + 4, &newCtrl, 4);
        cpu->readGuestMemory(esp + 8, &mask, 4);
        cpu->readGuestMemory(esp + 12, &x86Ptr, 4);
        cpu->readGuestMemory(esp + 16, &ssePtr, 4);
        s_fpControl = (s_fpControl & ~mask) | (newCtrl & mask);
        if (x86Ptr != 0) cpu->writeGuestMemory(x86Ptr, &s_fpControl, 4);
        if (ssePtr != 0) cpu->writeGuestMemory(ssePtr, &s_fpControl, 4);
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_clearfp" || sym == "msvcr100.dll!_statusfp") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_fpreset") {
        s_fpControl = 0x0009001Fu;
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__getmainargs") {
        uint32_t pArgc = 0, pArgv = 0, pEnv = 0;
        cpu->readGuestMemory(esp + 4, &pArgc, 4);
        cpu->readGuestMemory(esp + 8, &pArgv, 4);
        cpu->readGuestMemory(esp + 12, &pEnv, 4);
        const char arg0[] = "Stronghold3.exe";
        uint32_t arg0Ptr = allocGuest(sizeof(arg0));
        if (arg0Ptr != 0) cpu->writeGuestMemory(arg0Ptr, arg0, sizeof(arg0));
        uint32_t argvArr[2] = { arg0Ptr, 0u };
        uint32_t argvPtr = allocGuest(sizeof(argvArr));
        if (argvPtr != 0) cpu->writeGuestMemory(argvPtr, argvArr, sizeof(argvArr));
        uint32_t envArr[1] = { 0u };
        uint32_t envPtr = allocGuest(sizeof(envArr));
        if (envPtr != 0) cpu->writeGuestMemory(envPtr, envArr, sizeof(envArr));
        uint32_t argcVal = 1u;
        if (pArgc != 0) cpu->writeGuestMemory(pArgc, &argcVal, 4);
        if (pArgv != 0) cpu->writeGuestMemory(pArgv, &argvPtr, 4);
        if (pEnv  != 0) cpu->writeGuestMemory(pEnv,  &envPtr,  4);
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__wgetmainargs") {
        uint32_t pArgc = 0, pArgv = 0, pEnv = 0;
        cpu->readGuestMemory(esp + 4, &pArgc, 4);
        cpu->readGuestMemory(esp + 8, &pArgv, 4);
        cpu->readGuestMemory(esp + 12, &pEnv, 4);
        const char16_t arg0[] = u"Stronghold3.exe";
        uint32_t arg0Ptr = allocGuest(sizeof(arg0));
        if (arg0Ptr != 0) cpu->writeGuestMemory(arg0Ptr, arg0, sizeof(arg0));
        uint32_t argvArr[2] = { arg0Ptr, 0u };
        uint32_t argvPtr = allocGuest(sizeof(argvArr));
        if (argvPtr != 0) cpu->writeGuestMemory(argvPtr, argvArr, sizeof(argvArr));
        uint32_t envArr[1] = { 0u };
        uint32_t envPtr = allocGuest(sizeof(envArr));
        if (envPtr != 0) cpu->writeGuestMemory(envPtr, envArr, sizeof(envArr));
        uint32_t argcVal = 1u;
        if (pArgc != 0) cpu->writeGuestMemory(pArgc, &argcVal, 4);
        if (pArgv != 0) cpu->writeGuestMemory(pArgv, &argvPtr, 4);
        if (pEnv  != 0) cpu->writeGuestMemory(pEnv,  &envPtr,  4);
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__p___argc") {
        uint32_t ptr = allocGuest(4);
        uint32_t argcVal = 1u;
        if (ptr != 0) cpu->writeGuestMemory(ptr, &argcVal, 4);
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__p___argv" || sym == "msvcr100.dll!__p___wargv") {
        uint32_t arg0Ptr = 0;
        if (sym == "msvcr100.dll!__p___wargv") {
            const char16_t arg0[] = u"Stronghold3.exe";
            arg0Ptr = allocGuest(sizeof(arg0));
            if (arg0Ptr != 0) cpu->writeGuestMemory(arg0Ptr, arg0, sizeof(arg0));
        } else {
            const char arg0[] = "Stronghold3.exe";
            arg0Ptr = allocGuest(sizeof(arg0));
            if (arg0Ptr != 0) cpu->writeGuestMemory(arg0Ptr, arg0, sizeof(arg0));
        }
        uint32_t argvArr[2] = { arg0Ptr, 0u };
        uint32_t argvPtr = allocGuest(sizeof(argvArr));
        if (argvPtr != 0) cpu->writeGuestMemory(argvPtr, argvArr, sizeof(argvArr));
        uint32_t ppArgv = allocGuest(4);
        if (ppArgv != 0) cpu->writeGuestMemory(ppArgv, &argvPtr, 4);
        cpu->writeRegister(X86Reg::EAX, ppArgv);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__p__environ" || sym == "msvcr100.dll!__p__wenviron") {
        uint32_t envArr[1] = { 0u };
        uint32_t envPtr = allocGuest(sizeof(envArr));
        if (envPtr != 0) cpu->writeGuestMemory(envPtr, envArr, sizeof(envArr));
        uint32_t ppEnv = allocGuest(4);
        if (ppEnv != 0) cpu->writeGuestMemory(ppEnv, &envPtr, 4);
        cpu->writeRegister(X86Reg::EAX, ppEnv);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!FindWindowA" || sym == "dynamic!FindWindowA") {
        uint32_t pCls = 0, pWnd = 0;
        cpu->readGuestMemory(esp + 4, &pCls, 4);
        cpu->readGuestMemory(esp + 8, &pWnd, 4);
        char cls[48] = {}, wnd[48] = {};
        for (int i = 0; i < 47 && pCls >= 0x10000u; ++i) { char c = 0; cpu->readGuestMemory(pCls + i, &c, 1); if (c == 0) break; cls[i] = c; }
        for (int i = 0; i < 47 && pWnd >= 0x10000u; ++i) { char c = 0; cpu->readGuestMemory(pWnd + i, &c, 1); if (c == 0) break; wnd[i] = c; }
        cpu->writeRegister(X86Reg::EAX, 0u); // NULL
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall (2 args)
        outNextEip = returnAddr;
        char fbuf[160];
        snprintf(fbuf, sizeof(fbuf), "%s(\"%s\",\"%s\")->0", sym.c_str(), cls, wnd);
        if (m_handledLog.size() < 4096) m_handledLog.push_back(fbuf);
        return true;
    }

    if (sym == "user32.dll!FindWindowW" || sym == "dynamic!FindWindowW") {
        cpu->writeRegister(X86Reg::EAX, 0u); // NULL
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!FindWindowExA" || sym == "dynamic!FindWindowExA" ||
        sym == "user32.dll!FindWindowExW" || sym == "dynamic!FindWindowExW") {
        cpu->writeRegister(X86Reg::EAX, 0u); // NULL
        cpu->writeRegister(X86Reg::ESP, esp + 20); // stdcall (4 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetConsoleWindow" || sym == "dynamic!GetConsoleWindow") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall (0 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!AttachConsole" || sym == "dynamic!AttachConsole") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!AllocConsole" || sym == "dynamic!AllocConsole" ||
        sym == "kernel32.dll!FreeConsole" || sym == "dynamic!FreeConsole") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall (0 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!CheckRemoteDebuggerPresent" || sym == "dynamic!CheckRemoteDebuggerPresent") {
        uint32_t pRes = 0;
        cpu->readGuestMemory(esp + 8, &pRes, 4);
        if (pRes != 0) { uint32_t zero = 0u; cpu->writeGuestMemory(pRes, &zero, 4); }
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!MessageBoxW" || sym == "user32.dll!MessageBoxExW" ||
        sym == "dynamic!MessageBoxW" || sym == "dynamic!MessageBoxExW") {
        bool isEx = (sym.find("ExW") != std::string::npos);
        uint32_t pTxt = 0, pCap = 0, uType = 0;
        cpu->readGuestMemory(esp + 8, &pTxt, 4);
        cpu->readGuestMemory(esp + 12, &pCap, 4);
        cpu->readGuestMemory(esp + 16, &uType, 4);
        auto readWStr = [&](uint32_t ptr, int maxChars) {
            std::string s;
            if (ptr < 0x10000u) return s;
            for (int i = 0; i < maxChars; ++i) {
                uint16_t wc = 0;
                cpu->readGuestMemory(ptr + i * 2, &wc, 2);
                if (wc == 0) break;
                if (wc == 10u || wc == 13u) s.push_back(32);
                else if (wc < 0x80u) s.push_back(static_cast<char>(wc));
                else if (wc < 0x800u) {
                    s.push_back(static_cast<char>(0xC0u | (wc >> 6)));
                    s.push_back(static_cast<char>(0x80u | (wc & 0x3Fu)));
                } else {
                    s.push_back(static_cast<char>(0xE0u | (wc >> 12)));
                    s.push_back(static_cast<char>(0x80u | ((wc >> 6) & 0x3Fu)));
                    s.push_back(static_cast<char>(0x80u | (wc & 0x3Fu)));
                }
            }
            return s;
        };
        std::string txt = readWStr(pTxt, 240);
        std::string cap = readWStr(pCap, 120);
        char mbuf[512];
        snprintf(mbuf, sizeof(mbuf), "MSGBOX_W[%s]: %s (type=0x%X)", cap.c_str(), txt.c_str(), uType);
        m_lastMsgBox = mbuf;
        m_handledLog.push_back(mbuf);
        cpu->writeRegister(X86Reg::EAX, 1u); // IDOK
        cpu->writeRegister(X86Reg::ESP, esp + (isEx ? 24u : 20u)); // stdcall
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "user32.dll!MessageBoxA" || sym == "user32.dll!MessageBoxExA" ||
        sym == "dynamic!MessageBoxA" || sym == "dynamic!MessageBoxExA") {
        bool isEx = (sym.find("ExA") != std::string::npos);
        uint32_t pTxt = 0, pCap = 0, uType = 0;
        cpu->readGuestMemory(esp + 8, &pTxt, 4);
        cpu->readGuestMemory(esp + 12, &pCap, 4);
        cpu->readGuestMemory(esp + 16, &uType, 4);
        std::string txt = (pTxt >= 0x10000u) ? readCStr(pTxt, 240) : "";
        std::string cap = (pCap >= 0x10000u) ? readCStr(pCap, 120) : "";
        char mbuf[512];
        snprintf(mbuf, sizeof(mbuf), "MSGBOX_A[%s]: %s (type=0x%X)", cap.c_str(), txt.c_str(), uType);
        m_lastMsgBox = mbuf;
        m_handledLog.push_back(mbuf);
        cpu->writeRegister(X86Reg::EAX, 1u); // IDOK
        cpu->writeRegister(X86Reg::ESP, esp + (isEx ? 24u : 20u)); // stdcall
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "msvcr100.dll!__RTDynamicCast") {
        uint32_t inptr = 0, srcType = 0, targetType = 0, isRef = 0;
        int32_t vfDelta = 0;
        cpu->readGuestMemory(esp + 4,  &inptr,      4);
        cpu->readGuestMemory(esp + 8,  &vfDelta,    4);
        cpu->readGuestMemory(esp + 12, &srcType,    4);
        cpu->readGuestMemory(esp + 16, &targetType, 4);
        cpu->readGuestMemory(esp + 20, &isRef,      4);
        (void)srcType; (void)isRef;
        uint32_t result = 0;
        if (inptr >= 0x10000u && targetType >= 0x10000u) {
            std::string targetName = readCStr(targetType + 8, 256);
            uint32_t adjPtr = inptr - static_cast<uint32_t>(vfDelta);
            uint32_t vftable = 0;
            if (adjPtr >= 0x10000u) cpu->readGuestMemory(adjPtr, &vftable, 4);
            uint32_t pCol = 0;
            if (vftable >= 0x10004u) cpu->readGuestMemory(vftable - 4, &pCol, 4);
            if (pCol >= 0x10000u) {
                uint32_t col[5] = {};
                cpu->readGuestMemory(pCol, col, sizeof(col));
                uint32_t vtblOffset = col[1];
                uint32_t cdOffset   = col[2];
                uint32_t colTD      = col[3];
                uint32_t pChd       = col[4];
                uint32_t completeObj = adjPtr - vtblOffset;
                if (cdOffset != 0 && adjPtr >= cdOffset + 4) {
                    int32_t cdDisp = 0;
                    cpu->readGuestMemory(adjPtr - cdOffset, &cdDisp, 4);
                    completeObj -= static_cast<uint32_t>(cdDisp);
                }
                if (colTD == targetType || (colTD >= 0x10000u && !targetName.empty() && readCStr(colTD + 8, 256) == targetName)) {
                    result = completeObj;
                } else if (pChd >= 0x10000u) {
                    uint32_t chd[4] = {};
                    cpu->readGuestMemory(pChd, chd, sizeof(chd));
                    uint32_t numBases = chd[2];
                    uint32_t pBaseArr = chd[3];
                    if (numBases > 256u) numBases = 256u;
                    if (pBaseArr >= 0x10000u) {
                        for (uint32_t bi = 0; bi < numBases; ++bi) {
                            uint32_t pBcd = 0;
                            cpu->readGuestMemory(pBaseArr + bi * 4, &pBcd, 4);
                            if (pBcd < 0x10000u) continue;
                            uint32_t bcd[6] = {};
                            cpu->readGuestMemory(pBcd, bcd, sizeof(bcd));
                            uint32_t baseTD = bcd[0];
                            if (baseTD == targetType || (baseTD >= 0x10000u && !targetName.empty() && readCStr(baseTD + 8, 256) == targetName)) {
                                int32_t mdisp = static_cast<int32_t>(bcd[2]);
                                int32_t pdisp = static_cast<int32_t>(bcd[3]);
                                int32_t vdisp = static_cast<int32_t>(bcd[4]);
                                int32_t off = 0;
                                if (pdisp >= 0) {
                                    uint32_t vbtable = 0;
                                    cpu->readGuestMemory(completeObj + static_cast<uint32_t>(pdisp), &vbtable, 4);
                                    int32_t vboff = 0;
                                    if (vbtable >= 0x10000u) {
                                        cpu->readGuestMemory(vbtable + static_cast<uint32_t>(vdisp), &vboff, 4);
                                    }
                                    off = pdisp + vboff;
                                }
                                off += mdisp;
                                result = completeObj + static_cast<uint32_t>(off);
                                break;
                            }
                        }
                    }
                }
            }
        }
        cpu->writeRegister(X86Reg::EAX, result);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "msvcr100.dll!__RTCastToVoid") {
        uint32_t inptr = 0;
        cpu->readGuestMemory(esp + 4, &inptr, 4);
        uint32_t result = 0;
        if (inptr >= 0x10000u) {
            uint32_t vftable = 0, pCol = 0;
            cpu->readGuestMemory(inptr, &vftable, 4);
            if (vftable >= 0x10004u) cpu->readGuestMemory(vftable - 4, &pCol, 4);
            if (pCol >= 0x10000u) {
                uint32_t col[3] = {};
                cpu->readGuestMemory(pCol, col, sizeof(col));
                result = inptr - col[1];
                if (col[2] != 0 && inptr >= col[2] + 4) {
                    int32_t cdDisp = 0;
                    cpu->readGuestMemory(inptr - col[2], &cdDisp, 4);
                    result -= static_cast<uint32_t>(cdDisp);
                }
            }
        }
        cpu->writeRegister(X86Reg::EAX, result);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "msvcr100.dll!__RTtypeid") {
        uint32_t inptr = 0;
        cpu->readGuestMemory(esp + 4, &inptr, 4);
        uint32_t result = 0;
        if (inptr >= 0x10000u) {
            uint32_t vftable = 0, pCol = 0;
            cpu->readGuestMemory(inptr, &vftable, 4);
            if (vftable >= 0x10004u) cpu->readGuestMemory(vftable - 4, &pCol, 4);
            if (pCol >= 0x10000u) cpu->readGuestMemory(pCol + 12, &result, 4);
        }
        cpu->writeRegister(X86Reg::EAX, result);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        return true;
    }

    if (sym == "kernel32.dll!CreateThread") {
        uint32_t startAddr = 0, param = 0, flags = 0, pTid = 0;
        cpu->readGuestMemory(esp + 12, &startAddr, 4);
        cpu->readGuestMemory(esp + 16, &param, 4);
        cpu->readGuestMemory(esp + 20, &flags, 4);
        cpu->readGuestMemory(esp + 24, &pTid, 4);
        (void)startAddr; (void)param; (void)flags;
        static uint32_t s_threadHandle = 0x57000100u;
        static uint32_t s_threadId = 2u;
        uint32_t tid = s_threadId++;
        uint32_t hThread = s_threadHandle++;
        if (pTid >= 0x10000u) cpu->writeGuestMemory(pTid, &tid, 4);
        cpu->writeRegister(X86Reg::EAX, hThread);
        cpu->writeRegister(X86Reg::ESP, esp + 28); // stdcall (6 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_beginthreadex") {
        uint32_t pTid = 0;
        cpu->readGuestMemory(esp + 24, &pTid, 4);
        static uint32_t s_crtThreadHandle = 0x57100100u;
        static uint32_t s_crtThreadId = 100u;
        uint32_t tid = s_crtThreadId++;
        uint32_t hThread = s_crtThreadHandle++;
        if (pTid >= 0x10000u) cpu->writeGuestMemory(pTid, &tid, 4);
        cpu->writeRegister(X86Reg::EAX, hThread);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_beginthread") {
        static uint32_t s_crtThreadHandle2 = 0x57200100u;
        cpu->writeRegister(X86Reg::EAX, s_crtThreadHandle2++);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_endthreadex" || sym == "msvcr100.dll!_endthread") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!ResumeThread" || sym == "kernel32.dll!SuspendThread" ||
        sym == "kernel32.dll!GetThreadPriority") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 8); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!SetThreadPriority" || sym == "kernel32.dll!SetThreadAffinityMask" ||
        sym == "kernel32.dll!TerminateThread") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!SetThreadIdealProcessor") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!GetExitCodeThread") {
        uint32_t pCode = 0;
        cpu->readGuestMemory(esp + 8, &pCode, 4);
        if (pCode >= 0x10000u) { uint32_t z = 0u; cpu->writeGuestMemory(pCode, &z, 4); }
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 12); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "kernel32.dll!SwitchToThread") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // stdcall (0 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_setjmp3" || sym == "msvcr100.dll!_setjmp") {
        uint32_t envPtr = 0;
        cpu->readGuestMemory(esp + 4, &envPtr, 4);
        if (envPtr >= 0x10000u) {
            uint32_t jb[16] = {};
            jb[0] = cpu->readRegister(X86Reg::EBP);
            jb[1] = cpu->readRegister(X86Reg::EBX);
            jb[2] = cpu->readRegister(X86Reg::EDI);
            jb[3] = cpu->readRegister(X86Reg::ESI);
            jb[4] = esp + 4u;
            jb[5] = returnAddr;
            uint32_t seh = 0xFFFFFFFFu;
            cpu->readGuestMemory(0x7ffdf000u, &seh, 4);
            jb[6] = seh;
            jb[7] = 0xFFFFFFFFu;
            jb[8] = 0x56433230u; // VC20
            cpu->writeGuestMemory(envPtr, jb, sizeof(jb));
        }
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!longjmp") {
        uint32_t envPtr = 0, val = 0;
        cpu->readGuestMemory(esp + 4, &envPtr, 4);
        cpu->readGuestMemory(esp + 8, &val, 4);
        if (envPtr >= 0x10000u) {
            uint32_t jb[9] = {};
            cpu->readGuestMemory(envPtr, jb, sizeof(jb));
            cpu->writeRegister(X86Reg::EBP, jb[0]);
            cpu->writeRegister(X86Reg::EBX, jb[1]);
            cpu->writeRegister(X86Reg::EDI, jb[2]);
            cpu->writeRegister(X86Reg::ESI, jb[3]);
            cpu->writeRegister(X86Reg::ESP, jb[4]);
            if (jb[6] != 0u) cpu->writeGuestMemory(0x7ffdf000u, &jb[6], 4);
            cpu->writeRegister(X86Reg::EAX, (val == 0u) ? 1u : val);
            outNextEip = jb[5];
            logSym(sym);
            return true;
        }
        return false;
    }

    if (sym == "msvcr100.dll!localeconv") {
        static uint32_t s_lconv = 0;
        uint32_t chkPtr = 0;
        if (s_lconv != 0u) cpu->readGuestMemory(s_lconv, &chkPtr, 4);
        if (s_lconv == 0u || chkPtr < 0x10000u) {
            const char dotA[] = ".";
            const char empA[] = "";
            const char16_t dotW[] = u".";
            const char16_t empW[] = u"";
            uint32_t pDotA = allocGuest(sizeof(dotA));
            uint32_t pEmpA = allocGuest(sizeof(empA));
            uint32_t pDotW = allocGuest(sizeof(dotW));
            uint32_t pEmpW = allocGuest(sizeof(empW));
            if (pDotA != 0u) cpu->writeGuestMemory(pDotA, dotA, sizeof(dotA));
            if (pEmpA != 0u) cpu->writeGuestMemory(pEmpA, empA, sizeof(empA));
            if (pDotW != 0u) cpu->writeGuestMemory(pDotW, dotW, sizeof(dotW));
            if (pEmpW != 0u) cpu->writeGuestMemory(pEmpW, empW, sizeof(empW));
            s_lconv = allocGuest(96);
            if (s_lconv != 0u) {
                uint32_t ptrs[10] = { pDotA, pEmpA, pEmpA, pEmpA, pEmpA, pEmpA, pEmpA, pEmpA, pEmpA, pEmpA };
                uint8_t flags[8] = { 127, 127, 127, 127, 127, 127, 127, 127 };
                uint32_t wptrs[10] = { pDotW, pEmpW, pEmpW, pEmpW, pEmpW, pEmpW, pEmpW, pEmpW, pEmpW, pEmpW };
                cpu->writeGuestMemory(s_lconv,      ptrs,  sizeof(ptrs));
                cpu->writeGuestMemory(s_lconv + 40, flags, sizeof(flags));
                cpu->writeGuestMemory(s_lconv + 48, wptrs, sizeof(wptrs));
            }
        }
        cpu->writeRegister(X86Reg::EAX, s_lconv);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strcoll") {
        uint32_t s1 = 0, s2 = 0;
        cpu->readGuestMemory(esp + 4, &s1, 4);
        cpu->readGuestMemory(esp + 8, &s2, 4);
        int32_t diff = 0;
        if (s1 >= 0x10000u && s2 >= 0x10000u) {
            for (uint32_t i = 0; i < 4096u; ++i) {
                uint8_t c1 = 0, c2 = 0;
                cpu->readGuestMemory(s1 + i, &c1, 1);
                cpu->readGuestMemory(s2 + i, &c2, 1);
                if (c1 != c2 || c1 == 0u) { diff = static_cast<int32_t>(c1) - static_cast<int32_t>(c2); break; }
            }
        }
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(diff));
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strpbrk") {
        uint32_t s1 = 0, s2 = 0;
        cpu->readGuestMemory(esp + 4, &s1, 4);
        cpu->readGuestMemory(esp + 8, &s2, 4);
        uint32_t found = 0u;
        if (s1 >= 0x10000u && s2 >= 0x10000u) {
            std::string accept = readCStr(s2, 256);
            for (uint32_t i = 0; i < 65536u; ++i) {
                char c = 0;
                cpu->readGuestMemory(s1 + i, &c, 1);
                if (c == 0) break;
                if (accept.find(c) != std::string::npos) { found = s1 + i; break; }
            }
        }
        cpu->writeRegister(X86Reg::EAX, found);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strspn" || sym == "msvcr100.dll!strcspn") {
        bool isSpn = (sym == "msvcr100.dll!strspn");
        uint32_t s1 = 0, s2 = 0;
        cpu->readGuestMemory(esp + 4, &s1, 4);
        cpu->readGuestMemory(esp + 8, &s2, 4);
        uint32_t cnt = 0u;
        if (s1 >= 0x10000u && s2 >= 0x10000u) {
            std::string charset = readCStr(s2, 256);
            for (uint32_t i = 0; i < 65536u; ++i) {
                char c = 0;
                cpu->readGuestMemory(s1 + i, &c, 1);
                if (c == 0) break;
                bool inSet = (charset.find(c) != std::string::npos);
                if (isSpn ? !inSet : inSet) break;
                ++cnt;
            }
        }
        cpu->writeRegister(X86Reg::EAX, cnt);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strerror") {
        static uint32_t s_errStr = 0;
        uint8_t chk = 0;
        if (s_errStr != 0u) cpu->readGuestMemory(s_errStr, &chk, 1);
        if (s_errStr == 0u || chk != 0x4Eu) {
            const char msg[] = "No error";
            s_errStr = allocGuest(sizeof(msg));
            if (s_errStr != 0u) cpu->writeGuestMemory(s_errStr, msg, sizeof(msg));
        }
        cpu->writeRegister(X86Reg::EAX, s_errStr);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!getenv") {
        uint32_t namePtr = 0;
        cpu->readGuestMemory(esp + 4, &namePtr, 4);
        std::string varName = (namePtr >= 0x10000u) ? readCStr(namePtr, 128) : "";
        uint32_t res = 0u;
        if (varName == "TEMP" || varName == "TMP" || varName == "USERPROFILE" ||
            varName == "APPDATA" || varName == "LOCALAPPDATA") {
            static uint32_t s_envPath = 0u;
            uint8_t chk = 0;
            if (s_envPath != 0u) cpu->readGuestMemory(s_envPath, &chk, 1);
            if (s_envPath == 0u || chk != 0x43u) {
                const char p[] = "C:\\Stronghold3";
                s_envPath = allocGuest(sizeof(p));
                if (s_envPath != 0u) cpu->writeGuestMemory(s_envPath, p, sizeof(p));
            }
            res = s_envPath;
        }
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_wgetenv") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!getenv_s") {
        uint32_t pRet = 0, bufPtr = 0, bufSz = 0;
        cpu->readGuestMemory(esp + 4,  &pRet,   4);
        cpu->readGuestMemory(esp + 8,  &bufPtr, 4);
        cpu->readGuestMemory(esp + 12, &bufSz,  4);
        if (pRet >= 0x10000u) { uint32_t z = 0u; cpu->writeGuestMemory(pRet, &z, 4); }
        if (bufPtr >= 0x10000u && bufSz > 0u) { uint8_t nul = 0u; cpu->writeGuestMemory(bufPtr, &nul, 1); }
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_putenv" || sym == "msvcr100.dll!_putenv_s" || sym == "msvcr100.dll!system") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!setlocale") {
        static uint32_t s_cLoc = 0u;
        uint8_t chk = 0;
        if (s_cLoc != 0u) cpu->readGuestMemory(s_cLoc, &chk, 1);
        if (s_cLoc == 0u || chk != 0x43u) {
            const char loc[] = "C";
            s_cLoc = allocGuest(sizeof(loc));
            if (s_cLoc != 0u) cpu->writeGuestMemory(s_cLoc, loc, sizeof(loc));
        }
        cpu->writeRegister(X86Reg::EAX, s_cLoc);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_wsetlocale") {
        static uint32_t s_wcLoc = 0u;
        uint16_t chk = 0;
        if (s_wcLoc != 0u) cpu->readGuestMemory(s_wcLoc, &chk, 2);
        if (s_wcLoc == 0u || chk != 0x0043u) {
            const char16_t loc[] = u"C";
            s_wcLoc = allocGuest(sizeof(loc));
            if (s_wcLoc != 0u) cpu->writeGuestMemory(s_wcLoc, loc, sizeof(loc));
        }
        cpu->writeRegister(X86Reg::EAX, s_wcLoc);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!clock") {
        static uint64_t s_clockStartMs = 0;
        struct timespec ts{};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t nowMs = static_cast<uint64_t>(ts.tv_sec) * 1000ULL + static_cast<uint64_t>(ts.tv_nsec / 1000000L);
        if (s_clockStartMs == 0) s_clockStartMs = nowMs;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(nowMs - s_clockStartMs));
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!tmpnam") {
        uint32_t bufPtr = 0;
        cpu->readGuestMemory(esp + 4, &bufPtr, 4);
        const char tmpPath[] = "C:\\Stronghold3\\tmp0.tmp";
        uint32_t dst = bufPtr;
        if (dst < 0x10000u) {
            static uint32_t s_tmpBuf = 0u;
            uint8_t chk = 0;
            if (s_tmpBuf != 0u) cpu->readGuestMemory(s_tmpBuf, &chk, 1);
            if (s_tmpBuf == 0u || chk != 0x43u) s_tmpBuf = allocGuest(64);
            dst = s_tmpBuf;
        }
        if (dst >= 0x10000u) cpu->writeGuestMemory(dst, tmpPath, sizeof(tmpPath));
        cpu->writeRegister(X86Reg::EAX, dst);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strxfrm") {
        uint32_t dst = 0, src = 0, n = 0;
        cpu->readGuestMemory(esp + 4,  &dst, 4);
        cpu->readGuestMemory(esp + 8,  &src, 4);
        cpu->readGuestMemory(esp + 12, &n,   4);
        std::string s = (src >= 0x10000u) ? readCStr(src, 4096) : "";
        if (dst >= 0x10000u && n > 0u) {
            uint32_t cp = (s.size() < n - 1u) ? static_cast<uint32_t>(s.size()) : (n - 1u);
            if (cp > 0u) cpu->writeGuestMemory(dst, s.c_str(), cp);
            uint8_t nul = 0u;
            cpu->writeGuestMemory(dst + cp, &nul, 1);
        }
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(s.size()));
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!__daylight" || sym == "msvcr100.dll!__timezone" ||
        sym == "msvcr100.dll!__dstbias" || sym == "msvcr100.dll!__tzname") {
        static uint32_t s_tzBlock = 0u;
        uint32_t magic = 0u;
        if (s_tzBlock != 0u) cpu->readGuestMemory(s_tzBlock, &magic, 4);
        if (s_tzBlock == 0u || magic != 0x545A424Cu) {
            s_tzBlock = allocGuest(64);
            if (s_tzBlock != 0u) {
                uint32_t hdr[6] = { 0x545A424Cu, 0u, 0u, 0u, s_tzBlock + 24u, s_tzBlock + 28u };
                const char utc[] = "UTC";
                cpu->writeGuestMemory(s_tzBlock,      hdr, sizeof(hdr));
                cpu->writeGuestMemory(s_tzBlock + 24, utc, sizeof(utc));
                cpu->writeGuestMemory(s_tzBlock + 28, utc, sizeof(utc));
            }
        }
        uint32_t ptr = s_tzBlock + 4u;
        if (sym == "msvcr100.dll!__timezone") ptr = s_tzBlock + 8u;
        else if (sym == "msvcr100.dll!__dstbias") ptr = s_tzBlock + 12u;
        else if (sym == "msvcr100.dll!__tzname") ptr = s_tzBlock + 16u;
        cpu->writeRegister(X86Reg::EAX, ptr);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_tzset") {
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_get_daylight" || sym == "msvcr100.dll!_get_timezone" ||
        sym == "msvcr100.dll!_get_dstbias") {
        uint32_t pOut = 0u;
        cpu->readGuestMemory(esp + 4, &pOut, 4);
        if (pOut >= 0x10000u) { int32_t z = 0; cpu->writeGuestMemory(pOut, &z, 4); }
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_get_tzname") {
        uint32_t pRet = 0u, bufPtr = 0u, bufSz = 0u;
        cpu->readGuestMemory(esp + 4,  &pRet,   4);
        cpu->readGuestMemory(esp + 8,  &bufPtr, 4);
        cpu->readGuestMemory(esp + 12, &bufSz,  4);
        const char utc[] = "UTC";
        if (pRet >= 0x10000u) { uint32_t len = 4u; cpu->writeGuestMemory(pRet, &len, 4); }
        if (bufPtr >= 0x10000u && bufSz >= 4u) cpu->writeGuestMemory(bufPtr, utc, 4);
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_ftime32" || sym == "msvcr100.dll!_ftime64" ||
        sym == "msvcr100.dll!_ftime32_s" || sym == "msvcr100.dll!_ftime64_s") {
        bool is64 = (sym.find("64") != std::string::npos);
        uint32_t pTb = 0u;
        cpu->readGuestMemory(esp + 4, &pTb, 4);
        struct timespec ts{};
        clock_gettime(CLOCK_REALTIME, &ts);
        uint16_t ms = static_cast<uint16_t>(ts.tv_nsec / 1000000L);
        int16_t zero16 = 0;
        if (pTb >= 0x10000u) {
            if (is64) {
                int64_t sec64 = static_cast<int64_t>(ts.tv_sec);
                cpu->writeGuestMemory(pTb,      &sec64,  8);
                cpu->writeGuestMemory(pTb + 8,  &ms,     2);
                cpu->writeGuestMemory(pTb + 10, &zero16, 2);
                cpu->writeGuestMemory(pTb + 12, &zero16, 2);
            } else {
                int32_t sec32 = static_cast<int32_t>(ts.tv_sec);
                cpu->writeGuestMemory(pTb,      &sec32,  4);
                cpu->writeGuestMemory(pTb + 4,  &ms,     2);
                cpu->writeGuestMemory(pTb + 6,  &zero16, 2);
                cpu->writeGuestMemory(pTb + 8,  &zero16, 2);
            }
        }
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_localtime32" || sym == "msvcr100.dll!_localtime64" ||
        sym == "msvcr100.dll!_gmtime32" || sym == "msvcr100.dll!_gmtime64") {
        bool is64 = (sym.find("64") != std::string::npos);
        bool isGm = (sym.find("gmtime") != std::string::npos);
        uint32_t pTime = 0u;
        cpu->readGuestMemory(esp + 4, &pTime, 4);
        time_t tv = 0;
        if (pTime >= 0x10000u) {
            if (is64) { int64_t t64 = 0; cpu->readGuestMemory(pTime, &t64, 8); tv = static_cast<time_t>(t64); }
            else      { int32_t t32 = 0; cpu->readGuestMemory(pTime, &t32, 4); tv = static_cast<time_t>(t32); }
        }
        struct tm tmv{};
        if (isGm) gmtime_r(&tv, &tmv); else localtime_r(&tv, &tmv);
        static uint32_t s_tmBuf = 0u;
        uint32_t magic = 0u;
        if (s_tmBuf != 0u) cpu->readGuestMemory(s_tmBuf + 36, &magic, 4);
        if (s_tmBuf == 0u || magic != 0x544D4246u) {
            s_tmBuf = allocGuest(40);
            if (s_tmBuf != 0u) { uint32_t m = 0x544D4246u; cpu->writeGuestMemory(s_tmBuf + 36, &m, 4); }
        }
        if (s_tmBuf != 0u) {
            int32_t f[9] = { tmv.tm_sec, tmv.tm_min, tmv.tm_hour, tmv.tm_mday, tmv.tm_mon, tmv.tm_year, tmv.tm_wday, tmv.tm_yday, tmv.tm_isdst };
            cpu->writeGuestMemory(s_tmBuf, f, sizeof(f));
        }
        cpu->writeRegister(X86Reg::EAX, s_tmBuf);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_localtime32_s" || sym == "msvcr100.dll!_localtime64_s" ||
        sym == "msvcr100.dll!_gmtime32_s" || sym == "msvcr100.dll!_gmtime64_s") {
        bool is64 = (sym.find("64") != std::string::npos);
        bool isGm = (sym.find("gmtime") != std::string::npos);
        uint32_t pTm = 0u, pTime = 0u;
        cpu->readGuestMemory(esp + 4, &pTm,   4);
        cpu->readGuestMemory(esp + 8, &pTime, 4);
        time_t tv = 0;
        if (pTime >= 0x10000u) {
            if (is64) { int64_t t64 = 0; cpu->readGuestMemory(pTime, &t64, 8); tv = static_cast<time_t>(t64); }
            else      { int32_t t32 = 0; cpu->readGuestMemory(pTime, &t32, 4); tv = static_cast<time_t>(t32); }
        }
        struct tm tmv{};
        if (isGm) gmtime_r(&tv, &tmv); else localtime_r(&tv, &tmv);
        if (pTm >= 0x10000u) {
            int32_t f[9] = { tmv.tm_sec, tmv.tm_min, tmv.tm_hour, tmv.tm_mday, tmv.tm_mon, tmv.tm_year, tmv.tm_wday, tmv.tm_yday, tmv.tm_isdst };
            cpu->writeGuestMemory(pTm, f, sizeof(f));
        }
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_mktime32" || sym == "msvcr100.dll!_mktime64") {
        bool is64 = (sym.find("64") != std::string::npos);
        uint32_t pTm = 0u;
        cpu->readGuestMemory(esp + 4, &pTm, 4);
        int64_t res = -1;
        if (pTm >= 0x10000u) {
            int32_t f[9] = {};
            cpu->readGuestMemory(pTm, f, sizeof(f));
            struct tm tmv{};
            tmv.tm_sec = f[0]; tmv.tm_min = f[1]; tmv.tm_hour = f[2];
            tmv.tm_mday = f[3]; tmv.tm_mon = f[4]; tmv.tm_year = f[5];
            tmv.tm_wday = f[6]; tmv.tm_yday = f[7]; tmv.tm_isdst = f[8];
            res = static_cast<int64_t>(mktime(&tmv));
            int32_t nf[9] = { tmv.tm_sec, tmv.tm_min, tmv.tm_hour, tmv.tm_mday, tmv.tm_mon, tmv.tm_year, tmv.tm_wday, tmv.tm_yday, tmv.tm_isdst };
            cpu->writeGuestMemory(pTm, nf, sizeof(nf));
        }
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(res & 0xFFFFFFFFULL));
        if (is64) cpu->writeRegister(X86Reg::EDX, static_cast<uint32_t>((static_cast<uint64_t>(res) >> 32) & 0xFFFFFFFFULL));
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!strftime") {
        uint32_t dstPtr = 0u, maxSz = 0u, fmtPtr = 0u, pTm = 0u;
        cpu->readGuestMemory(esp + 4,  &dstPtr, 4);
        cpu->readGuestMemory(esp + 8,  &maxSz,  4);
        cpu->readGuestMemory(esp + 12, &fmtPtr, 4);
        cpu->readGuestMemory(esp + 16, &pTm,    4);
        uint32_t written = 0u;
        if (dstPtr >= 0x10000u && maxSz > 0u && fmtPtr >= 0x10000u && pTm >= 0x10000u) {
            std::string fmt = readCStr(fmtPtr, 256);
            int32_t f[9] = {};
            cpu->readGuestMemory(pTm, f, sizeof(f));
            struct tm tmv{};
            tmv.tm_sec = f[0]; tmv.tm_min = f[1]; tmv.tm_hour = f[2];
            tmv.tm_mday = f[3]; tmv.tm_mon = f[4]; tmv.tm_year = f[5];
            tmv.tm_wday = f[6]; tmv.tm_yday = f[7]; tmv.tm_isdst = f[8];
            uint32_t cap = (maxSz > 4096u) ? 4096u : maxSz;
            std::vector<char> outBuf(cap, 0);
            size_t n = strftime(outBuf.data(), cap, fmt.c_str(), &tmv);
            written = static_cast<uint32_t>(n);
            cpu->writeGuestMemory(dstPtr, outBuf.data(), (n + 1 <= cap) ? (n + 1) : cap);
        }
        cpu->writeRegister(X86Reg::EAX, written);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetKeyboardLayout") {
        cpu->writeRegister(X86Reg::EAX, 0x04090409u); // en-US HKL
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetKeyboardLayoutNameA" || sym == "user32.dll!GetKeyboardLayoutNameW") {
        bool isW = (sym.back() == 87);
        uint32_t bufPtr = 0u;
        cpu->readGuestMemory(esp + 4, &bufPtr, 4);
        if (bufPtr >= 0x10000u) {
            if (isW) { const char16_t s[] = u"00000409"; cpu->writeGuestMemory(bufPtr, s, sizeof(s)); }
            else     { const char s[] = "00000409";      cpu->writeGuestMemory(bufPtr, s, sizeof(s)); }
        }
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetKeyboardType") {
        uint32_t flag = 0u;
        cpu->readGuestMemory(esp + 4, &flag, 4);
        uint32_t res = (flag == 0u) ? 4u : ((flag == 2u) ? 12u : 0u);
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!MapVirtualKeyA" || sym == "user32.dll!MapVirtualKeyW" ||
        sym == "user32.dll!MapVirtualKeyExA" || sym == "user32.dll!MapVirtualKeyExW") {
        bool isEx = (sym.find("Ex") != std::string::npos);
        uint32_t uCode = 0u;
        cpu->readGuestMemory(esp + 4, &uCode, 4);
        cpu->writeRegister(X86Reg::EAX, uCode);
        cpu->writeRegister(X86Reg::ESP, esp + (isEx ? 16u : 12u)); // stdcall
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetKeyNameTextA" || sym == "user32.dll!GetKeyNameTextW") {
        bool isW = (sym.back() == 87);
        uint32_t bufPtr = 0u, cch = 0u;
        cpu->readGuestMemory(esp + 8,  &bufPtr, 4);
        cpu->readGuestMemory(esp + 12, &cch,    4);
        uint32_t len = 0u;
        if (bufPtr >= 0x10000u && cch > 1u) {
            if (isW) { const char16_t s[] = u"Key"; len = (cch > 3u) ? 3u : (cch - 1u); cpu->writeGuestMemory(bufPtr, s, (len + 1u) * 2u); }
            else     { const char s[] = "Key";      len = (cch > 3u) ? 3u : (cch - 1u); cpu->writeGuestMemory(bufPtr, s, len + 1u); }
        }
        cpu->writeRegister(X86Reg::EAX, len);
        cpu->writeRegister(X86Reg::ESP, esp + 16u); // stdcall (3 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetKeyboardState") {
        uint32_t pState = 0u;
        cpu->readGuestMemory(esp + 4, &pState, 4);
        if (pState >= 0x10000u) { uint8_t z[256] = {}; cpu->writeGuestMemory(pState, z, sizeof(z)); }
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetKeyState" || sym == "user32.dll!GetAsyncKeyState") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!VkKeyScanA" || sym == "user32.dll!VkKeyScanW" ||
        sym == "user32.dll!VkKeyScanExA" || sym == "user32.dll!VkKeyScanExW") {
        bool isEx = (sym.find("Ex") != std::string::npos);
        uint32_t ch = 0u;
        cpu->readGuestMemory(esp + 4, &ch, 4);
        cpu->writeRegister(X86Reg::EAX, ch & 0xFFu);
        cpu->writeRegister(X86Reg::ESP, esp + (isEx ? 12u : 8u)); // stdcall
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!ToAscii") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 24u); // stdcall (5 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!ToAsciiEx" || sym == "user32.dll!ToUnicode") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 28u); // stdcall (6 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!ToUnicodeEx") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 32u); // stdcall (7 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    static std::unordered_map<int32_t, uint32_t> s_classLongs;
    static uint32_t s_curCursor = 0x00010001u;
    if (sym == "user32.dll!SetClassLongA" || sym == "user32.dll!SetClassLongW" ||
        sym == "dynamic!SetClassLongA" || sym == "dynamic!SetClassLongW") {
        int32_t idx = 0; uint32_t val = 0u;
        cpu->readGuestMemory(esp + 8, &idx, 4); cpu->readGuestMemory(esp + 12, &val, 4);
        uint32_t prev = s_classLongs.count(idx) ? s_classLongs[idx] : (idx == -12 ? s_curCursor : 0u);
        s_classLongs[idx] = val; if (idx == -12) s_curCursor = val;
        cpu->writeRegister(X86Reg::EAX, prev); cpu->writeRegister(X86Reg::ESP, esp + 16u);
        outNextEip = returnAddr; logSym(sym); return true;
    }

    if (sym == "user32.dll!GetClassLongA" || sym == "user32.dll!GetClassLongW" ||
        sym == "dynamic!GetClassLongA" || sym == "dynamic!GetClassLongW") {
        int32_t idx = 0; cpu->readGuestMemory(esp + 8, &idx, 4);
        uint32_t val = s_classLongs.count(idx) ? s_classLongs[idx] : (idx == -12 ? s_curCursor : 0u);
        cpu->writeRegister(X86Reg::EAX, val); cpu->writeRegister(X86Reg::ESP, esp + 12u);
        outNextEip = returnAddr; logSym(sym); return true;
    }

    if (sym == "user32.dll!GetCursor" || sym == "dynamic!GetCursor") {
        cpu->writeRegister(X86Reg::EAX, s_curCursor); cpu->writeRegister(X86Reg::ESP, esp + 4u);
        outNextEip = returnAddr; logSym(sym); return true;
    }

    if (sym == "user32.dll!GetClipCursor" || sym == "dynamic!GetClipCursor") {
        uint32_t pr = 0u; cpu->readGuestMemory(esp + 4, &pr, 4);
        if (pr >= 0x10000u) { int32_t r[4] = {0, 0, 1280, 720}; cpu->writeGuestMemory(pr, r, 16); }
        cpu->writeRegister(X86Reg::EAX, 1u); cpu->writeRegister(X86Reg::ESP, esp + 8u);
        outNextEip = returnAddr; logSym(sym); return true;
    }

    if (sym == "user32.dll!LoadCursorFromFileA" || sym == "user32.dll!LoadCursorFromFileW" ||
        sym == "user32.dll!CreateIconIndirect") {
        cpu->writeRegister(X86Reg::EAX, 0x00010002u); cpu->writeRegister(X86Reg::ESP, esp + 8u);
        outNextEip = returnAddr; logSym(sym); return true;
    }

    if (sym == "msvcr100.dll!_lock_file" || sym == "msvcr100.dll!_unlock_file" ||
        sym == "msvcr100.dll!clearerr" || sym == "msvcr100.dll!clearerr_s") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4u);
        outNextEip = returnAddr; logSym(sym); return true;
    }

    if (sym == "msvcr100.dll!setvbuf" || sym == "dynamic!setvbuf") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4u);
        outNextEip = returnAddr; logSym(sym); return true;
    }

    if (sym == "dinput8.dll!DirectInput8Create" || sym == "dynamic!DirectInput8Create") {
        uint32_t riid = 0u, ppvOut = 0u;
        cpu->readGuestMemory(esp + 12, &riid,   4);
        cpu->readGuestMemory(esp + 16, &ppvOut, 4);
        if (riid >= 0x10000u) { uint32_t d1 = 0u; cpu->readGuestMemory(riid, &d1, 4); s_di8IsWide = (d1 == 0xBF798031u); }
        static uint32_t s_di8Obj = 0u;
        uint32_t existingVt = 0u;
        if (s_di8Obj != 0u) cpu->readGuestMemory(s_di8Obj, &existingVt, 4);
        if (s_di8Obj == 0u || existingVt == 0u) {
            uint32_t vtAddr = allocGuest(16 * 4);
            uint32_t objAddr = allocGuest(16);
            if (vtAddr != 0u && objAddr != 0u) {
                uint32_t vt[16];
                for (uint32_t si = 0; si < 16; ++si) {
                    vt[si] = 0x7000B000u + si * 4u;
                    char vname[64];
                    snprintf(vname, sizeof(vname), "IDirectInput8::vslot[%u]", si);
                    m_reverseMap[vt[si]] = vname;
                }
                cpu->writeGuestMemory(vtAddr, vt, sizeof(vt));
                cpu->writeGuestMemory(objAddr, &vtAddr, 4);
                s_di8Obj = objAddr;
            }
        }
        if (ppvOut >= 0x10000u) cpu->writeGuestMemory(ppvOut, &s_di8Obj, 4);
        cpu->writeRegister(X86Reg::EAX, 0u); // DI_OK
        cpu->writeRegister(X86Reg::ESP, esp + 24u); // stdcall (5 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "d3d9.dll!Direct3DCreate9" || sym == "dynamic!Direct3DCreate9") { if (m_d3dTrace.size()<512u) m_d3dTrace+="Create9 "; m_postD3dActive=true; if (m_d3d9Bridge.handleDirect3DCreate9(cpu,esp,returnAddr,outNextEip,[this](uint32_t s){return allocGuest(s);},[this](uint32_t a,const std::string& n){m_reverseMap[a]=n;})) { logSym(sym); return true; } }
    if (sym == "d3d9.dll!Direct3DCreate9" || sym == "dynamic!Direct3DCreate9") {
        if (m_d3dTrace.size() < 200u) m_d3dTrace += "Create9 ";
        m_postD3dActive = true;
        static uint32_t s_d3d9Obj = 0u;
        uint32_t existingVt = 0u;
        if (s_d3d9Obj != 0u) cpu->readGuestMemory(s_d3d9Obj, &existingVt, 4);
        if (s_d3d9Obj == 0u || existingVt == 0u) {
            uint32_t vtAddr = allocGuest(17 * 4);
            uint32_t objAddr = allocGuest(16);
            if (vtAddr != 0u && objAddr != 0u) {
                uint32_t vt[17];
                for (uint32_t si = 0; si < 17; ++si) {
                    vt[si] = 0x7000C000u + si * 4u;
                    char vname[64];
                    snprintf(vname, sizeof(vname), "IDirect3D9::vslot[%u]", si);
                    m_reverseMap[vt[si]] = vname;
                }
                cpu->writeGuestMemory(vtAddr, vt, sizeof(vt));
                cpu->writeGuestMemory(objAddr, &vtAddr, 4);
                s_d3d9Obj = objAddr;
            }
        }
        cpu->writeRegister(X86Reg::EAX, s_d3d9Obj);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg: SDKVersion)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "ws2_32.dll!#115" || sym == "ws2_32.dll!WSAStartup") {
        uint32_t wVer = 0u, pWsa = 0u;
        cpu->readGuestMemory(esp + 4, &wVer, 4);
        cpu->readGuestMemory(esp + 8, &pWsa, 4);
        if (pWsa >= 0x10000u) {
            std::vector<uint8_t> wsa(400, 0u);
            uint16_t ver = static_cast<uint16_t>(wVer & 0xFFFFu);
            if (ver == 0u) ver = 0x0202u;
            memcpy(wsa.data(),     &ver, 2);
            memcpy(wsa.data() + 2, &ver, 2);
            cpu->writeGuestMemory(pWsa, wsa.data(), wsa.size());
        }
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 12u); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "ws2_32.dll!#116" || sym == "ws2_32.dll!WSACleanup" ||
        sym == "ws2_32.dll!#111" || sym == "ws2_32.dll!WSAGetLastError") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // stdcall (0 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "ws2_32.dll!#112" || sym == "ws2_32.dll!WSASetLastError") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!LoadIconA" || sym == "user32.dll!LoadIconW" ||
        sym == "user32.dll!LoadCursorA" || sym == "user32.dll!LoadCursorW") {
        uint32_t h = (sym.find("Cursor") != std::string::npos) ? 0x00030001u : 0x00020001u;
        cpu->writeRegister(X86Reg::EAX, h);
        cpu->writeRegister(X86Reg::ESP, esp + 12u); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!LoadImageA" || sym == "user32.dll!LoadImageW") {
        cpu->writeRegister(X86Reg::EAX, 0x00020002u);
        cpu->writeRegister(X86Reg::ESP, esp + 28u); // stdcall (6 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!SetCursor") {
        cpu->writeRegister(X86Reg::EAX, 0x00030001u);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!ShowCursor") {
        static int32_t s_curVis = 0;
        uint32_t bShow = 0u;
        cpu->readGuestMemory(esp + 4, &bShow, 4);
        s_curVis += (bShow != 0u) ? 1 : -1;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(s_curVis));
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetCursorPos") {
        uint32_t lpPt = 0u;
        cpu->readGuestMemory(esp + 4, &lpPt, 4);
        if (lpPt >= 0x10000u) { int32_t pt[2] = { 640, 360 }; cpu->writeGuestMemory(lpPt, pt, 8); }
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!SetCursorPos" || sym == "user32.dll!UnregisterClassA" ||
        sym == "user32.dll!UnregisterClassW" || sym == "user32.dll!ShowWindow" ||
        sym == "user32.dll!SetWindowTextA" || sym == "user32.dll!SetWindowTextW" ||
        sym == "user32.dll!ClientToScreen" || sym == "user32.dll!ScreenToClient" ||
        sym == "user32.dll!ReleaseDC" || sym == "user32.dll!ValidateRect" ||
        sym == "user32.dll!KillTimer" || sym == "user32.dll!EnableWindow") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 12u); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!RegisterClassA" || sym == "user32.dll!RegisterClassW" ||
        sym == "user32.dll!RegisterClassExA" || sym == "user32.dll!RegisterClassExW") {
        cpu->writeRegister(X86Reg::EAX, 0xC001u);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetClassInfoA" || sym == "user32.dll!GetClassInfoW" ||
        sym == "user32.dll!GetClassInfoExA" || sym == "user32.dll!GetClassInfoExW") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 16u); // stdcall (3 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!CreateWindowExA" || sym == "user32.dll!CreateWindowExW") {
        uint32_t dwStyle = 0u, dwExStyle = 0u;
        cpu->readGuestMemory(esp + 4,  &dwExStyle, 4);
        cpu->readGuestMemory(esp + 16, &dwStyle,   4);
        m_winLongs[-16] = dwStyle;   // GWL_STYLE
        m_winLongs[-20] = dwExStyle; // GWL_EXSTYLE
        cpu->writeRegister(X86Reg::EAX, 0x000A0001u); // fake HWND
        cpu->writeRegister(X86Reg::ESP, esp + 52u); // stdcall (12 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!DestroyWindow" || sym == "user32.dll!ClipCursor" ||
        sym == "user32.dll!UpdateWindow" || sym == "user32.dll!SetForegroundWindow" ||
        sym == "user32.dll!BringWindowToTop") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!IsWindow" || sym == "user32.dll!IsWindowVisible" ||
        sym == "user32.dll!IsWindowEnabled") {
        uint32_t hwnd = 0u;
        cpu->readGuestMemory(esp + 4, &hwnd, 4);
        cpu->writeRegister(X86Reg::EAX, (hwnd != 0u) ? 1u : 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!IsIconic" || sym == "user32.dll!IsZoomed" ||
        sym == "user32.dll!SetCapture" || sym == "user32.dll!TranslateMessage" ||
        sym == "user32.dll!DispatchMessageA" || sym == "user32.dll!DispatchMessageW" ||
        sym == "user32.dll!PostQuitMessage") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!SetFocus" || sym == "user32.dll!SetActiveWindow") {
        cpu->writeRegister(X86Reg::EAX, 0x000A0001u);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetForegroundWindow" || sym == "user32.dll!GetActiveWindow" ||
        sym == "user32.dll!GetFocus" || sym == "user32.dll!GetDesktopWindow" ||
        sym == "user32.dll!GetCapture" || sym == "user32.dll!ReleaseCapture") {
        uint32_t res = 0x000A0001u;
        if (sym == "user32.dll!GetDesktopWindow") res = 0x00010010u;
        else if (sym == "user32.dll!GetCapture") res = 0u;
        else if (sym == "user32.dll!ReleaseCapture") res = 1u;
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // stdcall (0 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetWindowTextA" || sym == "user32.dll!GetWindowTextW") {
        bool isW = (sym.back() == 87);
        uint32_t bufPtr = 0u, maxCnt = 0u;
        cpu->readGuestMemory(esp + 8,  &bufPtr, 4);
        cpu->readGuestMemory(esp + 12, &maxCnt, 4);
        uint32_t len = 0u;
        if (bufPtr >= 0x10000u && maxCnt > 1u) {
            const char title[] = "Stronghold 3";
            len = (12u < maxCnt - 1u) ? 12u : (maxCnt - 1u);
            if (isW) {
                std::vector<uint16_t> w(len + 1u, 0u);
                for (uint32_t i = 0; i < len; ++i) w[i] = static_cast<uint16_t>(title[i]);
                cpu->writeGuestMemory(bufPtr, w.data(), (len + 1u) * 2u);
            } else {
                cpu->writeGuestMemory(bufPtr, title, len);
                uint8_t nul = 0u; cpu->writeGuestMemory(bufPtr + len, &nul, 1);
            }
        }
        cpu->writeRegister(X86Reg::EAX, len);
        cpu->writeRegister(X86Reg::ESP, esp + 16u); // stdcall (3 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!AdjustWindowRect" || sym == "user32.dll!InvalidateRect") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 16u); // stdcall (3 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!AdjustWindowRectEx") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 20u); // stdcall (4 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetClientRect" || sym == "user32.dll!GetWindowRect") {
        uint32_t pRect = 0u;
        cpu->readGuestMemory(esp + 8, &pRect, 4);
        if (pRect >= 0x10000u) {
            int32_t rc[4] = { 0, 0, 1280, 720 };
            cpu->writeGuestMemory(pRect, rc, sizeof(rc));
        }
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 12u); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!SetWindowPos") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 32u); // stdcall (7 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!MoveWindow") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 28u); // stdcall (6 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetSystemMetrics") {
        int32_t idx = 0;
        cpu->readGuestMemory(esp + 4, &idx, 4);
        int32_t val = 0;
        if (idx == 0 || idx == 16 || idx == 78) val = 1280;
        else if (idx == 1 || idx == 17 || idx == 79) val = 720;
        else if (idx == 80 || idx == 19) val = 1;
        else if (idx == 43) val = 3;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(val));
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!SystemParametersInfoA" || sym == "user32.dll!SystemParametersInfoW") {
        uint32_t uiAct = 0u, pvParam = 0u;
        cpu->readGuestMemory(esp + 4,  &uiAct,   4);
        cpu->readGuestMemory(esp + 12, &pvParam, 4);
        if (uiAct == 48u && pvParam >= 0x10000u) { // SPI_GETWORKAREA
            int32_t rc[4] = { 0, 0, 1280, 720 };
            cpu->writeGuestMemory(pvParam, rc, sizeof(rc));
        }
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 20u); // stdcall (4 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!MonitorFromWindow" || sym == "user32.dll!MonitorFromRect") {
        cpu->writeRegister(X86Reg::EAX, 0x00010001u);
        cpu->writeRegister(X86Reg::ESP, esp + 12u); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!MonitorFromPoint") {
        cpu->writeRegister(X86Reg::EAX, 0x00010001u);
        cpu->writeRegister(X86Reg::ESP, esp + 16u); // stdcall (POINT=2 DWORDs + dwFlags)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetMonitorInfoA" || sym == "user32.dll!GetMonitorInfoW") {
        bool isW = (sym.back() == 87);
        uint32_t lpmi = 0u;
        cpu->readGuestMemory(esp + 8, &lpmi, 4);
        if (lpmi >= 0x10000u) {
            uint32_t cb = 0u;
            cpu->readGuestMemory(lpmi, &cb, 4);
            int32_t rc[4] = { 0, 0, 1280, 720 };
            uint32_t flags = 1u;
            cpu->writeGuestMemory(lpmi + 4,  rc, sizeof(rc));
            cpu->writeGuestMemory(lpmi + 20, rc, sizeof(rc));
            cpu->writeGuestMemory(lpmi + 36, &flags, 4);
            if (!isW && cb >= 72u) { const char d[] = "\\\\.\\DISPLAY1"; cpu->writeGuestMemory(lpmi + 40, d, sizeof(d)); }
            else if (isW && cb >= 104u) { const char16_t d[] = u"\\\\.\\DISPLAY1"; cpu->writeGuestMemory(lpmi + 40, d, sizeof(d)); }
        }
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 12u); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!ChangeDisplaySettingsA" || sym == "user32.dll!ChangeDisplaySettingsW") {
        cpu->writeRegister(X86Reg::EAX, 0u); // DISP_CHANGE_SUCCESSFUL
        cpu->writeRegister(X86Reg::ESP, esp + 12u); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!ChangeDisplaySettingsExA" || sym == "user32.dll!ChangeDisplaySettingsExW") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 24u); // stdcall (5 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!EnumDisplaySettingsW" || sym == "dynamic!EnumDisplaySettingsW") {
        uint32_t iModeNum = 0u, lpDevMode = 0u;
        cpu->readGuestMemory(esp + 8,  &iModeNum,  4);
        cpu->readGuestMemory(esp + 12, &lpDevMode, 4);
        uint32_t retVal = 0u;
        if (iModeNum == 0u || iModeNum == 0xFFFFFFFFu || iModeNum == 0xFFFFFFFEu) {
            if (lpDevMode >= 0x10000u) {
                uint32_t dmFields = 0x005C0000u, bpp = 32u, w = 1280u, h = 720u, flags = 0u, freq = 60u;
                cpu->writeGuestMemory(lpDevMode + 72,  &dmFields, 4);
                cpu->writeGuestMemory(lpDevMode + 168, &bpp,      4);
                cpu->writeGuestMemory(lpDevMode + 172, &w,        4);
                cpu->writeGuestMemory(lpDevMode + 176, &h,        4);
                cpu->writeGuestMemory(lpDevMode + 180, &flags,    4);
                cpu->writeGuestMemory(lpDevMode + 184, &freq,     4);
            }
            retVal = 1u;
        }
        cpu->writeRegister(X86Reg::EAX, retVal);
        cpu->writeRegister(X86Reg::ESP, esp + 16u); // stdcall (3 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetWindowLongA" || sym == "user32.dll!GetWindowLongW") {
        int32_t idx = 0;
        cpu->readGuestMemory(esp + 8, &idx, 4);
        uint32_t val = 0u;
        auto it = m_winLongs.find(idx);
        if (it != m_winLongs.end()) val = it->second;
        else if (idx == -16) val = 0x10CF0000u;
        cpu->writeRegister(X86Reg::EAX, val);
        cpu->writeRegister(X86Reg::ESP, esp + 12u); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!SetWindowLongA" || sym == "user32.dll!SetWindowLongW") {
        int32_t idx = 0; uint32_t newVal = 0u;
        cpu->readGuestMemory(esp + 8,  &idx,    4);
        cpu->readGuestMemory(esp + 12, &newVal, 4);
        uint32_t oldVal = m_winLongs[idx];
        m_winLongs[idx] = newVal;
        cpu->writeRegister(X86Reg::EAX, oldVal);
        cpu->writeRegister(X86Reg::ESP, esp + 16u); // stdcall (3 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!PeekMessageA" || sym == "user32.dll!PeekMessageW") {
        cpu->writeRegister(X86Reg::EAX, 0u);
        cpu->writeRegister(X86Reg::ESP, esp + 24u); // stdcall (5 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!DefWindowProcA" || sym == "user32.dll!DefWindowProcW" ||
        sym == "user32.dll!SendMessageA" || sym == "user32.dll!SendMessageW" ||
        sym == "user32.dll!PostMessageA" || sym == "user32.dll!PostMessageW" ||
        sym == "user32.dll!SetTimer") {
        uint32_t res = (sym.find("PostMessage") != std::string::npos || sym == "user32.dll!SetTimer") ? 1u : 0u;
        cpu->writeRegister(X86Reg::EAX, res);
        cpu->writeRegister(X86Reg::ESP, esp + 20u); // stdcall (4 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetWindowThreadProcessId") {
        uint32_t pPid = 0u;
        cpu->readGuestMemory(esp + 8, &pPid, 4);
        if (pPid >= 0x10000u) { uint32_t pid = 0x1234u; cpu->writeGuestMemory(pPid, &pid, 4); }
        cpu->writeRegister(X86Reg::EAX, 0x1234u);
        cpu->writeRegister(X86Reg::ESP, esp + 12u); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "user32.dll!GetDC" || sym == "gdi32.dll!CreateCompatibleDC") {
        cpu->writeRegister(X86Reg::EAX, (sym == "user32.dll!GetDC") ? 0x000D0001u : 0x000D0002u);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "gdi32.dll!GetStockObject") {
        cpu->writeRegister(X86Reg::EAX, 0x00050001u);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "gdi32.dll!DeleteObject" || sym == "gdi32.dll!DeleteDC") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 8u); // stdcall (1 arg)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "gdi32.dll!SelectObject") {
        cpu->writeRegister(X86Reg::EAX, 0x00050001u);
        cpu->writeRegister(X86Reg::ESP, esp + 12u); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "gdi32.dll!GetDeviceCaps") {
        int32_t idx = 0;
        cpu->readGuestMemory(esp + 8, &idx, 4);
        int32_t val = 0;
        if (idx == 8) val = 1280; else if (idx == 10) val = 720;
        else if (idx == 12) val = 32; else if (idx == 14) val = 1;
        else if (idx == 88 || idx == 90) val = 96; else if (idx == 116) val = 60;
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(val));
        cpu->writeRegister(X86Reg::ESP, esp + 12u); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "gdi32.dll!SetDeviceGammaRamp" || sym == "gdi32.dll!GetDeviceGammaRamp") {
        if (sym == "gdi32.dll!GetDeviceGammaRamp") {
            uint32_t pRamp = 0u;
            cpu->readGuestMemory(esp + 8, &pRamp, 4);
            if (pRamp >= 0x10000u) {
                std::vector<uint16_t> ramp(768, 0u);
                for (uint32_t i = 0; i < 256u; ++i) {
                    uint16_t v = static_cast<uint16_t>(i << 8);
                    ramp[i] = v; ramp[256 + i] = v; ramp[512 + i] = v;
                }
                cpu->writeGuestMemory(pRamp, ramp.data(), ramp.size() * 2u);
            }
        }
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 12u); // stdcall (2 args)
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_CIpow" || sym == "msvcr100.dll!_CIatan2" || sym == "msvcr100.dll!_CIfmod") {
        double top = cpu->popFpuDouble();
        double base = cpu->popFpuDouble();
        double res = 0.0;
        if (sym == "msvcr100.dll!_CIpow")        res = std::pow(base, top);
        else if (sym == "msvcr100.dll!_CIatan2") res = std::atan2(base, top);
        else                                     res = std::fmod(base, top);
        cpu->pushFpuDouble(res);
        cpu->writeRegister(X86Reg::ESP, esp + 4u);
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_CIsin" || sym == "msvcr100.dll!_CIcos" || sym == "msvcr100.dll!_CItan" ||
        sym == "msvcr100.dll!_CIsinh" || sym == "msvcr100.dll!_CIcosh" || sym == "msvcr100.dll!_CItanh" ||
        sym == "msvcr100.dll!_CIasin" || sym == "msvcr100.dll!_CIacos" || sym == "msvcr100.dll!_CIatan" ||
        sym == "msvcr100.dll!_CIsqrt" || sym == "msvcr100.dll!_CIexp" || sym == "msvcr100.dll!_CIlog" ||
        sym == "msvcr100.dll!_CIlog10") {
        double x = cpu->popFpuDouble();
        double res = 0.0;
        if (sym == "msvcr100.dll!_CIsin")        res = std::sin(x);
        else if (sym == "msvcr100.dll!_CIcos")   res = std::cos(x);
        else if (sym == "msvcr100.dll!_CItan")   res = std::tan(x);
        else if (sym == "msvcr100.dll!_CIsinh")  res = std::sinh(x);
        else if (sym == "msvcr100.dll!_CIcosh")  res = std::cosh(x);
        else if (sym == "msvcr100.dll!_CItanh")  res = std::tanh(x);
        else if (sym == "msvcr100.dll!_CIasin")  res = std::asin(x);
        else if (sym == "msvcr100.dll!_CIacos")  res = std::acos(x);
        else if (sym == "msvcr100.dll!_CIatan")  res = std::atan(x);
        else if (sym == "msvcr100.dll!_CIsqrt")  res = std::sqrt(x);
        else if (sym == "msvcr100.dll!_CIexp")   res = std::exp(x);
        else if (sym == "msvcr100.dll!_CIlog")   res = std::log(x);
        else                                     res = std::log10(x);
        cpu->pushFpuDouble(res);
        cpu->writeRegister(X86Reg::ESP, esp + 4u);
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!pow" || sym == "msvcr100.dll!atan2" ||
        sym == "msvcr100.dll!fmod" || sym == "msvcr100.dll!_hypot") {
        double a = 0.0, b = 0.0;
        cpu->readGuestMemory(esp + 4,  &a, 8);
        cpu->readGuestMemory(esp + 12, &b, 8);
        double res = 0.0;
        if (sym == "msvcr100.dll!pow")        res = std::pow(a, b);
        else if (sym == "msvcr100.dll!atan2") res = std::atan2(a, b);
        else if (sym == "msvcr100.dll!fmod")  res = std::fmod(a, b);
        else                                  res = std::hypot(a, b);
        cpu->pushFpuDouble(res);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!sin" || sym == "msvcr100.dll!cos" || sym == "msvcr100.dll!tan" ||
        sym == "msvcr100.dll!sinh" || sym == "msvcr100.dll!cosh" || sym == "msvcr100.dll!tanh" ||
        sym == "msvcr100.dll!asin" || sym == "msvcr100.dll!acos" || sym == "msvcr100.dll!atan" ||
        sym == "msvcr100.dll!sqrt" || sym == "msvcr100.dll!exp" || sym == "msvcr100.dll!log" ||
        sym == "msvcr100.dll!log10" || sym == "msvcr100.dll!floor" || sym == "msvcr100.dll!ceil" ||
        sym == "msvcr100.dll!fabs") {
        double x = 0.0;
        cpu->readGuestMemory(esp + 4, &x, 8);
        double res = 0.0;
        if (sym == "msvcr100.dll!sin")        res = std::sin(x);
        else if (sym == "msvcr100.dll!cos")   res = std::cos(x);
        else if (sym == "msvcr100.dll!tan")   res = std::tan(x);
        else if (sym == "msvcr100.dll!sinh")  res = std::sinh(x);
        else if (sym == "msvcr100.dll!cosh")  res = std::cosh(x);
        else if (sym == "msvcr100.dll!tanh")  res = std::tanh(x);
        else if (sym == "msvcr100.dll!asin")  res = std::asin(x);
        else if (sym == "msvcr100.dll!acos")  res = std::acos(x);
        else if (sym == "msvcr100.dll!atan")  res = std::atan(x);
        else if (sym == "msvcr100.dll!sqrt")  res = std::sqrt(x);
        else if (sym == "msvcr100.dll!exp")   res = std::exp(x);
        else if (sym == "msvcr100.dll!log")   res = std::log(x);
        else if (sym == "msvcr100.dll!log10") res = std::log10(x);
        else if (sym == "msvcr100.dll!floor") res = std::floor(x);
        else if (sym == "msvcr100.dll!ceil")  res = std::ceil(x);
        else                                  res = std::fabs(x);
        cpu->pushFpuDouble(res);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!ldexp") {
        double x = 0.0; int32_t e = 0;
        cpu->readGuestMemory(esp + 4,  &x, 8);
        cpu->readGuestMemory(esp + 12, &e, 4);
        cpu->pushFpuDouble(std::ldexp(x, e));
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!modf") {
        double x = 0.0; uint32_t pInt = 0u;
        cpu->readGuestMemory(esp + 4,  &x,    8);
        cpu->readGuestMemory(esp + 12, &pInt, 4);
        double ip = 0.0;
        double frac = std::modf(x, &ip);
        if (pInt >= 0x10000u) cpu->writeGuestMemory(pInt, &ip, 8);
        cpu->pushFpuDouble(frac);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!frexp") {
        double x = 0.0; uint32_t pExp = 0u;
        cpu->readGuestMemory(esp + 4,  &x,    8);
        cpu->readGuestMemory(esp + 12, &pExp, 4);
        int e = 0;
        double m = std::frexp(x, &e);
        if (pExp >= 0x10000u) { int32_t e32 = e; cpu->writeGuestMemory(pExp, &e32, 4); }
        cpu->pushFpuDouble(m);
        cpu->writeRegister(X86Reg::ESP, esp + 4u); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_ftol" || sym == "msvcr100.dll!_ftol2" || sym == "msvcr100.dll!_ftol2_sse") {
        double v = cpu->popFpuDouble();
        int64_t iv = static_cast<int64_t>(v);
        cpu->writeRegister(X86Reg::EAX, static_cast<uint32_t>(static_cast<uint64_t>(iv) & 0xFFFFFFFFULL));
        cpu->writeRegister(X86Reg::EDX, static_cast<uint32_t>((static_cast<uint64_t>(iv) >> 32) & 0xFFFFFFFFULL));
        cpu->writeRegister(X86Reg::ESP, esp + 4u);
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!___lc_codepage_func") {
        cpu->writeRegister(X86Reg::EAX, 0u); // C locale
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!___lc_handle_func") {
        uint32_t hPtr = allocGuest(24);
        if (hPtr != 0) {
            uint32_t zeros[6] = { 0, 0, 0, 0, 0, 0 };
            cpu->writeGuestMemory(hPtr, zeros, sizeof(zeros));
        }
        cpu->writeRegister(X86Reg::EAX, hPtr);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!___mb_cur_max_func") {
        cpu->writeRegister(X86Reg::EAX, 1u);
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    if (sym == "msvcr100.dll!_lock" || sym == "msvcr100.dll!_unlock") {
        cpu->writeRegister(X86Reg::ESP, esp + 4); // cdecl
        outNextEip = returnAddr;
        logSym(sym);
        return true;
    }

    return false; // Unimplemented Win32 API -> stop cleanly
}
