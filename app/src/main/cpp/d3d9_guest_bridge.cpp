#include "d3d9_guest_bridge.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <unordered_map>
#include <vector>
#ifdef SH3_HAS_DXVK
#define DXVK_NATIVE 1
#define NOMINMAX 1
#include <d3d9.h>
extern "C" void* dxvkAndroidGetWindowHandle();
#endif
namespace {
#pragma pack(push, 1)
struct GuestPP { uint32_t W,H,Fmt,Cnt,MS,MSQ,Swap,Hwnd; int32_t Win,AutoDS; uint32_t DSFmt,Flags,Hz,Int; };
struct GuestCP { uint32_t Adapter, DevType, hFocus, Flags; };
struct GuestLR { int32_t Pitch; uint32_t pBits; };
#pragma pack(pop)
constexpr uint32_t VT_D3D9=0x7000C000u, VT_DEV=0x7000C100u, VT_SURF=0x7000C300u, VT_TEX=0x7000C400u;
constexpr uint32_t VT_VB=0x7000C500u, VT_IB=0x7000C600u, VT_VDECL=0x7000C700u, VT_VS=0x7000C800u;
constexpr uint32_t VT_PS=0x7000C900u, VT_SWAP=0x7000CA00u, VT_SB=0x7000CB00u, VT_QUERY=0x7000CC00u, VT_CUBE=0x7000CD00u;
uint32_t primVerts(uint32_t t, uint32_t c) { return t==1?c : t==2?c*2 : t==3?c+1 : t==4?c*3 : c+2; }
bool isBC(uint32_t f) { return f==0x31545844u||f==0x32545844u||f==0x33545844u||f==0x34545844u||f==0x35545844u||f==0x31495441u||f==0x32495441u; }
bool readDxso(IX86CPU* cpu, uint32_t ptr, std::vector<uint32_t>& out) {
    if (ptr < 0x10000u) return false;
    out.clear(); uint32_t a = ptr;
    for (uint32_t n = 0; n < 65536u; ++n) {
        uint32_t t = 0; if (!cpu->readGuestMemory(a, &t, 4)) return false;
        out.push_back(t); a += 4; if (t == 0x0000FFFFu) return true;
        if ((t & 0xFFFFu) == 0xFFFEu) {
            uint32_t k = (t >> 16) & 0x7FFFu; if (n + k >= 65536u) return false;
            for (uint32_t i = 0; i < k; ++i, ++n, a += 4) { uint32_t ct = 0; if (!cpu->readGuestMemory(a, &ct, 4)) return false; out.push_back(ct); }
        }
    }
    return false;
}
}
struct D3D9GuestBridge::Impl {
#ifdef SH3_HAS_DXVK
    struct LockSt { uint32_t gBuf=0, gCap=0, sz=0, flg=0; void* host=nullptr; bool on=false; };
    IDirect3D9* d3d9=nullptr; uint32_t d3d9G=0; IDirect3DDevice9* dev=nullptr; uint32_t devG=0, devHr=0xFFFFFFFFu, devW=1280, devH=720, focusHwnd=0x000A0001u;
    std::unordered_map<uint32_t, uint32_t> vtMap; std::unordered_map<void*, uint32_t> p2g;
    std::unordered_map<uint32_t, IDirect3DSurface9*> gSurf; std::unordered_map<uint32_t, IDirect3DTexture9*> gTex;
    std::unordered_map<uint32_t, IDirect3DCubeTexture9*> gCube; std::unordered_map<uint32_t, IDirect3DBaseTexture9*> gBaseTex;
    std::unordered_map<uint32_t, IDirect3DVertexBuffer9*> gVB; std::unordered_map<uint32_t, IDirect3DIndexBuffer9*> gIB;
    std::unordered_map<uint32_t, IDirect3DVertexDeclaration9*> gVDecl; std::unordered_map<uint32_t, IDirect3DVertexShader9*> gVS;
    std::unordered_map<uint32_t, IDirect3DPixelShader9*> gPS; std::unordered_map<uint32_t, IDirect3DSwapChain9*> gSwap;
    std::unordered_map<uint32_t, IDirect3DStateBlock9*> gSB; std::unordered_map<uint32_t, IDirect3DQuery9*> gQuery;
    std::unordered_map<uint64_t, LockSt> locks;
    uint32_t cntTex=0, cntVB=0, cntIB=0, cntVS=0, cntPS=0, cntClear=0, cntDraw=0, cntPresent=0;
    ~Impl() {
        for (auto& k:gQuery) if(k.second) k.second->Release(); for (auto& k:gSB) if(k.second) k.second->Release();
        for (auto& k:gSwap) if(k.second) k.second->Release(); for (auto& k:gPS) if(k.second) k.second->Release();
        for (auto& k:gVS) if(k.second) k.second->Release(); for (auto& k:gVDecl) if(k.second) k.second->Release();
        for (auto& k:gIB) if(k.second) k.second->Release(); for (auto& k:gVB) if(k.second) k.second->Release();
        for (auto& k:gCube) if(k.second) k.second->Release(); for (auto& k:gTex) if(k.second) k.second->Release();
        for (auto& k:gSurf) if(k.second) k.second->Release(); if(dev) dev->Release(); if(d3d9) d3d9->Release();
    }
    uint32_t ensureVt(uint32_t base, uint32_t n, const char* nm, IX86CPU* cpu, const GuestAllocFn& ag, const RegisterSymFn& rs) {
        auto it = vtMap.find(base); if (it != vtMap.end()) return it->second;
        uint32_t a = ag(n * 4u); if (!a) return 0;
        std::vector<uint32_t> vt(n);
        for (uint32_t i = 0; i < n; ++i) { vt[i] = base + i * 4u; char b[96]; snprintf(b, sizeof(b), "%s::vslot[%u]", nm, i); rs(vt[i], b); }
        cpu->writeGuestMemory(a, vt.data(), n * 4u); return vtMap[base] = a;
    }
    template <typename T> uint32_t wrap(T* p, uint32_t vb, uint32_t n, const char* nm, std::unordered_map<uint32_t,T*>& m, IX86CPU* cpu, const GuestAllocFn& ag, const RegisterSymFn& rs) {
        if (!p) return 0; auto it = p2g.find(p); if (it != p2g.end()) return it->second;
        uint32_t vt = ensureVt(vb, n, nm, cpu, ag, rs), o = ag(16); if (!vt || !o) return 0;
        cpu->writeGuestMemory(o, &vt, 4); p2g[p] = o; m[o] = p; return o;
    }
    uint32_t wrapTex(IDirect3DTexture9* t, IX86CPU* cpu, const GuestAllocFn& ag, const RegisterSymFn& rs) {
        uint32_t g = wrap(t, VT_TEX, 22, "IDirect3DTexture9", gTex, cpu, ag, rs);
        if (g) { gBaseTex[g] = t; p2g[static_cast<IDirect3DBaseTexture9*>(t)] = g; } return g;
    }
    uint32_t wrapCube(IDirect3DCubeTexture9* t, IX86CPU* cpu, const GuestAllocFn& ag, const RegisterSymFn& rs) {
        uint32_t g = wrap(t, VT_CUBE, 22, "IDirect3DCubeTexture9", gCube, cpu, ag, rs);
        if (g) { gBaseTex[g] = t; p2g[static_cast<IDirect3DBaseTexture9*>(t)] = g; } return g;
    }
    bool rdRect(IX86CPU* cpu, uint32_t a, RECT& r) { if (a < 0x10000u) return false; int32_t v[4]; cpu->readGuestMemory(a, v, 16); r={v[0],v[1],v[2],v[3]}; return true; }
    uint32_t beginLock(uint64_t key, void* bits, uint32_t sz, uint32_t flg, IX86CPU* cpu, const GuestAllocFn& ag) {
        LockSt& st = locks[key]; uint32_t cap = std::max(sz, 64u);
        if (!st.gBuf || st.gCap < cap) { st.gBuf = ag(cap); st.gCap = st.gBuf ? cap : 0; }
        if (!st.gBuf) return 0; st.host = bits; st.sz = sz; st.flg = flg; st.on = true;
        if (bits && sz && !(flg & D3DLOCK_DISCARD)) cpu->writeGuestMemory(st.gBuf, bits, sz);
        return st.gBuf;
    }
    void endLock(uint64_t key, IX86CPU* cpu) {
        auto it = locks.find(key); if (it == locks.end() || !it->second.on) return;
        if (it->second.host && it->second.sz && !(it->second.flg & D3DLOCK_READONLY)) cpu->readGuestMemory(it->second.gBuf, it->second.host, it->second.sz);
        it->second.on = false; it->second.host = nullptr;
    }
    void fillPP(const GuestPP& g, D3DPRESENT_PARAMETERS& p) {
        memset(&p, 0, sizeof(p)); p.BackBufferWidth = g.W?g.W:1280; p.BackBufferHeight = g.H?g.H:720;
        p.BackBufferFormat = g.Fmt ? (D3DFORMAT)g.Fmt : D3DFMT_X8R8G8B8; p.BackBufferCount = g.Cnt?g.Cnt:1;
        p.MultiSampleType = (D3DMULTISAMPLE_TYPE)g.MS; p.MultiSampleQuality = g.MSQ;
        p.SwapEffect = g.Swap ? (D3DSWAPEFFECT)g.Swap : D3DSWAPEFFECT_DISCARD;
        p.hDeviceWindow = (HWND)dxvkAndroidGetWindowHandle(); p.Windowed = TRUE;
        p.EnableAutoDepthStencil = g.AutoDS?TRUE:FALSE; p.AutoDepthStencilFormat = (D3DFORMAT)g.DSFmt;
        p.Flags = g.Flags; p.PresentationInterval = g.Int ? g.Int : D3DPRESENT_INTERVAL_IMMEDIATE;
    }
    void savePP(const D3DPRESENT_PARAMETERS& p, uint32_t a, IX86CPU* cpu) {
        if (a < 0x10000u) return; GuestPP g{}; cpu->readGuestMemory(a, &g, sizeof(g));
        g.W=p.BackBufferWidth; g.H=p.BackBufferHeight; g.Fmt=(uint32_t)p.BackBufferFormat; g.Cnt=p.BackBufferCount;
        g.MS=(uint32_t)p.MultiSampleType; g.MSQ=p.MultiSampleQuality; g.Swap=(uint32_t)p.SwapEffect;
        g.AutoDS=p.EnableAutoDepthStencil?1:0; g.DSFmt=(uint32_t)p.AutoDepthStencilFormat; g.Flags=p.Flags;
        cpu->writeGuestMemory(a, &g, sizeof(g));
    }
    bool doQI(IUnknown* u, uint32_t self, IX86CPU* cpu, uint32_t esp, uint32_t retA, uint32_t& nxt) {
        uint32_t pId=0, ppv=0; cpu->readGuestMemory(esp+8,&pId,4); cpu->readGuestMemory(esp+12,&ppv,4);
        HRESULT hr = E_NOINTERFACE;
        if (u && pId >= 0x10000u && ppv >= 0x10000u) {
            GUID id{}; cpu->readGuestMemory(pId, &id, sizeof(id)); void* o = nullptr; hr = u->QueryInterface(id, &o);
            if (SUCCEEDED(hr)) {
                if (o == u) cpu->writeGuestMemory(ppv, &self, 4);
                else if (p2g.count(o)) cpu->writeGuestMemory(ppv, &p2g[o], 4);
                else { static_cast<IUnknown*>(o)->Release(); uint32_t z=0; cpu->writeGuestMemory(ppv,&z,4); hr=E_NOINTERFACE; }
            } else { uint32_t z=0; cpu->writeGuestMemory(ppv,&z,4); }
        }
        cpu->writeRegister(X86Reg::EAX, (uint32_t)hr); cpu->writeRegister(X86Reg::ESP, esp+16); nxt = retA; return true;
    }
    bool doD3D9(uint32_t slot, IX86CPU* cpu, uint32_t esp, uint32_t retA, uint32_t& nxt, const GuestAllocFn& ag, const RegisterSymFn& rs) {
        if (!d3d9) return false;
        auto arg = [&](uint32_t i) { uint32_t v=0; cpu->readGuestMemory(esp+4+i*4,&v,4); return v; };
        auto ret = [&](uint32_t r, uint32_t n) { cpu->writeRegister(X86Reg::EAX,r); cpu->writeRegister(X86Reg::ESP,esp+4+n*4); nxt=retA; return true; };
        switch (slot) {
            case 0: return doQI(d3d9, arg(0), cpu, esp, retA, nxt);
            case 1: return ret(d3d9->AddRef(), 1);
            case 2: return ret(1, 1);
            case 3: return ret(0, 2);
            case 4: return ret(d3d9->GetAdapterCount(), 1);
            case 5: { D3DADAPTER_IDENTIFIER9 id{}; HRESULT hr=d3d9->GetAdapterIdentifier(arg(1),arg(2),&id); if(SUCCEEDED(hr)&&arg(3)>=0x10000u) cpu->writeGuestMemory(arg(3),&id,1100); return ret(hr,4); }
            case 6: return ret(d3d9->GetAdapterModeCount(arg(1),(D3DFORMAT)arg(2)), 3);
            case 7: { D3DDISPLAYMODE m{}; HRESULT hr=d3d9->EnumAdapterModes(arg(1),(D3DFORMAT)arg(2),arg(3),&m); if(SUCCEEDED(hr)&&arg(4)>=0x10000u) cpu->writeGuestMemory(arg(4),&m,sizeof(m)); return ret(hr,5); }
            case 8: { D3DDISPLAYMODE m{}; HRESULT hr=d3d9->GetAdapterDisplayMode(arg(1),&m); if(SUCCEEDED(hr)&&arg(2)>=0x10000u) cpu->writeGuestMemory(arg(2),&m,sizeof(m)); return ret(hr,3); }
            case 9: return ret(d3d9->CheckDeviceType(arg(1),(D3DDEVTYPE)arg(2),(D3DFORMAT)arg(3),(D3DFORMAT)arg(4),arg(5)!=0), 6);
            case 10: return ret(d3d9->CheckDeviceFormat(arg(1),(D3DDEVTYPE)arg(2),(D3DFORMAT)arg(3),arg(4),(D3DRESOURCETYPE)arg(5),(D3DFORMAT)arg(6)), 7);
            case 11: { DWORD q=0; uint32_t pq=arg(6); HRESULT hr=d3d9->CheckDeviceMultiSampleType(arg(1),(D3DDEVTYPE)arg(2),(D3DFORMAT)arg(3),arg(4)!=0,(D3DMULTISAMPLE_TYPE)arg(5),pq?&q:nullptr); if(pq>=0x10000u){uint32_t q32=q; cpu->writeGuestMemory(pq,&q32,4);} return ret(hr,7); }
            case 12: return ret(d3d9->CheckDepthStencilMatch(arg(1),(D3DDEVTYPE)arg(2),(D3DFORMAT)arg(3),(D3DFORMAT)arg(4),(D3DFORMAT)arg(5)), 6);
            case 13: return ret(d3d9->CheckDeviceFormatConversion(arg(1),(D3DDEVTYPE)arg(2),(D3DFORMAT)arg(3),(D3DFORMAT)arg(4)), 5);
            case 14: { D3DCAPS9 c{}; HRESULT hr=d3d9->GetDeviceCaps(arg(1),(D3DDEVTYPE)arg(2),&c); if(SUCCEEDED(hr)&&arg(3)>=0x10000u) cpu->writeGuestMemory(arg(3),&c,sizeof(c)); return ret(hr,4); }
            case 15: return ret(0x00010001u, 2);
            case 16: {
                uint32_t pPP=arg(5), ppDev=arg(6); focusHwnd = arg(3)?arg(3):0x000A0001u;
                GuestPP gpp{}; if(pPP>=0x10000u) cpu->readGuestMemory(pPP,&gpp,sizeof(gpp));
                D3DPRESENT_PARAMETERS pp{}; fillPP(gpp, pp); HWND nw=(HWND)dxvkAndroidGetWindowHandle();
                IDirect3DDevice9* rd=nullptr;
                HRESULT hr=d3d9->CreateDevice(arg(1),(D3DDEVTYPE)arg(2),nw,arg(4)?arg(4):D3DCREATE_HARDWARE_VERTEXPROCESSING,&pp,&rd);
                if (FAILED(hr)) { pp.MultiSampleType=D3DMULTISAMPLE_NONE; pp.MultiSampleQuality=0; pp.BackBufferFormat=D3DFMT_X8R8G8B8; pp.AutoDepthStencilFormat=D3DFMT_D24S8; hr=d3d9->CreateDevice(arg(1),D3DDEVTYPE_HAL,nw,D3DCREATE_HARDWARE_VERTEXPROCESSING,&pp,&rd); }
                devHr = (uint32_t)hr;
                if (SUCCEEDED(hr) && rd) {
                    if(dev) dev->Release(); dev=rd; devW=pp.BackBufferWidth; devH=pp.BackBufferHeight;
                    uint32_t vt=ensureVt(VT_DEV,119,"IDirect3DDevice9",cpu,ag,rs); devG=ag(16);
                    if(vt&&devG){ cpu->writeGuestMemory(devG,&vt,4); p2g[dev]=devG; }
                    savePP(pp,pPP,cpu); if(ppDev>=0x10000u) cpu->writeGuestMemory(ppDev,&devG,4);
                } else if(ppDev>=0x10000u){ uint32_t z=0; cpu->writeGuestMemory(ppDev,&z,4); }
                return ret(hr, 7);
            }
            default: return false;
        }
    }
    bool doDev(uint32_t slot, IX86CPU* cpu, uint32_t esp, uint32_t retA, uint32_t& nxt, const GuestAllocFn& ag, const RegisterSymFn& rs) {
        if (!dev) return false;
        auto arg = [&](uint32_t i) { uint32_t v=0; cpu->readGuestMemory(esp+4+i*4,&v,4); return v; };
        auto ret = [&](uint32_t r, uint32_t n) { cpu->writeRegister(X86Reg::EAX,r); cpu->writeRegister(X86Reg::ESP,esp+4+n*4); nxt=retA; return true; };
        auto retV = [&](uint32_t n) { cpu->writeRegister(X86Reg::ESP,esp+4+n*4); nxt=retA; return true; };
        switch (slot) {
            case 0: return doQI(dev, arg(0), cpu, esp, retA, nxt);
            case 1: return ret(dev->AddRef(), 1);
            case 2: return ret(1, 1);
            case 3: return ret(dev->TestCooperativeLevel(), 1);
            case 4: return ret(dev->GetAvailableTextureMem(), 1);
            case 5: return ret(dev->EvictManagedResources(), 1);
            case 6: { if(d3d9&&arg(1)>=0x10000u){d3d9->AddRef(); cpu->writeGuestMemory(arg(1),&d3d9G,4); return ret(0,2);} return ret(D3DERR_INVALIDCALL,2); }
            case 7: { D3DCAPS9 c{}; HRESULT hr=dev->GetDeviceCaps(&c); if(SUCCEEDED(hr)&&arg(1)>=0x10000u) cpu->writeGuestMemory(arg(1),&c,sizeof(c)); return ret(hr,2); }
            case 8: { D3DDISPLAYMODE m{}; HRESULT hr=dev->GetDisplayMode(arg(1),&m); if(SUCCEEDED(hr)&&arg(2)>=0x10000u) cpu->writeGuestMemory(arg(2),&m,sizeof(m)); return ret(hr,3); }
            case 9: { D3DDEVICE_CREATION_PARAMETERS c{}; HRESULT hr=dev->GetCreationParameters(&c); if(SUCCEEDED(hr)&&arg(1)>=0x10000u){ GuestCP g{c.AdapterOrdinal,(uint32_t)c.DeviceType,focusHwnd,(uint32_t)c.BehaviorFlags}; cpu->writeGuestMemory(arg(1),&g,sizeof(g)); } return ret(hr,2); }
            case 10: return ret(0, 4);
            case 11: return retV(4);
            case 12: return ret(dev->ShowCursor(arg(1)!=0)?1:0, 2);
            case 14: { IDirect3DSwapChain9* s=nullptr; HRESULT hr=dev->GetSwapChain(arg(1),&s); if(SUCCEEDED(hr)&&s&&arg(2)>=0x10000u){uint32_t g=wrap(s,VT_SWAP,10,"IDirect3DSwapChain9",gSwap,cpu,ag,rs); cpu->writeGuestMemory(arg(2),&g,4);} return ret(hr,3); }
            case 15: return ret(dev->GetNumberOfSwapChains(), 1);
            case 16: { GuestPP g{}; if(arg(1)>=0x10000u) cpu->readGuestMemory(arg(1),&g,sizeof(g)); D3DPRESENT_PARAMETERS p{}; fillPP(g,p); HRESULT hr=dev->Reset(&p); if(SUCCEEDED(hr)){devW=p.BackBufferWidth;devH=p.BackBufferHeight;savePP(p,arg(1),cpu);} return ret(hr,2); }
            case 17: { RECT s{},d{}; bool hs=rdRect(cpu,arg(1),s), hd=rdRect(cpu,arg(2),d); HRESULT hr=dev->Present(hs?&s:nullptr,hd?&d:nullptr,nullptr,nullptr); if(SUCCEEDED(hr)) ++cntPresent; return ret(hr,5); }
            case 18: { IDirect3DSurface9* s=nullptr; HRESULT hr=dev->GetBackBuffer(arg(1),arg(2),(D3DBACKBUFFER_TYPE)arg(3),&s); if(SUCCEEDED(hr)&&s&&arg(4)>=0x10000u){uint32_t g=wrap(s,VT_SURF,17,"IDirect3DSurface9",gSurf,cpu,ag,rs); cpu->writeGuestMemory(arg(4),&g,4);} return ret(hr,5); }
            case 19: { D3DRASTER_STATUS r{}; HRESULT hr=dev->GetRasterStatus(arg(1),&r); if(SUCCEEDED(hr)&&arg(2)>=0x10000u) cpu->writeGuestMemory(arg(2),&r,sizeof(r)); return ret(hr,3); }
            case 20: return ret(dev->SetDialogBoxMode(arg(1)!=0), 2);
            case 21: { if(arg(3)>=0x10000u){D3DGAMMARAMP r{}; cpu->readGuestMemory(arg(3),&r,sizeof(r)); dev->SetGammaRamp(arg(1),arg(2),&r);} return retV(4); }
            case 22: { if(arg(2)>=0x10000u){D3DGAMMARAMP r{}; dev->GetGammaRamp(arg(1),&r); cpu->writeGuestMemory(arg(2),&r,sizeof(r));} return retV(3); }
            case 23: { IDirect3DTexture9* t=nullptr; HRESULT hr=dev->CreateTexture(arg(1),arg(2),arg(3),arg(4),(D3DFORMAT)arg(5),(D3DPOOL)arg(6),&t,nullptr); if(SUCCEEDED(hr)&&t&&arg(7)>=0x10000u){uint32_t g=wrapTex(t,cpu,ag,rs); cpu->writeGuestMemory(arg(7),&g,4); ++cntTex;} return ret(hr,9); }
            case 25: { IDirect3DCubeTexture9* t=nullptr; HRESULT hr=dev->CreateCubeTexture(arg(1),arg(2),arg(3),(D3DFORMAT)arg(4),(D3DPOOL)arg(5),&t,nullptr); if(SUCCEEDED(hr)&&t&&arg(6)>=0x10000u){uint32_t g=wrapCube(t,cpu,ag,rs); cpu->writeGuestMemory(arg(6),&g,4); ++cntTex;} return ret(hr,8); }
            case 26: { IDirect3DVertexBuffer9* v=nullptr; HRESULT hr=dev->CreateVertexBuffer(arg(1),arg(2),arg(3),(D3DPOOL)arg(4),&v,nullptr); if(SUCCEEDED(hr)&&v&&arg(5)>=0x10000u){uint32_t g=wrap(v,VT_VB,14,"IDirect3DVertexBuffer9",gVB,cpu,ag,rs); cpu->writeGuestMemory(arg(5),&g,4); ++cntVB;} return ret(hr,7); }
            case 27: { IDirect3DIndexBuffer9* v=nullptr; HRESULT hr=dev->CreateIndexBuffer(arg(1),arg(2),(D3DFORMAT)arg(3),(D3DPOOL)arg(4),&v,nullptr); if(SUCCEEDED(hr)&&v&&arg(5)>=0x10000u){uint32_t g=wrap(v,VT_IB,14,"IDirect3DIndexBuffer9",gIB,cpu,ag,rs); cpu->writeGuestMemory(arg(5),&g,4); ++cntIB;} return ret(hr,7); }
            case 28: { IDirect3DSurface9* s=nullptr; HRESULT hr=dev->CreateRenderTarget(arg(1),arg(2),(D3DFORMAT)arg(3),(D3DMULTISAMPLE_TYPE)arg(4),arg(5),arg(6)!=0,&s,nullptr); if(SUCCEEDED(hr)&&s&&arg(7)>=0x10000u){uint32_t g=wrap(s,VT_SURF,17,"IDirect3DSurface9",gSurf,cpu,ag,rs); cpu->writeGuestMemory(arg(7),&g,4);} return ret(hr,9); }
            case 29: { IDirect3DSurface9* s=nullptr; HRESULT hr=dev->CreateDepthStencilSurface(arg(1),arg(2),(D3DFORMAT)arg(3),(D3DMULTISAMPLE_TYPE)arg(4),arg(5),arg(6)!=0,&s,nullptr); if(SUCCEEDED(hr)&&s&&arg(7)>=0x10000u){uint32_t g=wrap(s,VT_SURF,17,"IDirect3DSurface9",gSurf,cpu,ag,rs); cpu->writeGuestMemory(arg(7),&g,4);} return ret(hr,9); }
            case 30: { auto s=gSurf.find(arg(1)), d=gSurf.find(arg(3)); if(s==gSurf.end()||d==gSurf.end()) return ret(D3DERR_INVALIDCALL,5); RECT sr{}; POINT dp{}; bool hs=rdRect(cpu,arg(2),sr), hp=arg(4)>=0x10000u; if(hp){int32_t p[2]; cpu->readGuestMemory(arg(4),p,8); dp={p[0],p[1]};} return ret(dev->UpdateSurface(s->second,hs?&sr:nullptr,d->second,hp?&dp:nullptr),5); }
            case 31: { auto s=gBaseTex.find(arg(1)), d=gBaseTex.find(arg(2)); return ret((s==gBaseTex.end()||d==gBaseTex.end())?D3DERR_INVALIDCALL:dev->UpdateTexture(s->second,d->second),3); }
            case 32: { auto s=gSurf.find(arg(1)), d=gSurf.find(arg(2)); return ret((s==gSurf.end()||d==gSurf.end())?D3DERR_INVALIDCALL:dev->GetRenderTargetData(s->second,d->second),3); }
            case 34: { auto s=gSurf.find(arg(1)), d=gSurf.find(arg(3)); if(s==gSurf.end()||d==gSurf.end()) return ret(D3DERR_INVALIDCALL,6); RECT sr{},dr{}; bool hs=rdRect(cpu,arg(2),sr), hd=rdRect(cpu,arg(4),dr); return ret(dev->StretchRect(s->second,hs?&sr:nullptr,d->second,hd?&dr:nullptr,(D3DTEXTUREFILTERTYPE)arg(5)),6); }
            case 35: { auto s=gSurf.find(arg(1)); if(s==gSurf.end()) return ret(D3DERR_INVALIDCALL,4); RECT r{}; bool hr=rdRect(cpu,arg(2),r); return ret(dev->ColorFill(s->second,hr?&r:nullptr,arg(3)),4); }
            case 36: { IDirect3DSurface9* s=nullptr; HRESULT hr=dev->CreateOffscreenPlainSurface(arg(1),arg(2),(D3DFORMAT)arg(3),(D3DPOOL)arg(4),&s,nullptr); if(SUCCEEDED(hr)&&s&&arg(5)>=0x10000u){uint32_t g=wrap(s,VT_SURF,17,"IDirect3DSurface9",gSurf,cpu,ag,rs); cpu->writeGuestMemory(arg(5),&g,4);} return ret(hr,7); }
            case 37: { IDirect3DSurface9* s=gSurf.count(arg(2))?gSurf[arg(2)]:nullptr; return ret(dev->SetRenderTarget(arg(1),s),3); }
            case 38: { IDirect3DSurface9* s=nullptr; HRESULT hr=dev->GetRenderTarget(arg(1),&s); if(SUCCEEDED(hr)&&arg(2)>=0x10000u){uint32_t g=s?wrap(s,VT_SURF,17,"IDirect3DSurface9",gSurf,cpu,ag,rs):0; cpu->writeGuestMemory(arg(2),&g,4);} return ret(hr,3); }
            case 39: { IDirect3DSurface9* s=gSurf.count(arg(1))?gSurf[arg(1)]:nullptr; return ret(dev->SetDepthStencilSurface(s),2); }
            case 40: { IDirect3DSurface9* s=nullptr; HRESULT hr=dev->GetDepthStencilSurface(&s); if(SUCCEEDED(hr)&&arg(1)>=0x10000u){uint32_t g=s?wrap(s,VT_SURF,17,"IDirect3DSurface9",gSurf,cpu,ag,rs):0; cpu->writeGuestMemory(arg(1),&g,4);} return ret(hr,2); }
            case 41: return ret(dev->BeginScene(), 1);
            case 42: return ret(dev->EndScene(), 1);
            case 43: { std::vector<D3DRECT> rc; uint32_t cnt=arg(1), pr=arg(2); if(cnt&&pr>=0x10000u){uint32_t n=std::min(cnt,256u); rc.resize(n); for(uint32_t i=0;i<n;++i){int32_t v[4]; cpu->readGuestMemory(pr+i*16,v,16); rc[i]={v[0],v[1],v[2],v[3]};}} uint32_t zb=arg(5); float z=1.0f; memcpy(&z,&zb,4); HRESULT hr=dev->Clear((DWORD)rc.size(),rc.empty()?nullptr:rc.data(),arg(3),arg(4),z,arg(6)); if(SUCCEEDED(hr)) ++cntClear; return ret(hr,7); }
            case 44: case 46: { D3DMATRIX m{}; if(arg(2)>=0x10000u) cpu->readGuestMemory(arg(2),&m,64); return ret(slot==44?dev->SetTransform((D3DTRANSFORMSTATETYPE)arg(1),&m):dev->MultiplyTransform((D3DTRANSFORMSTATETYPE)arg(1),&m),3); }
            case 45: { D3DMATRIX m{}; HRESULT hr=dev->GetTransform((D3DTRANSFORMSTATETYPE)arg(1),&m); if(SUCCEEDED(hr)&&arg(2)>=0x10000u) cpu->writeGuestMemory(arg(2),&m,64); return ret(hr,3); }
            case 47: { D3DVIEWPORT9 v{}; if(arg(1)>=0x10000u) cpu->readGuestMemory(arg(1),&v,sizeof(v)); return ret(dev->SetViewport(&v),2); }
            case 48: { D3DVIEWPORT9 v{}; HRESULT hr=dev->GetViewport(&v); if(SUCCEEDED(hr)&&arg(1)>=0x10000u) cpu->writeGuestMemory(arg(1),&v,sizeof(v)); return ret(hr,2); }
            case 49: { D3DMATERIAL9 m{}; if(arg(1)>=0x10000u) cpu->readGuestMemory(arg(1),&m,sizeof(m)); return ret(dev->SetMaterial(&m),2); }
            case 50: { D3DMATERIAL9 m{}; HRESULT hr=dev->GetMaterial(&m); if(SUCCEEDED(hr)&&arg(1)>=0x10000u) cpu->writeGuestMemory(arg(1),&m,sizeof(m)); return ret(hr,2); }
            case 51: { D3DLIGHT9 l{}; if(arg(2)>=0x10000u) cpu->readGuestMemory(arg(2),&l,sizeof(l)); return ret(dev->SetLight(arg(1),&l),3); }
            case 53: return ret(dev->LightEnable(arg(1),arg(2)!=0),3);
            case 55: { float p[4]={}; if(arg(2)>=0x10000u) cpu->readGuestMemory(arg(2),p,16); return ret(dev->SetClipPlane(arg(1),p),3); }
            case 57: return ret(dev->SetRenderState((D3DRENDERSTATETYPE)arg(1),arg(2)),3);
            case 58: { DWORD v=0; HRESULT hr=dev->GetRenderState((D3DRENDERSTATETYPE)arg(1),&v); if(SUCCEEDED(hr)&&arg(2)>=0x10000u){uint32_t u=v; cpu->writeGuestMemory(arg(2),&u,4);} return ret(hr,3); }
            case 59: { IDirect3DStateBlock9* b=nullptr; HRESULT hr=dev->CreateStateBlock((D3DSTATEBLOCKTYPE)arg(1),&b); if(SUCCEEDED(hr)&&b&&arg(2)>=0x10000u){uint32_t g=wrap(b,VT_SB,6,"IDirect3DStateBlock9",gSB,cpu,ag,rs); cpu->writeGuestMemory(arg(2),&g,4);} return ret(hr,3); }
            case 60: return ret(dev->BeginStateBlock(),1);
            case 61: { IDirect3DStateBlock9* b=nullptr; HRESULT hr=dev->EndStateBlock(&b); if(SUCCEEDED(hr)&&b&&arg(1)>=0x10000u){uint32_t g=wrap(b,VT_SB,6,"IDirect3DStateBlock9",gSB,cpu,ag,rs); cpu->writeGuestMemory(arg(1),&g,4);} return ret(hr,2); }
            case 64: { IDirect3DBaseTexture9* t=nullptr; HRESULT hr=dev->GetTexture(arg(1),&t); if(SUCCEEDED(hr)&&arg(2)>=0x10000u){uint32_t g=(t&&p2g.count(t))?p2g[t]:0; cpu->writeGuestMemory(arg(2),&g,4);} return ret(hr,3); }
            case 65: { IDirect3DBaseTexture9* t=gBaseTex.count(arg(2))?gBaseTex[arg(2)]:nullptr; return ret(dev->SetTexture(arg(1),t),3); }
            case 66: { DWORD v=0; HRESULT hr=dev->GetTextureStageState(arg(1),(D3DTEXTURESTAGESTATETYPE)arg(2),&v); if(SUCCEEDED(hr)&&arg(3)>=0x10000u){uint32_t u=v; cpu->writeGuestMemory(arg(3),&u,4);} return ret(hr,4); }
            case 67: return ret(dev->SetTextureStageState(arg(1),(D3DTEXTURESTAGESTATETYPE)arg(2),arg(3)),4);
            case 68: { DWORD v=0; HRESULT hr=dev->GetSamplerState(arg(1),(D3DSAMPLERSTATETYPE)arg(2),&v); if(SUCCEEDED(hr)&&arg(3)>=0x10000u){uint32_t u=v; cpu->writeGuestMemory(arg(3),&u,4);} return ret(hr,4); }
            case 69: return ret(dev->SetSamplerState(arg(1),(D3DSAMPLERSTATETYPE)arg(2),arg(3)),4);
            case 70: { DWORD np=1; HRESULT hr=dev->ValidateDevice(&np); if(arg(1)>=0x10000u){uint32_t u=np; cpu->writeGuestMemory(arg(1),&u,4);} return ret(hr,2); }
            case 75: { RECT r{}; rdRect(cpu,arg(1),r); return ret(dev->SetScissorRect(&r),2); }
            case 76: { RECT r{}; HRESULT hr=dev->GetScissorRect(&r); if(SUCCEEDED(hr)&&arg(1)>=0x10000u){int32_t v[4]={(int32_t)r.left,(int32_t)r.top,(int32_t)r.right,(int32_t)r.bottom}; cpu->writeGuestMemory(arg(1),v,16);} return ret(hr,2); }
            case 77: return ret(dev->SetSoftwareVertexProcessing(arg(1)!=0),2);
            case 78: return ret(dev->GetSoftwareVertexProcessing()?1:0,1);
            case 79: { uint32_t b=arg(1); float f=0; memcpy(&f,&b,4); return ret(dev->SetNPatchMode(f),2); }
            case 80: { cpu->pushFpuDouble(dev->GetNPatchMode()); return retV(1); }
            case 81: { HRESULT hr=dev->DrawPrimitive((D3DPRIMITIVETYPE)arg(1),arg(2),arg(3)); if(SUCCEEDED(hr)) ++cntDraw; return ret(hr,4); }
            case 82: { HRESULT hr=dev->DrawIndexedPrimitive((D3DPRIMITIVETYPE)arg(1),(int32_t)arg(2),arg(3),arg(4),arg(5),arg(6)); if(SUCCEEDED(hr)) ++cntDraw; return ret(hr,7); }
            case 83: { uint32_t sz=primVerts(arg(1),arg(2))*arg(4); std::vector<uint8_t> b(sz); if(sz&&arg(3)>=0x10000u) cpu->readGuestMemory(arg(3),b.data(),sz); HRESULT hr=dev->DrawPrimitiveUP((D3DPRIMITIVETYPE)arg(1),arg(2),b.empty()?nullptr:b.data(),arg(4)); if(SUCCEEDED(hr)) ++cntDraw; return ret(hr,5); }
            case 84: { uint32_t ibs=primVerts(arg(1),arg(4))*(arg(6)==102?4:2), vbs=(arg(2)+arg(3))*arg(8); std::vector<uint8_t> ib(ibs), vb(vbs); if(ibs&&arg(5)>=0x10000u) cpu->readGuestMemory(arg(5),ib.data(),ibs); if(vbs&&arg(7)>=0x10000u) cpu->readGuestMemory(arg(7),vb.data(),vbs); HRESULT hr=dev->DrawIndexedPrimitiveUP((D3DPRIMITIVETYPE)arg(1),arg(2),arg(3),arg(4),ib.empty()?nullptr:ib.data(),(D3DFORMAT)arg(6),vb.empty()?nullptr:vb.data(),arg(8)); if(SUCCEEDED(hr)) ++cntDraw; return ret(hr,9); }
            case 86: { std::vector<D3DVERTEXELEMENT9> el; if(arg(1)>=0x10000u) for(uint32_t i=0;i<65;++i){D3DVERTEXELEMENT9 e{}; cpu->readGuestMemory(arg(1)+i*8,&e,8); el.push_back(e); if(e.Stream==0xFF) break;} IDirect3DVertexDeclaration9* d=nullptr; HRESULT hr=el.empty()?D3DERR_INVALIDCALL:dev->CreateVertexDeclaration(el.data(),&d); if(SUCCEEDED(hr)&&d&&arg(2)>=0x10000u){uint32_t g=wrap(d,VT_VDECL,5,"IDirect3DVertexDeclaration9",gVDecl,cpu,ag,rs); cpu->writeGuestMemory(arg(2),&g,4);} return ret(hr,3); }
            case 87: return ret(dev->SetVertexDeclaration(gVDecl.count(arg(1))?gVDecl[arg(1)]:nullptr),2);
            case 88: { IDirect3DVertexDeclaration9* d=nullptr; HRESULT hr=dev->GetVertexDeclaration(&d); if(SUCCEEDED(hr)&&arg(1)>=0x10000u){uint32_t g=d?wrap(d,VT_VDECL,5,"IDirect3DVertexDeclaration9",gVDecl,cpu,ag,rs):0; cpu->writeGuestMemory(arg(1),&g,4);} return ret(hr,2); }
            case 89: return ret(dev->SetFVF(arg(1)),2);
            case 90: { DWORD v=0; HRESULT hr=dev->GetFVF(&v); if(SUCCEEDED(hr)&&arg(1)>=0x10000u){uint32_t u=v; cpu->writeGuestMemory(arg(1),&u,4);} return ret(hr,2); }
            case 91: { std::vector<uint32_t> c; IDirect3DVertexShader9* s=nullptr; HRESULT hr=readDxso(cpu,arg(1),c)?dev->CreateVertexShader((const DWORD*)c.data(),&s):D3DERR_INVALIDCALL; if(SUCCEEDED(hr)&&s&&arg(2)>=0x10000u){uint32_t g=wrap(s,VT_VS,5,"IDirect3DVertexShader9",gVS,cpu,ag,rs); cpu->writeGuestMemory(arg(2),&g,4); ++cntVS;} return ret(hr,3); }
            case 92: return ret(dev->SetVertexShader(gVS.count(arg(1))?gVS[arg(1)]:nullptr),2);
            case 93: { IDirect3DVertexShader9* s=nullptr; HRESULT hr=dev->GetVertexShader(&s); if(SUCCEEDED(hr)&&arg(1)>=0x10000u){uint32_t g=s?wrap(s,VT_VS,5,"IDirect3DVertexShader9",gVS,cpu,ag,rs):0; cpu->writeGuestMemory(arg(1),&g,4);} return ret(hr,2); }
            case 94: case 109: { uint32_t cnt=arg(3); std::vector<float> b(cnt*4,0.f); if(cnt&&arg(2)>=0x10000u) cpu->readGuestMemory(arg(2),b.data(),b.size()*4); return ret(slot==94?dev->SetVertexShaderConstantF(arg(1),b.data(),cnt):dev->SetPixelShaderConstantF(arg(1),b.data(),cnt),4); }
            case 95: case 110: { uint32_t cnt=arg(3); std::vector<float> b(cnt*4,0.f); HRESULT hr=slot==95?dev->GetVertexShaderConstantF(arg(1),b.data(),cnt):dev->GetPixelShaderConstantF(arg(1),b.data(),cnt); if(SUCCEEDED(hr)&&cnt&&arg(2)>=0x10000u) cpu->writeGuestMemory(arg(2),b.data(),b.size()*4); return ret(hr,4); }
            case 96: case 111: { uint32_t cnt=arg(3); std::vector<int32_t> b(cnt*4,0); if(cnt&&arg(2)>=0x10000u) cpu->readGuestMemory(arg(2),b.data(),b.size()*4); return ret(slot==96?dev->SetVertexShaderConstantI(arg(1),b.data(),cnt):dev->SetPixelShaderConstantI(arg(1),b.data(),cnt),4); }
            case 98: case 113: { uint32_t cnt=arg(3); std::vector<BOOL> b(cnt,0); if(cnt&&arg(2)>=0x10000u) cpu->readGuestMemory(arg(2),b.data(),b.size()*sizeof(BOOL)); return ret(slot==98?dev->SetVertexShaderConstantB(arg(1),b.data(),cnt):dev->SetPixelShaderConstantB(arg(1),b.data(),cnt),4); }
            case 100: return ret(dev->SetStreamSource(arg(1),gVB.count(arg(2))?gVB[arg(2)]:nullptr,arg(3),arg(4)),5);
            case 101: { IDirect3DVertexBuffer9* v=nullptr; UINT o=0,st=0; HRESULT hr=dev->GetStreamSource(arg(1),&v,&o,&st); if(SUCCEEDED(hr)){if(arg(2)>=0x10000u){uint32_t g=v?wrap(v,VT_VB,14,"IDirect3DVertexBuffer9",gVB,cpu,ag,rs):0; cpu->writeGuestMemory(arg(2),&g,4);} if(arg(3)>=0x10000u) cpu->writeGuestMemory(arg(3),&o,4); if(arg(4)>=0x10000u) cpu->writeGuestMemory(arg(4),&st,4);} return ret(hr,5); }
            case 102: return ret(dev->SetStreamSourceFreq(arg(1),arg(2)),3);
            case 103: { UINT s=0; HRESULT hr=dev->GetStreamSourceFreq(arg(1),&s); if(SUCCEEDED(hr)&&arg(2)>=0x10000u) cpu->writeGuestMemory(arg(2),&s,4); return ret(hr,3); }
            case 104: return ret(dev->SetIndices(gIB.count(arg(1))?gIB[arg(1)]:nullptr),2);
            case 105: { IDirect3DIndexBuffer9* v=nullptr; HRESULT hr=dev->GetIndices(&v); if(SUCCEEDED(hr)&&arg(1)>=0x10000u){uint32_t g=v?wrap(v,VT_IB,14,"IDirect3DIndexBuffer9",gIB,cpu,ag,rs):0; cpu->writeGuestMemory(arg(1),&g,4);} return ret(hr,2); }
            case 106: { std::vector<uint32_t> c; IDirect3DPixelShader9* s=nullptr; HRESULT hr=readDxso(cpu,arg(1),c)?dev->CreatePixelShader((const DWORD*)c.data(),&s):D3DERR_INVALIDCALL; if(SUCCEEDED(hr)&&s&&arg(2)>=0x10000u){uint32_t g=wrap(s,VT_PS,5,"IDirect3DPixelShader9",gPS,cpu,ag,rs); cpu->writeGuestMemory(arg(2),&g,4); ++cntPS;} return ret(hr,3); }
            case 107: return ret(dev->SetPixelShader(gPS.count(arg(1))?gPS[arg(1)]:nullptr),2);
            case 108: { IDirect3DPixelShader9* s=nullptr; HRESULT hr=dev->GetPixelShader(&s); if(SUCCEEDED(hr)&&arg(1)>=0x10000u){uint32_t g=s?wrap(s,VT_PS,5,"IDirect3DPixelShader9",gPS,cpu,ag,rs):0; cpu->writeGuestMemory(arg(1),&g,4);} return ret(hr,2); }
            case 118: { IDirect3DQuery9* q=nullptr; HRESULT hr=dev->CreateQuery((D3DQUERYTYPE)arg(1),arg(2)?&q:nullptr); if(SUCCEEDED(hr)&&q&&arg(2)>=0x10000u){uint32_t g=wrap(q,VT_QUERY,8,"IDirect3DQuery9",gQuery,cpu,ag,rs); cpu->writeGuestMemory(arg(2),&g,4);} return ret(hr,3); }
            default: return false;
        }
    }
    bool doChild(uint32_t iface, uint32_t slot, IX86CPU* cpu, uint32_t esp, uint32_t retA, uint32_t& nxt, const GuestAllocFn& ag, const RegisterSymFn& rs) {
        auto arg = [&](uint32_t i) { uint32_t v=0; cpu->readGuestMemory(esp+4+i*4,&v,4); return v; };
        auto ret = [&](uint32_t r, uint32_t n) { cpu->writeRegister(X86Reg::EAX,r); cpu->writeRegister(X86Reg::ESP,esp+4+n*4); nxt=retA; return true; };
        auto retV = [&](uint32_t n) { cpu->writeRegister(X86Reg::ESP,esp+4+n*4); nxt=retA; return true; };
        auto retDev = [&]() { if(dev&&arg(1)>=0x10000u){dev->AddRef(); cpu->writeGuestMemory(arg(1),&devG,4); return ret(0,2);} return ret(D3DERR_INVALIDCALL,2); };
        uint32_t self = arg(0);
        if (iface == 3 && gSurf.count(self)) {
            auto* s = gSurf[self];
            if (slot==0) return doQI(s,self,cpu,esp,retA,nxt);
            if (slot==1) return ret(s->AddRef(),1); if (slot==2) return ret(1,1); if (slot==3) return retDev();
            if (slot==9) { s->PreLoad(); return retV(1); } if (slot==10) return ret(s->GetType(),1);
            if (slot==12) { D3DSURFACE_DESC d{}; HRESULT hr=s->GetDesc(&d); if(SUCCEEDED(hr)&&arg(1)>=0x10000u) cpu->writeGuestMemory(arg(1),&d,sizeof(d)); return ret(hr,2); }
            if (slot==13) { RECT rc{}; bool hrR=rdRect(cpu,arg(2),rc); D3DLOCKED_RECT lr{}; HRESULT hr=s->LockRect(&lr,hrR?&rc:nullptr,arg(3)); if(SUCCEEDED(hr)&&arg(1)>=0x10000u){ D3DSURFACE_DESC d{}; s->GetDesc(&d); uint32_t h=hrR?std::max<uint32_t>(1,rc.bottom-rc.top):std::max(1u,d.Height); uint32_t rows=isBC(d.Format)?std::max(1u,(h+3)/4):h; GuestLR glr{(int32_t)lr.Pitch, beginLock((uint64_t)self<<16,lr.pBits,std::max<INT>(0,lr.Pitch)*rows,arg(3),cpu,ag)}; cpu->writeGuestMemory(arg(1),&glr,sizeof(glr)); } return ret(hr,4); }
            if (slot==14) { endLock((uint64_t)self<<16,cpu); return ret(s->UnlockRect(),1); }
        }
        if (iface == 4 && gTex.count(self)) {
            auto* t = gTex[self];
            if (slot==0) return doQI(t,self,cpu,esp,retA,nxt);
            if (slot==1) return ret(t->AddRef(),1); if (slot==2) return ret(1,1); if (slot==3) return retDev();
            if (slot==9) { t->PreLoad(); return retV(1); } if (slot==10) return ret(t->GetType(),1);
            if (slot==11) return ret(t->SetLOD(arg(1)),2); if (slot==12) return ret(t->GetLOD(),1); if (slot==13) return ret(t->GetLevelCount(),1);
            if (slot==14) return ret(t->SetAutoGenFilterType((D3DTEXTUREFILTERTYPE)arg(1)),2); if (slot==15) return ret(t->GetAutoGenFilterType(),1);
            if (slot==16) { t->GenerateMipSubLevels(); return retV(1); }
            if (slot==17) { D3DSURFACE_DESC d{}; HRESULT hr=t->GetLevelDesc(arg(1),&d); if(SUCCEEDED(hr)&&arg(2)>=0x10000u) cpu->writeGuestMemory(arg(2),&d,sizeof(d)); return ret(hr,3); }
            if (slot==18) { IDirect3DSurface9* s=nullptr; HRESULT hr=t->GetSurfaceLevel(arg(1),&s); if(SUCCEEDED(hr)&&s&&arg(2)>=0x10000u){uint32_t g=wrap(s,VT_SURF,17,"IDirect3DSurface9",gSurf,cpu,ag,rs); cpu->writeGuestMemory(arg(2),&g,4);} return ret(hr,3); }
            if (slot==19) { RECT rc{}; bool hrR=rdRect(cpu,arg(3),rc); D3DLOCKED_RECT lr{}; HRESULT hr=t->LockRect(arg(1),&lr,hrR?&rc:nullptr,arg(4)); if(SUCCEEDED(hr)&&arg(2)>=0x10000u){ D3DSURFACE_DESC d{}; t->GetLevelDesc(arg(1),&d); uint32_t h=hrR?std::max<uint32_t>(1,rc.bottom-rc.top):std::max(1u,d.Height); uint32_t rows=isBC(d.Format)?std::max(1u,(h+3)/4):h; GuestLR glr{(int32_t)lr.Pitch, beginLock(((uint64_t)self<<16)|(arg(1)&0xFFFFu),lr.pBits,std::max<INT>(0,lr.Pitch)*rows,arg(4),cpu,ag)}; cpu->writeGuestMemory(arg(2),&glr,sizeof(glr)); } return ret(hr,5); }
            if (slot==20) { endLock(((uint64_t)self<<16)|(arg(1)&0xFFFFu),cpu); return ret(t->UnlockRect(arg(1)),2); }
            if (slot==21) { RECT rc{}; bool hrR=rdRect(cpu,arg(1),rc); return ret(t->AddDirtyRect(hrR?&rc:nullptr),2); }
        }
        if (iface == 5 && gVB.count(self)) {
            auto* v = gVB[self];
            if (slot==0) return doQI(v,self,cpu,esp,retA,nxt);
            if (slot==1) return ret(v->AddRef(),1); if (slot==2) return ret(1,1); if (slot==3) return retDev(); if (slot==10) return ret(v->GetType(),1);
            if (slot==11) { void* p=nullptr; HRESULT hr=v->Lock(arg(1),arg(2),&p,arg(4)); if(SUCCEEDED(hr)&&arg(3)>=0x10000u){ D3DVERTEXBUFFER_DESC d{}; v->GetDesc(&d); uint32_t sz=(!arg(2)&&d.Size>arg(1))?d.Size-arg(1):arg(2); uint32_t g=beginLock((uint64_t)self<<16,p,sz,arg(4),cpu,ag); cpu->writeGuestMemory(arg(3),&g,4);} return ret(hr,5); }
            if (slot==12) { endLock((uint64_t)self<<16,cpu); return ret(v->Unlock(),1); }
            if (slot==13) { D3DVERTEXBUFFER_DESC d{}; HRESULT hr=v->GetDesc(&d); if(SUCCEEDED(hr)&&arg(1)>=0x10000u) cpu->writeGuestMemory(arg(1),&d,sizeof(d)); return ret(hr,2); }
        }
        if (iface == 6 && gIB.count(self)) {
            auto* v = gIB[self];
            if (slot==0) return doQI(v,self,cpu,esp,retA,nxt);
            if (slot==1) return ret(v->AddRef(),1); if (slot==2) return ret(1,1); if (slot==3) return retDev(); if (slot==10) return ret(v->GetType(),1);
            if (slot==11) { void* p=nullptr; HRESULT hr=v->Lock(arg(1),arg(2),&p,arg(4)); if(SUCCEEDED(hr)&&arg(3)>=0x10000u){ D3DINDEXBUFFER_DESC d{}; v->GetDesc(&d); uint32_t sz=(!arg(2)&&d.Size>arg(1))?d.Size-arg(1):arg(2); uint32_t g=beginLock((uint64_t)self<<16,p,sz,arg(4),cpu,ag); cpu->writeGuestMemory(arg(3),&g,4);} return ret(hr,5); }
            if (slot==12) { endLock((uint64_t)self<<16,cpu); return ret(v->Unlock(),1); }
            if (slot==13) { D3DINDEXBUFFER_DESC d{}; HRESULT hr=v->GetDesc(&d); if(SUCCEEDED(hr)&&arg(1)>=0x10000u) cpu->writeGuestMemory(arg(1),&d,sizeof(d)); return ret(hr,2); }
        }
        if ((iface==7&&gVDecl.count(self)) || (iface==8&&gVS.count(self)) || (iface==9&&gPS.count(self))) {
            IUnknown* u = iface==7?(IUnknown*)gVDecl[self] : iface==8?(IUnknown*)gVS[self] : (IUnknown*)gPS[self];
            if (slot==0) return doQI(u,self,cpu,esp,retA,nxt);
            if (slot==1) return ret(u->AddRef(),1); if (slot==2) return ret(1,1); if (slot==3) return retDev();
        }
        if (iface == 10 && gSwap.count(self)) {
            auto* sc = gSwap[self];
            if (slot==0) return doQI(sc,self,cpu,esp,retA,nxt);
            if (slot==1) return ret(sc->AddRef(),1); if (slot==2) return ret(1,1); if (slot==8) return retDev();
            if (slot==3) { HRESULT hr=sc->Present(nullptr,nullptr,nullptr,nullptr,arg(5)); if(SUCCEEDED(hr)) ++cntPresent; return ret(hr,6); }
            if (slot==5) { IDirect3DSurface9* s=nullptr; HRESULT hr=sc->GetBackBuffer(arg(1),(D3DBACKBUFFER_TYPE)arg(2),&s); if(SUCCEEDED(hr)&&s&&arg(3)>=0x10000u){uint32_t g=wrap(s,VT_SURF,17,"IDirect3DSurface9",gSurf,cpu,ag,rs); cpu->writeGuestMemory(arg(3),&g,4);} return ret(hr,4); }
            if (slot==7) { D3DDISPLAYMODE m{}; HRESULT hr=sc->GetDisplayMode(&m); if(SUCCEEDED(hr)&&arg(1)>=0x10000u) cpu->writeGuestMemory(arg(1),&m,sizeof(m)); return ret(hr,2); }
            if (slot==9) { D3DPRESENT_PARAMETERS p{}; HRESULT hr=sc->GetPresentParameters(&p); if(SUCCEEDED(hr)) savePP(p,arg(1),cpu); return ret(hr,2); }
        }
        if (iface == 11 && gSB.count(self)) {
            auto* b = gSB[self];
            if (slot==0) return doQI(b,self,cpu,esp,retA,nxt);
            if (slot==1) return ret(b->AddRef(),1); if (slot==2) return ret(1,1); if (slot==3) return retDev();
            if (slot==4) return ret(b->Capture(),1); if (slot==5) return ret(b->Apply(),1);
        }
        if (iface == 12 && gQuery.count(self)) {
            auto* q = gQuery[self];
            if (slot==0) return doQI(q,self,cpu,esp,retA,nxt);
            if (slot==1) return ret(q->AddRef(),1); if (slot==2) return ret(1,1); if (slot==3) return retDev();
            if (slot==4) return ret(q->GetType(),1); if (slot==5) return ret(q->GetDataSize(),1); if (slot==6) return ret(q->Issue(arg(1)),2);
            if (slot==7) { uint32_t sz=arg(2); std::vector<uint8_t> b(sz,0); HRESULT hr=q->GetData(sz?b.data():nullptr,sz,arg(3)); if(hr==S_OK&&sz&&arg(1)>=0x10000u) cpu->writeGuestMemory(arg(1),b.data(),sz); return ret(hr,4); }
        }
        if (iface == 13 && gCube.count(self)) {
            auto* ct = gCube[self];
            if (slot==0) return doQI(ct,self,cpu,esp,retA,nxt);
            if (slot==1) return ret(ct->AddRef(),1); if (slot==2) return ret(1,1); if (slot==3) return retDev();
            if (slot==10) return ret(ct->GetType(),1); if (slot==13) return ret(ct->GetLevelCount(),1);
            if (slot==17) { D3DSURFACE_DESC d{}; HRESULT hr=ct->GetLevelDesc(arg(1),&d); if(SUCCEEDED(hr)&&arg(2)>=0x10000u) cpu->writeGuestMemory(arg(2),&d,sizeof(d)); return ret(hr,3); }
            if (slot==18) { IDirect3DSurface9* s=nullptr; HRESULT hr=ct->GetCubeMapSurface((D3DCUBEMAP_FACES)arg(1),arg(2),&s); if(SUCCEEDED(hr)&&s&&arg(3)>=0x10000u){uint32_t g=wrap(s,VT_SURF,17,"IDirect3DSurface9",gSurf,cpu,ag,rs); cpu->writeGuestMemory(arg(3),&g,4);} return ret(hr,4); }
            if (slot==19) { RECT rc{}; bool hrR=rdRect(cpu,arg(4),rc); D3DLOCKED_RECT lr{}; HRESULT hr=ct->LockRect((D3DCUBEMAP_FACES)arg(1),arg(2),&lr,hrR?&rc:nullptr,arg(5)); if(SUCCEEDED(hr)&&arg(3)>=0x10000u){ D3DSURFACE_DESC d{}; ct->GetLevelDesc(arg(2),&d); uint32_t h=hrR?std::max<uint32_t>(1,rc.bottom-rc.top):std::max(1u,d.Height); uint32_t rows=isBC(d.Format)?std::max(1u,(h+3)/4):h; uint64_t k=((uint64_t)self<<16)|((arg(1)&0xFu)<<8)|(arg(2)&0xFFu); GuestLR glr{(int32_t)lr.Pitch, beginLock(k,lr.pBits,std::max<INT>(0,lr.Pitch)*rows,arg(5),cpu,ag)}; cpu->writeGuestMemory(arg(3),&glr,sizeof(glr)); } return ret(hr,6); }
            if (slot==20) { uint64_t k=((uint64_t)self<<16)|((arg(1)&0xFu)<<8)|(arg(2)&0xFFu); endLock(k,cpu); return ret(ct->UnlockRect((D3DCUBEMAP_FACES)arg(1),arg(2)),3); }
        }
        return false;
    }
#endif
};
D3D9GuestBridge::D3D9GuestBridge() : m_impl(std::make_unique<Impl>()) {}
D3D9GuestBridge::~D3D9GuestBridge() = default;
bool D3D9GuestBridge::handleDirect3DCreate9(IX86CPU* cpu, uint32_t esp, uint32_t retA, uint32_t& nxt, const GuestAllocFn& ag, const RegisterSymFn& rs) {
#ifndef SH3_HAS_DXVK
    (void)cpu;(void)esp;(void)retA;(void)nxt;(void)ag;(void)rs; return false;
#else
    if (!m_impl->d3d9) {
        m_impl->d3d9 = Direct3DCreate9(D3D_SDK_VERSION);
        if (m_impl->d3d9) {
            uint32_t vt = m_impl->ensureVt(VT_D3D9, 17, "IDirect3D9", cpu, ag, rs);
            m_impl->d3d9G = ag(16);
            if (vt && m_impl->d3d9G) { cpu->writeGuestMemory(m_impl->d3d9G, &vt, 4); m_impl->p2g[m_impl->d3d9] = m_impl->d3d9G; }
        }
    }
    cpu->writeRegister(X86Reg::EAX, m_impl->d3d9G); cpu->writeRegister(X86Reg::ESP, esp + 8u); nxt = retA; return true;
#endif
}
bool D3D9GuestBridge::handleVtableThunk(uint32_t addr, IX86CPU* cpu, uint32_t esp, uint32_t retA, uint32_t& nxt, const GuestAllocFn& ag, const RegisterSymFn& rs) {
#ifndef SH3_HAS_DXVK
    (void)addr;(void)cpu;(void)esp;(void)retA;(void)nxt;(void)ag;(void)rs; return false;
#else
    if (addr >= VT_D3D9 && addr < VT_DEV)  return m_impl->doD3D9((addr - VT_D3D9) >> 2, cpu, esp, retA, nxt, ag, rs);
    if (addr >= VT_DEV  && addr < VT_SURF) return m_impl->doDev((addr - VT_DEV) >> 2, cpu, esp, retA, nxt, ag, rs);
    if (addr >= VT_SURF && addr < 0x7000CE00u) return m_impl->doChild((addr - VT_D3D9) >> 8, ((addr - VT_D3D9) & 0xFFu) >> 2, cpu, esp, retA, nxt, ag, rs);
    return false;
#endif
}
std::string D3D9GuestBridge::statusSummary() const {
#ifndef SH3_HAS_DXVK
    return "";
#else
    if (!m_impl->d3d9) return "";
    std::ostringstream ss; ss << "D3D9=REAL_DXVK | Dev=" << (m_impl->dev?"OK":"NONE");
    if (m_impl->devHr != 0xFFFFFFFFu) { char b[32]; snprintf(b, sizeof(b), "(hr=0x%X,%ux%u)", m_impl->devHr, m_impl->devW, m_impl->devH); ss << b; }
    ss << " | Tex=" << m_impl->cntTex << " VB=" << m_impl->cntVB << " IB=" << m_impl->cntIB << " VS=" << m_impl->cntVS << " PS=" << m_impl->cntPS << " | Clear=" << m_impl->cntClear << " Draw=" << m_impl->cntDraw << " Present=" << m_impl->cntPresent;
    return ss.str();
#endif
}
