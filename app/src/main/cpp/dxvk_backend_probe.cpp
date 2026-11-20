#include "dxvk_backend_probe.h"
#include <sstream>

#ifdef SH3_HAS_DXVK
#define DXVK_NATIVE 1
#define NOMINMAX 1
#include <d3d9.h>

extern "C" void dxvkAndroidSetWindow(ANativeWindow* window);
extern "C" void* dxvkAndroidGetWindowHandle();
#endif

static ANativeWindow* g_sh3Window = nullptr;

void sh3DxvkSetNativeWindow(ANativeWindow* window) {
    if (g_sh3Window == window) return;
    if (g_sh3Window) {
        ANativeWindow_release(g_sh3Window);
        g_sh3Window = nullptr;
    }
    if (window) {
        ANativeWindow_acquire(window);
        g_sh3Window = window;
    }
#ifdef SH3_HAS_DXVK
    dxvkAndroidSetWindow(g_sh3Window);
#endif
}

std::string sh3DxvkRunLiveProbe() {
#ifndef SH3_HAS_DXVK
    return "[DXVK PROBE] Disabled (libdxvk_android.a not linked)";
#else
    std::ostringstream ss;
    IDirect3D9* d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (!d3d) {
        return "[DXVK PROBE] Direct3DCreate9 FAILED (Vulkan init error)";
    }
    D3DADAPTER_IDENTIFIER9 ident{};
    HRESULT hrId = d3d->GetAdapterIdentifier(0, 0, &ident);
    bool dxt1 = SUCCEEDED(d3d->CheckDeviceFormat(0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0, D3DRTYPE_TEXTURE, D3DFMT_DXT1));
    bool dxt3 = SUCCEEDED(d3d->CheckDeviceFormat(0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0, D3DRTYPE_TEXTURE, D3DFMT_DXT3));
    bool dxt5 = SUCCEEDED(d3d->CheckDeviceFormat(0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0, D3DRTYPE_TEXTURE, D3DFMT_DXT5));
    d3d->Release();

    ss << "[DXVK PROBE] GPU=" << (SUCCEEDED(hrId) ? ident.Description : "Unknown")
       << " | DXT1=" << (dxt1 ? "OK" : "SW_NEEDED")
       << " DXT3=" << (dxt3 ? "OK" : "SW_NEEDED")
       << " DXT5=" << (dxt5 ? "OK" : "SW_NEEDED")
       << " | Surface=" << (dxvkAndroidGetWindowHandle() ? "READY" : "NONE");
    return ss.str();
#endif
}
