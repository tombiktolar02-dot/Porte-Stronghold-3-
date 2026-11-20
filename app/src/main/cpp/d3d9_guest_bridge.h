#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include "i_x86_cpu.h"

class D3D9GuestBridge {
public:
    using GuestAllocFn  = std::function<uint32_t(uint32_t)>;
    using RegisterSymFn = std::function<void(uint32_t, const std::string&)>;
    D3D9GuestBridge();
    ~D3D9GuestBridge();
    D3D9GuestBridge(const D3D9GuestBridge&) = delete;
    D3D9GuestBridge& operator=(const D3D9GuestBridge&) = delete;
    bool handleDirect3DCreate9(IX86CPU* cpu, uint32_t esp, uint32_t returnAddr, uint32_t& outNextEip, const GuestAllocFn& allocGuest, const RegisterSymFn& regSym);
    bool handleVtableThunk(uint32_t thunkAddr, IX86CPU* cpu, uint32_t esp, uint32_t returnAddr, uint32_t& outNextEip, const GuestAllocFn& allocGuest, const RegisterSymFn& regSym);
    std::string statusSummary() const;
private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};
