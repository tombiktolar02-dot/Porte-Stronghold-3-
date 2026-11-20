cmake_minimum_required(VERSION 3.22.1)
project("stronghold3wrapper")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENABLE_STAGE5_EXECUTION "Enable Stage 5 x86 execution environment" ON)

set(UNICORN_PREBUILT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/unicorn")
set(UNICORN_LIB_PATH "${UNICORN_PREBUILT_DIR}/lib/libunicorn.a")

set(DXVK_PREBUILT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/dxvk")
set(DXVK_LIB_PATH "${DXVK_PREBUILT_DIR}/lib/libdxvk_android.a")

if(NOT DEFINED SH3_X86_BACKEND)
    if(EXISTS "${UNICORN_LIB_PATH}")
        set(SH3_X86_BACKEND "UNICORN" CACHE STRING "x86 CPU Backend: STUB or UNICORN")
    else()
        set(SH3_X86_BACKEND "STUB" CACHE STRING "x86 CPU Backend: STUB or UNICORN")
    endif()
endif()

message(STATUS "SH3_X86_BACKEND = ${SH3_X86_BACKEND}")

set(STAGE5_SOURCES
    win32_env_setup.cpp
    thunk_dispatcher.cpp
    dxvk_backend_probe.cpp
    d3d9_guest_bridge.cpp
)

if(SH3_X86_BACKEND STREQUAL "UNICORN" AND EXISTS "${UNICORN_LIB_PATH}")
    list(APPEND STAGE5_SOURCES unicorn_x86_cpu.cpp)
else()
    list(APPEND STAGE5_SOURCES stub_x86_cpu.cpp)
endif()

add_library(
    pe_arm64_bridge
    SHARED
    pe_arm64_bridge.cpp
    ${STAGE5_SOURCES}
)

find_library(log-lib log)
find_library(android-lib android)
find_library(vulkan-lib vulkan)

set(BRIDGE_LIBS ${log-lib} ${android-lib})

if(SH3_X86_BACKEND STREQUAL "UNICORN" AND EXISTS "${UNICORN_LIB_PATH}")
    add_library(unicorn_static STATIC IMPORTED)
    set_target_properties(unicorn_static PROPERTIES IMPORTED_LOCATION "${UNICORN_LIB_PATH}")
    target_include_directories(pe_arm64_bridge PRIVATE "${UNICORN_PREBUILT_DIR}/include")
    list(APPEND BRIDGE_LIBS unicorn_static)
endif()

if(EXISTS "${DXVK_LIB_PATH}")
    message(STATUS "SH3_DXVK_BACKEND = ENABLED (${DXVK_LIB_PATH})")
    add_library(dxvk_android_static STATIC IMPORTED)
    set_target_properties(dxvk_android_static PROPERTIES IMPORTED_LOCATION "${DXVK_LIB_PATH}")
    target_compile_definitions(pe_arm64_bridge PRIVATE SH3_HAS_DXVK=1)
    target_include_directories(pe_arm64_bridge PRIVATE
        "${DXVK_PREBUILT_DIR}/include/native/windows"
        "${DXVK_PREBUILT_DIR}/include/native/directx"
    )
    list(APPEND BRIDGE_LIBS dxvk_android_static ${vulkan-lib})
endif()

target_link_libraries(pe_arm64_bridge ${BRIDGE_LIBS})
