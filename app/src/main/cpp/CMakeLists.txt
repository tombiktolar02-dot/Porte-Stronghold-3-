cmake_minimum_required(VERSION 3.22.1)
project("stronghold3wrapper")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENABLE_STAGE5_EXECUTION "Enable Stage 5 x86 execution environment" ON)
set(SH3_X86_BACKEND "STUB" CACHE STRING "x86 CPU Backend: STUB or UNICORN")

set(STAGE5_SOURCES
    win32_env_setup.cpp
    thunk_dispatcher.cpp
)

if(SH3_X86_BACKEND STREQUAL "STUB")
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

target_link_libraries(
    pe_arm64_bridge
    ${log-lib}
    ${android-lib}
)
