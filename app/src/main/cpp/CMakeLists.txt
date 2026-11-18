cmake_minimum_required(VERSION 3.22.1)
project("pe_arm64_bridge" LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(pe_arm64_bridge SHARED
    pe_arm64_bridge.cpp
)

find_library(log-lib log)
find_library(android-lib android)

target_link_libraries(pe_arm64_bridge
    ${log-lib}
    ${android-lib}
)
