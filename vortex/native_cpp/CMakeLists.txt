cmake_minimum_required(VERSION 3.20)
project(AegisVortexNative LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    add_executable(aegis_vortex_core aegis_vortex_core.cpp)
    target_link_libraries(aegis_vortex_core PRIVATE ntdll advapi32 user32)

    add_library(aegis_sleep_hook SHARED sleep_patch_hook.cpp)
    target_link_libraries(aegis_sleep_hook PRIVATE kernel32 ntdll)
endif()
