# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.31)

project (NcaFinder)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED yes)

add_compile_options(-fsanitize=address)
add_link_options(-fsanitize=address)

# Fetch latest argparse
include(FetchContent)
FetchContent_Declare(
    argparse
    GIT_REPOSITORY https://github.com/p-ranav/argparse.git
)
FetchContent_MakeAvailable(argparse)

FetchContent_Declare(
    mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls
)
FetchContent_MakeAvailable(mbedtls)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(CMN_PLAT_SOURCE source/MultiLogger.posix.h source/MultiLogger.posix.cpp)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(CMN_PLAT_SOURCE source/MultiLogger.win32.h source/MultiLogger.win32.cpp)
else()
    message(FATAL_ERROR "Unsupported OS")
endif()

# TODO: Separate this into its own subdir?
add_library(CommonUtils
    source/Aes.h source/Aes.cpp
    source/AesCtrDecryptor.h source/AesCtrDecryptor.cpp
    source/AesCtrStorage.h source/AesCtrStorage.cpp
    source/BlockRecoverer.h source/BlockRecoverer.cpp
    source/ErrorCode.h source/ErrorCode.cpp
    source/FileStorage.h source/FileStorage.cpp
    source/HISha256Processor.h source/HISha256Processor.cpp
    source/IvfcProcessor.h source/IvfcProcessor.cpp
    source/ProgressBar.h source/ProgressBar.cpp
    source/NcaHeaders.h source/NcaHeaders.cpp
    source/NcaProcessor.h source/NcaProcessor.cpp
    source/PlaintextDecryptor.h source/PlaintextDecryptor.cpp
    source/SubDecryptor.h source/SubDecryptor.cpp
    source/SubStorage.h source/SubStorage.cpp
    ${CMN_PLAT_SOURCE}
)
target_link_libraries(CommonUtils PUBLIC MbedTLS::mbedtls)

add_executable (NcaFinder "source/NcaFinder.cpp")
target_link_libraries(NcaFinder PRIVATE argparse CommonUtils)

add_executable(NcaDumper "source/NcaDumper.cpp")
target_link_libraries(NcaDumper PRIVATE argparse CommonUtils)



# Add compiler options.
if(NOT WIN32)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    target_link_libraries(NcaFinder PRIVATE pthread)
endif()
