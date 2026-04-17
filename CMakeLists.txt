cmake_minimum_required(VERSION 3.10)
project(PQC_Project LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_COLOR_DIAGNOSTICS ON)

set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
set(OQS_USE_OPENSSL OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

add_subdirectory(extern/liboqs)

add_executable(PQC_Project
    src/cli/main.cpp
    src/core/kyber.cpp
    src/core/dilithium.cpp
    src/core/aes_gcm.cpp
    src/vault/pqc_format.cpp
    src/vault/vault.cpp
    src/messenger/handshake.cpp
    src/messenger/server.cpp
)

target_include_directories(PQC_Project PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    build/extern/liboqs/include
)

target_link_libraries(PQC_Project PRIVATE
    oqs
)

find_package(OpenSSL REQUIRED)

target_link_libraries(PQC_Project PRIVATE
    oqs
    OpenSSL::SSL
    OpenSSL::Crypto
    ws2_32
)