# path: RankGateInsane/client/CMakeLists.txt
#
# RankGate Insane native client. C++20, MSVC, links libsodium (via vcpkg).
#
# Configure (from a Developer shell, libsodium installed via vcpkg):
#   cmake -S client -B client/build -G Ninja \
#         -DCMAKE_PREFIX_PATH=<vcpkg>/installed/x64-windows-static \
#         -DCMAKE_BUILD_TYPE=Release
#   cmake --build client/build
#
# Targets:
#   rg_core      static library: crypto + protocol + vm + challenge logic
#   rankgate     the challenge client executable
#   rg_selftest  byte-parity crypto self-test (CTest)
cmake_minimum_required(VERSION 3.20)
project(RankGateInsane LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Static MSVC runtime to match the static libsodium triplet (x64-windows-static).
cmake_policy(SET CMP0091 NEW)
if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  add_compile_options(/utf-8 /W3 /EHsc)
endif()

# libsodium: point -DSODIUM_ROOT at a vcpkg static install
# (<vcpkg>/installed/x64-windows-static), or rely on the vcpkg toolchain's
# find_package(unofficial-sodium).
if(DEFINED SODIUM_ROOT)
  add_library(sodium_ext STATIC IMPORTED)
  set_target_properties(sodium_ext PROPERTIES
    IMPORTED_LOCATION "${SODIUM_ROOT}/lib/libsodium.lib"
    INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_ROOT}/include")
  set(SODIUM_TARGET sodium_ext)
else()
  find_package(unofficial-sodium CONFIG REQUIRED)
  set(SODIUM_TARGET unofficial-sodium::sodium)
endif()

# ---------------------------------------------------------------------------
# Core static library (grows as modules land). Crypto first.
# ---------------------------------------------------------------------------
add_library(rg_core STATIC
  src/crypto/crypto.cpp
  src/crypto/kdf.cpp
  src/crypto/base64.cpp
  src/vm/vm.cpp
  src/vm/bytecode_blob.cpp
  src/net/binary_frame.cpp
  src/net/http_client.cpp
  src/net/protocol.cpp
  src/challenge/transcript.cpp
  src/challenge/license_format.cpp
  src/challenge/proof_builder.cpp
  src/protection/anti_debug.cpp
  src/protection/anti_tamper.cpp
  src/protection/decoys.cpp
)
target_include_directories(rg_core PUBLIC src)
target_link_libraries(rg_core PUBLIC ${SODIUM_TARGET} winhttp)
target_compile_definitions(rg_core PUBLIC SODIUM_STATIC=1)

# ---------------------------------------------------------------------------
# The challenge client executable.
# ---------------------------------------------------------------------------
add_executable(rankgate src/main.cpp src/app.cpp)
target_link_libraries(rankgate PRIVATE rg_core)

# ---------------------------------------------------------------------------
# Self-test (byte-parity vs Python). Registered with CTest.
# ---------------------------------------------------------------------------
enable_testing()
add_executable(rg_selftest tests/selftest_crypto.cpp)
target_link_libraries(rg_selftest PRIVATE rg_core)
add_test(NAME crypto_selftest COMMAND rg_selftest)

add_executable(rg_selftest_vm tests/selftest_vm.cpp)
target_link_libraries(rg_selftest_vm PRIVATE rg_core)
add_test(NAME vm_selftest COMMAND rg_selftest_vm)
