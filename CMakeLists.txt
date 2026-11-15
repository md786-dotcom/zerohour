cmake_minimum_required(VERSION 3.20)
project(zerohour CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-Wall -Wextra)

option(ZH_ASAN "Build with AddressSanitizer + UBSan" OFF)
if(ZH_ASAN)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

if(APPLE)
  list(APPEND CMAKE_PREFIX_PATH /opt/homebrew/opt/openssl@3 /opt/homebrew/opt/libsodium /opt/homebrew/opt/googletest)
endif()
find_package(OpenSSL 3 REQUIRED)
find_package(GTest REQUIRED)
find_library(PCAP_LIB pcap REQUIRED)
find_path(SODIUM_INCLUDE sodium.h HINTS /opt/homebrew/opt/libsodium/include REQUIRED)
find_library(SODIUM_LIB sodium HINTS /opt/homebrew/opt/libsodium/lib REQUIRED)

# One library per module so each test target builds only what it tests.
add_library(zh_trw STATIC src/trw.cpp)
target_include_directories(zh_trw PUBLIC src)
add_library(zh_tls STATIC src/tls.cpp)
target_include_directories(zh_tls PUBLIC src)
target_link_libraries(zh_tls PUBLIC OpenSSL::Crypto)
add_library(zh_chainlog STATIC src/chainlog.cpp)
target_include_directories(zh_chainlog PUBLIC src ${SODIUM_INCLUDE})
target_link_libraries(zh_chainlog PUBLIC ${SODIUM_LIB})
add_library(zhcore STATIC src/sensor.cpp)
target_link_libraries(zhcore PUBLIC zh_trw zh_tls zh_chainlog ${PCAP_LIB})

add_executable(zerohour src/main.cpp src/serve.cpp)
target_link_libraries(zerohour PRIVATE zhcore)
target_compile_definitions(zerohour PRIVATE ZH_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

# Lab: real TLS 1.2 handshakes through OpenSSL memory BIOs, written to PCAP files.
add_executable(zh_lab lab/lab.cpp)
target_link_libraries(zh_lab PRIVATE OpenSSL::SSL OpenSSL::Crypto ${PCAP_LIB})
add_custom_target(pcaps
  COMMAND sh ${CMAKE_SOURCE_DIR}/lab/certs.sh ${CMAKE_SOURCE_DIR}/lab/certs
  COMMAND $<TARGET_FILE:zh_lab> ${CMAKE_SOURCE_DIR}/lab/certs ${CMAKE_SOURCE_DIR}/lab/pcaps
  DEPENDS zh_lab)

enable_testing()
include(GoogleTest)
foreach(t trw tls chainlog)
  add_executable(${t}_test tests/${t}_test.cpp)
  target_link_libraries(${t}_test PRIVATE zh_${t} GTest::gtest_main)
  gtest_discover_tests(${t}_test)
endforeach()
