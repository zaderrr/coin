cmake_minimum_required(VERSION 3.20)
project(coin VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

include(FetchContent)
FetchContent_Declare(
  ed25519
  GIT_REPOSITORY https://github.com/orlp/ed25519.git
  GIT_TAG master
)
FetchContent_MakeAvailable(ed25519)

add_library(ed25519_lib
  ${ed25519_SOURCE_DIR}/src/add_scalar.c
  ${ed25519_SOURCE_DIR}/src/fe.c
  ${ed25519_SOURCE_DIR}/src/ge.c
  ${ed25519_SOURCE_DIR}/src/key_exchange.c
  ${ed25519_SOURCE_DIR}/src/keypair.c
  ${ed25519_SOURCE_DIR}/src/sc.c
  ${ed25519_SOURCE_DIR}/src/seed.c
  ${ed25519_SOURCE_DIR}/src/sha512.c
  ${ed25519_SOURCE_DIR}/src/sign.c
  ${ed25519_SOURCE_DIR}/src/verify.c
)
target_include_directories(ed25519_lib PUBLIC ${ed25519_SOURCE_DIR}/src)
set_target_properties(ed25519_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)
add_subdirectory(coin_protocol)
add_subdirectory(client)
add_subdirectory(node)
