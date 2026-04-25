cmake_minimum_required(VERSION 3.20)
project(coin VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(FETCHCONTENT_BASE_DIR ${CMAKE_SOURCE_DIR}/third_party CACHE PATH "" FORCE)

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

FetchContent_Declare(
  blst
  GIT_REPOSITORY https://github.com/supranational/blst.git
  GIT_TAG        v0.3.15
)
FetchContent_MakeAvailable(blst)

set(BLST_LIB ${blst_SOURCE_DIR}/libblst.a)

# Run blst's own build.sh once; it knows where its own files are.
add_custom_command(
  OUTPUT  ${BLST_LIB}
  COMMAND ./build.sh
  WORKING_DIRECTORY ${blst_SOURCE_DIR}
  COMMENT "Building blst via its own build.sh"
  VERBATIM
)
add_custom_target(blst_build DEPENDS ${BLST_LIB})

# Expose blst as a linkable target with proper include paths.
add_library(blst STATIC IMPORTED GLOBAL)
set_target_properties(blst PROPERTIES
  IMPORTED_LOCATION             ${BLST_LIB}
  INTERFACE_INCLUDE_DIRECTORIES ${blst_SOURCE_DIR}/bindings
)
add_dependencies(blst blst_build)

add_subdirectory(coin_protocol)
add_subdirectory(client)
add_subdirectory(node)
target_link_libraries(coin_protocol PUBLIC blst)
