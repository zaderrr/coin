add_library(coin_protocol SHARED
  src/message.c
)

target_include_directories(coin_protocol PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)