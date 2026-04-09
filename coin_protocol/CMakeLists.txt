add_library(coin_protocol SHARED
  src/message.c
  src/block.c
)

target_include_directories(coin_protocol PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(coin_protocol PUBLIC ${SODIUM_LIBRARIES})
target_include_directories(coin_protocol PUBLIC ${SODIUM_INCLUDE_DIRS})
