add_library(node_lib lib/node.c)
target_include_directories(node_lib PUBLIC include)
target_link_libraries(node_lib PUBLIC ed25519_lib coin_protocol)

add_executable(node src/main.c)
target_link_libraries(node PRIVATE node_lib ed25519_lib coin_protocol ${SODIUM_LIBRARIES})
target_include_directories(node PRIVATE ${SODIUM_INCLUDE_DIRS})

