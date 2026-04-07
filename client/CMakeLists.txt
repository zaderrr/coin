add_library(client_lib lib/client.c)
target_include_directories(client_lib PUBLIC include)
target_link_libraries(client_lib PUBLIC ed25519_lib coin_protocol)

add_executable(client src/main.c)
target_link_libraries(client PRIVATE client_lib ed25519_lib coin_protocol ${SODIUM_LIBRARIES})
target_include_directories(client PRIVATE ${SODIUM_INCLUDE_DIRS})

