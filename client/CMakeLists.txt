add_library(client_lib lib/client.c lib/network.c lib/transaction.c lib/command.c)
target_include_directories(client_lib PUBLIC include)
target_link_libraries(client_lib PUBLIC ed25519_lib coin_protocol)

enable_testing()

add_executable(test_transaction tests/test_transaction.c)
target_link_libraries(test_transaction PRIVATE client_lib)
add_test(NAME test_transaction COMMAND test_transaction)

add_executable(client src/main.c)
target_link_libraries(client PRIVATE client_lib ed25519_lib coin_protocol ${SODIUM_LIBRARIES})
target_include_directories(client PRIVATE ${SODIUM_INCLUDE_DIRS})
