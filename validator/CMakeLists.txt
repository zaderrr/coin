add_executable(validator src/main.c)
target_link_libraries(validator PRIVATE coin_protocol)
