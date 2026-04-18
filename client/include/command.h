#include "wallet.h"
#include <sys/poll.h>
#ifndef CLIENT_COMMAND_H
#define CLIENT_COMMAND_H
enum command_type {
  BALNCE,
  SEND,
  STAKE,
  PEERS,
};

typedef struct {
  enum command_type type;
  int arg_count;
  unsigned char **args;
} command;

void execute_command(command *cmd, int fd, Wallet *wallet);
int listen_for_command(struct pollfd *infd, command *cmd);
#endif
