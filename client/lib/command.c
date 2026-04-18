#include "command.h"
#include "transaction.h"
#include "wallet.h"
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <unistd.h>
int handle_command(char *cmd, command *command) {
  char *token = strtok(cmd, " \n");
  if (!token)
    return 1;
  if (strncmp(cmd, "balance", 7) == 0) {
    return 1;
  } else if (strcmp(token, "stake") == 0) {
    char *amount_str = strtok(NULL, " \n");
    if (!amount_str) {
      printf("Usage: stake <amount>\n");
      return 1;
    }

    char *endptr;
    uint64_t amount = strtoull(amount_str, &endptr, 10);

    if (*endptr != '\0') {
      printf("Amount is not a valid number\n");
      return 1;
    }

    command->type = STAKE;
    command->arg_count = 1;
    command->args = malloc(sizeof(char *) * 1);
    command->args[0] = strdup(amount_str);
    return 0;
  } else if (strcmp(token, "send") == 0) {
    char *amount_str = strtok(NULL, " \n");
    char *address_str = strtok(NULL, " \n");

    if (!amount_str || !address_str) {
      printf("Usage: send <amount> <address>\n");
      return 1;
    }

    char *endptr;
    uint64_t amount = strtoull(amount_str, &endptr, 10);

    if (*endptr != '\0') {
      printf("Amount is not a valid number\n");
      return 1;
    }

    for (int i = 0; i < 64; i++) {
      if (!isxdigit(address_str[i])) {
        printf("Invalid recipient address\n");
        return 1;
      }
    }

    unsigned char receiver[32];
    for (int i = 0; i < 32; i++) {
      sscanf(address_str + i * 2, "%2hhx", &receiver[i]);
    }

    command->type = SEND;
    command->arg_count = 2;
    command->args = malloc(sizeof(char *) * 2);
    command->args[0] = strdup(amount_str);
    command->args[1] = malloc(32);
    memcpy(command->args[1], receiver, 32);
    return 0;
  }
  return 1;
}

int listen_for_command(struct pollfd *infd, command *cmd) {
  char command[256];
  ssize_t n = read(STDIN_FILENO, command, sizeof(command) - 1);
  if (n > 0) {
    command[n] = '\0';
    return handle_command(command, cmd);
  }
  return 1;
}

void execute_command(command *cmd, int fd, Wallet *wallet) {
  if (cmd->type == SEND) {
    uint64_t amount = strtoull((const char *)cmd->args[0], NULL, 10);
    send_transaction(cmd->args[1], amount, fd, wallet, TX_TRANSFER);
    free(cmd->args[0]);
    free(cmd->args[1]);
  } else if (cmd->type == STAKE) {
    uint64_t amount = strtoull((const char *)cmd->args[0], NULL, 10);
    unsigned char null_addr[32] = {0};
    send_transaction(null_addr, amount, fd, wallet, TX_STAKE_DEPOSIT);
    free(cmd->args[0]);
  }
}
