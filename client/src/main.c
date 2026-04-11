#include "block.h"
#include "client.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <limits.h>
#include <message.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

int get_peers(Peer **peers) {
  Peer *p = malloc(sizeof(Peer) * 2);
  p[0].IP = inet_addr("127.0.0.1");
  p[0].PORT = 8080;
  p[1].IP = inet_addr("127.0.0.1");
  p[1].PORT = 8090;
  *peers = p;
  return 0;
}

int main(int argc, char *args[]) {
  if (sodium_init() < 0)
    return 1;
  Wallet *wallet = malloc(sizeof(Wallet));
  char wallet_loc[512];
  if (argc > 1) {
    if (strcmp(args[1], "--wallet") == 0) {
      printf("Loading specified wallet\n");
      memcpy(wallet_loc, args[2], strlen(args[2]));
    }
  }
  if (init_wallet(wallet, wallet_loc) == 1) {
    printf("Error initializing wallet\n");
    return 1;
  }
  char buff[128];
  Peer *peers;
  printf("Wallet: ");
  print_public_key(wallet->public_key);
  get_peers(&peers);
  int client_fd = connect_to_node(peers[0], wallet->public_key);
  struct pollfd fds[2];
  fds[0].fd = client_fd;
  fds[0].events = POLLIN;
  fds[1].fd = STDIN_FILENO;
  fds[1].events = POLLIN;
  while (1) {
    int ready = poll(fds, 2, -1);
    if (ready < 0) {
      perror("poll");
      return 1;
    }
    if ((fds[0].revents & POLLIN)) {
      peer_message(&fds[0]);
    }
    if ((fds[1].revents & POLLIN)) {
      command *cmd = malloc(sizeof(command));
      int res = listen_for_command(&fds[1], cmd);
      if (res == 0) {
        // Do something with command...
        execute_command(cmd, fds[0].fd, wallet);
        free(cmd->args);
      }
      free(cmd);
    }
  }
}
