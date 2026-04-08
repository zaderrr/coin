#include "client.h"
#include "ed25519.h"
#include <dirent.h>
#include <limits.h>
#include <message.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

int main() {
  if (sodium_init() < 0)
    return 1;
  Wallet *wallet = malloc(sizeof(Wallet));
  init_wallet(wallet);
  int client_fd = connect_to_node(wallet->public_key);
  struct pollfd srv;
  srv.fd = client_fd;
  srv.events = POLLIN;
  while (1) {
    int listen = listen_to_node(&srv);
  }
}
