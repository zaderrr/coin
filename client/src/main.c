#include "client.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <limits.h>
#include <message.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdint.h>
#include <stdlib.h>
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

int main() {
  if (sodium_init() < 0)
    return 1;
  Wallet *wallet = malloc(sizeof(Wallet));
  init_wallet(wallet);
  char buff[128];
  Peer *peers;

  printf("Wallet: 0x");
  for (size_t i = 0; i < 32; i++) {
    printf("%02x", wallet->public_key[i]);
  }
  printf("\n");
  get_peers(&peers);
  int client_fd = connect_to_node(peers[0], wallet->public_key);
  struct pollfd srv;
  srv.fd = client_fd;
  srv.events = POLLIN;
  while (1) {
    int listen = listen_to_node(&srv);
  }
}
