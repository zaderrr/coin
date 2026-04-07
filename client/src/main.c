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

int handle_decoded(Message *message, struct pollfd client_fd) {
  switch (message->header->type) {
  case INIT_BALANCE: {
    handle_init_balance(message->payload, client_fd);
  }
  default: {
    break;
  }
  }
  return 0;
}

int get_password(char *password) {
  printf("Enter password: ");
  fgets(password, sizeof password, stdin);
  password[strcspn(password, "\n")] = '\0';
  return 1;
}

int main() {
  if (sodium_init() < 0)
    return 1;

  // Check if user has a wallet
  char walletLoc[512];
  const char *home = getenv("HOME");
  if (!home) {
    fprintf(stderr, "HOME not set\n");
    return 1;
  }
  snprintf(walletLoc, sizeof walletLoc, "%s/Documents/keys/wallet.coin", home);
  FILE *fptr;
  fptr = fopen(walletLoc, "rb");
  Wallet *wallet;
  wallet = malloc(sizeof(Wallet));
  char password[128];
  get_password(password);
  if (fptr == NULL) {
    printf("Creating wallet...\n");
    create_wallet(wallet, password);
  } else {
    decrypt_wallet(fptr, wallet, password);
  }
  int client_fd = connect_to_node(wallet->public_key);
  struct pollfd srv;
  srv.fd = client_fd;
  srv.events = POLLIN;
  while (1) {
    int ready = poll(&srv, 1, -1);
    if (ready < 0) {
      perror("poll");
      break;
    }
    if (!(srv.revents & POLLIN))
      continue;
    unsigned char buf[4096];
    ssize_t n = recv(srv.fd, buf, sizeof(buf), 0);
    if (n <= 0) {
      close(srv.fd);
    } else {
      buf[n] = '\0';
      printf("Message received\n");
      Message *message;
      decode_message(buf, &message);
      handle_decoded(message, srv);
      free(message->payload);
      free(message->header);
      free(message);
    }
  }
}
