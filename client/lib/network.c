#include "message.h"
#include "util.h"
#include "wallet.h"
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int connect_to_node(Peer *peer) {
  int status, valread, client_fd;
  struct sockaddr_in serv_addr;
  if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Socket creation error \n");
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(peer->PORT);
  serv_addr.sin_addr.s_addr = peer->IP;

  if ((status = connect(client_fd, (struct sockaddr *)&serv_addr,
                        sizeof(serv_addr))) < 0) {
    printf("\nConnection Failed \n");
    return -1;
  }
  return client_fd;
}

int send_balance_request(int fd, Wallet *wallet) {
  unsigned char payload[32] = {0};
  unsigned char out[32 + 5];

  Writer w = {payload, payload + 32};
  WRITE_FIELD(&w, *wallet->public_key, 32);

  create_message(HANDSHAKE, 32, payload, out);
  send_message(32 + 5, out, fd);
  return 0;
}

int handle_init_balance(unsigned char *balance, struct pollfd client_fd,
                        Wallet *wallet) {
  Reader r = {balance, balance + sizeof(uint64_t) * 2};
  READ_FIELD(&r, wallet->balance, sizeof(uint64_t));
  READ_FIELD(&r, wallet->nonce, sizeof(uint64_t));

  wallet->balance = htonll(wallet->balance);
  wallet->nonce = htonll(wallet->nonce);

  printf("Balance: %lu\n", wallet->balance);
  printf("Nonce: %lu\n", wallet->nonce);
  return 0;
}
int handle_decoded(Message *message, struct pollfd client_fd, Wallet *wallet) {

  switch (message->header->type) {
  case INIT_BALANCE: {
    int b = handle_init_balance(message->payload, client_fd, wallet);
  }
  default: {
    break;
  }
  }
  return 0;
}

int peer_message(struct pollfd *srv, Wallet *wallet) {
  unsigned char buf[4096];
  ssize_t n = recv(srv->fd, buf, sizeof(buf), 0);
  if (n <= 0) {
    close(srv->fd);
  } else {

    Message *message = malloc(sizeof(Message));
    decode_message(buf, &message);
    handle_decoded(message, *srv, wallet);
    free(message->payload);
    free(message->header);
    free(message);
  }
  return 0;
}
