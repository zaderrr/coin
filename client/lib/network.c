#include "message.h"
#include "protocol.h"
#include "wallet.h"
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PUB_KEY_LEN 32

int connect_to_node(Peer peer, unsigned char *public_key) {
  int status, valread, client_fd;
  struct sockaddr_in serv_addr;
  if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Socket creation error \n");
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(peer.PORT);
  serv_addr.sin_addr.s_addr = peer.IP;

  if ((status = connect(client_fd, (struct sockaddr *)&serv_addr,
                        sizeof(serv_addr))) < 0) {
    printf("\nConnection Failed \n");
    return -1;
  }
  unsigned char buffer[PUB_KEY_LEN + 5];
  // Write public key to buffer and send
  create_message(HANDSHAKE, 32, public_key, buffer);
  send_message(sizeof(buffer), buffer, client_fd);
  return client_fd;
}
int handle_init_balance(unsigned char *balance, struct pollfd client_fd,
                        Wallet *wallet) {
  uint64_t bal = read_uint_64(balance);
  wallet->balance = bal;
  printf("Balance: %lu\n", bal);
  return 0;
}
int handle_decoded(Message *message, struct pollfd client_fd, Wallet *wallet) {
  switch (message->header->type) {
  case INIT_BALANCE: {
    handle_init_balance(message->payload, client_fd, wallet);
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
    buf[n] = '\0';
    Message *message = malloc(sizeof(Message));
    decode_message(buf, &message);
    handle_decoded(message, *srv, wallet);
    free(message->payload);
    free(message->header);
    free(message);
  }
  return 0;
}
