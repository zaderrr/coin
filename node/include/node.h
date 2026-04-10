#include "block.h"
#include "protocol.h"
#include "stdbool.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/poll.h>
#include <sys/types.h>
#ifndef NODE_H
#define NODE_H

typedef struct {
  transaction *tx;
  uint32_t tx_count;
  uint32_t capacity;
} mempool;

typedef struct {
  state *current_state;
  Peer *peers;
  uint32_t peer_count;
  mempool *mempool;
  bool is_validator;
  unsigned char *signing_key;
} node_ctx;

unsigned char *get_public_key(unsigned char *buff);
struct pollfd *start_server();
int accept_connections(struct pollfd *fds, int *nfds);
int read_friends(char *file_location, char *friends);
int listen_for_message(struct pollfd *fds, int *nfds, node_ctx ctx);
int decrypt_wallet(FILE *fptr, unsigned char *private_key, char *password);
#endif
