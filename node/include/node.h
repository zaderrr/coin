#include "block.h"
#include "protocol.h"
#include "stdbool.h"
#include "wallet.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/poll.h>
#include <sys/types.h>
#ifndef NODE_H
#define NODE_H

typedef struct {
  uint32_t tx_count;
  uint32_t capacity;
  transaction *tx;
} mempool;

typedef struct {
  uint32_t peer_count;
  Peer *peers;
  struct pollfd *fds;
} PeerManager;

typedef struct {
  state *current_state;
  PeerManager *peer_manager;
  mempool *mempool;
  Wallet *wallet;
  bool is_validator;
} node_ctx;

typedef struct {
  bool is_validator;
  uint16_t port;
} config;

unsigned char *get_public_key(unsigned char *buff);
struct pollfd start_server(uint16_t port);
int accept_connections(node_ctx *ctx);
int read_friends(char *file_location, char *friends);
int listen_for_message(node_ctx *ctx);
block build_next_block(block *previous_block, node_ctx *ctx);
#endif
