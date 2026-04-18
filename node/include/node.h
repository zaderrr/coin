#include "block.h"
#include "state.h"
#include "stdbool.h"
#include "wallet.h"

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
  block *current_block;
} node_ctx;

typedef struct {
  bool is_validator;
  uint16_t port;
  unsigned char *wallet_loc;
} config;

block build_next_block(block *previous_block, node_ctx *ctx);
int read_args(int count, char **args, config *out);
int init_validator(node_ctx *ctx, unsigned char *wallet_loc);
node_ctx init_context();
void display_state(node_ctx *ctx);
#endif
