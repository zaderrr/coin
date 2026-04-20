#include "block.h"
#include "state.h"
#include "stdbool.h"
#include "wallet.h"
#include <stdint.h>

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

typedef enum {
  INIT,
  READY,
  SYNCING,
} node_state;

typedef struct chain_node {
  struct chain_node *next_node;
  struct chain_node *previous_node;
  block *block;
} chain_node;

typedef struct {
  chain_node *start;
  chain_node *end;
  uint64_t count;
} chain;

typedef struct {
  uint64_t last_progress;
  uint64_t last_received_height;
  int tip_confirmations;
  Peer confirming_peers[5];
  bool confirming;
  int confirming_peer_count;
} sync_ctx;

typedef struct {
  state *current_state;
  PeerManager *peer_manager;
  mempool *mempool;
  Wallet *wallet;
  bool is_validator;
  block *current_block;
  node_state state;
  uint64_t target_height;
  chain *chain;
  sync_ctx *sync;
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
int add_node(node_ctx *ctx, block *next_block);
void display_state(node_ctx *ctx);
#endif
