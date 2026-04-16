#include "block.h"
#include "message.h"
#include "node.h"
#include "server.h"
#include "transaction.h"
#include "util.h"
#include "validation.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

unsigned char *get_public_key(unsigned char *buff) {
  unsigned char *public_key;
  public_key = malloc(32);
  memcpy(public_key, buff, 32);
  return public_key;
}

int mempool_contains(mempool *pool, transaction *tx) {
  for (int i = 0; i < pool->tx_count; i++) {
    if (memcmp(pool->tx[i].signature, tx->signature, 64) == 0) {
      return 0;
    }
  }
  return 1;
}

int handle_handshake(unsigned char *buff, struct pollfd client_fd,
                     state *current_state) {
  unsigned char *public_key = get_public_key(buff);
  unsigned char payload[8];
  // Write response + send
  uint64_t balance = get_balance(public_key, current_state);

  balance = htonll(balance);

  // Write balance to response
  memcpy(payload, &balance, 8);
  unsigned char res[8 + 5];
  create_message(INIT_BALANCE, sizeof(uint64_t), payload, res);
  send_message(sizeof(res), res, client_fd.fd);
  free(public_key);
  return 0;
}

int handle_tx(unsigned char *payload, node_ctx *ctx) {
  Reader r = {payload, payload + TX_SIZE};
  transaction *tx = malloc(sizeof(transaction));
  deserialize_tx(&r, tx);
  // TODO: Add validation for received data...
  if (verify_transaction(payload, tx) != 1) {
    printf("Invalid signature.\n");
    return 1;
  }
  if (ctx->mempool->tx_count >= ctx->mempool->capacity) {
    printf("Mempool full\n");
    return 1;
  }
  // Check we don't already have this transaction
  if (mempool_contains(ctx->mempool, tx) == 0) {
    printf("We already have this tx...\n");
    return 1;
  }
  account *from = get_account(ctx->current_state, tx->from);
  if (validate_tx(tx, ctx->current_state, from, ctx->current_block) == 1) {
    return 1;
  }
  int mempool_count = ctx->mempool->tx_count;
  ctx->mempool->tx[mempool_count] = *tx;
  ctx->mempool->tx_count++;
  broadcast_tx(ctx, tx);
  return 0;
}

int handle_block_proposal(unsigned char *payload, node_ctx *ctx, int length) {
  block *new_block = malloc(sizeof(block));
  if (deserialize_block(payload, length, new_block) == 1) {
    return 1;
  }
  if (verify_block(payload, new_block, length) != 1) {
    printf("Invalid signature...\n");
    free(new_block);
    return 1;
  };
  if (validate_block(new_block, ctx->current_block, ctx->current_state) != 1) {
    printf("Invalid block\n");
    free(new_block);
    return 1;
  }
  free(ctx->current_block->transactions);
  free(ctx->current_block);
  ctx->current_block = new_block;
  printf("Valid block!\n");
  return 0;
}
