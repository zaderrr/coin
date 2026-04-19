#include "block.h"
#include "merkle.h"
#include "message.h"
#include "node.h"
#include "server.h"
#include "transaction.h"
#include "util.h"
#include "validation.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

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
  unsigned char public_key[32];

  Reader r = {buff, buff + 32};
  read_bytes(&r, public_key, 32);

  unsigned char payload[16];

  // Write response + send
  account *acc = get_account(current_state, public_key);
  if (acc == NULL) {
    printf("Account doesn't exist\n");
    return 1;
  }
  uint64_t balance = acc->balance;
  uint64_t nonce = acc->nonce;
  balance = htonll(balance);
  nonce = htonll(nonce);
  // Write balance to response

  Writer w = {payload, payload + (sizeof(uint64_t) * 2)};

  WRITE_FIELD(&w, balance, sizeof(uint64_t));
  WRITE_FIELD(&w, nonce, sizeof(uint64_t));

  unsigned char res[16 + 5];
  create_message(INIT_BALANCE, sizeof(uint64_t) * 2, payload, res);

  send_message(sizeof(res), res, client_fd.fd);

  return 0;
}

int handle_tx(unsigned char *payload, node_ctx *ctx) {
  Reader r = {payload, payload + TX_SIZE};
  transaction tx = {0};
  if (deserialize_tx(&r, &tx) != 0) {
    return 1;
  }
  // TODO: Add validation for received data...
  if (verify_transaction(payload, &tx) != 1) {
    return 1;
  }
  if (ctx->mempool->tx_count >= ctx->mempool->capacity) {
    return 1;
  }
  // Check we don't already have this transaction
  if (mempool_contains(ctx->mempool, &tx) == 0) {
    return 1;
  }
  account *from = get_account(ctx->current_state, tx.from);
  if (validate_tx(&tx, ctx->current_state, from, ctx->current_block) == 1) {
    return 1;
  }
  int mempool_count = ctx->mempool->tx_count;
  ctx->mempool->tx[mempool_count] = tx;
  ctx->mempool->tx_count++;
  broadcast_tx(ctx, &tx);
  return 0;
}

int free_block(block *block) {
  if (block == NULL) {
    return 1;
  }
  if (block->transactions != NULL) {
    free(block->transactions);
  }
  free(block);
  return 0;
}

int handle_block_proposal(unsigned char *payload, node_ctx *ctx, int length) {
  block *new_block = malloc(sizeof(block));
  if (deserialize_block(payload, length, new_block) == 1) {
    free_block(new_block);
    return 1;
  }
  if (verify_block(payload, new_block, length) != 1) {
    free_block(new_block);
    return 1;
  };
  if (validate_block(new_block, ctx->current_block, ctx->current_state) != 1) {
    free_block(new_block);
    return 1;
  }
  free_block(ctx->current_block);
  ctx->current_block = new_block;
  unsigned char send_buff[length + 5];
  create_message(BLOCK_PROPOSAL, length, payload, send_buff);
  broadcast_message(send_buff, length + 5, ctx->peer_manager);
  display_state(ctx);
  return 0;
}
