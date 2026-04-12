#include "message.h"
#include "node.h"
#include "server.h"
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

// Read transaction from payload
transaction read_tx_from_buff(unsigned char *payload) {

  uint64_t amount_n = 0;
  uint64_t nonce_n = 0;

  // Acknowledged that this is very fragile
  transaction tx = {0};
  memcpy(&tx.type, payload, 1);
  memcpy(tx.from, payload + 1, 32);
  memcpy(tx.to, payload + 33, 32);
  memcpy(&amount_n, payload + 65, 8);
  memcpy(&nonce_n, payload + 73, 8);
  memcpy(tx.signature, payload + 81, 64);

  tx.amount = htonll(amount_n);
  tx.nonce = htonll(nonce_n);
  return tx;
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
  unsigned char res[1024];
  // Write response + send
  write_header(INIT_BALANCE, sizeof(uint64_t), res);
  uint64_t balance = get_balance(public_key, current_state);
  balance = htonll(balance);
  // Write balance to response
  memcpy(res + 5, &balance, 8);
  send(client_fd.fd, res, 1024, 0);
  free(public_key);
  return 0;
}

int handle_tx(unsigned char *payload, node_ctx *ctx) {
  transaction tx = read_tx_from_buff(payload);
  // TODO: Add validation for received data...
  if (verify_transaction(payload, &tx) != 1) {
    printf("Invalid signature.\n");
    return 1;
  }
  if (ctx->mempool->tx_count >= ctx->mempool->capacity) {
    printf("Mempool full\n");
    return 1;
  }
  // Check we don't already have this transaction
  if (mempool_contains(ctx->mempool, &tx) == 0) {
    printf("We already have this tx...\n");
    return 1;
  }
  if (validate_tx(&tx, ctx) == 1) {
    return 1;
  }
  int mempool_count = ctx->mempool->tx_count;
  ctx->mempool->tx[mempool_count] = tx;
  ctx->mempool->tx_count++;
  broadcast_tx(ctx, &tx);
  return 0;
}
