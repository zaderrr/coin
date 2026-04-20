#include "block.h"
#include "merkle.h"
#include "message.h"
#include "node.h"
#include "server.h"
#include "state.h"
#include "transaction.h"
#include "util.h"
#include "validation.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

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
  add_node(ctx, new_block);
  unsigned char send_buff[length + 5];
  create_message(BLOCK_PROPOSAL, length, payload, send_buff);
  broadcast_message(send_buff, length + 5, ctx->peer_manager);
  display_state(ctx);
  return 0;
}

int compare_heights(const void *a, const void *b) {
  uint64_t *height_a = (uint64_t *)a;
  uint64_t *height_b = (uint64_t *)b;
  if (*height_a < *height_b)
    return -1;
  if (*height_a > *height_b)
    return 1;
  return 0;
}

int handle_get_blocks(Message *message, node_ctx *ctx, int fd) {
  Reader r = {message->payload,
              message->payload + message->header->payload_len};

  uint64_t num_blocks = 0;

  READ_FIELD(&r, num_blocks, sizeof(uint64_t));
  num_blocks = htonll(num_blocks);

  uint64_t block_heights[num_blocks];

  for (int i = 0; i < num_blocks; i++) {
    READ_FIELD(&r, block_heights[i], sizeof(uint64_t));
    block_heights[i] = htonll(block_heights[i]);
    if (block_heights[i] > ctx->current_block->height) {
      block_heights[i] = 0;
    }
  }

  qsort(block_heights, num_blocks, sizeof(uint64_t), compare_heights);

  block *requested_blocks[num_blocks];
  uint64_t retrieved = 0;

  chain_node *current_node = ctx->chain->start;

  while (retrieved != num_blocks) {
    if (current_node->block->height == block_heights[retrieved]) {
      requested_blocks[retrieved] = current_node->block;
      retrieved++;
    }
    if (current_node->next_node == NULL) {
      printf("height doesn't exist....\n");
      break;
    }
    current_node = current_node->next_node;
  }

  printf("Found %lu blocks\n", num_blocks);

  uint64_t total_size = 0;
  for (int i = 0; i < num_blocks; i++) {
    total_size += get_block_size(requested_blocks[i]);
  }
  // Num blocks + Total block size + numblocks * size
  total_size += sizeof(uint64_t) * (num_blocks + 1);
  unsigned char payload[total_size];
  uint64_t ptr = 0;

  // Insert number of blocks in request
  uint64_t net_num = htonll(num_blocks);
  memcpy(payload, &net_num, sizeof(num_blocks));
  ptr += sizeof(num_blocks);

  for (int i = 0; i < num_blocks; i++) {
    uint64_t size = get_block_size(requested_blocks[i]);
    uint64_t net_size = htonll(size);

    // Insert block size before block
    memcpy(payload + ptr, &net_size, sizeof(size));
    ptr += sizeof(size);

    serialize_block(requested_blocks[i], payload + ptr, true);
    ptr += size;
  }
  unsigned char out[total_size + 5];
  create_message(BLOCKS, total_size, payload, out);
  send_message(sizeof(out), out, fd);
  return 0;
}

int handle_blocks_received(Message *message, node_ctx *ctx) {
  Reader r = {message->payload,
              message->payload + message->header->payload_len};
  uint64_t num_blocks = 0;
  READ_FIELD(&r, num_blocks, sizeof(uint64_t));
  num_blocks = htonll(num_blocks);
  printf("Number of blocks returned: %lu\n", num_blocks);

  for (int i = 0; i < num_blocks; i++) {
    uint64_t size = 0;
    READ_FIELD(&r, size, sizeof(uint64_t));
    size = htonll(size);

    unsigned char t[size];
    READ_FIELD(&r, t, size);

    block *recv_block = malloc(sizeof(block));
    deserialize_block(t, size, recv_block);
    if (verify_block(t, recv_block, size) != 1) {
      free_block(recv_block);
      printf("Incorrect signature\n");
      return 1;
    };
    if (validate_block(recv_block, ctx->current_block, ctx->current_state) ==
        0) {
      printf("Not valid broski\n");
      return 1;
    }

    add_node(ctx, recv_block);
    printf("Valid block %lu\n", recv_block->height);
  }

  return 0;
}

int handle_get_block(Message *message, node_ctx *ctx, int fd) {
  int size = get_block_size(ctx->current_block);
  unsigned char serialized_block[size];
  serialize_block(ctx->current_block, serialized_block, true);
  unsigned char payload[size + 5];
  create_message(BLOCK, size, serialized_block, payload);
  send_message(sizeof(payload), payload, fd);
  return 0;
}

int handle_get_height(Message *message, node_ctx *ctx, int fd) {
  uint64_t height = htonll(ctx->current_block->height);
  unsigned char height_data[sizeof(uint64_t)];

  Writer w = {height_data, height_data + sizeof(uint64_t)};
  WRITE_FIELD(&w, height, sizeof(uint64_t));
  unsigned char out[sizeof(height_data) + 5];

  create_message(HEIGHT, sizeof(uint64_t), height_data, out);
  send_message(sizeof(out), out, fd);
  return 0;
}

int handle_height_response(Message *message, node_ctx *ctx) {
  uint64_t height = 0;
  Reader r = {message->payload,
              message->payload + message->header->payload_len};
  READ_FIELD(&r, height, sizeof(uint64_t));
  height = htonll(height);
  printf("Current height: %lu\n", height);
  ctx->target_height = height;
  return 0;
}

int handle_block_received(Message *message) {
  block recv_block = {0};
  deserialize_block(message->payload, message->header->payload_len,
                    &recv_block);
  return 0;
}
