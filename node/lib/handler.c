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

#define MAX_BLOCKS_PER_REQUEST 500

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

int parse_get_blocks_request(Message *message, uint64_t *block_heights,
                             uint64_t *valid_count_out, node_ctx *ctx) {
  Reader r = {message->payload,
              message->payload + message->header->payload_len};
  uint64_t num_blocks = 0;
  READ_FIELD(&r, num_blocks, sizeof(uint64_t));
  num_blocks = htonll(num_blocks);
  if (num_blocks == 0 || num_blocks > MAX_BLOCKS_PER_REQUEST) {
    printf("Invalid num_blocks: %lu\n", num_blocks);
    return 1;
  }
  if (ctx->chain == NULL || ctx->chain->start == NULL) {
    printf("Chain is empty, cannot serve blocks\n");
    return 1;
  }
  bool height_valid[MAX_BLOCKS_PER_REQUEST] = {0};
  uint64_t valid_count = 0;
  for (uint64_t i = 0; i < num_blocks; i++) {
    uint64_t h;
    READ_FIELD(&r, h, sizeof(uint64_t));
    h = htonll(h);
    if (h <= ctx->current_block->height) {
      block_heights[valid_count] = h;
      height_valid[valid_count] = true;
      valid_count++;
    }
  }
  if (valid_count == 0) {
    printf("No valid heights requested\n");
    return 1;
  }
  qsort(block_heights, valid_count, sizeof(uint64_t), compare_heights);
  *valid_count_out = valid_count;
  return 0;
}

uint64_t find_blocks_by_height(node_ctx *ctx, uint64_t *block_heights,
                               uint64_t valid_count, block **requested_blocks) {
  uint64_t retrieved = 0;
  chain_node *current_node = ctx->chain->start;
  while (retrieved < valid_count && current_node != NULL) {
    if (current_node->block->height == block_heights[retrieved]) {
      requested_blocks[retrieved] = current_node->block;
      retrieved++;
      continue;
    }
    current_node = current_node->next_node;
  }
  return retrieved;
}

unsigned char *build_blocks_payload(block **requested_blocks,
                                    uint64_t retrieved,
                                    uint64_t *total_size_out) {
  uint64_t total_size = 0;
  for (uint64_t i = 0; i < retrieved; i++) {
    total_size += get_block_size(requested_blocks[i]);
  }
  total_size += sizeof(uint64_t) * (retrieved + 1);
  unsigned char *payload = malloc(total_size);
  if (!payload) {
    printf("Failed to allocate payload\n");
    return NULL;
  }
  uint64_t ptr = 0;
  uint64_t net_num = htonll(retrieved);
  // Insert number of blocks returned
  memcpy(payload, &net_num, sizeof(net_num));
  ptr += sizeof(net_num);
  for (uint64_t i = 0; i < retrieved; i++) {
    uint64_t size = get_block_size(requested_blocks[i]);
    uint64_t net_size = htonll(size);
    // Insert size of this block
    memcpy(payload + ptr, &net_size, sizeof(net_size));
    ptr += sizeof(net_size);
    serialize_block(requested_blocks[i], payload + ptr, true);
    ptr += size;
  }
  *total_size_out = total_size;
  return payload;
}

int send_blocks_response(unsigned char *payload, uint64_t total_size, int fd) {
  unsigned char *out = malloc(total_size + 5);
  create_message(BLOCKS, total_size, payload, out);
  send_message(total_size + 5, out, fd);
  free(payload);
  free(out);
  return 0;
}

int handle_get_blocks(Message *message, node_ctx *ctx, int fd) {
  uint64_t block_heights[MAX_BLOCKS_PER_REQUEST];
  uint64_t valid_count = 0;
  if (parse_get_blocks_request(message, block_heights, &valid_count, ctx) !=
      0) {
    return 1;
  }
  block *requested_blocks[MAX_BLOCKS_PER_REQUEST] = {0};
  uint64_t retrieved =
      find_blocks_by_height(ctx, block_heights, valid_count, requested_blocks);
  if (retrieved == 0) {
    printf("No requested blocks found in chain\n");
    return 1;
  }
  uint64_t total_size = 0;
  unsigned char *payload =
      build_blocks_payload(requested_blocks, retrieved, &total_size);
  if (!payload) {
    return 1;
  }
  return send_blocks_response(payload, total_size, fd);
}

int handle_blocks_received(Message *message, node_ctx *ctx) {
  Reader r = {message->payload,
              message->payload + message->header->payload_len};
  uint64_t num_blocks = 0;
  READ_FIELD(&r, num_blocks, sizeof(uint64_t));
  num_blocks = htonll(num_blocks);

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
  ctx->target_height = height;
  if (height == ctx->target_height) {
    ctx->sync->last_received_height = height;
    ctx->sync->tip_confirmations++;
  } else {
    ctx->sync->last_received_height = height;
    ctx->sync->tip_confirmations = 1;
    printf("Current chain height: %lu\n", height);
  }
  return 0;
}

int handle_block_received(Message *message) {
  block recv_block = {0};
  deserialize_block(message->payload, message->header->payload_len,
                    &recv_block);
  return 0;
}
