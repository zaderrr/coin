#include "block.h"
#include "merkle.h"
#include "message.h"
#include "node.h"
#include "server.h"
#include "state.h"
#include "transaction.h"
#include "util.h"
#include "validation.h"
#include <blst.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define MAX_BLOCKS_PER_REQUEST 500
#define VOTE_SIZE 44 + 48

int serialize_vote(Vote *vote, uint8_t *out) {
  Writer w = {out, out + 44 + 48};

  uint64_t height_n = htonll(vote->height);
  uint32_t type_n = htonl(vote->type);

  WRITE_FIELD(&w, height_n, sizeof(vote->height));
  WRITE_FIELD(&w, type_n, sizeof(vote->type));
  WRITE_FIELD(&w, vote->ident, sizeof(vote->ident));
  WRITE_FIELD(&w, vote->signature, sizeof(vote->signature));

  return 0;
}

int mempool_contains(mempool *pool, transaction *tx) {
  for (int i = 0; i < pool->tx_count; i++) {
    if (memcmp(pool->tx[i]->signature, tx->signature, 64) == 0) {
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

  unsigned char res[16 + HEADER_SIZE];
  create_message(INIT_BALANCE, sizeof(uint64_t) * 2, payload, res);

  send_message(sizeof(res), res, client_fd.fd);

  return 0;
}

int handle_tx(Message *message, node_ctx *ctx) {
  Reader r = {message->payload,
              message->payload + message->header->payload_len};

  int tx_size = 0;
  READ_FIELD(&r, tx_size, sizeof(tx_size));
  tx_size = ntohl(tx_size);
  int32_t body_size = tx_size - TX_WIRE_FIXED_SIZE;
  size_t mem_size = sizeof(transaction) + body_size;
  transaction *tx = calloc(1, mem_size);

  if (deserialize_tx(&r, tx) != 0) {
    return 1;
  }

  if (verify_transaction(message->payload, tx) != 1) {
    return 1;
  }

  if (ctx->mempool->tx_count >= ctx->mempool->capacity) {
    return 1;
  }

  // Check we don't already have this transaction
  if (mempool_contains(ctx->mempool, tx) == 0) {
    return 1;
  }

  int mempool_count = ctx->mempool->tx_count;
  ctx->mempool->tx[mempool_count] = tx;
  ctx->mempool->tx_count++;
  broadcast_tx(ctx, message->payload, tx_size);
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

int sign_vote(Vote *vote, Wallet *wallet) {
  blst_p1 sig;
  blst_p1 hash;

  blst_scalar sk_scalar;
  blst_scalar_from_bendian(&sk_scalar, wallet->bls_sk);

  char *DST = "COIN_VOTE_COMMIT_V1";

  uint8_t vote_hash[44];

  Writer w = {vote_hash, vote_hash + sizeof(vote_hash)};
  WRITE_FIELD(&w, vote->height, sizeof(vote->height));
  WRITE_FIELD(&w, vote->type, sizeof(vote->type));
  WRITE_FIELD(&w, vote->ident, sizeof(vote->ident));

  blst_hash_to_g1(&hash, vote_hash, sizeof(vote_hash), (unsigned char *)DST,
                  strlen(DST), NULL, 0);

  blst_sign_pk_in_g2(&sig, &hash, &sk_scalar);

  blst_p1_compress(vote->signature, &sig);

  explicit_bzero(&sk_scalar, sizeof(sk_scalar));

  return 0;
}

int verify_vote(Vote *vote, unsigned char *bls_pk, unsigned char *vote_bytes) {
  blst_p1_affine sig;
  blst_p2_affine pk;

  blst_p2_uncompress(&pk, bls_pk);
  blst_p1_uncompress(&sig, vote->signature);

  char *DST = "COIN_VOTE_COMMIT_V1";
  BLST_ERROR res =
      blst_core_verify_pk_in_g2(&pk, &sig, true, vote_bytes, VOTE_SIZE,
                                (unsigned char *)DST, strlen(DST), NULL, 0);
  if (res == BLST_SUCCESS) {
    return 0;
  }
  return 1;
}

int create_vote(block *vote_block, Wallet *wallet, Vote *out) {
  Vote block_vote = {0};
  block_vote.height = vote_block->height;
  block_vote.type = COMMIT;

  uint8_t block_hash[32];
  hash_block(vote_block, block_hash);
  memcpy(block_vote.ident, block_hash, sizeof(block_hash));

  sign_vote(&block_vote, wallet);
  *out = block_vote;
  return 0;
};

int handle_block_proposal(unsigned char *payload, node_ctx *ctx, int length) {
  block *new_block = malloc(sizeof(block));

  if (deserialize_block(payload, length, new_block) == 1) {
    free_block(new_block);
    return 1;
  }

  if (verify_block(payload, new_block, length) != 1) {
    free_block(new_block);
    return 1;
  }

  if (validate_block(new_block, ctx->current_block, ctx->current_state) != 1) {
    free_block(new_block);
    return 1;
  }
  Vote *valid_vote = malloc(sizeof(Vote));
  create_vote(new_block, ctx->wallet, valid_vote);
  add_node(ctx, new_block);
  write_block_to_file(new_block);
  unsigned char send_buff[length + HEADER_SIZE];
  create_message(BLOCK_PROPOSAL, length, payload, send_buff);
  broadcast_message(send_buff, length + HEADER_SIZE, ctx->peer_manager);

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
  unsigned char *out = malloc(total_size + HEADER_SIZE);
  create_message(BLOCKS, total_size, payload, out);
  send_message(total_size + HEADER_SIZE, out, fd);
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
    write_block_to_file(recv_block);
  }
  return 0;
}

int handle_get_block(Message *message, node_ctx *ctx, int fd) {
  int size = get_block_size(ctx->current_block);
  unsigned char serialized_block[size];
  serialize_block(ctx->current_block, serialized_block, true);
  unsigned char payload[size + HEADER_SIZE];
  create_message(BLOCK, size, serialized_block, payload);
  send_message(sizeof(payload), payload, fd);
  return 0;
}

int handle_get_height(Message *message, node_ctx *ctx, int fd) {
  uint64_t height = htonll(ctx->current_block->height);
  unsigned char height_data[sizeof(uint64_t)];

  Writer w = {height_data, height_data + sizeof(uint64_t)};
  WRITE_FIELD(&w, height, sizeof(uint64_t));
  unsigned char out[sizeof(height_data) + HEADER_SIZE];

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
