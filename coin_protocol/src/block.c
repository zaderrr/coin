#include "block.h"
#include "sodium.h"
#include <stdlib.h>
#include <string.h>

int compute_merkle_root(uint8_t **leaves, uint32_t count, uint8_t *root,
                        size_t leaf_size) {
  if (count == 0) {
    memset(root, 0, 32);
    return 1;
  }

  // hash each leaf
  uint8_t *hashes = malloc(count * 32);
  for (uint32_t i = 0; i < count; i++) {
    crypto_hash_sha256(hashes + i * 32, leaves[i], leaf_size);
  }

  // pair and hash up the tree
  uint32_t n = count;
  while (n > 1) {
    for (uint32_t i = 0; i < n; i += 2) {
      if (i + 1 < n) {
        // hash left || right
        uint8_t pair[64];
        memcpy(pair, hashes + i * 32, 32);
        memcpy(pair + 32, hashes + (i + 1) * 32, 32);
        crypto_hash_sha256(hashes + (i / 2) * 32, pair, 64);
      } else {
        // odd one out, promote it
        memcpy(hashes + (i / 2) * 32, hashes + i * 32, 32);
      }
    }
    n = (n + 1) / 2;
  }
  memcpy(root, hashes, 32);
  free(hashes);
  return 0;
}

uint8_t *state_to_leaf(unsigned char *state) {
  size_t leaf_size = 32 + 8 + 8;
  uint8_t *leaf = malloc(leaf_size);
  memcpy(leaf, state, 32);
  memcpy(leaf + 32, state + 32, 8);
  memcpy(leaf + 40, state + 32 + 8, 8);
  return leaf;
}

void free_leaves(unsigned char **leaves, size_t count) {
  if (!leaves)
    return;
  for (size_t i = 0; i < count; i++) {
    free(leaves[i]);
  }
  free(leaves);
}

block build_genesis(account *accounts, validator *validators) {
  block genesis = {
      .height = 0,
      .prev_hash = {0},
      .timestamp = 233366400,
      .tx_count = 0,
      .transactions = NULL,
      .proposer = {0},
      .signature = {0},
      .tx_root = {0},
  };
  size_t leaf_size = 32 + 8 + 8;
  uint8_t *acc_leaf = state_to_leaf((unsigned char *)&accounts[0]);
  uint8_t *val_leaf = state_to_leaf((unsigned char *)&validators[0]);
  compute_merkle_root(&acc_leaf, 1, genesis.state_root, leaf_size);
  compute_merkle_root(&val_leaf, 1, genesis.validator_root, leaf_size);

  free(acc_leaf);
  free(val_leaf);
  return genesis;
}

int build_gen_state(state *current_state) {
  account *accounts = malloc(sizeof(account));
  validator *validators = malloc(sizeof(validator));

  account init_account = {
      .public_key = {0x9e, 0x17, 0x0c, 0x42, 0xb3, 0xb9, 0x9d, 0xc2,
                     0x84, 0xe9, 0xc1, 0x3d, 0x65, 0x9c, 0x79, 0x88,
                     0xd4, 0x13, 0xb6, 0xc9, 0x55, 0x01, 0xfe, 0x96,
                     0x27, 0x96, 0x88, 0x5e, 0x40, 0x26, 0xf8, 0x76},
      .balance = 10000,
      .nonce = 0,
  };
  memcpy(accounts, &init_account, 48);
  validator init_validator = {
      .public_key = {0x9e, 0x17, 0x0c, 0x42, 0xb3, 0xb9, 0x9d, 0xc2,
                     0x84, 0xe9, 0xc1, 0x3d, 0x65, 0x9c, 0x79, 0x88,
                     0xd4, 0x13, 0xb6, 0xc9, 0x55, 0x01, 0xfe, 0x96,
                     0x27, 0x96, 0x88, 0x5e, 0x40, 0x26, 0xf8, 0x76},
      .stake = 1000,
      .block_joined = 0,
  };
  memcpy(validators, &init_validator, 48);
  current_state->accounts_count = 1;
  current_state->validators_count = 1;
  current_state->accounts = accounts;
  current_state->validators = validators;
  return 0;
}

int init_chain(state *current_state, block *gen_block) {
  build_gen_state(current_state);
  *gen_block =
      build_genesis(current_state->accounts, current_state->validators);
  return 0;
}

uint64_t get_balance(unsigned char *public_key, state *current_state) {
  account *accounts = current_state->accounts;
  for (int i = 0; i < current_state->accounts_count; i++) {
    if (memcmp(accounts[i].public_key, public_key, 32) == 0) {
      return accounts[i].balance;
    }
  }
  return 0;
}

void print_public_key(unsigned char *public_key) {
  printf("0x");
  for (int i = 0; i < 32; i++) {
    printf("%02x", public_key[i]);
  }
  printf("\n");
}

uint64_t htonll(uint64_t val) {
  if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) {
    return __builtin_bswap64(val);
  }
  return val;
}

int hash_block(block *block, unsigned char buff[32]) {
  // Height, prev_hash, tx_root, proposer, timestamp
  int size = 4 + 32 + 32 + 32 + 8;

  unsigned char block_buff[size];
  memcpy(block_buff, &block->height, 4);
  memcpy(block_buff + 4, block->prev_hash, 32);
  memcpy(block_buff + 36, block->tx_root, 32);
  memcpy(block_buff + 68, block->proposer, 32);
  memcpy(block_buff + 100, &block->timestamp, 8);
  crypto_hash_sha256(buff, block_buff, size);
  return 0;
}
