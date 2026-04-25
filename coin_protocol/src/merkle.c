#include "state.h"
#include <sodium/crypto_hash_sha256.h>
#include <stddef.h>
#include <stdint.h>
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

uint8_t *account_to_leaf(account *state) {
  size_t leaf_size = 32 + 8 + 8;
  uint8_t *leaf = malloc(leaf_size);
  memcpy(leaf, state->public_key, 32);
  memcpy(leaf + 32, &state->balance, 8);
  memcpy(leaf + 40, &state->nonce, 8);
  return leaf;
}

// TODO: Update these to Writers
uint8_t *validator_to_leaf(validator *state) {
  size_t leaf_size = 32 + 8;
  uint8_t *leaf = malloc(leaf_size);
  memcpy(leaf, state, 32);
  memcpy(leaf + 32, &state->stake, 8);
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
unsigned char *build_tx_leaf(transaction *tx) {
  // From, To, Nonce, type
  size_t leaf_size = 32 + 32 + 8 + 1;

  unsigned char type_byte = (unsigned char)tx->type;
  unsigned char *leaf = malloc(leaf_size);
  memcpy(leaf, tx->from, 32);
  memcpy(leaf + 32, tx->to, 32);
  memcpy(leaf + 64, &tx->nonce, 8);
  memcpy(leaf + 72, &type_byte, 1);

  return leaf;
}
int build_root(unsigned char *root, transaction **tx, int tx_count) {
  size_t leaf_size = 32 + 32 + 8 + 1;
  unsigned char **leafs = malloc(sizeof(unsigned char *) * tx_count);
  for (int i = 0; i < tx_count; i++) {
    leafs[i] = build_tx_leaf(tx[i]);
  }
  compute_merkle_root(leafs, tx_count, root, leaf_size);
  for (int i = 0; i < tx_count; i++) {
    free(leafs[i]);
  }
  free(leafs);
  return 0;
}

int build_accounts_hash(account *acc, unsigned char *out_buf, int count) {
  unsigned char **leaves = malloc(sizeof(char *) * count);

  for (int i = 0; i < count; i++) {
    leaves[i] = account_to_leaf(&acc[i]);
  }

  size_t leaf_size = 32 + 8 + 8;
  compute_merkle_root(leaves, count, out_buf, leaf_size);

  free_leaves(leaves, count);

  return 0;
}

int build_validators_hash(validator *val, unsigned char *out_buf, int count) {
  unsigned char **leaves = malloc(sizeof(char *) * count);

  for (int i = 0; i < count; i++) {
    leaves[i] = validator_to_leaf(&val[i]);
  }

  size_t leaf_size = 32 + 8;
  compute_merkle_root(leaves, count, out_buf, leaf_size);

  free_leaves(leaves, count);

  return 0;
}
