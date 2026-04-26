#include "block.h"
#include "ed25519.h"
#include "merkle.h"
#include "sodium.h"
#include "state.h"
#include "transaction.h"
#include "util.h"
#include "validation.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

int sign_block(block *next_block, unsigned char *block_buff, int size,
               Wallet *wallet) {
  ed25519_sign(next_block->signature, block_buff, size - 64, wallet->public_key,
               wallet->private_key);
  memcpy(block_buff + (size - 64), next_block->signature, 64);
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

int hash_block(block *block, unsigned char buff[32]) {
  // Height, prev_hash, tx_root, proposer, timestamp
  int size = 8 + 32 + 32 + 32 + 8;
  unsigned char block_buff[size];
  Writer w = {block_buff, block_buff + size};
  WRITE_FIELD(&w, block->height, sizeof(block->height));
  WRITE_FIELD(&w, block->prev_hash, sizeof(block->prev_hash));
  WRITE_FIELD(&w, block->tx_root, sizeof(block->tx_root));
  WRITE_FIELD(&w, block->proposer, sizeof(block->proposer));
  WRITE_FIELD(&w, block->timestamp, sizeof(block->timestamp));
  crypto_hash_sha256(buff, block_buff, size);
  return 0;
}

int get_block_size(block *block) {
  if (block == NULL) {
    return -1;
  }
  int size = 32 + 32 + 32 + 32 + 32 + 64 + 8 + 8 + 4 + 4 + block->tx_size;

  return size;
}

int serialize_block(block *next_block, unsigned char *buff,
                    bool include_signature) {
  int size = get_block_size(next_block);
  if (size == -1) {
    return 1;
  }
  unsigned char serialized_block[size];

  uint64_t timestamp = htonll(next_block->timestamp);
  uint64_t height = htonll(next_block->height);
  uint32_t tx_count = htonl(next_block->tx_count);
  uint32_t tx_size = htonl(next_block->tx_size);

  Writer w = {buff, buff + size};
  WRITE_FIELD(&w, height, sizeof(next_block->height));
  WRITE_FIELD(&w, next_block->prev_hash, sizeof(next_block->prev_hash));
  WRITE_FIELD(&w, next_block->state_root, sizeof(next_block->state_root));
  WRITE_FIELD(&w, next_block->validator_root,
              sizeof(next_block->validator_root));
  WRITE_FIELD(&w, next_block->tx_root, sizeof(next_block->tx_root));
  WRITE_FIELD(&w, timestamp, sizeof(next_block->timestamp));
  WRITE_FIELD(&w, next_block->proposer, sizeof(next_block->proposer));
  WRITE_FIELD(&w, tx_count, sizeof(next_block->tx_count));
  WRITE_FIELD(&w, tx_size, sizeof(next_block->tx_size));

  for (int i = 0; i < next_block->tx_count; i++) {
    transaction *tx = next_block->transactions[i];
    serialize_tx(&w, tx, true);
  }

  if (include_signature == true) {
    WRITE_FIELD(&w, next_block->signature, sizeof(next_block->signature));
  }
  return 0;
}

int deserialize_block(unsigned char *buff, int length, block *out) {
  Reader r = {buff, buff + length};

  READ_FIELD(&r, out->height, sizeof(out->height));
  READ_FIELD(&r, out->prev_hash, sizeof(out->prev_hash));
  READ_FIELD(&r, out->state_root, sizeof(out->state_root));
  READ_FIELD(&r, out->validator_root, sizeof(out->validator_root));
  READ_FIELD(&r, out->tx_root, sizeof(out->tx_root));
  READ_FIELD(&r, out->timestamp, sizeof(out->timestamp));
  READ_FIELD(&r, out->proposer, sizeof(out->proposer));
  READ_FIELD(&r, out->tx_count, sizeof(out->tx_count));
  READ_FIELD(&r, out->tx_size, sizeof(out->tx_size));

  out->tx_count = ntohl(out->tx_count);
  out->height = htonll(out->height);
  out->timestamp = htonll(out->timestamp);
  out->tx_size = ntohl(out->tx_size);

  out->transactions = malloc(out->tx_count * sizeof(transaction *));

  for (int i = 0; i < out->tx_count; i++) {
    int tx_size = 0;
    READ_FIELD(&r, tx_size, sizeof(tx_size));
    tx_size = ntohl(tx_size);
    transaction *tx = calloc(1, tx_size);
    if (deserialize_tx(&r, tx) == 1) {
      return 1;
    }
    out->transactions[i] = tx;
  }

  READ_FIELD(&r, out->signature, sizeof(out->signature));

  return 0;
}

int verify_block(unsigned char *buff, block *block, int size) {
  return ed25519_verify(block->signature, buff, size - 64, block->proposer);
}

int validate_previous_hash(block *val_block, block *prev_block) {
  unsigned char prev_hash[32];
  hash_block(prev_block, prev_hash);
  if (memcmp(val_block->prev_hash, prev_hash, 32) != 0) {
    return 1;
  }
  return 0;
}

int build_new_state(block *val_block, state *current_state) {
  state built_state;
  if (copy_state(&built_state, current_state) == 1) {
    printf("Failed copying\n");
    return 1;
  }
  for (size_t i = 0; i < val_block->tx_count; i++) {
    transaction *tx = val_block->transactions[i];
    account *acc = get_account(&built_state, tx->from);

    if (validate_tx(tx, &built_state, acc, val_block) != 0) {
      printf("Invalid tx at index %zu\n", i);
      free_state_contents(&built_state);
      return 1;
    }
    update_state(&built_state, tx, val_block);
  }

  free_state_contents(current_state);
  *current_state = built_state;
  return 0;
}

int validate_roots(block *val_block, state *state) {
  unsigned char root[32];
  build_root(root, val_block->transactions, val_block->tx_count);
  if (memcmp(root, val_block->tx_root, 32) != 0) {
    printf("TX merkle does not match\n");
    return 0;
  }

  unsigned char account_merkle[32];
  unsigned char val_merkle[32];

  build_accounts_hash(state->accounts, account_merkle, state->accounts_count);
  if (memcmp(account_merkle, val_block->state_root, 32) != 0) {
    printf("State hash does not match\n");
    return 0;
  }
  build_validators_hash(state->validators, val_merkle, state->validators_count);
  if (memcmp(val_merkle, val_block->validator_root, 32) != 0) {
    printf("Validator hash does not match\n");
    return 0;
  }
  return 1;
}
// TODO: Move updating state from this function
int validate_block(block *val_block, block *prev_block, state *state) {

  validator *val = get_validator_for_height(state, val_block->height);
  if (val == NULL) {
    return 0;
  }
  if (memcmp(val_block->proposer, val->public_key, 32) != 0) {
    return 0;
  }
  if (validate_previous_hash(val_block, prev_block) == 1) {
    return 0;
  }

  if (val_block->height != prev_block->height + 1) {
    return 0;
  }
  if (build_new_state(val_block, state) == 1) {
    printf("Failed to build state\n");
  } else {
  }

  if (validate_roots(val_block, state) == 0) {
    return 0;
  }

  return 1;
}
