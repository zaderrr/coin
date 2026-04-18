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

int deserialize_block(unsigned char *buff, int length, block *out) {
  block next_block = {0};
  Reader r = {buff, buff + length};

  READ_FIELD(&r, next_block.height, sizeof(next_block.height));
  READ_FIELD(&r, next_block.prev_hash, sizeof(next_block.prev_hash));
  READ_FIELD(&r, next_block.state_root, sizeof(next_block.state_root));
  READ_FIELD(&r, next_block.validator_root, sizeof(next_block.validator_root));
  READ_FIELD(&r, next_block.tx_root, sizeof(next_block.tx_root));
  READ_FIELD(&r, next_block.timestamp, sizeof(next_block.timestamp));
  READ_FIELD(&r, next_block.proposer, sizeof(next_block.proposer));
  READ_FIELD(&r, next_block.tx_count, sizeof(next_block.tx_count));

  next_block.tx_count = ntohl(next_block.tx_count);
  next_block.height = htonll(next_block.height);
  next_block.timestamp = htonll(next_block.timestamp);

  next_block.transactions = malloc(sizeof(transaction) * next_block.tx_count);

  for (int i = 0; i < next_block.tx_count; i++) {
    transaction tx = {0};
    if (deserialize_tx(&r, &tx) == 1) {
      return 1;
    }
    next_block.transactions[i] = tx;
  }
  READ_FIELD(&r, next_block.signature, sizeof(next_block.signature));
  memcpy(out, &next_block, sizeof(next_block));

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

int build_new_state(block *val_block, state *state) {
  for (int i = 0; i < val_block->tx_count; i++) {
    account *acc = get_account(state, val_block->transactions[i].from);
    if (validate_tx(&val_block->transactions[i], state, acc, val_block) == 1) {
      printf("Invalid tx\n");
      return 0;
    }
    if (valid_nonce(acc, &val_block->transactions[i]) == 1) {
      printf("Invalid nonce\n");
      return 0;
    }
    update_state(state, &val_block->transactions[i], val_block);
  }
  return 1;
}

// TODO: Refactor this with the same as build_next_block
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
    printf("Calculated: ");
    print_public_key(account_merkle);
    printf("Received: ");
    print_public_key(val_block->state_root);
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

int validate_block(block *val_block, block *prev_block, state *state) {
  validator *val = get_next_validator(state, prev_block);
  if (memcmp(val_block->proposer, val->public_key, 32) != 0) {
    return 0;
  }
  if (validate_previous_hash(val_block, prev_block) == 1) {
    return 0;
  }

  if (val_block->height != prev_block->height + 1) {
    return 0;
  }

  build_new_state(val_block, state);

  if (validate_roots(val_block, state) == 0) {
    return 0;
  }

  return 1;
}
