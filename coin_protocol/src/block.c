#include "block.h"
#include "ed25519.h"
#include "merkle.h"
#include "protocol.h"
#include "sodium.h"
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
  memcpy(block_buff, &block->height, 8);
  memcpy(block_buff + 8, block->prev_hash, 32);
  memcpy(block_buff + 40, block->tx_root, 32);
  memcpy(block_buff + 72, block->proposer, 32);
  memcpy(block_buff + 104, &block->timestamp, 8);
  crypto_hash_sha256(buff, block_buff, size);
  return 0;
}

block deserialize_block(unsigned char *buff, int length) {
  block next_block = {0};
  int offset = 0;

  memcpy(&next_block.height, buff + offset, 8);
  offset += 8;
  memcpy(&next_block.prev_hash, buff + offset, 32);
  offset += 32;
  memcpy(&next_block.state_root, buff + offset, 32);
  offset += 32;
  memcpy(&next_block.validator_root, buff + offset, 32);
  offset += 32;
  memcpy(&next_block.tx_root, buff + offset, 32);
  offset += 32;
  memcpy(&next_block.timestamp, buff + offset, 8);
  offset += 8;
  memcpy(&next_block.proposer, buff + offset, 32);
  offset += 32;
  memcpy(&next_block.tx_count, buff + offset, 4);
  offset += 4;

  next_block.tx_count = ntohl(next_block.tx_count);
  next_block.height = htonll(next_block.height);
  next_block.timestamp = htonll(next_block.timestamp);

  next_block.transactions = malloc(sizeof(transaction) * next_block.tx_count);

  for (int i = 0; i < next_block.tx_count; i++) {
    unsigned char tx[TX_SIZE];
    memcpy(tx, buff + offset, TX_SIZE);
    transaction deserialized_tx = deserialize_tx(tx);
    next_block.transactions[i] = deserialized_tx;
    offset += TX_SIZE;
  }

  memcpy(&next_block.signature, buff + offset, 64);
  offset += 64;

  return next_block;
}

int verify_block(unsigned char *buff, block *block, int size) {
  return ed25519_verify(block->signature, buff, size - 64, block->proposer);
}

int create_new_account(state *current_state, transaction *tx) {
  current_state->accounts_count++;
  int count = current_state->accounts_count;
  account *new_accounts =
      realloc(current_state->accounts, sizeof(account) * count);

  account new = {0};
  new.nonce = 0;
  memcpy(new.public_key, tx->to, 32);

  if (new_accounts == NULL) {
    printf("Failed to add account\n");
    return 1;
  }

  current_state->accounts = new_accounts;
  current_state->accounts[current_state->accounts_count - 1] = new;
  return 0;
}

int update_state(state *current_state, transaction *tx) {
  if (tx->type == TX_TRANSFER) {
    account *from = get_account(current_state, tx->from);
    account *to = get_account(current_state, tx->to);
    if (to == NULL) {
      if (create_new_account(current_state, tx) == 1) {
        return 1;
      }
      // Creating account, reallocates memory - Have to get pointers again
      from = get_account(current_state, tx->from);
      to = get_account(current_state, tx->to);
    }
    to->balance += tx->amount;
    from->balance -= tx->amount;
    from->nonce++;
  }
  return 0;
}

int validate_block(block *val_block, block *prev_block, state *state) {
  int next_index = get_next_validator(state, prev_block);
  if (memcmp(val_block->proposer, state->validators[next_index].public_key,
             32) != 0) {
    printf("Incorrect proposer\n");
    return 0;
  }
  unsigned char prev_hash[32];
  hash_block(prev_block, prev_hash);
  if (memcmp(val_block->prev_hash, prev_hash, 32) != 0) {
    printf("Prev hash incorrect\n");
    return 0;
  }
  if (val_block->height != prev_block->height + 1) {
    printf("Invalid height\n");
    return 0;
  }

  for (int i = 0; i < val_block->tx_count; i++) {
    account *acc = get_account(state, val_block->transactions[i].from);
    if (validate_tx(&val_block->transactions[i], state, acc, val_block) == 1) {
      printf("Invalid tx");
      return 0;
    }
    update_state(state, &val_block->transactions[i]);
  }
  unsigned char root[32];
  build_root(root, val_block->transactions, val_block->tx_count);
  if (memcmp(root, val_block->tx_root, 32) != 0) {
    printf("TX merkle does not match\n");
    return 0;
  }
  unsigned char account_merkle[32];
  unsigned char val_merkle[32];
  build_root_hash((unsigned char *)state->accounts, account_merkle,
                  state->accounts_count);
  if (memcmp(account_merkle, val_block->state_root, 32) != 0) {
    printf("State hash does not match\n");
    return 0;
  }
  build_root_hash((unsigned char *)state->validators, val_merkle,
                  state->validators_count);
  if (memcmp(val_merkle, val_block->validator_root, 32) != 0) {
    printf("Validator hash does not match\n");
    return 0;
  }

  return 1;
}
