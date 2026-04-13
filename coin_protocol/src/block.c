#include "block.h"
#include "merkle.h"
#include "sodium.h"
#include <stdlib.h>
#include <string.h>

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
