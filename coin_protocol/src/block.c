#include "block.h"
#include "merkle.h"
#include "sodium.h"
#include "transaction.h"
#include "util.h"
#include <netinet/in.h>
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
    printf("Done %d tx\n", i);
  }

  memcpy(&next_block.signature, buff + offset, 64);
  offset += 64;

  return next_block;
}

int validate_block() {}
