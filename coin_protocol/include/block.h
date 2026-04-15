#ifndef COIN_BLOCK_H
#define COIN_BLOCK_H
#include "transaction.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
  unsigned char public_key[32];
  uint64_t stake;
  uint64_t block_joined;
} validator;

typedef struct {
  unsigned char public_key[32];
  uint64_t balance;
  uint64_t nonce;
} account;

typedef struct {
  uint64_t height;
  uint8_t prev_hash[32];
  uint8_t state_root[32];
  uint8_t validator_root[32];
  uint8_t tx_root[32];
  uint64_t timestamp;
  unsigned char proposer[32];
  uint32_t tx_count;
  transaction *transactions;
  uint8_t signature[64];
} block;

typedef struct {
  uint32_t accounts_count;
  uint32_t validators_count;
  account *accounts;
  validator *validators;
  block *previous_block;
} state;

_Static_assert(sizeof(account) == sizeof(validator), "struct size mismatch");
_Static_assert(sizeof(account) == 48, "unexpected struct size");

uint64_t get_balance(unsigned char *public_key, state *current_state);
int hash_block(block *block, unsigned char buff[32]);
#endif
