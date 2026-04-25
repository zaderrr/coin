#ifndef COIN_STATE_H
#define COIN_STATE_H

#include "transaction.h"
#include <stddef.h>
#include <stdint.h>

typedef struct block block;

typedef struct {
  uint64_t joined;
  uint64_t left;
} validator_activity;

typedef struct {
  unsigned char public_key[32];
  unsigned char bls_key[96];
  unsigned char bls_pop[48];
  uint64_t stake;
  validator_activity *activity;
  size_t activity_length;
} validator;

typedef struct {
  unsigned char public_key[32];
  uint64_t balance;
  uint64_t nonce;
} account;

typedef struct state {
  uint32_t accounts_count;
  uint32_t validators_count;
  account *accounts;
  validator *validators;
} state;

void free_state_contents(state *s);
int copy_state(state *built_state, state *current_state);
account *get_account(state *current_state, unsigned char public_key[32]);
validator *get_validator(state *current_state, unsigned char public_key[32]);
validator *get_validator_for_height(state *current_state, int height);
bool is_validator_active(validator *validator);
int update_state(state *current_state, transaction *tx, block *next_block);
#endif
