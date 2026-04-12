
#include "block.h"
#include <stdio.h>
#include <string.h>
#define MIN_VALIDATOR_LENGTH 5

int min_validator_length() { return MIN_VALIDATOR_LENGTH; }

int valid_nonce(account *account, transaction *tx) {
  if (account->nonce != tx->nonce) {
    printf("Invalid nonce\n");
    return 1;
  }
  return 0;
}
int validate_funds(account *account, state *current_state, transaction *tx) {
  if (account->balance < tx->amount) {
    printf("Insufficent balance\n");
    return 1;
  }
  if (valid_nonce(account, tx) == 1) {
    return 1;
  }
  return 0;
}

int get_next_validator(state *current_state) {
  int height;
  if (current_state->previous_block == NULL) {
    height = 0;
  } else {
    height = current_state->previous_block->height + 1;
  }
  int val_index = height % current_state->validators_count;
  return val_index;
}

account *get_account(state *current_state, unsigned char public_key[32]) {
  account *accounts = current_state->accounts;
  for (int i = 0; i < current_state->accounts_count; i++) {
    if (memcmp(accounts[i].public_key, public_key, 32) == 0) {
      return &accounts[i];
    }
  }
  return NULL;
}

validator *get_validator(state *current_state, unsigned char public_key[32]) {
  validator *validators = current_state->validators;
  for (int i = 0; i < current_state->validators_count; i++) {
    if (memcmp(validators[i].public_key, public_key, 32) == 0) {
      return &validators[i];
    }
  }
  return NULL;
}

int can_wirthdraw_stake(account *account, validator *val, transaction *tx,
                        state *current_state) {
  // Check if next proposer
  int index = get_next_validator(current_state);
  validator *at_index = &current_state->validators[index];
  if (val == at_index) {
    printf("Can't withdraw, they're the next proposer\n");
    return 1;
  }

  // Check they have been a validator for atleast X blocks
  int required_join =
      current_state->previous_block->height - min_validator_length();
  if (val->block_joined > required_join) {
    printf("Not been validating long enough\n");
    return 1;
  }

  if (valid_nonce(account, tx) == 1) {
    return 1;
  }
  return 0;
}
