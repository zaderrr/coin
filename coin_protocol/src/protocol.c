#include "block.h"
#include "ed25519.h"
#include "message.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#define MIN_VALIDATOR_LENGTH 5

int min_validator_length() { return MIN_VALIDATOR_LENGTH; }

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
