#include "block.h"
#include "ed25519.h"
#include "message.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#define MIN_VALIDATOR_LENGTH 5

int min_validator_length() { return MIN_VALIDATOR_LENGTH; }

int get_next_validator(state *current_state, block *block) {
  int height;
  if (block == NULL) {
    height = 0;
  } else {
    height = block->height + 1;
  }
  int val_index = height % current_state->validators_count;
  return val_index;
}

account *get_account(state *current_state, unsigned char public_key[32]) {
  for (int i = 0; i < current_state->accounts_count; i++) {
    if (memcmp(current_state->accounts[i].public_key, public_key, 32) == 0) {
      return &current_state->accounts[i];
    }
  }
  return NULL;
}

validator *get_validator(state *current_state, unsigned char public_key[32]) {
  for (int i = 0; i < current_state->validators_count; i++) {
    if (memcmp(current_state->validators[i].public_key, public_key, 32) == 0) {
      return &current_state->validators[i];
    }
  }
  return NULL;
}
