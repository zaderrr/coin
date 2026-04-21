#include "block.h"
#include "ed25519.h"
#include "state.h"
#include "transaction.h"
#include <stdio.h>
#include <string.h>

int can_wirthdraw_stake(account *account, validator *val, transaction *tx,
                        state *current_state, block *block) {
  // Check if next proposer
  validator *next_val = get_next_validator(current_state, block);
  if (memcmp(next_val->public_key, val->public_key, 32)) {
    printf("Can't withdraw, they're the next proposer\n");
    return 1;
  }

  // Check they have been a validator for atleast X blocks
  int required_join = block->height - MIN_VALIDATOR_LENGTH;
  if (val->activity[val->activity_length - 1].joined > required_join) {
    printf("Not been validating long enough\n");
    return 1;
  }

  if (tx->amount > val->stake) {
    printf("Withdrawing too much");
    return 1;
  }

  return 0;
}

int validate_funds(account *account, state *current_state, transaction *tx) {
  if (account->balance < tx->amount) {
    printf("Insufficent balance\n");
    return 1;
  }
  return 0;
}

int valid_nonce(account *account, transaction *tx) {
  if (account->nonce != tx->nonce) {
    printf("Invalid nonce\n");
    return 1;
  }
  return 0;
}

int validate_stake_deposit(transaction *tx, state *state, account *from) {
  unsigned char null_addr[32] = {0};
  if (memcmp(tx->to, null_addr, 32) != 0) {
    return 1;
  }
  if (validate_funds(from, state, tx) == 1) {
    return 1;
  }
  return 0;
}

int validate_tx(transaction *tx, state *state, account *from, block *block) {
  if (from == NULL) {
    return 1;
  }
  // Check account can withdraw (validator)
  if (tx->type == TX_STAKE_DEPOSIT) {
    if (validate_stake_deposit(tx, state, from) == 1) {
      return 1;
    }
  } else if (tx->type == TX_STAKE_WITHDRAW) {
    validator *validator = get_validator(state, tx->from);
    if (validator == NULL) {
      return 1;
    }

    if (can_wirthdraw_stake(from, validator, tx, state, block) == 1) {
      return 1;
    }

  } else if (tx->type == TX_TRANSFER) {
    if (validate_funds(from, state, tx) == 1) {
      return 1;
    }
  }
  return 0;
}

int verify_transaction(unsigned char *payload, transaction *tx) {
  return ed25519_verify(tx->signature, payload, 81, tx->from);
}
