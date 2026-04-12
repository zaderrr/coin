#include "ed25519.h"
#include "node.h"

int valid_nonce(account *account, transaction *tx) {
  if (account->nonce != tx->nonce) {
    printf("Invalid nonce\n");
    return 1;
  }
  return 0;
}

int validate_tx(transaction *tx, node_ctx *ctx) {
  account *account = get_account(ctx->current_state, tx->from);
  if (account == NULL) {
    printf("Account is null :( no balance\n");
    return 1;
  }
  // Check account can withdraw (validator)
  if (tx->type == TX_STAKE_WITHDRAW) {
    validator *validator = get_validator(ctx->current_state, tx->from);
    if (validator == NULL) {
      return 1;
    }

    if (can_wirthdraw_stake(account, validator, tx, ctx->current_state) == 1) {
      return 1;
    }

  } else if (tx->type == TX_TRANSFER) {
    // Validate transfer, balance + nonce
    if (validate_funds(account, ctx->current_state, tx) == 1) {
      return 1;
    }
  }
  return 0;
}

int verify_transaction(unsigned char *payload, transaction *tx) {
  return ed25519_verify(tx->signature, payload, 81, tx->from);
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
