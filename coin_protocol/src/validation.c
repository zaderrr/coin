#include "block.h"
#include "ed25519.h"
#include "state.h"
#include "transaction.h"
#include <stdio.h>
#include <string.h>

static int reward_count = 0;
static block *curr_block = NULL;

int can_wirthdraw_stake(account *account, validator *val, transaction *tx,
                        state *current_state, block *block) {
  // Check they have been a validator for atleast X blocks
  int required_join = block->height - MIN_VALIDATOR_LENGTH;
  if (val->activity[val->activity_length - 1].joined > required_join) {
    printf("Not been validating long enough\n");
    return 1;
  }

  if (tx->amount > val->stake) {
    printf("Withdrawing too much\n");
    return 1;
  }

  return 0;
}

int validate_reward(state *current_state, transaction *tx, block *new_block) {
  if (curr_block == NULL || new_block != curr_block) {
    curr_block = new_block;
    reward_count = 0;
  }
  if (reward_count > 1) {
    printf("Too many rewards...\n");
    return 1;
  }
  if (memcmp(tx->to, new_block->proposer, 32) != 0) {
    printf("Invalid receiver\n");
    return 1;
  }

  validator *val = get_validator(current_state, tx->to);
  if (val == NULL) {
    printf("validator doesn't exist\n");
    return 1;
  }

  if (is_validator_active(val) == false) {
    printf("Validator not active...\n");
    return 1;
  }

  if (tx->amount != BLOCK_REWARD) {
    printf("Invalid reward\n");
    return 1;
  }
  reward_count++;
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
  if (tx->type == TX_REWARD) {
    return 0;
  }
  if (account == NULL) {
    return 1;
  }
  if (account->nonce != tx->nonce) {
    printf("Invalid nonce\n");
    return 1;
  }
  return 0;
}

int validate_stake_deposit(transaction *tx, state *state, account *from) {
  if (from == NULL) {
    return 1;
  }
  unsigned char null_addr[32] = {0};
  if (memcmp(tx->to, null_addr, 32) != 0) {
    return 1;
  }
  if (validate_funds(from, state, tx) == 1) {
    return 1;
  }
  return 0;
}

int verify_transaction(unsigned char *payload, transaction *tx) {
  return ed25519_verify(tx->signature, payload, 81, tx->from);
}

int validate_tx(transaction *tx, state *state, account *from, block *block) {
  // Reward TX isn't signed not have nonce
  if (tx->type != TX_REWARD) {
    unsigned char tx_buff[TX_SIZE];
    Writer w = {tx_buff, tx_buff + TX_SIZE};
    serialize_tx(&w, tx, true);

    if (verify_transaction(tx_buff, tx) != 1) {
      printf("Invalid signature!\n");
      return 1;
    }

    if (valid_nonce(from, tx) == 1) {
      printf("Invalid nonce\n");
      return 1;
    }
  }
  switch (tx->type) {
  case TX_STAKE_DEPOSIT: {
    if (validate_stake_deposit(tx, state, from) == 1) {
      return 1;
    }
    break;
  }
  case TX_STAKE_WITHDRAW: {
    validator *validator = get_validator(state, tx->from);
    if (validator == NULL) {
      return 1;
    }
    if (can_wirthdraw_stake(from, validator, tx, state, block) == 1) {
      return 1;
    }
    break;
  }
  case TX_TRANSFER: {
    if (validate_funds(from, state, tx) == 1) {
      return 1;
    }
    break;
  }
  case TX_REWARD: {
    if (validate_reward(state, tx, block) == 1) {
      return 1;
    }
    break;
  }
  default: {
    printf("Unrecognized transaction type\n");
    break;
  }
  }
  return 0;
}
