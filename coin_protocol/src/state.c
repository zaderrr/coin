#include "state.h"
#include "block.h"
#include <stdint.h>
#include <stdlib.h>

bool is_validator_active(validator *validator) {
  if (validator == NULL) {
    return false;
  }
  validator_activity recent =
      validator->activity[validator->activity_length - 1];
  // Left is set to 0 whilst active
  return recent.left == 0;
}

int make_validator_inactive(validator *val, uint64_t left) {
  if (val == NULL) {
    return 1;
  }
  val->activity[val->activity_length - 1].left = left;
  return 0;
}

validator *get_validator_for_height(state *current_state, int height) {
  validator *validators[current_state->validators_count];
  int active_vals = 0;

  for (int i = 0; i < current_state->validators_count; i++) {
    validator *val = &current_state->validators[i];
    if (is_validator_active(val)) {
      validators[active_vals++] = val;
    }
  }

  if (active_vals == 0) {
    return NULL;
  }

  return validators[height % active_vals];
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

int create_new_validator(state *current_state, transaction *tx) {
  current_state->validators_count++;
  int count = current_state->validators_count;
  validator *new_validators =
      realloc(current_state->validators, sizeof(validator) * count);

  validator new = {0};
  new.activity = malloc(sizeof(validator_activity) * 1);
  new.activity_length = 1;
  memcpy(new.public_key, tx->from, 32);

  if (new_validators == NULL) {
    current_state->validators_count--;
    free(new.activity);
    printf("Failed to add validator\n");
    return 1;
  }

  current_state->validators = new_validators;
  current_state->validators[current_state->validators_count - 1] = new;
  return 0;
}

int create_new_account(state *current_state, transaction *tx) {
  current_state->accounts_count++;
  int count = current_state->accounts_count;
  account *new_accounts =
      realloc(current_state->accounts, sizeof(account) * count);

  account new = {0};
  new.nonce = 0;
  memcpy(new.public_key, tx->to, 32);

  if (new_accounts == NULL) {
    printf("Failed to add account\n");
    return 1;
  }

  current_state->accounts = new_accounts;
  current_state->accounts[current_state->accounts_count - 1] = new;
  return 0;
}

int update_validator_deposit(state *current_state, transaction *tx,
                             block *new_block) {
  validator *val = get_validator(current_state, tx->from);
  if (val == NULL) {
    if (create_new_validator(current_state, tx) == 1) {
      return 1;
    }
    val = get_validator(current_state, tx->from);
    val->activity[0].joined = new_block->height;
    val->activity[0].left = 0;
  } else if (is_validator_active(val) == false) {
    val->activity_length++;
    validator_activity *new_list = realloc(
        val->activity, sizeof(validator_activity) * val->activity_length);

    if (new_list == NULL) {
      val->activity_length--;
      return 1;
    }

    validator_activity new_act = {0};
    new_act.left = 0;
    new_act.joined = new_block->height;

    val->activity = new_list;
    val->activity[val->activity_length - 1] = new_act;
  }
  account *from = get_account(current_state, tx->from);
  from->balance -= tx->amount;
  from->nonce++;
  val->stake += tx->amount;
  return 0;
}

int update_validator_withdrawl(state *current_state, transaction *tx,
                               block *new_block) {
  validator *val = get_validator(current_state, tx->from);
  if (val == NULL) {
    return 1;
  }
  // Theoretically, you can't have staked without an account
  account *from = get_account(current_state, tx->from);
  if (from == NULL) {
    return 1;
  }

  if (tx->amount == val->stake) {
    val->activity[val->activity_length - 1].left = new_block->height - 1;
  }

  from->balance += tx->amount;
  from->nonce++;
  val->stake -= tx->amount;
  return 0;
}

int update_tx_reward(state *current_state, transaction *tx) {
  validator *to = get_validator(current_state, tx->to);
  if (to == NULL) {
    return 1;
  }
  to->stake += tx->amount;
  return 0;
}

int update_tx_transfer(state *current_state, transaction *tx) {
  account *from = get_account(current_state, tx->from);
  account *to = get_account(current_state, tx->to);
  if (to == NULL) {
    if (create_new_account(current_state, tx) == 1) {
      return 1;
    }
    // Creating account, reallocates memory - Have to get pointers again
    from = get_account(current_state, tx->from);
    to = get_account(current_state, tx->to);
  }
  to->balance += tx->amount;
  from->balance -= tx->amount;
  from->nonce++;
  return 0;
}

int update_state(state *current_state, transaction *tx, block *next_block) {
  if (tx->type == TX_TRANSFER) {
    update_tx_transfer(current_state, tx);
  } else if (tx->type == TX_STAKE_DEPOSIT) {
    update_validator_deposit(current_state, tx, next_block);
  } else if (tx->type == TX_STAKE_WITHDRAW) {
    update_validator_withdrawl(current_state, tx, next_block);
  } else if (tx->type == TX_REWARD) {
    update_tx_reward(current_state, tx);
  }
  return 0;
}

int copy_state(state *built_state, state *current_state) {

  *built_state = *current_state;

  size_t acc_bytes = sizeof(account) * current_state->accounts_count;
  size_t val_bytes = sizeof(validator) * current_state->validators_count;

  account *new_accounts = malloc(acc_bytes);
  validator *new_validators = malloc(val_bytes);

  if (!new_accounts || !new_validators) {
    free(new_accounts);
    free(new_validators);
    return 1;
  }
  built_state->validators = new_validators;
  built_state->accounts = new_accounts;

  memcpy(built_state->accounts, current_state->accounts, acc_bytes);
  memcpy(built_state->validators, current_state->validators, val_bytes);

  for (size_t i = 0; i < built_state->validators_count; i++) {
    validator_activity *a = malloc(sizeof(validator_activity) *
                                   built_state->validators[i].activity_length);
    if (!a) {
      for (size_t j = 0; j < i; j++)
        free(new_validators[j].activity);
      free(new_accounts);
      free(new_validators);
      return 1;
    }
    int act_count = built_state->validators[i].activity_length;
    memcpy(a, built_state->validators[i].activity,
           sizeof(validator_activity) * act_count);
    for (int act_index = 0; act_index < act_count; act_index++) {
      *a = *current_state->validators[i].activity;
    }
    new_validators[i].activity = a;
  }
  return 0;
}

void free_state_contents(state *s) {
  if (!s)
    return;

  if (s->validators) {
    for (size_t i = 0; i < s->validators_count; i++) {
      free(s->validators[i].activity);
    }
    free(s->validators);
  }

  if (s->accounts) {
    free(s->accounts);
  }

  s->validators = NULL;
  s->accounts = NULL;
}
