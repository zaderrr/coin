#include "block.h"
#include "merkle.h"
#include "state.h"
#include <stdlib.h>

block build_genesis(account *accounts, validator *validators) {
  block genesis = {
      .height = 0,
      .prev_hash = {0},
      .timestamp = 233366400,
      .tx_count = 0,
      .transactions = NULL,
      .proposer = {0},
      .signature = {0},
      .tx_root = {0},
  };
  build_accounts_hash(accounts, genesis.state_root, 1);
  build_validators_hash(validators, genesis.validator_root, 1);
  return genesis;
}

int build_gen_state(state *current_state) {
  account *accounts = malloc(sizeof(account));
  validator *validators = malloc(sizeof(validator));
  account init_account = {
      .public_key = {0xf5, 0x7b, 0x51, 0x6f, 0x55, 0x3a, 0xa8, 0xbc,
                     0x05, 0xfe, 0x9d, 0x13, 0x7c, 0xa0, 0x59, 0x89,
                     0x93, 0x60, 0x6b, 0x42, 0xff, 0xf4, 0x70, 0x8e,
                     0x4f, 0xb1, 0x52, 0xf3, 0x12, 0xcf, 0x4b, 0x47},
      .balance = 9000,
      .nonce = 0,
  };
  accounts[0] = init_account;

  validator init_validator = {
      .public_key = {0xf5, 0x7b, 0x51, 0x6f, 0x55, 0x3a, 0xa8, 0xbc,
                     0x05, 0xfe, 0x9d, 0x13, 0x7c, 0xa0, 0x59, 0x89,
                     0x93, 0x60, 0x6b, 0x42, 0xff, 0xf4, 0x70, 0x8e,
                     0x4f, 0xb1, 0x52, 0xf3, 0x12, 0xcf, 0x4b, 0x47},
      .stake = 1000,
  };
  validator_activity act = {0};
  act.joined = 0;
  act.left = 0;
  init_validator.activity = malloc(sizeof(validator_activity));
  init_validator.activity[0] = act;
  init_validator.activity_length = 1;
  validators[0] = init_validator;

  current_state->accounts_count = 1;
  current_state->validators_count = 1;
  current_state->accounts = accounts;
  current_state->validators = validators;
  return 0;
}

int init_chain(state *current_state, block *gen_block) {
  build_gen_state(current_state);
  *gen_block =
      build_genesis(current_state->accounts, current_state->validators);
  return 0;
}
