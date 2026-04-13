#include "block.h"
#include "merkle.h"
#include <stdlib.h>
#include <string.h>
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
  size_t leaf_size = 32 + 8 + 8;
  uint8_t *acc_leaf = state_to_leaf((unsigned char *)&accounts[0]);
  uint8_t *val_leaf = state_to_leaf((unsigned char *)&validators[0]);
  compute_merkle_root(&acc_leaf, 1, genesis.state_root, leaf_size);
  compute_merkle_root(&val_leaf, 1, genesis.validator_root, leaf_size);

  free(acc_leaf);
  free(val_leaf);
  return genesis;
}

int build_gen_state(state *current_state) {
  account *accounts = malloc(sizeof(account));
  validator *validators = malloc(sizeof(validator));
  account init_account = {
      .public_key =
          {
              0x9e, 0xb9, 0x81, 0xae, 0x32, 0x72, 0x0e, 0xb3, 0x81, 0xf8, 0x46,
              0xcf, 0xf1, 0x6d, 0xf1, 0x8f, 0x16, 0x67, 0x88, 0xda, 0x3c, 0x71,
              0x9e, 0x04, 0x55, 0x34, 0xde, 0x15, 0x6f, 0x64, 0x7f, 0x02,
          },
      .balance = 9000,
      .nonce = 0,
  };
  memcpy(accounts, &init_account, 48);
  validator init_validator = {
      .public_key =
          {
              0x9e, 0xb9, 0x81, 0xae, 0x32, 0x72, 0x0e, 0xb3, 0x81, 0xf8, 0x46,
              0xcf, 0xf1, 0x6d, 0xf1, 0x8f, 0x16, 0x67, 0x88, 0xda, 0x3c, 0x71,
              0x9e, 0x04, 0x55, 0x34, 0xde, 0x15, 0x6f, 0x64, 0x7f, 0x02,
          },

      .stake = 1000,
      .block_joined = 0,
  };
  memcpy(validators, &init_validator, 48);
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
