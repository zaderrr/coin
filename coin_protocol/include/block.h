#ifndef COIN_BLOCK_H
#define COIN_BLOCK_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  TX_TRANSFER,
  TX_STAKE_DEPOSIT,
  TX_STAKE_WITHDRAW,
} tx_type;

typedef struct {
  unsigned char from[32];
  unsigned char to[32];
  unsigned char signature[64];
  tx_type type;
  uint64_t amount;
  uint64_t nonce;
} transaction;

typedef struct {
  unsigned char public_key[32];
  uint64_t stake;
  uint64_t block_joined;
} validator;

typedef struct {
  uint32_t height;
  uint8_t prev_hash[32];
  uint8_t state_root[32];
  uint8_t validator_root[32];
  uint8_t tx_root[32];
  uint64_t timestamp;
  uint8_t proposer[32];
  uint8_t signature[64];
  uint32_t tx_count;
  transaction *transactions;
} block;

typedef struct {
  unsigned char public_key[32];
  uint64_t balance;
  uint64_t nonce;
} account;

typedef struct {
  uint32_t accounts_count;
  uint32_t validators_count;
  account *accounts;
  validator *validators;
  block *previous_block;
} state;

int compute_merkle_root(uint8_t **leaves, uint32_t count, uint8_t *root,
                        size_t leaf_size);
uint8_t *account_to_leaf(const account *acc);
uint8_t *validator_to_leaf(const validator *val);
block build_genesis(account *accounts, validator *validators);
int build_gen_state(state *current_state);
int init_chain(state *current_state, block *gen_block);
uint64_t get_balance(unsigned char *public_key, state *current_state);
void print_public_key(unsigned char *public_key);
#endif
