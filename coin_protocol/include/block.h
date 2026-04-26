#ifndef COIN_BLOCK_H
#define COIN_BLOCK_H
#include "transaction.h"
#include <stddef.h>
#include <stdint.h>

#define MIN_VALIDATOR_LENGTH 5
#define BLOCK_REWARD ((uint64_t)100)

typedef struct state state;

typedef struct block {
  uint64_t height;
  uint64_t timestamp;
  transaction **transactions;
  uint32_t tx_size;
  uint32_t tx_count;
  uint8_t prev_hash[32];
  uint8_t state_root[32];
  uint8_t validator_root[32];
  uint8_t tx_root[32];
  uint8_t proposer[32];
  uint8_t signature[64];
} block;

uint64_t get_balance(unsigned char *public_key, state *current_state);
int hash_block(block *block, unsigned char buff[32]);
int deserialize_block(unsigned char *buff, int length, block *out);
int sign_block(block *next_block, unsigned char *block_buff, int size,
               Wallet *wallet);
int free_block(block *block);
int get_block_size(block *block);
int serialize_block(block *next_block, unsigned char *buff,
                    bool include_signature);
int verify_block(unsigned char *buff, block *block, int size);
int validate_block(block *val_block, block *prev_block, state *state);
#endif
