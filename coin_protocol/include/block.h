#include <stdint.h>

typedef enum {
  TX_TRANSFER,
  TX_STAKE_DEPOSIT,
  TX_STAKE_WITHDRAW,
} tx_type;

typedef struct {
  unsigned char from[32];
  unsigned char to[32];
  tx_type type;
  uint32_t amount;
  unsigned char *signature;
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
