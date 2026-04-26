#ifndef COIN_TX_H
#define COIN_TX_H
#include "util.h"
#include "wallet.h"
#include <stdint.h>

#define TX_WIRE_FIXED_SIZE (4 + 1 + 32 + 32 + 8 + 8 + 4 + 64)

typedef enum {
  TX_TRANSFER,
  TX_STAKE_DEPOSIT,
  TX_STAKE_WITHDRAW,
  TX_REWARD,
} tx_type;

typedef struct {
  unsigned char signature[64];
  unsigned char from[32];
  unsigned char to[32];
  tx_type type;
  uint64_t nonce;
  uint64_t amount;
  int32_t body_size;
  unsigned char body[];
} transaction;

typedef struct {
  unsigned char message[256];
} tx_transfer_body;

typedef struct {
  unsigned char bls_pk[96];
  unsigned char pop[48];
} tx_stake_body;

int send_transaction(transaction *tx, int fd, Wallet *wallet);
int deserialize_tx(Reader *reader, transaction *out);
int create_tx(transaction *tx, unsigned char *to, Wallet *wallet,
              uint64_t amount, tx_type type);
int get_tx_size(transaction *tx);
int serialize_tx(Writer *writer, transaction *tx, bool include_signature);
int sign_transaction(transaction *tx, Wallet *wallet, unsigned char *buff);
int get_stake_body(transaction *tx, tx_stake_body *stake_body);
int verify_pop(unsigned char *pop, unsigned char *bls_pk);
int create_block_reward(unsigned char *to, transaction *tx);
#endif
