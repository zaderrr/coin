#ifndef COIN_TX_H
#define COIN_TX_H
#include "wallet.h"
#include <stdbool.h>

#define TX_SIZE 145

typedef enum {
  TX_TRANSFER,
  TX_STAKE_DEPOSIT,
  TX_STAKE_WITHDRAW,
} tx_type;

typedef struct {
  unsigned char from[32];
  unsigned char to[32];
  unsigned char signature[64];
  uint64_t amount;
  uint64_t nonce;
  tx_type type;
} transaction;

// +4 for padding, + 3 for type->char
_Static_assert(sizeof(transaction) - 7 == TX_SIZE, "struct size mismatch");

int send_transaction(char **args, int fd, Wallet *wallet);
int serialize_tx(unsigned char *buff, transaction *tx, bool include_signature);
#endif
