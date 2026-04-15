#include "transaction.h"
#include "block.h"
#include "ed25519.h"
#include "message.h"
#include "util.h"
#include "wallet.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define TX_DATA_SIZE 81 // 1 + 32 + 32 + 8 + 8

// Writes `tx` to `buff`, `include_signature` writes the signature directly.
// Ensure buff is correct size before `include_signature` = true
int serialize_tx(unsigned char *buff, transaction *tx, bool include_signature) {
  uint64_t amount_n = htonll(tx->amount);
  uint64_t nonce_n = htonll(tx->nonce);
  memcpy(buff, &tx->type, 1);
  memcpy(buff + 1, tx->from, 32);
  memcpy(buff + 33, tx->to, 32);
  memcpy(buff + 65, &amount_n, 8);
  memcpy(buff + 73, &nonce_n, 8);

  if (include_signature == true) {
    memcpy(buff + 81, tx->signature, 64);
  }

  return 0;
}

// Writes signature of transaction to tx.signature and copies signature to buff
int sign_transaction(transaction *tx, Wallet *wallet, unsigned char *buff) {
  ed25519_sign(tx->signature, buff, TX_DATA_SIZE, wallet->public_key,
               wallet->private_key);
  memcpy(buff + TX_DATA_SIZE, tx->signature, 64);
  return 0;
}

// Create transaction from args
transaction create_tx(char **args, Wallet *wallet) {
  uint64_t amount = strtoull(args[0], NULL, 10);

  transaction tx = {0};
  tx.amount = amount;
  tx.type = TX_TRANSFER;

  // TODO: Sync nonce from server
  tx.nonce = wallet->nonce;
  memcpy(tx.from, wallet->public_key, 32);
  memcpy(tx.to, args[1], 32);

  return tx;
}
// Read transaction from payload
transaction deserialize_tx(unsigned char *payload) {
  // Acknowledged that this is very fragile
  transaction tx = {0};
  memcpy(&tx.type, payload, 1);
  read_public_key(payload + 1, tx.from);
  read_public_key(payload + 33, tx.to);
  tx.amount = read_uint_64(payload + 65);
  tx.nonce = read_uint_64(payload + 73);
  read_signature(payload + 81, tx.signature);

  return tx;
}

int send_transaction(char **args, int fd, Wallet *wallet) {
  transaction tx = create_tx(args, wallet);
  unsigned char tx_buff[TX_SIZE];
  // Write tx to buffer + sign it.
  serialize_tx(tx_buff, &tx, false);
  sign_transaction(&tx, wallet, tx_buff);

  unsigned char buff[TX_SIZE + 5];
  create_message(TX_SUBMIT, TX_SIZE, tx_buff, buff);
  send_message(sizeof(buff), buff, fd);
  free(args[0]);
  free(args[1]);
  wallet->nonce++;
  return 0;
}
