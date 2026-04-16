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
int serialize_tx(Writer *w, transaction *tx, bool include_signature) {
  uint64_t amount_n = htonll(tx->amount);
  uint64_t nonce_n = htonll(tx->nonce);

  WRITE_FIELD(w, tx->type, 1);
  WRITE_FIELD(w, tx->from, sizeof(tx->from));
  WRITE_FIELD(w, tx->to, sizeof(tx->to));
  WRITE_FIELD(w, amount_n, sizeof(amount_n));
  WRITE_FIELD(w, nonce_n, sizeof(nonce_n));

  if (include_signature == true) {
    WRITE_FIELD(w, tx->signature, sizeof(tx->signature));
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
int deserialize_tx(Reader *r, transaction *out) {
  transaction tx = {0};
  READ_FIELD(r, tx.type, 1);
  READ_FIELD(r, tx.from, sizeof(tx.from));
  READ_FIELD(r, tx.to, sizeof(tx.to));
  READ_FIELD(r, tx.amount, sizeof(tx.amount));
  READ_FIELD(r, tx.nonce, sizeof(tx.nonce));
  READ_FIELD(r, tx.signature, sizeof(tx.signature));

  tx.nonce = htonll(tx.nonce);
  tx.amount = htonll(tx.amount);
  memcpy(out, &tx, TX_SIZE);
  return 0;
}

int send_transaction(char **args, int fd, Wallet *wallet) {
  transaction tx = create_tx(args, wallet);
  unsigned char tx_buff[TX_SIZE];
  // Write tx to buffer + sign it.
  Writer w = {tx_buff, tx_buff + TX_SIZE};
  serialize_tx(&w, &tx, false);
  sign_transaction(&tx, wallet, tx_buff);

  unsigned char buff[TX_SIZE + 5];
  create_message(TX_SUBMIT, TX_SIZE, tx_buff, buff);
  send_message(sizeof(buff), buff, fd);
  free(args[0]);
  free(args[1]);
  wallet->nonce++;
  return 0;
}
