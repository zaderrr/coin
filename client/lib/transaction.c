#include "block.h"
#include "ed25519.h"
#include "message.h"
#include "protocol.h"
#include "wallet.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define TX_DATA_SIZE 81 // 1 + 32 + 32 + 8 + 8

int write_tx_to_buff(unsigned char *buff, transaction *tx) {
  uint64_t amount_n = htonll(tx->amount);
  uint64_t nonce_n = htonll(tx->nonce);
  memcpy(buff, &tx->type, 1);
  memcpy(buff + 1, tx->from, 32);
  memcpy(buff + 33, tx->to, 32);
  memcpy(buff + 65, &amount_n, 8);
  memcpy(buff + 73, &nonce_n, 8);
  // Signature coppied during signing
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

int send_transaction(char **args, int fd, Wallet *wallet) {
  transaction tx = create_tx(args, wallet);

  unsigned char tx_buff[sizeof(transaction)];
  // Write tx to buffer + sign it.
  write_tx_to_buff(tx_buff, &tx);
  sign_transaction(&tx, wallet, tx_buff);

  int32_t payload_len = sizeof(transaction);
  unsigned char buff[256];
  create_message(TX_SUBMIT, payload_len, tx_buff, buff);
  send_message(payload_len, buff, fd);
  free(args[0]);
  free(args[1]);
  wallet->nonce++;
  return 0;
}
