#include "transaction.h"
#include "block.h"
#include "ed25519.h"
#include "message.h"
#include "util.h"
#include "wallet.h"
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#define TX_DATA_SIZE 81 // 1 + 32 + 32 + 8 + 8

int get_tx_size(transaction *tx) {
  int size = 4 + 1 + 32 + 32 + 8 + 8 + 4 + tx->body_size + 64;
  return size;
}

// Writes `tx` to `buff`, `include_signature` writes the signature directly.
// Ensure buff is correct size before `include_signature` = true
// Note: TX_Size is serialized as part of the transaction
// and signed against.
int serialize_tx(Writer *w, transaction *tx, bool include_signature) {
  uint64_t amount_n = htonll(tx->amount);
  uint64_t nonce_n = htonll(tx->nonce);
  int body_len_n = htonl(tx->body_size);
  int tx_size = htonl(get_tx_size(tx));

  WRITE_FIELD(w, tx_size, sizeof(tx_size));
  WRITE_FIELD(w, tx->type, 1);
  WRITE_FIELD(w, tx->from, sizeof(tx->from));
  WRITE_FIELD(w, tx->to, sizeof(tx->to));
  WRITE_FIELD(w, amount_n, sizeof(amount_n));
  WRITE_FIELD(w, nonce_n, sizeof(nonce_n));
  WRITE_FIELD(w, tx->body_size, sizeof(tx->body_size));
  WRITE_FIELD(w, tx->body, tx->body_size);

  if (include_signature == true) {
    WRITE_FIELD(w, tx->signature, sizeof(tx->signature));
  }

  return 0;
}

// Writes signature of transaction to tx.signature and copies signature to buff
int sign_transaction(transaction *tx, Wallet *wallet, unsigned char *buff) {
  int tx_size = get_tx_size(tx);
  ed25519_sign(tx->signature, buff, tx_size - 64, wallet->public_key,
               wallet->private_key);
  memcpy(buff + (tx_size - 64), tx->signature, 64);
  return 0;
}

int create_tx(transaction *tx, unsigned char *to, Wallet *wallet,
              uint64_t amount, tx_type type) {
  tx->amount = amount;
  tx->type = type;
  tx->nonce = wallet->nonce;

  memcpy(tx->from, wallet->public_key, 32);
  memcpy(tx->to, to, 32);

  return 0;
}

// Read transaction from payload
int deserialize_tx(Reader *r, transaction *out) {
  transaction tx = {0};

  READ_FIELD(r, tx.type, 1);
  READ_FIELD(r, tx.from, sizeof(tx.from));
  READ_FIELD(r, tx.to, sizeof(tx.to));
  READ_FIELD(r, tx.amount, sizeof(tx.amount));
  READ_FIELD(r, tx.nonce, sizeof(tx.nonce));
  READ_FIELD(r, tx.body_size, sizeof(tx.body_size));
  READ_FIELD(r, tx.body, tx.body_size);
  READ_FIELD(r, tx.signature, sizeof(tx.signature));

  tx.nonce = htonll(tx.nonce);
  tx.body_size = ntohl(tx.body_size);
  tx.amount = htonll(tx.amount);
  *out = tx;
  return 0;
}

int send_transaction(transaction *tx, int fd, Wallet *wallet) {
  int tx_size = get_tx_size(tx);
  unsigned char tx_buff[tx_size];
  // Write tx to buffer + sign it.
  Writer w = {tx_buff, tx_buff + tx_size};
  serialize_tx(&w, tx, false);
  sign_transaction(tx, wallet, tx_buff);
  unsigned char buff[tx_size + HEADER_SIZE];
  create_message(TX_SUBMIT, tx_size, tx_buff, buff);
  send_message(sizeof(buff), buff, fd);
  wallet->nonce++;
  return 0;
}

int create_block_reward(unsigned char *to, transaction *tx) {
  memcpy(tx->to, to, 32);
  tx->amount = BLOCK_REWARD;
  tx->type = TX_REWARD;
  return 0;
}
