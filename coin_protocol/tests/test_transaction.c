#include "transaction.h"
#include "util.h"
#include "validation.h"
#include "wallet.h"
#include <arpa/inet.h>
#include <assert.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RUN_TEST(t)                                                            \
  do {                                                                         \
    printf("[ RUN  ] %s\n", #t);                                               \
    t();                                                                       \
    printf("[  OK  ] %s\n", #t);                                               \
  } while (0)

static transaction *alloc_tx(int32_t body_size) {
  transaction *tx = calloc(1, sizeof(transaction) + body_size);
  tx->body_size = body_size;
  return tx;
}

static transaction *make_stake_request(Wallet *wallet, uint64_t amount,
                                       uint64_t nonce, unsigned char *out_buff,
                                       int *out_size) {
  transaction *tx = alloc_tx(0);
  tx->type = TX_STAKE_DEPOSIT;
  tx->amount = amount;
  tx->nonce = nonce;
  memcpy(tx->from, wallet->public_key, 32);

  int size = get_tx_size(tx);
  Writer w = {out_buff, out_buff + size};
  assert(serialize_tx(&w, tx, false) == 0);
  assert(sign_transaction(tx, wallet, out_buff) == 0);
  *out_size = size;
  return tx;
}

static transaction *make_signed_transfer(Wallet *wallet, uint8_t to[32],
                                         uint64_t amount, uint64_t nonce,
                                         unsigned char *out_buff, int *out_size,
                                         int body_size, uint8_t *body,
                                         tx_type type) {
  transaction *tx = alloc_tx(body_size);
  tx->type = type;
  tx->amount = amount;
  tx->nonce = nonce;

  memcpy(tx->from, wallet->public_key, 32);
  memcpy(tx->to, to, 32);
  memcpy(tx->body, body, body_size);

  int size = get_tx_size(tx);
  Writer w = {out_buff, out_buff + size};
  assert(serialize_tx(&w, tx, false) == 0);
  assert(sign_transaction(tx, wallet, out_buff) == 0);
  *out_size = size;
  return tx;
}

static void test_get_tx_size_no_body(void) {
  transaction *tx = alloc_tx(0);
  // 4 (size) + 1 (type) + 32 (from) + 32 (to) + 8 (amount)
  // + 8 (nonce) + 4 (body_size) + 0 (body) + 64 (sig) = 153
  assert(get_tx_size(tx) == 153);
  free(tx);
}

static void test_get_tx_size_with_stake_body(void) {
  transaction *tx = alloc_tx(sizeof(tx_stake_body)); // 96 + 48 = 144
  assert(get_tx_size(tx) == 153 + 144);
  free(tx);
}

static void test_create_block_reward(void) {
  transaction *tx = alloc_tx(0);
  uint8_t to[32];
  for (int i = 0; i < 32; i++)
    to[i] = (uint8_t)(i + 1);

  assert(create_block_reward(to, tx) == 0);
  assert(tx->type == TX_REWARD);
  assert(tx->amount == BLOCK_REWARD);
  assert(memcmp(tx->to, to, 32) == 0);
  free(tx);
}

static void test_serialize_tx_roundtrip_no_body(void) {
  transaction *tx = alloc_tx(0);
  tx->type = TX_TRANSFER;
  tx->amount = 0xDEADBEEF;
  tx->nonce = 7;
  for (int i = 0; i < 32; i++) {
    tx->from[i] = (uint8_t)(0xA0 | i);
    tx->to[i] = (uint8_t)(0xB0 | i);
  }
  for (int i = 0; i < 64; i++)
    tx->signature[i] = (uint8_t)i;

  int size = get_tx_size(tx);
  unsigned char buff[size];
  Writer w = {buff, buff + size};
  assert(serialize_tx(&w, tx, true) == 0);

  // The wire format starts with a 4-byte network-order tx_size; deserialize_tx
  // expects the reader to be positioned past it (matches handle_tx).
  Reader r = {buff, buff + size};
  uint32_t prefix = 0;
  assert(read_bytes(&r, &prefix, sizeof(prefix)) == 1);
  assert((int)ntohl(prefix) == size);

  transaction *decoded = alloc_tx(0);
  assert(deserialize_tx(&r, decoded) == 0);

  assert(decoded->type == tx->type);
  assert(decoded->amount == tx->amount);
  assert(decoded->nonce == tx->nonce);
  assert(decoded->body_size == 0);
  assert(memcmp(decoded->from, tx->from, 32) == 0);
  assert(memcmp(decoded->to, tx->to, 32) == 0);
  assert(memcmp(decoded->signature, tx->signature, 64) == 0);

  free(tx);
  free(decoded);
}

static void test_serialize_tx_roundtrip_with_body(void) {
  int32_t body_size = (int32_t)sizeof(tx_stake_body);
  transaction *tx = alloc_tx(body_size);
  tx->type = TX_STAKE_DEPOSIT;
  tx->amount = 1000;
  tx->nonce = 0;
  for (int i = 0; i < body_size; i++)
    tx->body[i] = (uint8_t)(0x55 ^ i);

  int size = get_tx_size(tx);
  unsigned char buff[size];
  Writer w = {buff, buff + size};
  assert(serialize_tx(&w, tx, true) == 0);

  Reader r = {buff, buff + size};
  uint32_t prefix = 0;
  read_bytes(&r, &prefix, sizeof(prefix));

  transaction *decoded = alloc_tx(body_size);
  assert(deserialize_tx(&r, decoded) == 0);

  assert(decoded->body_size == body_size);
  assert(memcmp(decoded->body, tx->body, (size_t)body_size) == 0);

  free(tx);
  free(decoded);
}

static void test_sign_and_verify_transaction(void) {
  Wallet wallet = {0};
  assert(create_wallet(&wallet) == 0);

  uint8_t to[32];
  for (int i = 0; i < 32; i++)
    to[i] = (uint8_t)(0x10 | i);

  unsigned char buff[153];
  int size = 0;
  transaction *tx = make_signed_transfer(&wallet, to, 42, 0, buff, &size, 0,
                                         NULL, TX_TRANSFER);
  assert(size == 153);

  assert(verify_transaction(buff, tx) == 1);

  // Alter message from what was signed
  buff[0] ^= 0xFF;
  assert(verify_transaction(buff, tx) != 1);

  free(tx);
}

static void test_get_stake_body(void) {
  int32_t body_size = (int32_t)sizeof(tx_stake_body);
  transaction *tx = alloc_tx(body_size);
  tx->type = TX_STAKE_DEPOSIT;

  // Pack a known pattern into the body
  for (int i = 0; i < 96; i++)
    tx->body[i] = (uint8_t)(0xAA ^ i);
  for (int i = 0; i < 48; i++)
    tx->body[96 + i] = (uint8_t)(0xBB ^ i);

  tx_stake_body decoded = {0};
  assert(get_stake_body(tx, &decoded) == 0);

  for (int i = 0; i < 96; i++)
    assert(decoded.bls_pk[i] == (uint8_t)(0xAA ^ i));
  for (int i = 0; i < 48; i++)
    assert(decoded.pop[i] == (uint8_t)(0xBB ^ i));

  free(tx);
}

static void test_valid_nonce(void) {
  account acc = {.nonce = 5};
  transaction *tx = alloc_tx(0);
  tx->type = TX_TRANSFER;
  tx->nonce = 5;
  assert(valid_nonce(&acc, tx) == 0);

  tx->nonce = 4;
  assert(valid_nonce(&acc, tx) == 1);

  // Reward tx is exempt from the nonce check
  tx->type = TX_REWARD;
  tx->nonce = 999;
  assert(valid_nonce(&acc, tx) == 0);

  free(tx);
}

static void test_validate_funds(void) {
  account acc = {.balance = 100};
  transaction *tx = alloc_tx(0);
  tx->amount = 50;
  assert(validate_funds(&acc, NULL, tx) == 0);

  tx->amount = 150;
  assert(validate_funds(&acc, NULL, tx) == 1);

  free(tx);
}

int main(void) {
  if (sodium_init() < 0) {
    fprintf(stderr, "sodium_init failed\n");
    return 1;
  }

  RUN_TEST(test_get_tx_size_no_body);
  RUN_TEST(test_get_tx_size_with_stake_body);
  RUN_TEST(test_create_block_reward);
  RUN_TEST(test_serialize_tx_roundtrip_no_body);
  RUN_TEST(test_serialize_tx_roundtrip_with_body);
  RUN_TEST(test_sign_and_verify_transaction);
  RUN_TEST(test_get_stake_body);
  RUN_TEST(test_valid_nonce);
  RUN_TEST(test_validate_funds);
  printf("All transaction tests passed.\n");
  return 0;
}
