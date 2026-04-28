#include "block.h"
#include "genesis.h"
#include "merkle.h"
#include "state.h"
#include "transaction.h"
#include "wallet.h"
#include <assert.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// validate_previous_hash isn't exposed in block.h — declare locally.
int validate_previous_hash(block *val_block, block *prev_block);

// Header wire size: 5*32 + 64 + 2*8 + 2*4 = 248
#define BLOCK_HEADER_WIRE_SIZE 248

#define RUN_TEST(t)                                                            \
  do {                                                                         \
    printf("[ RUN  ] %s\n", #t);                                               \
    t();                                                                       \
    printf("[  OK  ] %s\n", #t);                                               \
  } while (0)

static transaction *make_unsigned_transfer(uint8_t from[32], uint8_t to[32],
                                           uint64_t amount, uint64_t nonce) {
  transaction *tx = calloc(1, sizeof(transaction));
  tx->type = TX_TRANSFER;
  tx->amount = amount;
  tx->nonce = nonce;
  tx->body_size = 0;
  memcpy(tx->from, from, 32);
  memcpy(tx->to, to, 32);
  return tx;
}

static void test_block_size_empty(void) {
  block b = {0};
  assert(get_block_size(&b) == BLOCK_HEADER_WIRE_SIZE);
}

static void test_block_size_null_returns_negative(void) {
  assert(get_block_size(NULL) == -1);
}

static void test_block_size_grows_with_tx_size(void) {
  block b = {0};
  b.tx_size = 153; // 1 reward tx, no body
  assert(get_block_size(&b) == BLOCK_HEADER_WIRE_SIZE + 153);
  b.tx_size = 153 * 4;
  assert(get_block_size(&b) == BLOCK_HEADER_WIRE_SIZE + 612);
}

static void test_hash_block_deterministic(void) {
  block b = {.height = 7, .timestamp = 1700000000};
  unsigned char h1[32];
  unsigned char h2[32];
  hash_block(&b, h1);
  hash_block(&b, h2);
  assert(memcmp(h1, h2, 32) == 0);
}

static void test_hash_block_changes_with_field(void) {
  block a = {.height = 1, .timestamp = 100};
  block b = {.height = 2, .timestamp = 100};
  unsigned char ha[32];
  unsigned char hb[32];
  hash_block(&a, ha);
  hash_block(&b, hb);
  assert(memcmp(ha, hb, 32) != 0);

  // Bumping a non-hashed field (tx_count) must NOT change the hash
  block c = a;
  c.tx_count = 99;
  unsigned char hc[32];
  hash_block(&c, hc);
  assert(memcmp(ha, hc, 32) == 0);
}

static void test_serialize_block_roundtrip_no_tx(void) {
  block original = {
      .height = 42, .timestamp = 1700000000, .tx_count = 0, .tx_size = 0};
  for (int i = 0; i < 32; i++) {
    original.prev_hash[i] = (uint8_t)i;
    original.state_root[i] = (uint8_t)(i + 1);
    original.validator_root[i] = (uint8_t)(i + 2);
    original.tx_root[i] = (uint8_t)(i + 3);
    original.proposer[i] = (uint8_t)(i + 4);
  }
  for (int i = 0; i < 64; i++) {
    original.signature[i] = (uint8_t)(0x80 | i);
  }

  int size = get_block_size(&original);
  unsigned char buff[size];
  assert(serialize_block(&original, buff, true) == 0);

  block decoded = {0};
  assert(deserialize_block(buff, size, &decoded) == 0);

  assert(decoded.height == original.height);
  assert(decoded.timestamp == original.timestamp);
  assert(decoded.tx_count == 0);
  assert(decoded.tx_size == 0);
  assert(memcmp(decoded.prev_hash, original.prev_hash, 32) == 0);
  assert(memcmp(decoded.state_root, original.state_root, 32) == 0);
  assert(memcmp(decoded.validator_root, original.validator_root, 32) == 0);
  assert(memcmp(decoded.tx_root, original.tx_root, 32) == 0);
  assert(memcmp(decoded.proposer, original.proposer, 32) == 0);
  assert(memcmp(decoded.signature, original.signature, 64) == 0);

  free(decoded.transactions);
}

static void test_serialize_block_roundtrip_with_txs(void) {
  uint8_t alice[32];
  uint8_t bob[32];
  uint8_t carol[32];
  for (int i = 0; i < 32; i++) {
    alice[i] = 0xA0 | i;
    bob[i] = 0xB0 | i;
    carol[i] = 0xC0 | i;
  }

  transaction *t1 = make_unsigned_transfer(alice, bob, 100, 0);
  transaction *t2 = make_unsigned_transfer(alice, carol, 250, 1);
  for (int i = 0; i < 64; i++) {
    t1->signature[i] = (uint8_t)i;
    t2->signature[i] = (uint8_t)(i + 1);
  }

  block original = {.height = 5, .timestamp = 1700001234, .tx_count = 2};
  original.tx_size = get_tx_size(t1) + get_tx_size(t2);
  transaction *txs[2] = {t1, t2};
  original.transactions = txs;

  int size = get_block_size(&original);
  unsigned char buff[size];
  assert(serialize_block(&original, buff, true) == 0);

  block decoded = {0};
  assert(deserialize_block(buff, size, &decoded) == 0);

  assert(decoded.tx_count == 2);
  assert(decoded.tx_size == original.tx_size);
  assert(memcmp(decoded.transactions[0]->from, alice, 32) == 0);
  assert(memcmp(decoded.transactions[0]->to, bob, 32) == 0);
  assert(decoded.transactions[0]->amount == 100);
  assert(decoded.transactions[0]->nonce == 0);
  assert(decoded.transactions[1]->amount == 250);
  assert(decoded.transactions[1]->nonce == 1);

  for (uint32_t i = 0; i < decoded.tx_count; i++) {
    free(decoded.transactions[i]);
  }
  free(decoded.transactions);
  free(t1);
  free(t2);
}

static void test_sign_and_verify_block(void) {
  Wallet wallet = {0};
  assert(create_wallet(&wallet) == 0);

  block b = {.height = 9, .timestamp = 1700000000, .tx_count = 0, .tx_size = 0};
  memcpy(b.proposer, wallet.public_key, 32);

  int size = get_block_size(&b);
  unsigned char serialized[size];
  assert(serialize_block(&b, serialized, false) == 0);
  assert(sign_block(&b, serialized, size, &wallet) == 0);

  // verify_block expects a buffer that includes the signature (last 64 bytes).
  // sign_block already wrote it into `serialized`.
  assert(verify_block(serialized, &b, size) == 1);

  // Tamper with the payload: signature must no longer verify
  serialized[0] ^= 0xFF;
  assert(verify_block(serialized, &b, size) != 1);
}

static void test_validate_previous_hash(void) {
  block prev = {.height = 0, .timestamp = 1};
  block next = {.height = 1, .timestamp = 2};
  assert(hash_block(&prev, next.prev_hash) == 0);
  assert(validate_previous_hash(&next, &prev) == 0);

  // Tamper: prev_hash mismatch must return non-zero
  next.prev_hash[0] ^= 0x01;
  assert(validate_previous_hash(&next, &prev) == 1);
}

int main(void) {
  if (sodium_init() < 0) {
    fprintf(stderr, "sodium_init failed\n");
    return 1;
  }

  RUN_TEST(test_block_size_empty);
  RUN_TEST(test_block_size_null_returns_negative);
  RUN_TEST(test_block_size_grows_with_tx_size);
  RUN_TEST(test_hash_block_deterministic);
  RUN_TEST(test_hash_block_changes_with_field);
  RUN_TEST(test_serialize_block_roundtrip_no_tx);
  RUN_TEST(test_serialize_block_roundtrip_with_txs);
  RUN_TEST(test_sign_and_verify_block);
  RUN_TEST(test_validate_previous_hash);
  printf("All block tests passed.\n");
  return 0;
}
