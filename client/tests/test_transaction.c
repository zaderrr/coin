#include "protocol.h"
#include "transaction.h"
#include "util.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void test_write_tx_to_buff(void) {
  transaction tx = {0};
  tx.type = 0x01;
  memset(tx.from, 0xAA, 32);
  memset(tx.to, 0xBB, 32);
  tx.amount = 1000;
  tx.nonce = 42;

  unsigned char buf[256] = {0};
  int ret = write_tx_to_buff(buf, &tx);
  assert(ret == 0);

  // type at offset 0
  assert(buf[0] == 0x01);

  // from at offset 1
  for (int i = 0; i < 32; i++)
    assert(buf[1 + i] == 0xAA);

  // to at offset 33
  for (int i = 0; i < 32; i++)
    assert(buf[33 + i] == 0xBB);

  // amount at offset 65, network byte order
  uint64_t amount_out;
  memcpy(&amount_out, buf + 65, 8);
  assert(htonll(amount_out) == 1000);

  // nonce at offset 73, network byte order
  uint64_t nonce_out;
  memcpy(&nonce_out, buf + 73, 8);
  assert(htonll(nonce_out) == 42);

  printf("  PASS: write_tx_to_buff\n");
}

int main(void) {
  printf("Transaction client tests:\n");
  test_write_tx_to_buff();
  printf("all passed\n");
  return 0;
}
