#include "transaction.h"
#include "util.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void test_serialize(void) {
  transaction tx = {0};
  tx.type = 0x01;
  memset(tx.from, 0xAA, 32);
  memset(tx.to, 0xBB, 32);
  tx.amount = 1000;
  tx.nonce = 42;

  unsigned char buf[256] = {0};
  int tx_size = get_tx_size(&tx);
  Writer w = {buf, buf + tx_size};
  int ret = serialize_tx(&w, &tx, false);

  assert(ret == 0);
  // type at offset 5
}

int main(void) {
  printf("Transaction client tests:\n");
  test_serialize();
  printf("all passed\n");
  return 0;
}
