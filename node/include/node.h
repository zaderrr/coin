#include <sys/poll.h>
#include <sys/types.h>

typedef struct Transaction {
  char From[32];
  char To[32];
  ulong amount;
  int nonce;
} Transaction;

typedef struct block {
  char validator[32];
  int transaction_count;
  Transaction *transactions;
  char previous_block[64];
} block;

unsigned char *get_public_key(unsigned char *buff);
unsigned char *handle_handshake(unsigned char *buff, struct pollfd client_fd);
