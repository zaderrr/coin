#include "block.h"
#include "wallet.h"
int send_transaction(char **args, int fd, Wallet *wallet);
int write_tx_to_buff(unsigned char *buff, transaction *tx);
