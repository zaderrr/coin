#include "command.h"
#include "wallet.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/poll.h>
int generate_wallet(unsigned char pub[32], unsigned char private[64]);
int encrypt_keys(Wallet *wallet, char *password, struct FileEncryption *cipher);
int write_keys_to_file(FileEncryption *cipher, char wallet_loc[512]);
int create_wallet(Wallet *wallet, char *password);
int decrypt_wallet(FILE *fptr, Wallet *wallet, char *password);
int init_wallet(Wallet *wallet, char wallet_loc[512]);
