#include <stdio.h>

#ifndef COIN_WALLET_H
#define COIN_WALLET_H

typedef struct FileEncryption {
  unsigned char *CipherText;
  unsigned char *nonce;
  unsigned char *salt;
} FileEncryption;

typedef struct Wallet {
  unsigned char *public_key;
  unsigned char *private_key;
} Wallet;
int generate_wallet(unsigned char pub[32], unsigned char private[64]);
int encrypt_keys(unsigned char public_key[32], unsigned char private_key[64],
                 char *password, struct FileEncryption *cipher);
int write_keys_to_file(FileEncryption *cipher);
int create_wallet(Wallet *wallet, char *password);
int decrypt_wallet(FILE *fptr, Wallet *wallet, char *password);
#endif
