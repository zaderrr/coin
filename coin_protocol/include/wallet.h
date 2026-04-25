#include "blst.h"
#include <stdint.h>
#include <stdio.h>
#ifndef COIN_WALLET_H
#define COIN_WALLET_H

#define wallet_len 224
typedef struct FileEncryption {
  unsigned char *CipherText;
  unsigned char *nonce;
  unsigned char *salt;
} FileEncryption;

typedef struct Wallet {
  unsigned char public_key[32];
  unsigned char private_key[64];
  unsigned char bls_pk[96];
  unsigned char bls_sk[32];

  uint64_t balance;
  uint64_t nonce;
} Wallet;

int generate_wallet(unsigned char pub[32], unsigned char private[64]);
int encrypt_keys(Wallet *wallet, char *password, struct FileEncryption *cipher);
int create_wallet(Wallet *wallet, char *password);
int create_pop(Wallet *wallet, unsigned char *sig_out);
int bls_keygen(blst_scalar *sk_out, blst_p2_affine *pk_out);
int decrypt_wallet(FILE *fptr, Wallet *wallet, char *password);
#endif
