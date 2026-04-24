#include "client.h"
#include "sodium.h"
#include "wallet.h"
#include <message.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int write_keys_to_file(FileEncryption *cipher, char wallet_loc[512]) {
  FILE *fptr;
  fptr = fopen(wallet_loc, "wb");
  if (fptr == NULL) {
    printf("Something went badly wrong...\n");
    return 1;
  }

  fwrite(cipher->salt, 1, crypto_pwhash_SALTBYTES, fptr);
  fwrite(cipher->nonce, 1, crypto_secretbox_NONCEBYTES, fptr);
  unsigned long long ciphertext_len = crypto_secretbox_MACBYTES + wallet_len;

  fwrite(cipher->CipherText, 1, ciphertext_len, fptr);
  fclose(fptr);
  free(cipher->CipherText);
  free(cipher->nonce);
  free(cipher->salt);
  free(cipher);
  return 0;
}

int get_password(char *password) {
  printf("Enter password: ");
  fgets(password, sizeof password, stdin);
  password[strcspn(password, "\n")] = '\0';
  return 1;
}

int init_wallet(Wallet *wallet, char walletLoc[512]) {
  const char *home = getenv("HOME");
  if (!home) {
    fprintf(stderr, "HOME not set\n");
    return 1;
  }
  if (strlen(walletLoc) == 0) {
    snprintf(walletLoc, 512, "%s/Documents/keys/wallet.coin", home);
  }
  FILE *fptr;
  fptr = fopen(walletLoc, "rb");
  char password[128];
  get_password(password);
  if (fptr == NULL) {
    printf("Creating wallet...\n");
    create_wallet(wallet, password);
    struct FileEncryption *file;
    file = malloc(sizeof(struct FileEncryption));
    encrypt_keys(wallet, password, file);
    return write_keys_to_file(file, walletLoc);
  } else {
    return decrypt_wallet(fptr, wallet, password);
  }
  return 0;
}
