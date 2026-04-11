#include "wallet.h"
#include "ed25519.h"
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/randombytes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int generate_wallet(unsigned char pub[32], unsigned char private[64]) {
  unsigned char seed[32];
  if (ed25519_create_seed(seed)) {
    printf("error while generating seed\n");
    return 0;
  }

  ed25519_create_keypair(pub, private, seed);
  return 1;
}

int create_wallet(Wallet *wallet, char *password) {
  unsigned char public_key[32];
  unsigned char private_key[64];
  if (generate_wallet(public_key, private_key) != 1) {
    printf("problem generating wallet\n");
    return 1;
  }
  wallet->public_key = malloc(32);
  wallet->private_key = malloc(64);
  memcpy(wallet->public_key, public_key, 32);
  memcpy(wallet->private_key, private_key, 64);

  return 0;
}

int encrypt_keys(unsigned char public_key[32], unsigned char private_key[64],
                 char *password, struct FileEncryption *cipher) {
  // public = 32, private = 64
  unsigned long long message_len = 32 + 64;
  unsigned char message[32 + 64];
  memcpy(message, public_key, 32);
  memcpy(message + 32, private_key, 64);
  cipher->salt = malloc(crypto_pwhash_SALTBYTES);
  unsigned char key[crypto_secretbox_KEYBYTES];
  randombytes_buf(cipher->salt, crypto_pwhash_SALTBYTES);

  if (crypto_pwhash(key, sizeof key, password, strlen(password), cipher->salt,
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    printf("Key derivation failed\n");
    return 0;
  }
  cipher->nonce = malloc(crypto_secretbox_NONCEBYTES);
  randombytes_buf(cipher->nonce, crypto_secretbox_NONCEBYTES);

  unsigned long long ciphertext_len = crypto_secretbox_MACBYTES + message_len;
  cipher->CipherText = malloc(ciphertext_len);
  crypto_secretbox_easy(cipher->CipherText, (const unsigned char *)message,
                        message_len, cipher->nonce, key);
  return 1;
}

int decrypt_wallet(FILE *fptr, Wallet *wallet, char *password) {

  // Nonce = 24, Salt = 16, MAC = 16, Message = 32 + 64, + 2 commas + 2 space
  // Salt -> Nonce -> Cipher
  unsigned char salt[16];
  unsigned char nonce[24];
  unsigned char cipher[112]; // 32 + 64

  fread(salt, 1, sizeof(salt), fptr);
  fread(nonce, 1, sizeof(nonce), fptr);
  fread(cipher, 1, sizeof(cipher), fptr);
  unsigned char key[crypto_secretbox_KEYBYTES];
  if (crypto_pwhash(key, sizeof key, password, strlen(password), salt,
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    printf("Key derivation failed\n");
    return 1;
  }
  int ciphertext_len = sizeof(cipher);
  unsigned long long decrypted_len = ciphertext_len - crypto_secretbox_MACBYTES;
  unsigned char *decrypted = malloc(decrypted_len);

  if (crypto_secretbox_open_easy(decrypted, cipher, ciphertext_len, nonce,
                                 key) != 0) {
    printf("Wrong password or tampered data\n");
    return 1;
  }
  wallet->public_key = malloc(32);
  wallet->private_key = malloc(64);

  memcpy(wallet->public_key, decrypted, 32);
  memcpy(wallet->private_key, &decrypted[32], 64);

  return 0;
}
