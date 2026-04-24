#include "wallet.h"
#include "ed25519.h"
#include "sys/random.h"
#include "util.h"
#include <blst.h>
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

int bls_keygen(blst_scalar *sk_out, blst_p2_affine *pk_out) { return 0; }

int generate_bls_keypair(unsigned char *sk_bytes, unsigned char *pk_bytes) {
  uint8_t ikm[32];

  if (getrandom(ikm, sizeof(ikm), 0) != (ssize_t)sizeof(ikm)) {
    return -1;
  }

  blst_scalar sk;
  blst_keygen(&sk, ikm, sizeof(ikm), NULL, 0);

  blst_p2_affine pk;

  blst_p2 pk_jacobian;
  blst_sk_to_pk_in_g2(&pk_jacobian, &sk);
  blst_p2_to_affine(&pk, &pk_jacobian);

  blst_bendian_from_scalar(sk_bytes, &sk);
  blst_p2_affine_compress(pk_bytes, &pk);

  memset(ikm, 0, sizeof(ikm));

  return 0;
}

int create_wallet(Wallet *wallet, char *password) {
  if (generate_wallet(wallet->public_key, wallet->private_key) != 1) {
    printf("problem generating wallet\n");
    return 1;
  }
  generate_bls_keypair(wallet->bls_sk, wallet->bls_pk);

  return 0;
}

int encrypt_keys(Wallet *wallet, char *password,
                 struct FileEncryption *cipher) {
  // public = 32, private = 64, bls pk = 96, bls sk = 32
  unsigned char message[wallet_len];

  Writer w = {message, message + wallet_len};
  WRITE_FIELD(&w, wallet->public_key, sizeof(wallet->public_key));
  WRITE_FIELD(&w, wallet->private_key, sizeof(wallet->private_key));
  WRITE_FIELD(&w, wallet->bls_pk, sizeof(wallet->bls_pk));
  WRITE_FIELD(&w, wallet->bls_sk, sizeof(wallet->bls_sk));

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

  unsigned long long ciphertext_len = crypto_secretbox_MACBYTES + wallet_len;
  cipher->CipherText = malloc(ciphertext_len);
  crypto_secretbox_easy(cipher->CipherText, (const unsigned char *)message,
                        wallet_len, cipher->nonce, key);
  return 1;
}

int decrypt_wallet(FILE *fptr, Wallet *wallet, char *password) {
  // Nonce = 24, Salt = 16, MAC = 16, Message = 32 + 64, + 96 + 32
  // Salt -> Nonce -> Cipher
  unsigned char salt[16];
  unsigned char nonce[24];
  unsigned char cipher[wallet_len + crypto_secretbox_MACBYTES];

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

  Reader r = {decrypted, decrypted + wallet_len};
  READ_FIELD(&r, wallet->public_key, sizeof(wallet->public_key));
  READ_FIELD(&r, wallet->private_key, sizeof(wallet->private_key));
  READ_FIELD(&r, wallet->bls_pk, sizeof(wallet->bls_pk));
  READ_FIELD(&r, wallet->bls_sk, sizeof(wallet->bls_sk));

  free(decrypted);
  return 0;
}
