#include "client.h"
#include "ed25519.h"
#include "sodium.h"
#include <arpa/inet.h>
#include <message.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define PUB_KEY_LEN 32
#define PORT 8080

int connect_to_node(unsigned char *public_key) {
  int status, valread, client_fd;
  struct sockaddr_in serv_addr;
  if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Socket creation error \n");
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);

  if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
    printf("\nInvalid address/ Address not supported \n");
    return -1;
  }

  if ((status = connect(client_fd, (struct sockaddr *)&serv_addr,
                        sizeof(serv_addr))) < 0) {
    printf("\nConnection Failed \n");
    return -1;
  }
  unsigned char buffer[1024];
  // Write public key to buffer and send
  write_header(HANDSHAKE, PUB_KEY_LEN, buffer);
  memcpy(buffer + 5, public_key, PUB_KEY_LEN);
  send(client_fd, buffer, 1024, 0);
  return client_fd;
}

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
    return 0;
  }
  printf("Wallet created!:)\n");
  struct FileEncryption *file;
  file = malloc(sizeof(struct FileEncryption));
  encrypt_keys(public_key, private_key, password, file);
  wallet->public_key = malloc(32);
  wallet->private_key = malloc(64);
  memcpy(wallet->public_key, public_key, 32);
  memcpy(wallet->private_key, private_key, 64);
  write_keys_to_file(file);
  free(file);
  return 1;
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

int write_keys_to_file(FileEncryption *cipher) {
  const char *home = getenv("HOME");
  if (!home) {
    fprintf(stderr, "HOME not set\n");
    return 1;
  }

  char walletLoc[512];
  snprintf(walletLoc, sizeof walletLoc, "%s/Documents/keys/wallet.coin", home);
  FILE *fptr;
  fptr = fopen(walletLoc, "wb");
  if (fptr == NULL) {
    printf("Something went badly wrong...\n");
    return 0;
  }
  fwrite(cipher->salt, 1, crypto_pwhash_SALTBYTES, fptr);
  fwrite(cipher->nonce, 1, crypto_secretbox_NONCEBYTES, fptr);
  unsigned long long ciphertext_len = crypto_secretbox_MACBYTES + 32 + 64;
  fwrite(cipher->CipherText, 1, ciphertext_len, fptr);
  fclose(fptr);

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

int32_t *read_balance(unsigned char *balance) {
  int32_t *bal = malloc(4);
  memcpy(bal, balance, 4);
  *bal = ntohl(*bal);
  return bal;
}
int handle_init_balance(unsigned char *balance, struct pollfd client_fd) {
  int32_t *bal = read_balance(balance);
  printf("Balance: %d\n", *bal);
  return 0;
}

int read_friends(char *file_location, char *friends) {
  FILE *fptr;
  fptr = fopen(file_location, "r+");
  if (fptr == NULL) {
    printf("Couldn't open friend list");
    return 1;
  }
  char buff[1024];
  fgets(buff, 1024, fptr);
  printf("%s", buff);
  return 0;
}

int handle_decoded(Message *message, struct pollfd client_fd) {
  switch (message->header->type) {
  case INIT_BALANCE: {
    handle_init_balance(message->payload, client_fd);
  }
  default: {
    break;
  }
  }
  return 0;
}

int listen_to_node(struct pollfd *srv) {
  int ready = poll(srv, 1, -1);
  if (ready < 0) {
    perror("poll");
    return 1;
  }
  if ((srv->revents & POLLIN)) {
    unsigned char buf[4096];
    ssize_t n = recv(srv->fd, buf, sizeof(buf), 0);
    if (n <= 0) {
      close(srv->fd);
    } else {
      buf[n] = '\0';
      printf("Message received\n");
      Message *message;
      decode_message(buf, &message);
      handle_decoded(message, *srv);
      free(message->payload);
      free(message->header);
      free(message);
    }
  }
  return 0;
}

int get_password(char *password) {
  printf("Enter password: ");
  fgets(password, sizeof password, stdin);
  password[strcspn(password, "\n")] = '\0';
  return 1;
}

int init_wallet(Wallet *wallet) {
  char walletLoc[512];
  const char *home = getenv("HOME");
  if (!home) {
    fprintf(stderr, "HOME not set\n");
    return 1;
  }
  snprintf(walletLoc, sizeof walletLoc, "%s/Documents/keys/wallet.coin", home);
  FILE *fptr;
  fptr = fopen(walletLoc, "rb");
  char password[128];
  get_password(password);
  if (fptr == NULL) {
    printf("Creating wallet...\n");
    create_wallet(wallet, password);
  } else {
    decrypt_wallet(fptr, wallet, password);
  }
  return 0;
}
