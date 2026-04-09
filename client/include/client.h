#include <protocol.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/poll.h>
typedef struct FileEncryption {
  unsigned char *CipherText;
  unsigned char *nonce;
  unsigned char *salt;
} FileEncryption;

typedef struct Wallet {
  unsigned char *public_key;
  unsigned char *private_key;

} Wallet;

int connect_to_node(Peer peer, unsigned char *public_key);
int generate_wallet(unsigned char pub[32], unsigned char private[64]);
int encrypt_keys(unsigned char public_key[32], unsigned char private_key[64],
                 char *password, struct FileEncryption *cipher);
int write_keys_to_file(FileEncryption *cipher);
int create_wallet(Wallet *wallet, char *password);
int decrypt_wallet(FILE *fptr, Wallet *wallet, char *password);
int32_t *read_balance(unsigned char *balance);
int handle_init_balance(unsigned char *balance, struct pollfd client_fd);
int listen_to_node(struct pollfd *srv);
int read_friends(char *file_location, char *friends);
int init_wallet(Wallet *wallet);
