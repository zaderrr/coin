#include "wallet.h"
#include <protocol.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/poll.h>
enum command_type {
  BALNCE,
  SEND,
  PEERS,
};

typedef struct {
  enum command_type type;
  int arg_count;
  char **args;
} command;

int connect_to_node(Peer peer, unsigned char *public_key);
int generate_wallet(unsigned char pub[32], unsigned char private[64]);
int encrypt_keys(unsigned char public_key[32], unsigned char private_key[64],
                 char *password, struct FileEncryption *cipher);
int write_keys_to_file(FileEncryption *cipher, char wallet_loc[512]);
int create_wallet(Wallet *wallet, char *password);
int decrypt_wallet(FILE *fptr, Wallet *wallet, char *password);
int peer_message(struct pollfd *srv, Wallet *wallet);
int listen_for_command(struct pollfd *infd, command *cmd);
int listen_to_node(struct pollfd *srv);
int read_friends(char *file_location, char *friends);
int init_wallet(Wallet *wallet, char wallet_loc[512]);
void execute_command(command *cmd, int fd, Wallet *wallet);
